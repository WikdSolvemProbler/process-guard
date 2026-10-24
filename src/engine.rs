// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! The engine: one command in a job object, a deadline, and the cleanup of
//! every process in the job.

use crate::auth;
use crate::extend::{
    enclosed, next_token, not_started_text, open_log, register_start, release, write_standard_error, Extension, Log, Settings, Token, BACKSTOP_MS,
    CHANNEL_VARIABLE, DEFAULT_MAX_EXTENSION, LOG_FLUSH_MS,
};
use crate::sys::*;
use crate::GuardError;
use std::ffi::c_void;

/// The identifiers of the processes in the job, those in jobs nested in it
/// included; None when the list cannot be read. The list is
/// JOBOBJECT_BASIC_PROCESS_ID_LIST: two 32 bit counts, then pointer sized IDs.
pub fn job_process_ids(job: Handle) -> Option<Vec<u32>> {
    // Grow the buffer until the whole list fits (the call fails with more data otherwise).
    let mut capacity = 1024usize;
    let mut list;
    let mut ok;
    loop {
        list = vec![0usize; 1 + capacity];
        ok = unsafe {
            QueryInformationJobObject(job, PROCESS_ID_LIST_CLASS, list.as_mut_ptr() as *mut c_void,
                (list.len() * std::mem::size_of::<usize>()) as u32, std::ptr::null_mut())
        };
        let assigned = (list[0] as u64 & 0xffff_ffff) as usize;
        if ok != 0 || assigned <= capacity || capacity >= 1 << 20 {
            break;
        }
        capacity = (assigned + 256).next_power_of_two();
    }
    if ok == 0 {
        return None;
    }
    let count = ((list[0] as u64) >> 32) as usize;
    Some(list.iter().skip(1).take(count.min(capacity)).map(|&id| id as u32).collect())
}

/// Terminate every process in the job and wait, at most `milliseconds`, until
/// each has fully exited. Termination is asynchronous, so without this the
/// guard could return while a descendant is still exiting. Processes are
/// opened before termination so each one can be waited on by handle.
fn terminate_and_wait(job: Handle, code: u32, milliseconds: u32) {
    let mut members: Vec<Handle> = Vec::new();
    for id in job_process_ids(job).unwrap_or_default() {
        let handle = unsafe { OpenProcess(SYNCHRONIZE, 0, id) };
        if !handle.is_null() {
            members.push(handle);
        }
    }
    unsafe { TerminateJobObject(job, code) };
    let start = std::time::Instant::now();
    for handle in members {
        let spent = start.elapsed().as_millis() as u32;
        unsafe {
            WaitForSingleObject(handle, milliseconds.saturating_sub(spent));
            CloseHandle(handle);
        }
    }
    let spent = start.elapsed().as_millis() as u32;
    wait_until_empty(job, milliseconds.saturating_sub(spent));
}

/// Wait, at most `milliseconds`, until the job reports no active process.
fn wait_until_empty(job: Handle, milliseconds: u32) {
    let mut waited = 0;
    loop {
        let mut info = BasicAccountingInformation::default();
        let ok = unsafe {
            QueryInformationJobObject(job, BASIC_ACCOUNTING_CLASS, &mut info as *mut _ as *mut c_void,
                std::mem::size_of::<BasicAccountingInformation>() as u32, std::ptr::null_mut())
        };
        if ok == 0 || info.active_processes == 0 || waited >= milliseconds {
            return;
        }
        unsafe { Sleep(10) };
        waited += 10;
    }
}

/// Locate an executable as the PATH search does, honouring PATHEXT. This finds
/// the program the caller asked to run and the shell the guard chooses, as in 1.x;
/// the guard's own files are never found this way.
pub fn which(name: &str) -> Option<String> {
    use std::path::{Path, PathBuf};
    let pathext: Vec<String> = std::env::var("PATHEXT")
        .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
        .split(';').filter(|e| !e.is_empty()).map(|e| e.to_ascii_lowercase()).collect();
    let lower = name.to_ascii_lowercase();
    let candidates: Vec<String> = if pathext.iter().any(|e| lower.ends_with(e.as_str())) {
        vec![name.to_string()]
    } else {
        pathext.iter().map(|e| format!("{}{}", name, e)).collect()
    };
    let is_file = |p: &Path| p.is_file();
    if name.contains('/') || name.contains('\\') {
        return candidates.iter().map(PathBuf::from).find(|p| is_file(p)).map(|p| p.to_string_lossy().into_owned());
    }
    let mut dirs: Vec<PathBuf> = Vec::new();
    if std::env::var_os("NoDefaultCurrentDirectoryInExePath").is_none() {
        dirs.push(PathBuf::from("."));
    }
    if let Some(path) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&path));
    }
    for dir in dirs {
        for candidate in &candidates {
            let full = dir.join(candidate);
            if is_file(&full) {
                return Some(full.to_string_lossy().into_owned());
            }
        }
    }
    None
}

/// Quote arguments into one command line exactly as the C runtime parses it back.
pub(crate) fn list2cmdline(args: &[String]) -> String {
    let mut result = String::new();
    for arg in args {
        let mut backslashes = String::new();
        if !result.is_empty() {
            result.push(' ');
        }
        let quote = arg.is_empty() || arg.contains(' ') || arg.contains('\t');
        if quote {
            result.push('"');
        }
        for c in arg.chars() {
            match c {
                '\\' => backslashes.push(c),
                '"' => {
                    result.push_str(&"\\".repeat(backslashes.len() * 2));
                    backslashes.clear();
                    result.push_str("\\\"");
                }
                _ => {
                    result.push_str(&backslashes);
                    backslashes.clear();
                    result.push(c);
                }
            }
        }
        result.push_str(&backslashes);
        if quote {
            result.push_str(&backslashes);
            result.push('"');
        }
    }
    result
}

/// The parent's process ID straight from this process's own record; falls back
/// to a full process snapshot only if that query fails.
pub(crate) fn parent_process_id() -> Result<u32, GuardError> {
    unsafe {
        let mut info: ProcessBasicInformation = std::mem::zeroed();
        let status = NtQueryInformationProcess(GetCurrentProcess(), 0, &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<ProcessBasicInformation>() as u32, std::ptr::null_mut());
        if status == 0 && info.parent_process_id != 0 {
            return Ok(info.parent_process_id as u32);
        }
    }
    parent_process_id_by_snapshot()
}

fn parent_process_id_by_snapshot() -> Result<u32, GuardError> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE {
            return Err(os_error());
        }
        let me = GetCurrentProcessId();
        let mut entry: ProcessEntry32W = std::mem::zeroed();
        entry.size = std::mem::size_of::<ProcessEntry32W>() as u32;
        let mut found = None;
        let mut ok = Process32FirstW(snapshot, &mut entry);
        while ok != 0 {
            if entry.process_id == me {
                found = Some(entry.parent_process_id);
                break;
            }
            ok = Process32NextW(snapshot, &mut entry);
        }
        CloseHandle(snapshot);
        found.ok_or_else(|| GuardError("cannot find the parent process".into()))
    }
}

pub(crate) fn format_seconds(seconds: f64) -> String {
    if seconds.fract() == 0.0 { format!("{}", seconds as u64) } else { format!("{}", seconds) }
}

static STARTED: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// The trace lines not yet written.
static TRACE_LINES: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// With PROCESS_GUARD_TRACE set, note the milliseconds since start at each stage. The lines are
/// kept and written to standard error by `flush_trace` once the tree has ended, never while it
/// runs: a write to a standard error that nobody reads waits, and a wait must never be what
/// keeps the tree past its deadline.
pub fn trace(stage: &str) {
    if std::env::var_os("PROCESS_GUARD_TRACE").is_some() {
        let start = STARTED.get_or_init(std::time::Instant::now);
        let line = format!("PROCESS_GUARD_TRACE {:>8.2} ms {}", start.elapsed().as_secs_f64() * 1000.0, stage);
        TRACE_LINES.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).push(line);
    }
}

/// Write the trace lines kept so far, and `notice` after them, to standard error as one
/// notice (see `notify`).
pub(crate) fn flush_trace(notice: Option<String>) {
    let mut lines = std::mem::take(&mut *TRACE_LINES.lock().unwrap_or_else(|poisoned| poisoned.into_inner()));
    lines.extend(notice);
    if !lines.is_empty() {
        notify(lines.join("\n"));
    }
}

/// Writes what the trace kept when the run returns by any path, once the tree is gone.
struct FlushTrace;

impl Drop for FlushTrace {
    fn drop(&mut self) {
        flush_trace(None);
    }
}

/// What a unit test of the engine looks at in a run just before its command starts: the
/// extension (the cap it was made with) and how many owners are watched. Only under `cfg(test)`.
#[cfg(test)]
type BeforeStart = Box<dyn Fn(Option<&Extension>, usize)>;

#[cfg(test)]
thread_local! {
    static BEFORE_START: std::cell::RefCell<Option<BeforeStart>> = const { std::cell::RefCell::new(None) };
}

/// How a run differs from a plain deadline.
#[derive(Default)]
pub struct RunMode {
    /// A top-level extendable run (`--extendable`): its channel, cap and audit file.
    pub extendable: Option<Settings>,
    /// The contain role: refuse to run unless an extendable run encloses the program.
    pub require_channel: bool,
    /// A call of the library: the process that made it goes on when it returns, so the
    /// hold that its start made on the enclosing run ends with the call.
    pub library: bool,
}

/// The environment of this process with `name` set to `value`, as the block
/// `CreateProcessW` takes: sorted by name (compared in upper case, the name being the
/// text before the first `=` after the first character), each entry ended by NUL, then
/// one more NUL.
fn environment_block(name: &str, value: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    let mut entries: Vec<(String, Vec<u16>)> = std::env::vars_os()
        .filter(|(key, _)| !key.to_string_lossy().eq_ignore_ascii_case(name))
        .map(|(key, value)| {
            let mut entry: Vec<u16> = key.encode_wide().collect();
            entry.push(b'=' as u16);
            entry.extend(value.encode_wide());
            (key.to_string_lossy().to_uppercase(), entry)
        })
        .collect();
    entries.push((name.to_uppercase(), name.encode_utf16().chain(std::iter::once(b'=' as u16)).chain(value.encode_utf16()).collect()));
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut block = Vec::new();
    for (_, entry) in entries {
        block.extend(entry);
        block.push(0);
    }
    block.push(0);
    block
}

/// Wait for the child or an owner (the indexes of `waits`) while the deadline of an
/// extendable run is recalculated under its lock: whenever a process in the job
/// exits, whenever the backstop interval passes, and so on until the deadline
/// itself passes. Returns what `WaitForMultipleObjects` would, `WAIT_TIMEOUT` for
/// the deadline.
fn wait_extendable(extension: &Extension, waits: &[Handle]) -> u32 {
    wait_until(|| extension.remaining(), extension.wake(), waits)
}

/// `wait_extendable` with the time left given by `remaining`, and the event `wake` that
/// ends a wait early so that it is asked again. When no time is left the command and the
/// owners are looked at once more before the deadline is reported: a command that has
/// already ended wins over a deadline that passed as it ended, as it does when
/// `WaitForMultipleObjects` has both ready in the plain wait. The hold of a command that
/// was the last holder ends with it, which is what brings the deadline back to a passed one.
fn wait_until(mut remaining: impl FnMut() -> Option<u64>, wake: Handle, waits: &[Handle]) -> u32 {
    let mut handles = waits.to_vec();
    handles.push(wake);
    loop {
        let milliseconds = match remaining() {
            Some(milliseconds) => milliseconds,
            None => return unsafe { WaitForMultipleObjects(waits.len() as u32, waits.as_ptr(), 0, 0) },
        };
        let status = unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, wait_slice(milliseconds)) };
        if status != WAIT_TIMEOUT && status as usize != waits.len() {
            return status;
        }
    }
}

/// How long to wait before the deadline is calculated again: no longer than the time
/// left, and never longer than the backstop, which is what finds an exit whose message
/// from the job was lost.
fn wait_slice(remaining_milliseconds: u64) -> u32 {
    remaining_milliseconds.min(BACKSTOP_MS) as u32
}

/// How long a notice may wait to be written to a standard error that is not being read.
const NOTICE_WAIT_MS: u64 = 500;

/// Write a notice to standard error, after the tree has ended. A standard error that
/// nobody reads cannot keep the tree alive that way, and must not keep the guard from
/// returning either: the write gets a moment on a thread of its own and is then left.
fn notify(text: String) {
    let (done, finished) = std::sync::mpsc::channel();
    let line = text.clone();
    let spawned = std::thread::Builder::new().name("notice".into()).spawn(move || {
        // Never `eprintln!`: with panic = abort, a standard error whose reader has gone would
        // end the guard with a crash instead of its exit code. And one write for the line,
        // as the log writes its lines, so that neither lands inside the other.
        write_standard_error(&line);
        let _ = done.send(());
    });
    match spawned {
        Ok(_) => {
            let _ = finished.recv_timeout(std::time::Duration::from_millis(NOTICE_WAIT_MS));
        }
        Err(_) => write_standard_error(&text),
    }
}

/// Run `argv` in a new job object with a deadline of `seconds`. With
/// `watch_ancestors` the guard also ends the tree when any live ancestor exits,
/// not only its parent (automatic mode). Returns the child's exit code, 124 on
/// the deadline, or 125 when an owner exited first.
pub fn run_job(argv: &[String], seconds: f64, raw_tail: Option<&str>, watch_ancestors: bool) -> Result<u32, GuardError> {
    run_job_with(argv, seconds, raw_tail, watch_ancestors, &RunMode::default())
}

/// `run_job` for a call of the library: inside an extendable run, the hold that its start
/// makes ends when the call returns.
pub fn run_library_job(argv: &[String], seconds: f64, raw_tail: Option<&str>, watch_ancestors: bool) -> Result<u32, GuardError> {
    run_job_with(argv, seconds, raw_tail, watch_ancestors, &RunMode { library: true, ..RunMode::default() })
}

/// Ends the hold that the start of a library call made on the enclosing run, when the call
/// returns. The hold is the call's own (its token), so a call that overlaps it, on another
/// thread of the same process, keeps its hold.
struct EndHold(Option<Token>);

impl Drop for EndHold {
    fn drop(&mut self) {
        if let Some(token) = self.0 {
            let _ = release(token);
        }
    }
}

/// `run_job` for a run with a mode: extendable at the top, or inside an extendable run.
pub fn run_job_with(argv: &[String], seconds: f64, raw_tail: Option<&str>, watch_ancestors: bool, mode: &RunMode) -> Result<u32, GuardError> {
    trace("run");
    let _flush = FlushTrace;
    let executable = which(&argv[0]).ok_or_else(|| GuardError(format!("executable not found: {}", argv[0])))?;
    let lower = executable.to_ascii_lowercase();
    if lower.ends_with(".cmd") || lower.ends_with(".bat") {
        return Err(GuardError("For .cmd/.bat, explicitly invoke cmd.exe /d /s /c under this guard".into()));
    }
    let mut full = vec![executable.clone()];
    full.extend_from_slice(&argv[1..]);
    trace("resolved executable");
    // A guard with an exception that is started inside an extendable run is refused before it asks
    // that run for anything, so that a run that is refused places no hold on the run around it.
    if let Some(settings) = mode.extendable.as_ref().filter(|settings| settings.exception.is_some()) {
        if enclosed() {
            let opened = open_log(settings)?;
            let error = match auth::decide(settings, true, &executable, "", &[], &auth::Owners::empty(), &opened) {
                Err(error) => error,
                Ok(()) => GuardError("an exception above the cap cannot be granted inside another run".into()),
            };
            opened.finish(LOG_FLUSH_MS);
            return Err(error);
        }
    }
    // Started inside an extendable run, the guard asks it for this deadline first; a
    // refusal (over the cap, a rate limit, no verified place in the job) ends it here.
    let token = if mode.library { next_token() } else { 0 };
    let held = register_start(seconds, mode.require_channel, token)?;
    // A guard program ends with its command, and its hold with it. A library call returns to a
    // process that goes on, so the hold is ended when the call returns, whatever the outcome.
    let _end = EndHold((held && mode.library).then_some(token));

    // Every cap over the default is an exception that was built with the means to ask for it. A
    // caller that builds settings with a large cap and no exception gets no run, not a run with
    // a cap that nobody approved.
    if let Some(settings) = mode.extendable.as_ref() {
        if settings.max_seconds > DEFAULT_MAX_EXTENSION && settings.exception.is_none() {
            return Err(GuardError("a cap over the default needs the approval of the signed-in user; the run did not start".into()));
        }
    }
    // A cap over the default needs the approval of the signed-in user. It is asked for now, once the
    // command is known to be runnable and before the job exists or the command starts, and the
    // log it is recorded in is passed on to the extension. A run inside another run is refused.
    // The process that started the guard is opened first and watched while a prompt is open, so
    // that a prompt is never answered for a run that nobody started.
    // The handle of that process that the prompt watched is kept, and is the one the run is
    // watched against: a process that took its identifier in between is never taken for it.
    let mut log: Option<Log> = None;
    let mut kept: Vec<Handle> = Vec::new();
    if let Some(settings) = mode.extendable.as_ref().filter(|settings| settings.exception.is_some()) {
        let opened = open_log(settings)?;
        // A run inside another run is refused before anything else is looked at, so it needs no owner.
        let owners = if held {
            auth::Owners::empty()
        } else {
            match parent_process_id().and_then(|id| auth::Owners::open(&[id])) {
                Ok(owners) => owners,
                Err(error) => {
                    let error = auth::refuse_unwatched(settings, &opened, error.message());
                    opened.finish(LOG_FLUSH_MS);
                    return Err(error);
                }
            }
        };
        let parent = owners.image();
        // Every live process above the guard, for the refusal of a run that another guard started.
        let ancestors = if held { Vec::new() } else { ancestor_images() };
        match auth::decide(settings, held, &executable, &parent, &ancestors, &owners, &opened) {
            Ok(()) => {
                log = Some(opened);
                kept = owners.into_handles();
            }
            Err(error) => {
                opened.finish(LOG_FLUSH_MS);
                return Err(error);
            }
        }
    }

    // The kept handles are closed with the others, at the end of the run.
    let mut handles: Vec<Handle> = kept.clone();
    let mut info = ProcessInformation { process: std::ptr::null_mut(), thread: std::ptr::null_mut(), process_id: 0, thread_id: 0 };
    let mut assigned = false;
    // Set once the command is running, so that a run whose exception was approved and which then fails to start says so in the log.
    let mut started_command = false;
    let mut extension: Option<Extension> = None;
    // The notice for the end of the run, written once the tree is gone.
    let mut notice: Option<String> = None;
    let job = unsafe { CreateJobObjectW(std::ptr::null_mut(), std::ptr::null()) };
    if job.is_null() {
        let error = os_error();
        if let Some(log) = log.take() {
            log.note(&not_started_text(&error));
            log.finish(LOG_FLUSH_MS);
        }
        for handle in handles.drain(..) {
            unsafe { CloseHandle(handle) };
        }
        return Err(error);
    }
    handles.push(job);

    let outcome = (|| -> Result<u32, GuardError> {
        unsafe {
            let mut limits = ExtendedLimitInformation::default();
            limits.basic.limit_flags = KILL_ON_JOB_CLOSE; // No breakaway allowed.
            checked(SetInformationJobObject(job, EXTENDED_LIMIT_CLASS, &mut limits as *mut _ as *mut c_void,
                std::mem::size_of::<ExtendedLimitInformation>() as u32))?;
            if let Some(settings) = &mode.extendable {
                extension = Some(Extension::start(job, settings, seconds, log.take())?);
            }

            let mut startup: StartupInfoW = std::mem::zeroed();
            startup.cb = std::mem::size_of::<StartupInfoW>() as u32;
            startup.flags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            startup.show_window = 0;
            let current = GetCurrentProcess();
            for (which_handle, slot) in [(-10i32, 0usize), (-11, 1), (-12, 2)] {
                let original = GetStdHandle(which_handle as u32);
                if !original.is_null() && original != INVALID_HANDLE {
                    let mut duplicate: Handle = std::ptr::null_mut();
                    checked(DuplicateHandle(current, original, current, &mut duplicate, 0, 1, DUPLICATE_SAME_ACCESS))?;
                    handles.push(duplicate);
                    match slot {
                        0 => startup.std_input = duplicate,
                        1 => startup.std_output = duplicate,
                        _ => startup.std_error = duplicate,
                    }
                }
            }
            // Owners: the parent, or in automatic mode every live ancestor, so a
            // host that kills only the outer launcher of a shell still ends the tree.
            // A run with an exception already holds its parent (nearest first), opened for the prompt.
            let owner_ids = if watch_ancestors {
                ancestor_ids(false)
            } else if kept.is_empty() {
                vec![parent_process_id()?]
            } else {
                Vec::new()
            };
            let mut owners: Vec<Handle> = kept.clone();
            for id in owner_ids.iter().skip(kept.len()).take(60) {
                let owner = OpenProcess(SYNCHRONIZE, 0, *id);
                if !owner.is_null() {
                    handles.push(owner);
                    owners.push(owner);
                } else if owners.is_empty() {
                    return Err(os_error());
                }
            }
            trace("job ready, owners opened");
            // For the unit tests of the engine only: a look at the run just before its command starts.
            #[cfg(test)]
            BEFORE_START.with(|hook| {
                if let Some(hook) = hook.borrow().as_ref() {
                    hook(extension.as_ref(), owners.len());
                }
            });

            // The child cannot run or spawn until it belongs to the job.
            let application = wide(&executable);
            // cmd.exe does not read backslash-escaped quotes, so its payload is
            // appended verbatim inside one pair of quotes that /s strips.
            let mut line = list2cmdline(&full);
            if let Some(tail) = raw_tail {
                line.push_str(" \"");
                line.push_str(tail);
                line.push('"');
            }
            let mut command_line = wide(&line);
            // The child of an extendable run is told where its channel is.
            let mut environment = extension.as_ref().map(|extension| environment_block(CHANNEL_VARIABLE, &extension.channel));
            let (environment_pointer, environment_flag) = match environment.as_mut() {
                Some(block) => (block.as_mut_ptr() as *mut c_void, CREATE_UNICODE_ENVIRONMENT),
                None => (std::ptr::null_mut(), 0),
            };
            // A child shares the guard's console when there is one, which saves
            // creating a console host per command; without one it gets a hidden console.
            let console = if GetConsoleWindow().is_null() { CREATE_NO_WINDOW } else { 0 };
            checked(CreateProcessW(application.as_ptr(), command_line.as_mut_ptr(), std::ptr::null_mut(),
                std::ptr::null_mut(), 1, CREATE_SUSPENDED | console | environment_flag, environment_pointer,
                std::ptr::null(), &mut startup, &mut info))?;
            handles.push(info.process);
            handles.push(info.thread);
            checked(AssignProcessToJobObject(job, info.process))?;
            assigned = true;
            if ResumeThread(info.thread) == u32::MAX {
                return Err(os_error());
            }
            started_command = true;
            trace("child started");
            let mut waits = vec![info.process];
            waits.extend_from_slice(&owners);
            let milliseconds = (seconds * 1000.0).ceil() as u32;
            let status = match extension.as_ref() {
                None => WaitForMultipleObjects(waits.len() as u32, waits.as_ptr(), 0, milliseconds),
                Some(extension) => wait_extendable(extension, &waits),
            };
            match status {
                WAIT_TIMEOUT => {
                    // An extendable run reports the time it ran, since its deadline moved.
                    let shown = extension.as_ref().map_or(seconds, Extension::elapsed_seconds);
                    notice = Some(format!("PROCESS_TIMEOUT: exceeded {} seconds; terminating process tree", format_seconds(shown)));
                    Ok(124)
                }
                n if n >= 1 && (n as usize) < waits.len() => {
                    notice = Some("PROCESS_OWNER_EXITED: terminating process tree".into());
                    Ok(125)
                }
                0 => {
                    let mut code = 0u32;
                    checked(GetExitCodeProcess(info.process, &mut code))?;
                    Ok(code)
                }
                _ => Err(os_error()),
            }
        }
    })();
    trace("child finished");

    // A log that was opened for an exception and never passed on (the job could not be set up): it says that the approved run
    // did not start, as the log of the extension does when the failure comes after it was made.
    if let Some(log) = log.take() {
        if let Err(error) = &outcome {
            log.note(&not_started_text(error));
        }
        log.finish(LOG_FLUSH_MS);
    }
    if let (Err(error), false, Some(extension)) = (&outcome, started_command, extension.as_ref()) {
        if mode.extendable.as_ref().map_or(false, |settings| settings.exception.is_some()) {
            extension.note(&not_started_text(error));
        }
    }
    // No more grants once the command has finished or the deadline has passed.
    if let Some(extension) = extension.as_ref() {
        extension.close();
    }
    unsafe {
        if assigned {
            terminate_and_wait(job, 124, 5000);
            trace("job empty");
        } else if !info.process.is_null() {
            TerminateProcess(info.process, 125);
        }
        if !info.process.is_null() {
            WaitForSingleObject(info.process, 5000);
        }
    }
    // Nothing is written before the tree is gone: a standard error that nobody reads
    // blocks a write, and a write that waits must never be what keeps the tree alive.
    // The trace, when asked for, is written with the notice, in one write.
    flush_trace(notice.take());
    // The channel is closed after the tree is gone, so a stalled client never delays the kill.
    if let Some(mut extension) = extension.take() {
        extension.shutdown();
    }
    unsafe {
        for handle in handles.into_iter().rev() {
            CloseHandle(handle);
        }
    }
    outcome
}

/// The time the process behind `handle` was created, as the system counts it; the handle needs
/// the right to query limited information.
pub(crate) fn started_at(handle: Handle) -> Option<u64> {
    let (mut c, mut e, mut k, mut u) = (0u64, 0u64, 0u64, 0u64);
    let ok = unsafe { GetProcessTimes(handle, &mut c, &mut e, &mut k, &mut u) };
    if ok == 0 { None } else { Some(c) }
}

fn creation_time(id: u32) -> Option<u64> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, id);
        if handle.is_null() {
            return None;
        }
        let started = started_at(handle);
        CloseHandle(handle);
        started
    }
}

/// The programs of the desktop shell and of the system that end the walk up the parents (for the
/// refusal of a run that another guard started, only when they are the files at their system paths).
const WALK_ENDS_AT: [&str; 6] = ["explorer.exe", "services.exe", "wininit.exe", "winlogon.exe", "svchost.exe", "smss.exe"];

/// The Windows folder as the system gives it, without a final separator; empty when it cannot be read.
fn windows_folder() -> String {
    let mut buffer = [0u16; 512];
    let length = unsafe { GetSystemWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return String::new();
    }
    String::from_utf16_lossy(&buffer[..length]).trim_end_matches('\\').to_string()
}

/// Whether the walk up the parents ends at a parent with this file name and image path: only one
/// of the six programs of the system, at its system path (explorer.exe in the Windows folder, the
/// other five in System32). A program of that name in any other folder, one under the Windows
/// folder included, is a copy that a process of the user may be able to make, and is walked past
/// like any other process; so is one whose path cannot be read, which fails toward a refusal.
fn ends_the_walk(name: &str, image: &str, windows: &str) -> bool {
    if windows.is_empty() || image.is_empty() || !WALK_ENDS_AT.contains(&name) {
        return false;
    }
    let folder = if name == "explorer.exe" { windows.to_string() } else { format!("{}\\System32", windows) };
    image.eq_ignore_ascii_case(&format!("{}\\{}", folder, name))
}

/// Live ancestors of this process, nearest first: each one must have started
/// before its child (so a reused process ID is never mistaken for an ancestor),
/// and the walk stops at the desktop shell or system processes. With `strict`, as the refusal of
/// a run that another guard started needs, a program of those names ends the walk only when it
/// is the file at its system path; without it, as the owner list of automatic mode has always
/// had it, the name alone ends the walk.
fn ancestor_ids(strict: bool) -> Vec<u32> {
    let windows = if strict { windows_folder() } else { String::new() };
    let mut map = std::collections::HashMap::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(SNAPPROCESS, 0);
        if snapshot != INVALID_HANDLE {
            let mut entry: ProcessEntry32W = std::mem::zeroed();
            entry.size = std::mem::size_of::<ProcessEntry32W>() as u32;
            let mut ok = Process32FirstW(snapshot, &mut entry);
            while ok != 0 {
                let len = entry.exe_file.iter().position(|&c| c == 0).unwrap_or(260);
                let name = String::from_utf16_lossy(&entry.exe_file[..len]).to_ascii_lowercase();
                map.insert(entry.process_id, (entry.parent_process_id, name));
                ok = Process32NextW(snapshot, &mut entry);
            }
            CloseHandle(snapshot);
        }
    }
    let mut out = Vec::new();
    let mut child = unsafe { GetCurrentProcessId() };
    let mut child_started = creation_time(child).unwrap_or(u64::MAX);
    for _ in 0..32 {
        let parent = match map.get(&child) { Some((p, _)) => *p, None => break };
        let name = match map.get(&parent) { Some((_, n)) => n.clone(), None => break };
        if parent == 0 || parent == 4 || out.contains(&parent)
            || (WALK_ENDS_AT.contains(&name.as_str()) && (!strict || ends_the_walk(&name, &image_path_of_id(parent), &windows))) {
            break;
        }
        let started = match creation_time(parent) { Some(t) => t, None => break };
        if started > child_started {
            break;
        }
        out.push(parent);
        child = parent;
        child_started = started;
    }
    if out.is_empty() {
        if let Ok(parent) = parent_process_id() {
            out.push(parent);
        }
    }
    out
}

/// The path of the file of the process behind `handle` as the system gives it, letter case
/// included; empty when it cannot be read. The handle needs the right to query limited information.
pub(crate) fn image_path_of_handle(handle: Handle) -> String {
    let mut buffer = [0u16; 1024];
    let mut size = buffer.len() as u32;
    if unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size) } == 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buffer[..size as usize])
}

fn image_path_of_id(id: u32) -> String {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, id);
        if handle.is_null() {
            return String::new();
        }
        let path = image_path_of_handle(handle);
        CloseHandle(handle);
        path
    }
}

/// The path of the file of the process that launched the guard, as the system gives it;
/// empty when it cannot be read.
pub(crate) fn parent_image_path() -> String {
    parent_process_id().map_or_else(|_| String::new(), image_path_of_id)
}

/// Image file name of the process that launched the guard, lower case.
pub fn parent_image() -> String {
    parent_image_path().to_ascii_lowercase()
}

/// The images of every live ancestor of this process, nearest first (see `ancestor_ids`); an
/// image that cannot be read is empty.
fn ancestor_images() -> Vec<String> {
    ancestor_ids(true).into_iter().map(image_path_of_id).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_image_of_a_process_keeps_its_letter_case_for_the_prompt_and_is_lower_case_for_the_rest() {
        use std::os::windows::io::AsRawHandle;
        // A process that is started here has a system folder path, which the system writes with capitals.
        let mut child = std::process::Command::new("cmd").args(["/d", "/c", "ping -n 6 127.0.0.1 >nul"])
            .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).spawn().expect("start a process");
        let path = image_path_of_handle(child.as_raw_handle() as Handle);
        let by_identifier = image_path_of_id(child.id());
        let _ = child.kill();
        let _ = child.wait();
        assert!(path.to_ascii_lowercase().ends_with("\\cmd.exe"), "{}", path);
        assert_ne!(path, path.to_ascii_lowercase(), "the path is as the system gives it: {}", path);
        assert_eq!(path, by_identifier);
        // The parent of this process: the path keeps its case; the old name is the same path in lower case.
        let parent = parent_image_path();
        assert!(!parent.is_empty() && parent_image() == parent.to_ascii_lowercase(), "{} {}", parent, parent_image());
        // An unreadable process has no image.
        assert_eq!(image_path_of_id(0xffff_fff0), "");
    }

    #[test]
    fn the_walk_ends_at_the_programs_at_their_system_paths_and_goes_past_a_copy_under_the_same_name() {
        let windows = windows_folder();
        assert!(windows.len() > 3 && !windows.ends_with('\\'), "{}", windows);
        // The files of the system end it at their system paths, whatever the letter case.
        assert!(ends_the_walk("explorer.exe", &format!("{}\\explorer.exe", windows), &windows));
        assert!(ends_the_walk("svchost.exe", &format!("{}\\System32\\svchost.exe", windows.to_ascii_uppercase()), &windows));
        for name in ["services.exe", "wininit.exe", "winlogon.exe", "svchost.exe", "smss.exe"] {
            assert!(ends_the_walk(name, &format!("{}\\System32\\{}", windows, name), &windows), "{}", name);
        }
        // Another folder, a folder whose name only begins like the Windows folder, a folder under the Windows folder that is not the
        // system path (some of them can be written to by a standard user), the system path of another program, a name that is not one
        // of the six, and a path that cannot be read do not end it.
        assert!(!ends_the_walk("explorer.exe", "C:\\Tools\\explorer.exe", &windows));
        assert!(!ends_the_walk("explorer.exe", &format!("{}2\\explorer.exe", windows), &windows));
        assert!(!ends_the_walk("explorer.exe", &format!("{}\\Temp\\explorer.exe", windows), &windows));
        assert!(!ends_the_walk("svchost.exe", &format!("{}\\Tasks\\svchost.exe", windows), &windows));
        assert!(!ends_the_walk("smss.exe", &format!("{}\\System32\\spool\\drivers\\color\\smss.exe", windows), &windows));
        assert!(!ends_the_walk("services.exe", &format!("{}\\explorer.exe", windows), &windows));
        assert!(!ends_the_walk("explorer.exe", &format!("{}\\System32\\explorer.exe", windows), &windows));
        assert!(!ends_the_walk("svchost.exe", &format!("{}\\svchost.exe", windows), &windows));
        assert!(!ends_the_walk("cmd.exe", &format!("{}\\System32\\cmd.exe", windows), &windows));
        assert!(!ends_the_walk("explorer.exe", "", &windows));
        assert!(!ends_the_walk("explorer.exe", &format!("{}\\explorer.exe", windows), ""));
        // A copy of an ordinary program under the name of the shell, as any process of the user can make, is walked past.
        let folder = std::env::temp_dir().join(format!("ptg-walk-{}", std::process::id()));
        std::fs::create_dir_all(&folder).expect("make a folder");
        let copy = folder.join("explorer.exe");
        let system = format!("{}\\System32\\cmd.exe", windows);
        std::fs::copy(&system, &copy).expect("copy a program");
        let mut child = std::process::Command::new(&copy).args(["/d", "/c", "ping -n 6 127.0.0.1 >nul"])
            .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).spawn().expect("start the copy");
        let image = image_path_of_id(child.id());
        let ends = ends_the_walk("explorer.exe", &image, &windows);
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&folder);
        assert!(image.to_ascii_lowercase().ends_with("\\explorer.exe") && !ends, "{} {}", image, ends);
    }

    #[test]
    fn the_deadline_is_calculated_again_at_least_every_backstop_interval() {
        assert_eq!(wait_slice(60_000), BACKSTOP_MS as u32, "a long wait is cut to the backstop");
        assert_eq!(wait_slice(BACKSTOP_MS), BACKSTOP_MS as u32);
        assert_eq!(wait_slice(30), 30, "and never past the time left");
        assert_eq!(wait_slice(0), 0);
    }

    fn event(signaled: bool) -> Handle {
        let handle = unsafe { CreateEventW(std::ptr::null_mut(), 1, signaled as Bool, std::ptr::null()) };
        assert!(!handle.is_null());
        handle
    }

    #[test]
    fn a_command_that_ended_wins_over_a_deadline_that_passed() {
        let (command, owner, wake) = (event(true), event(false), event(false));
        // No time is left, as when the hold of the last holder ended with the command.
        assert_eq!(wait_until(|| None, wake, &[command, owner]), 0, "the command's exit is reported, not the deadline");
        let owner_gone = event(true);
        let command_running = event(false);
        assert_eq!(wait_until(|| None, wake, &[command_running, owner_gone]), 1, "so is the exit of an owner");
        assert_eq!(wait_until(|| None, wake, &[command_running, owner]), WAIT_TIMEOUT, "and the deadline when nothing has ended");
        // The command ending while time is left is reported the same way.
        assert_eq!(wait_until(|| Some(10_000), wake, &[command, owner]), 0);
        // A wake with time left asks again; the second answer, none left, is the deadline.
        let mut asked = 0;
        let woken = event(true);
        let status = wait_until(|| { asked += 1; if asked == 1 { Some(10_000) } else { None } }, woken, &[command_running, owner]);
        assert_eq!((status, asked), (WAIT_TIMEOUT, 2));
        for handle in [command, owner, wake, owner_gone, command_running, woken] {
            unsafe { CloseHandle(handle) };
        }
    }

    #[test]
    fn a_command_that_was_the_last_holder_and_ended_after_the_runs_own_deadline_is_not_a_timeout() {
        use std::os::windows::io::AsRawHandle;
        let quiet = || std::process::Stdio::null();
        unsafe {
            let job = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
            assert!(!job.is_null());
            // The command holds the run for 30 seconds and ends on its own after two, a second after the run's own deadline of one.
            let mut child = std::process::Command::new("ping.exe").args(["-n", "3", "127.0.0.1"]).stdin(quiet()).stdout(quiet()).stderr(quiet()).spawn().expect("start ping.exe");
            assert_ne!(AssignProcessToJobObject(job, child.as_raw_handle() as Handle), 0, "put the command in the job");
            let extension = Extension::start(job, &Settings { max_seconds: 60.0, log_path: None, exception: None }, 1.0, None).expect("start the extension");
            extension.hold_for_test(child.id(), 30.0);
            child.wait().expect("the command ends");
            // The hold ended with the command, so the deadline is back at the one that passed long ago, and the exit is still reported.
            assert_eq!(wait_extendable(&extension, &[child.as_raw_handle() as Handle]), 0, "the command's exit wins over the deadline");
            // A command that is still running when the deadline has passed is the deadline.
            let mut running = std::process::Command::new("ping.exe").args(["-n", "60", "127.0.0.1"]).stdin(quiet()).stdout(quiet()).stderr(quiet()).spawn().expect("start ping.exe");
            assert_ne!(AssignProcessToJobObject(job, running.as_raw_handle() as Handle), 0, "put the command in the job");
            assert_eq!(wait_extendable(&extension, &[running.as_raw_handle() as Handle]), WAIT_TIMEOUT);
            running.kill().expect("end the command");
            running.wait().expect("reap the command");
            drop(extension);
            CloseHandle(job);
        }
    }

    /// The entries of an environment block, as text.
    fn entries_of(block: &[u16]) -> Vec<String> {
        block.split(|unit| *unit == 0).filter(|entry| !entry.is_empty()).map(String::from_utf16_lossy).collect()
    }

    #[test]
    fn the_environment_block_is_sorted_by_name() {
        // '(' sorts below '=', so sorting the whole entry puts ProgramFiles(x86) before ProgramFiles.
        std::env::set_var("PTG_BLOCK_B", "1");
        std::env::set_var("PTG_BLOCK_B(X86)", "2");
        std::env::set_var("ptg_block_c", "3");
        let block = environment_block("PTG_BLOCK_A", "added");
        let entries = entries_of(&block);
        assert!(block.ends_with(&[0, 0]), "the block ends with one more NUL");
        let at = |prefix: &str| entries.iter().position(|entry| entry.starts_with(prefix)).unwrap_or_else(|| panic!("{} is in the block", prefix));
        assert!(at("PTG_BLOCK_A=") < at("PTG_BLOCK_B=") && at("PTG_BLOCK_B=") < at("PTG_BLOCK_B(X86)="), "{:?}", entries);
        assert!(at("PTG_BLOCK_B(X86)=") < at("ptg_block_c="), "names compare in upper case: {:?}", entries);
        assert!(entries.contains(&"PTG_BLOCK_A=added".to_string()));
        let names: Vec<String> = entries.iter().map(|entry| entry.char_indices().skip(1).find(|(_, c)| *c == '=').map_or(entry.clone(), |(at, _)| entry[..at].to_uppercase())).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "every entry of the block is in order of its name");
        // The variable that is added replaces an inherited one of the same name, in any letter case.
        std::env::set_var("PTG_BLOCK_D", "old");
        let replaced = entries_of(&environment_block("ptg_block_d", "new"));
        assert!(replaced.contains(&"ptg_block_d=new".to_string()) && !replaced.iter().any(|entry| entry.eq_ignore_ascii_case("PTG_BLOCK_D=old")), "{:?}", replaced);
    }

    #[test]
    fn a_cap_over_the_default_that_nobody_approved_is_not_a_run() {
        // Settings built by a caller that did not build the exception: the cap is over the default and nothing asks for it.
        // The refusal comes before the job is made, so the command (which would end at once) is never started.
        let argv: Vec<String> = ["cmd.exe", "/c", "exit"].iter().map(|part| part.to_string()).collect();
        for max_seconds in [DEFAULT_MAX_EXTENSION + 1.0, 86_400.0] {
            let mode = RunMode { extendable: Some(Settings { max_seconds, log_path: None, exception: None }), ..RunMode::default() };
            let error = run_job_with(&argv, 5.0, None, false, &mode).expect_err("a cap that nobody approved");
            assert!(error.message().contains("needs the approval of the signed-in user") && error.message().contains("did not start"), "{}", error);
        }
    }

    /// The settings of a run over the default cap with the audit file `log`.
    fn exception_settings(log: &std::path::Path) -> Settings {
        Settings {
            max_seconds: 86_400.0,
            log_path: Some(log.to_path_buf()),
            exception: Some(auth::Exception { method: auth::Method::Console, command: "cmd.exe".into(), timeout: 20.0 }),
        }
    }

    #[test]
    fn an_approved_exception_runs_its_command_with_the_cap_and_the_owner_that_were_opened_and_a_refused_one_never_starts_it() {
        let folder = std::env::temp_dir().join(format!("process-tree-guard-engine-{}", std::process::id()));
        std::fs::create_dir_all(&folder).expect("make a folder for the files of the test");
        let argv: Vec<String> = ["cmd.exe", "/d", "/s", "/c"].iter().map(|part| part.to_string()).collect();
        let command = |marker: &std::path::Path| format!("echo ran> \"{}\" & exit 3", marker.display());
        let lines = |log: &std::path::Path| std::fs::read_to_string(log).unwrap_or_default().lines().map(String::from).collect::<Vec<String>>();
        // Approved: the command runs and its exit code passes through; the run has the cap that was approved, one owner (the
        // process that started the guard, opened for the prompt and kept for the run), and one approval line.
        let (marker, log) = (folder.join("approved.txt"), folder.join("approved.log"));
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let recorder = seen.clone();
        BEFORE_START.with(|hook| *hook.borrow_mut() = Some(Box::new(move |extension, owners| {
            let extension = extension.expect("an extendable run has its extension");
            // A hold of the whole cap is granted only by a run that was made with that cap.
            extension.hold_for_test(std::process::id(), 86_400.0);
            recorder.borrow_mut().push(owners);
        })));
        auth::seam::ANSWER.with(|answer| answer.set(Some(true)));
        let mode = RunMode { extendable: Some(exception_settings(&log)), ..RunMode::default() };
        let code = run_job_with(&argv, 20.0, Some(&command(&marker)), false, &mode).expect("an approved exception runs its command");
        assert_eq!(code, 3, "the exit code of the command passes through");
        assert!(marker.exists(), "the command ran");
        assert_eq!(*seen.borrow(), [1], "the run was made with the cap, and watches the one owner that the prompt opened");
        let approved = lines(&log);
        assert_eq!(approved.iter().filter(|line| line.contains("decision=exception-approved")).count(), 1, "{:?}", approved);
        assert!(approved.iter().all(|line| !line.contains("decision=exception-refused")) && approved[0].contains("requested=86400")
            && approved[0].contains("attempt=1 "), "{:?}", approved);
        // Refused: the prompt is cancelled, the run does not start, and the extension is never made.
        let (marker, log) = (folder.join("refused.txt"), folder.join("refused.log"));
        seen.borrow_mut().clear();
        auth::seam::ANSWER.with(|answer| answer.set(Some(false)));
        let mode = RunMode { extendable: Some(exception_settings(&log)), ..RunMode::default() };
        let error = run_job_with(&argv, 20.0, Some(&command(&marker)), false, &mode).expect_err("a cancelled prompt refuses the run");
        assert!(error.message().contains("exception refused") && error.message().contains("the run did not start"), "{}", error);
        assert!(!marker.exists() && seen.borrow().is_empty(), "the command never started");
        let refused = lines(&log);
        assert!(refused.len() == 1 && refused[0].contains("decision=exception-refused") && refused[0].contains("the prompt was cancelled"), "{:?}", refused);
        // Approved, and then the command cannot be started (a real program, a copy of cmd.exe, that this test holds open without
        // sharing, so the system cannot open it to start it): the record does not leave a cap approved for a command that never
        // ran, and says that it did not start. A file whose bytes are not a program is never used: Windows would try it as a
        // 16-bit program and show a dialog. Should the hold not take, the copy runs `exit 0` and the test fails without a dialog.
        let (held_program, log) = (folder.join("held-program.exe"), folder.join("not-started.log"));
        std::fs::copy(format!("{}\\System32\\cmd.exe", windows_folder()), &held_program).expect("copy a real program");
        let _held = {
            use std::os::windows::fs::OpenOptionsExt;
            std::fs::OpenOptions::new().read(true).share_mode(0).open(&held_program).expect("hold the program without sharing")
        };
        auth::seam::ANSWER.with(|answer| answer.set(Some(true)));
        let mode = RunMode { extendable: Some(exception_settings(&log)), ..RunMode::default() };
        let argv = [held_program.display().to_string(), "/d".into(), "/c".into(), "exit 0".into()];
        let error = run_job_with(&argv, 20.0, None, false, &mode).expect_err("a program held without sharing does not start");
        let not_started = lines(&log);
        assert_eq!(not_started.iter().filter(|line| line.contains("decision=exception-approved")).count(), 1, "{:?}", not_started);
        assert!(not_started.iter().any(|line| line.contains("notice=\"the approved run did not start: ") && line.contains(&error.message().replace('\\', "\\\\"))),
            "the log says that the approved run did not start, and why: {:?} {}", not_started, error);
        auth::seam::ANSWER.with(|answer| answer.set(None));
        BEFORE_START.with(|hook| *hook.borrow_mut() = None);
        let _ = std::fs::remove_dir_all(&folder);
    }

    #[test]
    fn quoting_matches_the_c_runtime_rules() {
        let cases: [(&[&str], &str); 6] = [
            (&["a", "b c"], "a \"b c\""),
            (&["a\\\"b"], "a\\\\\\\"b"),
            (&["", "x"], "\"\" x"),
            (&["c:\\dir with space\\"], "\"c:\\dir with space\\\\\""),
            (&["plain\\path"], "plain\\path"),
            (&["a b", "say \"hi\"", "c:\\x y\\"], "\"a b\" \"say \\\"hi\\\"\" \"c:\\x y\\\\\""),
        ];
        for (args, expected) in cases {
            let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            assert_eq!(list2cmdline(&owned), expected);
        }
    }
}
