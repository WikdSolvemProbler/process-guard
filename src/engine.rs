// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! The engine: one command in a job object, a deadline, and the cleanup of
//! every process in the job.

use crate::extend::{next_token, register_start, release, write_standard_error, Extension, Settings, Token, BACKSTOP_MS, CHANNEL_VARIABLE};
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
fn list2cmdline(args: &[String]) -> String {
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
fn parent_process_id() -> Result<u32, GuardError> {
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
    // Started inside an extendable run, the guard asks it for this deadline first; a
    // refusal (over the cap, a rate limit, no verified place in the job) ends it here.
    let token = if mode.library { next_token() } else { 0 };
    let held = register_start(seconds, mode.require_channel, token)?;
    // A guard program ends with its command, and its hold with it. A library call returns to a
    // process that goes on, so the hold is ended when the call returns, whatever the outcome.
    let _end = EndHold((held && mode.library).then_some(token));

    let mut handles: Vec<Handle> = Vec::new();
    let mut info = ProcessInformation { process: std::ptr::null_mut(), thread: std::ptr::null_mut(), process_id: 0, thread_id: 0 };
    let mut assigned = false;
    let mut extension: Option<Extension> = None;
    // The notice for the end of the run, written once the tree is gone.
    let mut notice: Option<String> = None;
    let job = unsafe { CreateJobObjectW(std::ptr::null_mut(), std::ptr::null()) };
    if job.is_null() {
        return Err(os_error());
    }
    handles.push(job);

    let outcome = (|| -> Result<u32, GuardError> {
        unsafe {
            let mut limits = ExtendedLimitInformation::default();
            limits.basic.limit_flags = KILL_ON_JOB_CLOSE; // No breakaway allowed.
            checked(SetInformationJobObject(job, EXTENDED_LIMIT_CLASS, &mut limits as *mut _ as *mut c_void,
                std::mem::size_of::<ExtendedLimitInformation>() as u32))?;
            if let Some(settings) = &mode.extendable {
                extension = Some(Extension::start(job, settings, seconds)?);
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
            let owner_ids = if watch_ancestors {
                ancestor_ids()
            } else {
                vec![parent_process_id()?]
            };
            let mut owners: Vec<Handle> = Vec::new();
            for id in owner_ids.iter().take(60) {
                let owner = OpenProcess(SYNCHRONIZE, 0, *id);
                if !owner.is_null() {
                    handles.push(owner);
                    owners.push(owner);
                } else if owners.is_empty() {
                    return Err(os_error());
                }
            }
            trace("job ready, owners opened");

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

fn creation_time(id: u32) -> Option<u64> {
    unsafe {
        let handle = OpenProcess(0x1000, 0, id);
        if handle.is_null() {
            return None;
        }
        let (mut c, mut e, mut k, mut u) = (0u64, 0u64, 0u64, 0u64);
        let ok = GetProcessTimes(handle, &mut c, &mut e, &mut k, &mut u);
        CloseHandle(handle);
        if ok == 0 { None } else { Some(c) }
    }
}

/// Live ancestors of this process, nearest first: each one must have started
/// before its child (so a reused process ID is never mistaken for an ancestor),
/// and the walk stops at the desktop shell or system processes.
fn ancestor_ids() -> Vec<u32> {
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
            || ["explorer.exe", "services.exe", "wininit.exe", "winlogon.exe", "svchost.exe", "smss.exe"].contains(&name.as_str()) {
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

/// Image file name of the process that launched the guard, lower case.
pub fn parent_image() -> String {
    unsafe {
        let id = match parent_process_id() { Ok(id) => id, Err(_) => return String::new() };
        let handle = OpenProcess(0x1000, 0, id); // PROCESS_QUERY_LIMITED_INFORMATION
        if handle.is_null() {
            return String::new();
        }
        let mut buffer = [0u16; 1024];
        let mut size = buffer.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size);
        CloseHandle(handle);
        if ok == 0 {
            return String::new();
        }
        String::from_utf16_lossy(&buffer[..size as usize]).to_ascii_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            let extension = Extension::start(job, &Settings { max_seconds: 60.0, log_path: None }, 1.0).expect("start the extension");
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
    fn quoting_matches_the_c_runtime_rules() {
        let cases: [(&[&str], &str); 5] = [
            (&["a", "b c"], "a \"b c\""),
            (&["a\\\"b"], "a\\\\\\\"b"),
            (&["", "x"], "\"\" x"),
            (&["c:\\dir with space\\"], "\"c:\\dir with space\\\\\""),
            (&["plain\\path"], "plain\\path"),
        ];
        for (args, expected) in cases {
            let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            assert_eq!(list2cmdline(&owned), expected);
        }
    }
}
