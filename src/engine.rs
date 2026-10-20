// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! The engine: one command in a job object, a deadline, and the cleanup of
//! every process in the job.

use crate::sys::*;
use crate::GuardError;
use std::ffi::c_void;

/// Terminate every process in the job and wait, at most `milliseconds`, until
/// each has fully exited. Termination is asynchronous, so without this the
/// guard could return while a descendant is still exiting. Processes are
/// opened before termination so each one can be waited on by handle. The list
/// is JOBOBJECT_BASIC_PROCESS_ID_LIST: two 32 bit counts, then pointer sized IDs.
fn terminate_and_wait(job: Handle, code: u32, milliseconds: u32) {
    let mut members: Vec<Handle> = Vec::new();
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
    if ok != 0 {
        let count = ((list[0] as u64) >> 32) as usize;
        for &id in list.iter().skip(1).take(count.min(capacity)) {
            let handle = unsafe { OpenProcess(SYNCHRONIZE, 0, id as u32) };
            if !handle.is_null() {
                members.push(handle);
            }
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

fn format_seconds(seconds: f64) -> String {
    if seconds.fract() == 0.0 { format!("{}", seconds as u64) } else { format!("{}", seconds) }
}

static STARTED: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// With PROCESS_GUARD_TRACE set, report milliseconds since start at each stage on standard error.
pub fn trace(stage: &str) {
    if std::env::var_os("PROCESS_GUARD_TRACE").is_some() {
        let start = STARTED.get_or_init(std::time::Instant::now);
        eprintln!("PROCESS_GUARD_TRACE {:>8.2} ms {}", start.elapsed().as_secs_f64() * 1000.0, stage);
    }
}

/// Run `argv` in a new job object with a deadline of `seconds`. With
/// `watch_ancestors` the guard also ends the tree when any live ancestor exits,
/// not only its parent (automatic mode). Returns the child's exit code, 124 on
/// the deadline, or 125 when an owner exited first.
pub fn run_job(argv: &[String], seconds: f64, raw_tail: Option<&str>, watch_ancestors: bool) -> Result<u32, GuardError> {
    trace("run");
    let executable = which(&argv[0]).ok_or_else(|| GuardError(format!("executable not found: {}", argv[0])))?;
    let lower = executable.to_ascii_lowercase();
    if lower.ends_with(".cmd") || lower.ends_with(".bat") {
        return Err(GuardError("For .cmd/.bat, explicitly invoke cmd.exe /d /s /c under this guard".into()));
    }
    let mut full = vec![executable.clone()];
    full.extend_from_slice(&argv[1..]);
    trace("resolved executable");

    let mut handles: Vec<Handle> = Vec::new();
    let mut info = ProcessInformation { process: std::ptr::null_mut(), thread: std::ptr::null_mut(), process_id: 0, thread_id: 0 };
    let mut assigned = false;
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
            // A child shares the guard's console when there is one, which saves
            // creating a console host per command; without one it gets a hidden console.
            let console = if GetConsoleWindow().is_null() { CREATE_NO_WINDOW } else { 0 };
            checked(CreateProcessW(application.as_ptr(), command_line.as_mut_ptr(), std::ptr::null_mut(),
                std::ptr::null_mut(), 1, CREATE_SUSPENDED | console, std::ptr::null_mut(),
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
            match WaitForMultipleObjects(waits.len() as u32, waits.as_ptr(), 0, milliseconds) {
                WAIT_TIMEOUT => {
                    eprintln!("PROCESS_TIMEOUT: exceeded {} seconds; terminating process tree", format_seconds(seconds));
                    Ok(124)
                }
                n if n >= 1 && (n as usize) < waits.len() => {
                    eprintln!("PROCESS_OWNER_EXITED: terminating process tree");
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
