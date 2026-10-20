// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! Windows process tree deadline. No implicit timeout and no third party crates.
//!
//! Runs one command inside a job object that kills every process in the tree
//! when the job closes. Exit codes: the child's own code; 124 on timeout; 125
//! for any guard error or when the process that launched the guard exits. The
//! guard never exits with 2, because 2 blocks a host hook event.
//!
//! The program is `process-tree-guard`. The 1.x name `process-guard` is an alias
//! through all of 2.x: the same executable under either name, or under either
//! name with `-auto` added, behaves identically, because only the program name's
//! ending is read.

use std::ffi::c_void;
use std::process::exit;

mod hook;

const MAX_SECONDS: f64 = 86400.0;
const USAGE: &str = "usage: process-tree-guard --timeout SECONDS (--shell {powershell,bash,cmd} --command-b64 BASE64 | [--] COMMAND [ARGS...])";

type Handle = *mut c_void;
type Bool = i32;

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    reserved: *mut u16,
    desktop: *mut u16,
    title: *mut u16,
    x: u32,
    y: u32,
    x_size: u32,
    y_size: u32,
    x_count_chars: u32,
    y_count_chars: u32,
    fill_attribute: u32,
    flags: u32,
    show_window: u16,
    reserved2_size: u16,
    reserved2: *mut u8,
    std_input: Handle,
    std_output: Handle,
    std_error: Handle,
}

#[repr(C)]
struct ProcessInformation {
    process: Handle,
    thread: Handle,
    process_id: u32,
    thread_id: u32,
}

#[repr(C)]
#[derive(Default)]
struct BasicLimitInformation {
    per_process_user_time_limit: i64,
    per_job_user_time_limit: i64,
    limit_flags: u32,
    minimum_working_set_size: usize,
    maximum_working_set_size: usize,
    active_process_limit: u32,
    affinity: usize,
    priority_class: u32,
    scheduling_class: u32,
}

#[repr(C)]
#[derive(Default)]
struct IoCounters {
    counts: [u64; 6],
}

#[repr(C)]
#[derive(Default)]
struct ExtendedLimitInformation {
    basic: BasicLimitInformation,
    io: IoCounters,
    process_memory_limit: usize,
    job_memory_limit: usize,
    peak_process_memory_used: usize,
    peak_job_memory_used: usize,
}

#[repr(C)]
#[derive(Default)]
struct BasicAccountingInformation {
    times: [i64; 4],
    total_page_fault_count: u32,
    total_processes: u32,
    active_processes: u32,
    total_terminated_processes: u32,
}

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

#[repr(C)]
struct ProcessEntry32W {
    size: u32,
    usage: u32,
    process_id: u32,
    default_heap_id: usize,
    module_id: u32,
    threads: u32,
    parent_process_id: u32,
    priority_base: i32,
    flags: u32,
    exe_file: [u16; 260],
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateJobObjectW(attributes: *mut c_void, name: *const u16) -> Handle;
    fn SetInformationJobObject(job: Handle, class: i32, info: *mut c_void, length: u32) -> Bool;
    fn AssignProcessToJobObject(job: Handle, process: Handle) -> Bool;
    fn TerminateJobObject(job: Handle, code: u32) -> Bool;
    fn QueryInformationJobObject(job: Handle, class: i32, info: *mut c_void, length: u32, returned: *mut u32) -> Bool;
    fn Sleep(milliseconds: u32);
    fn CreateProcessW(
        application: *const u16,
        command_line: *mut u16,
        process_attributes: *mut c_void,
        thread_attributes: *mut c_void,
        inherit_handles: Bool,
        creation_flags: u32,
        environment: *mut c_void,
        current_directory: *const u16,
        startup: *mut StartupInfoW,
        information: *mut ProcessInformation,
    ) -> Bool;
    fn ResumeThread(thread: Handle) -> u32;
    fn CloseHandle(handle: Handle) -> Bool;
    fn GetStdHandle(which: u32) -> Handle;
    fn GetCurrentProcess() -> Handle;
    fn GetCurrentProcessId() -> u32;
    fn DuplicateHandle(
        source_process: Handle,
        source: Handle,
        target_process: Handle,
        target: *mut Handle,
        access: u32,
        inherit: Bool,
        options: u32,
    ) -> Bool;
    fn OpenProcess(access: u32, inherit: Bool, process_id: u32) -> Handle;
    fn WaitForMultipleObjects(count: u32, handles: *const Handle, wait_all: Bool, milliseconds: u32) -> u32;
    fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    fn GetExitCodeProcess(process: Handle, code: *mut u32) -> Bool;
    fn TerminateProcess(process: Handle, code: u32) -> Bool;
    fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> Handle;
    fn Process32FirstW(snapshot: Handle, entry: *mut ProcessEntry32W) -> Bool;
    fn Process32NextW(snapshot: Handle, entry: *mut ProcessEntry32W) -> Bool;
    fn GetLastError() -> u32;
    fn GetConsoleWindow() -> Handle;
    fn QueryFullProcessImageNameW(process: Handle, flags: u32, name: *mut u16, size: *mut u32) -> Bool;
    fn GetProcessTimes(process: Handle, creation: *mut u64, exit: *mut u64, kernel: *mut u64, user: *mut u64) -> Bool;
}

const INVALID_HANDLE: Handle = -1isize as Handle;
const KILL_ON_JOB_CLOSE: u32 = 0x2000;
const EXTENDED_LIMIT_CLASS: i32 = 9;
const BASIC_ACCOUNTING_CLASS: i32 = 1;
const PROCESS_ID_LIST_CLASS: i32 = 3;
const STARTF_USESTDHANDLES: u32 = 0x100;
const STARTF_USESHOWWINDOW: u32 = 0x1;
const CREATE_SUSPENDED: u32 = 0x4;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const DUPLICATE_SAME_ACCESS: u32 = 2;
const WAIT_TIMEOUT: u32 = 0x102;
const SNAPPROCESS: u32 = 0x2;

struct GuardError(String);

fn os_error() -> GuardError {
    let code = unsafe { GetLastError() };
    GuardError(format!("[WinError {}] {}", code, std::io::Error::from_raw_os_error(code as i32)))
}

fn checked(ok: Bool) -> Result<(), GuardError> {
    if ok == 0 { Err(os_error()) } else { Ok(()) }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Seconds from text: a finite number greater than zero and at most 86400.
fn duration(value: &str) -> Result<f64, GuardError> {
    let seconds: f64 = value.trim().parse().map_err(|_| GuardError("timeout must be a number".into()))?;
    if !seconds.is_finite() || seconds <= 0.0 || seconds > MAX_SECONDS {
        return Err(GuardError("timeout must be greater than zero and at most 86400 seconds".into()));
    }
    Ok(seconds)
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Strict standard base64: full quartets, padding only at the end.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    let padding = bytes.iter().rev().take_while(|&&b| b == b'=').count();
    if padding > 2 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut acc: u32 = 0;
    let body = &bytes[..bytes.len() - padding];
    for (i, &b) in body.iter().enumerate() {
        let value = ALPHABET.iter().position(|&a| a == b)? as u32;
        acc = (acc << 6) | value;
        if i % 4 == 3 {
            out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8, acc as u8]);
            acc = 0;
        }
    }
    match padding {
        // Unused trailing bits are ignored, as the reference decoder does.
        1 => { acc <<= 6; out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8]); }
        2 => { acc <<= 12; out.push((acc >> 16) as u8); }
        _ => {}
    }
    Some(out)
}

fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let n = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn decode_command(value: &str) -> Result<String, GuardError> {
    let bytes = base64_decode(value).ok_or_else(|| GuardError("--command-b64 is not valid base64".into()))?;
    let command = String::from_utf8(bytes).map_err(|_| GuardError("--command-b64 is not valid UTF-8".into()))?;
    if command.trim().is_empty() || command.contains('\0') {
        return Err(GuardError("command must be nonempty and contain no NUL".into()));
    }
    Ok(command)
}

/// Locate an executable as the PATH search does, honouring PATHEXT.
fn which(name: &str) -> Option<String> {
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

#[repr(C)]
struct ProcessBasicInformation {
    exit_status: i32,
    peb: *mut c_void,
    affinity: usize,
    base_priority: i32,
    unique_process_id: usize,
    parent_process_id: usize,
}

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(process: Handle, class: u32, info: *mut c_void, length: u32, returned: *mut u32) -> i32;
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
fn trace(stage: &str) {
    if std::env::var_os("PROCESS_GUARD_TRACE").is_some() {
        let start = STARTED.get_or_init(std::time::Instant::now);
        eprintln!("PROCESS_GUARD_TRACE {:>8.2} ms {}", start.elapsed().as_secs_f64() * 1000.0, stage);
    }
}

fn run_windows(argv: &[String], seconds: f64, raw_tail: Option<&str>) -> Result<u32, GuardError> {
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
            let owner_ids = if WATCH_ANCESTORS.load(std::sync::atomic::Ordering::Relaxed) {
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

struct Options {
    timeout: Option<String>,
    shell: Option<String>,
    command_b64: Option<String>,
    command: Vec<String>,
}

/// Parse the argument list. Errors become exit 125, never 2.
fn parse(args: Vec<String>) -> Result<Options, GuardError> {
    let mut options = Options { timeout: None, shell: None, command_b64: None, command: Vec::new() };
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if !arg.starts_with('-') || arg == "--" {
            options.command = args[i..].to_vec();
            break;
        }
        if arg == "-h" || arg == "--help" {
            println!("{}", USAGE);
            exit(0);
        }
        let (key, inline) = match arg.split_once('=') {
            Some((k, v)) => (k.to_string(), Some(v.to_string())),
            None => (arg.clone(), None),
        };
        if !["--timeout", "--shell", "--command-b64"].contains(&key.as_str()) {
            return Err(GuardError(format!("unrecognized arguments: {}", key)));
        }
        let value = match inline {
            Some(v) => v,
            None => {
                i += 1;
                args.get(i).cloned().ok_or_else(|| GuardError(format!("argument {}: expected one argument", key)))?
            }
        };
        match key.as_str() {
            "--timeout" => options.timeout = Some(value),
            "--shell" => {
                if !["powershell", "bash", "cmd"].contains(&value.as_str()) {
                    return Err(GuardError(format!("argument --shell: invalid choice: '{}'", value)));
                }
                options.shell = Some(value)
            }
            "--command-b64" => options.command_b64 = Some(value),
            _ => return Err(GuardError(format!("unrecognized arguments: {}", key))),
        }
        i += 1;
    }
    Ok(options)
}

fn run() -> Result<u32, GuardError> {
    let mut args = Vec::new();
    for arg in std::env::args_os().skip(1) {
        args.push(arg.into_string().map_err(|_| GuardError("arguments must be valid Unicode".into()))?);
    }
    let options = parse(args)?;
    let timeout = options.timeout.ok_or_else(|| GuardError("the following arguments are required: --timeout".into()))?;
    let seconds = duration(&timeout)?;
    let mut raw_tail: Option<String> = None;
    let child: Vec<String> = if let Some(shell) = options.shell {
        let encoded = match (&options.command_b64, options.command.is_empty()) {
            (Some(b64), true) => b64,
            _ => return Err(GuardError("--shell requires --command-b64 and no additional arguments".into())),
        };
        let command = decode_command(encoded)?;
        match shell.as_str() {
            "powershell" => {
                let utf16: Vec<u8> = command.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
                let host = which("pwsh.exe").unwrap_or_else(|| "powershell.exe".into());
                vec![host, "-NoLogo".into(), "-NoProfile".into(), "-NonInteractive".into(),
                     "-EncodedCommand".into(), base64_encode(&utf16)]
            }
            "bash" => vec!["C:/Program Files/Git/bin/bash.exe".into(), "--noprofile".into(), "--norc".into(), "-c".into(), command],
            _ => {
                raw_tail = Some(command);
                vec![std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".into()), "/d".into(), "/s".into(), "/c".into()]
            }
        }
    } else {
        if options.command_b64.is_some() {
            return Err(GuardError("--command-b64 requires --shell".into()));
        }
        let child: Vec<String> = if options.command.first().map(String::as_str) == Some("--") {
            options.command[1..].to_vec()
        } else {
            options.command
        };
        if child.is_empty() {
            return Err(GuardError("a command is required after --".into()));
        }
        child
    };
    run_windows(&child, seconds, raw_tail.as_deref())
}

static WATCH_ANCESTORS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

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

/// Default hard deadline for `auto` mode: two hours, the longest any host shell call may run.
const AUTO_DEFAULT_SECONDS: f64 = 7200.0;

/// Image file name of the process that launched the guard, lower case.
fn parent_image() -> String {
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

/// The environment variables that set the automatic deadline, in the order they
/// are read: the 2.0 name, the 1.x name (an alias through 2.x), then the legacy
/// host name. The first one that is set is used.
const AUTO_TIMEOUT_VARIABLES: [&str; 3] = ["PROCESS_TREE_GUARD_AUTO_TIMEOUT", "PROCESS_GUARD_AUTO_TIMEOUT", "HARNESS_AUTO_TIMEOUT"];

/// The value of the first of AUTO_TIMEOUT_VARIABLES that `lookup` finds.
fn auto_timeout_setting(lookup: impl Fn(&str) -> Option<String>) -> Option<String> {
    AUTO_TIMEOUT_VARIABLES.iter().find_map(|name| lookup(name))
}

/// `process-tree-guard auto [--timeout SECONDS] [--shell powershell|bash|cmd] [--] COMMAND...`
///
/// The automatic wrapper a host puts in front of every shell command. One
/// remaining argument is a command line for a shell: the shell named by
/// --shell, otherwise the same kind of shell that launched the guard (Git
/// Bash when unknown). Several remaining arguments are a program and its
/// arguments. The deadline is --timeout, else the first of
/// AUTO_TIMEOUT_VARIABLES that is set, else two hours. The host's own
/// per-call timeout still applies: when the host kills the process that
/// launched the guard, the guard kills the whole tree.
fn auto(skip: usize) -> Result<u32, GuardError> {
    WATCH_ANCESTORS.store(true, std::sync::atomic::Ordering::Relaxed);
    let mut args: Vec<String> = Vec::new();
    for arg in std::env::args_os().skip(skip) {
        args.push(arg.into_string().map_err(|_| GuardError("arguments must be valid Unicode".into()))?);
    }
    let mut timeout: Option<String> = auto_timeout_setting(|name| std::env::var(name).ok());
    let mut shell: Option<String> = None;
    let mut encoded: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--timeout" if i + 1 < args.len() => { timeout = Some(args[i + 1].clone()); i += 2; }
            "--shell" if i + 1 < args.len() => { shell = Some(args[i + 1].clone()); i += 2; }
            "--command-b64" if i + 1 < args.len() => { encoded = Some(decode_command(&args[i + 1])?); i += 2; }
            "--" => { i += 1; break; }
            _ => break,
        }
    }
    let mut rest: Vec<String> = args[i..].to_vec();
    let seconds = match timeout {
        Some(t) => duration(&t)?,
        None => AUTO_DEFAULT_SECONDS,
    };
    if let Some(command) = encoded {
        if !rest.is_empty() {
            return Err(GuardError("auto: --command-b64 takes no further arguments".into()));
        }
        rest.push(command);
    }
    if rest.is_empty() {
        return Err(GuardError("auto: a command is required".into()));
    }
    if rest.len() > 1 {
        return run_windows(&rest, seconds, None);
    }
    let command = rest[0].clone();
    if command.trim().is_empty() || command.contains('\0') {
        return Err(GuardError("command must be nonempty and contain no NUL".into()));
    }
    let parent = parent_image();
    let parent_name = parent.rsplit(['\\', '/']).next().unwrap_or("").to_string();
    let parent_is_powershell = parent_name.starts_with("pwsh") || parent_name.starts_with("powershell");
    let shell = shell.unwrap_or_else(|| {
        if parent_is_powershell {
            "powershell".into()
        } else if parent_name == "cmd.exe" {
            "cmd".into()
        } else {
            "bash".into()
        }
    });
    let (mut child, tail) = shell_command(&shell, command)?;
    // PowerShell runs in the same edition that called the wrapper (Windows
    // PowerShell or PowerShell 7), so behaviour matches an unwrapped call.
    if shell == "powershell" && parent_is_powershell && !parent.is_empty() {
        child[0] = parent.clone();
    }
    run_windows(&child, seconds, tail.as_deref())
}

/// The argument list (and verbatim cmd tail) that runs `command` in `shell`.
fn shell_command(shell: &str, command: String) -> Result<(Vec<String>, Option<String>), GuardError> {
    Ok(match shell {
        "powershell" => {
            let utf16: Vec<u8> = command.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            let host = which("pwsh.exe").unwrap_or_else(|| "powershell.exe".into());
            (vec![host, "-NoLogo".into(), "-NoProfile".into(), "-NonInteractive".into(), "-EncodedCommand".into(), base64_encode(&utf16)], None)
        }
        "bash" => (vec!["C:/Program Files/Git/bin/bash.exe".into(), "--noprofile".into(), "--norc".into(), "-c".into(), command], None),
        "cmd" => (vec![std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".into()), "/d".into(), "/s".into(), "/c".into()], Some(command)),
        other => return Err(GuardError(format!("argument --shell: invalid choice: '{}'", other))),
    })
}

fn main() {
    trace("start");
    let mut args = std::env::args_os().skip(1);
    // Installed under a name ending in "-auto", the binary is the automatic
    // wrapper itself, so a host can name it as a single program path. Only the
    // ending is read, so process-tree-guard-auto and the 1.x alias
    // process-guard-auto select it alike.
    let auto_by_name = std::env::current_exe().ok()
        .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().to_ascii_lowercase()))
        .map_or(false, |s| s.ends_with("-auto"));
    if auto_by_name {
        match auto(1) {
            Ok(code) => exit(code as i32),
            Err(GuardError(message)) => {
                eprintln!("PROCESS_GUARD_ERROR: {}", message);
                exit(125);
            }
        }
    }
    match args.next().as_deref().and_then(|a| a.to_str()) {
        Some("hook") => {
            let vendor = args.next().and_then(|v| v.into_string().ok()).unwrap_or_else(|| "pretooluse".into());
            exit(hook::main(&vendor));
        }
        Some("auto") => match auto(2) {
            Ok(code) => exit(code as i32),
            Err(GuardError(message)) => {
                eprintln!("PROCESS_GUARD_ERROR: {}", message);
                exit(125);
            }
        },
        _ => {}
    }
    match run() {
        Ok(code) => exit(code as i32),
        Err(GuardError(message)) => {
            eprintln!("PROCESS_GUARD_ERROR: {}", message);
            exit(125);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trip_and_strictness() {
        for text in ["", "a", "ab", "abc", "abcd", "Write-Output 'guard-ok'"] {
            let encoded = base64_encode(text.as_bytes());
            if !text.is_empty() {
                assert_eq!(base64_decode(&encoded).unwrap(), text.as_bytes());
            }
        }
        assert_eq!(base64_encode(b"Write-Output 'guard-ok'"), "V3JpdGUtT3V0cHV0ICdndWFyZC1vayc=");
        for bad in ["////=", "abc", "ab=c", "a===", "Zm9v!", "Zg=x"] {
            assert!(base64_decode(bad).is_none(), "{}", bad);
        }
    }

    #[test]
    fn duration_bounds() {
        assert!(duration(".3").is_ok());
        assert!(duration("86400").is_ok());
        for bad in ["0", "-1", "nan", "inf", "86401", "x", ""] {
            assert!(duration(bad).is_err(), "{}", bad);
        }
    }

    #[test]
    fn automatic_deadline_variables_are_read_in_order() {
        let set = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| pairs.iter().find(|(k, _)| *k == name).map(|(_, v)| v.to_string())
        };
        assert_eq!(auto_timeout_setting(set(&[])), None);
        assert_eq!(auto_timeout_setting(set(&[("HARNESS_AUTO_TIMEOUT", "3")])).as_deref(), Some("3"));
        assert_eq!(auto_timeout_setting(set(&[("HARNESS_AUTO_TIMEOUT", "3"), ("PROCESS_GUARD_AUTO_TIMEOUT", "2")])).as_deref(), Some("2"));
        assert_eq!(auto_timeout_setting(set(&[("PROCESS_GUARD_AUTO_TIMEOUT", "2"), ("HARNESS_AUTO_TIMEOUT", "3"), ("PROCESS_TREE_GUARD_AUTO_TIMEOUT", "1")])).as_deref(), Some("1"));
        assert_eq!(auto_timeout_setting(set(&[("PROCESS_TREE_GUARD_AUTO_TIMEOUT", ""), ("PROCESS_GUARD_AUTO_TIMEOUT", "2")])).as_deref(), Some(""));
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

    #[test]
    fn argument_errors_never_exit_two() {
        assert!(parse(vec!["--bogus".into(), "1".into()]).is_err());
        assert!(matches!(parse(vec!["--bogus".into()]), Err(GuardError(m)) if m.starts_with("unrecognized")));
        assert!(parse(vec!["--shell".into(), "zsh".into()]).is_err());
        assert!(parse(vec!["--timeout".into()]).is_err());
        let ok = parse(vec!["--timeout=5".into(), "--".into(), "x".into()]).ok().unwrap();
        assert_eq!(ok.timeout.as_deref(), Some("5"));
        assert_eq!(ok.command, vec!["--".to_string(), "x".to_string()]);
    }
}
