// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! Helper process for the process guard tests.
//!
//! One small executable stands in for every child the tests need: sleepers,
//! exit codes, standard stream relays, argument reporters, markers that record
//! their process identifier, wide and deep process trees, bulk output, calls of
//! the library, requests to an extendable run, an owner that leaves when told, and a guard
//! run on a window station or in a pseudo console that nobody can see.
//! The first argument selects the subcommand. A usage error exits with 97.
//!
//! Markers are written to a temporary name and renamed into place, so a reader
//! never sees a half written file.

use std::ffi::{c_void, OsStr};
use std::fs;
use std::io::{Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{exit, Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// A thread in a snapshot (THREADENTRY32).
#[repr(C)]
struct ThreadEntry {
    size: u32,
    usage: u32,
    thread_id: u32,
    owner_process_id: u32,
    base_priority: i32,
    delta_priority: i32,
    flags: u32,
}

/// A process in a snapshot (PROCESSENTRY32W).
#[repr(C)]
struct ProcessEntry {
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
    fn Process32FirstW(snapshot: *mut c_void, entry: *mut ProcessEntry) -> i32;
    fn Process32NextW(snapshot: *mut c_void, entry: *mut ProcessEntry) -> i32;
    fn GetCurrentProcessId() -> u32;
    fn GetStdHandle(which: u32) -> *mut c_void;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn GetNamedPipeInfo(pipe: *mut c_void, flags: *mut u32, out_buffer: *mut u32, in_buffer: *mut u32, max_instances: *mut u32) -> i32;
    fn CreateNamedPipeW(name: *const u16, open_mode: u32, pipe_mode: u32, max_instances: u32, out_buffer: u32, in_buffer: u32, timeout: u32, attributes: *mut c_void) -> *mut c_void;
    fn ConnectNamedPipe(pipe: *mut c_void, overlapped: *mut c_void) -> i32;
    fn ReadFile(handle: *mut c_void, buffer: *mut u8, count: u32, read: *mut u32, overlapped: *mut c_void) -> i32;
    fn WriteFile(handle: *mut c_void, buffer: *const u8, count: u32, written: *mut u32, overlapped: *mut c_void) -> i32;
    fn OpenProcess(access: u32, inherit: i32, id: u32) -> *mut c_void;
    fn GetProcessTimes(process: *mut c_void, creation: *mut u64, exit: *mut u64, kernel: *mut u64, user: *mut u64) -> i32;
    fn QueryFullProcessImageNameW(process: *mut c_void, flags: u32, name: *mut u16, size: *mut u32) -> i32;
    fn GetSystemWindowsDirectoryW(buffer: *mut u16, size: u32) -> u32;
    fn CreatePipe(read: *mut *mut c_void, write: *mut *mut c_void, attributes: *mut c_void, size: u32) -> i32;
    fn GetLastError() -> u32;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
    fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> *mut c_void;
    fn Thread32First(snapshot: *mut c_void, entry: *mut ThreadEntry) -> i32;
    fn Thread32Next(snapshot: *mut c_void, entry: *mut ThreadEntry) -> i32;
    fn OpenThread(access: u32, inherit: i32, thread_id: u32) -> *mut c_void;
    fn GetThreadTimes(thread: *mut c_void, creation: *mut u64, exit: *mut u64, kernel: *mut u64, user: *mut u64) -> i32;
    fn SuspendThread(thread: *mut c_void) -> u32;
    fn ResumeThread(thread: *mut c_void) -> u32;
    fn SetHandleInformation(handle: *mut c_void, mask: u32, flags: u32) -> i32;
    fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
    fn GetExitCodeProcess(process: *mut c_void, code: *mut u32) -> i32;
    fn TerminateProcess(process: *mut c_void, code: u32) -> i32;
    fn CreateProcessW(application: *const u16, command_line: *mut u16, process_attributes: *mut c_void, thread_attributes: *mut c_void, inherit_handles: i32,
        creation_flags: u32, environment: *mut c_void, current_directory: *const u16, startup: *mut StartupInfo, information: *mut ProcessInfo) -> i32;
    fn CreatePseudoConsole(size: u32, input: *mut c_void, output: *mut c_void, flags: u32, console: *mut *mut c_void) -> i32;
    fn ClosePseudoConsole(console: *mut c_void);
    fn InitializeProcThreadAttributeList(list: *mut c_void, count: u32, flags: u32, size: *mut usize) -> i32;
    fn UpdateProcThreadAttribute(list: *mut c_void, flags: u32, attribute: usize, value: *mut c_void, size: usize, previous: *mut c_void, returned: *mut usize) -> i32;
    fn DeleteProcThreadAttributeList(list: *mut c_void);
    fn CreateJobObjectW(attributes: *mut c_void, name: *const u16) -> *mut c_void;
    fn AssignProcessToJobObject(job: *mut c_void, process: *mut c_void) -> i32;
    fn QueryInformationJobObject(job: *mut c_void, class: i32, info: *mut c_void, length: u32, returned: *mut u32) -> i32;
    fn TerminateJobObject(job: *mut c_void, code: u32) -> i32;
}

#[link(name = "user32")]
extern "system" {
    fn CreateWindowStationW(name: *const u16, flags: u32, access: u32, attributes: *mut c_void) -> *mut c_void;
    fn SetProcessWindowStation(station: *mut c_void) -> i32;
    fn GetProcessWindowStation() -> *mut c_void;
    fn CreateDesktopW(name: *const u16, device: *const u16, mode: *mut c_void, flags: u32, access: u32, attributes: *mut c_void) -> *mut c_void;
    fn GetUserObjectInformationW(object: *mut c_void, index: i32, info: *mut c_void, length: u32, needed: *mut u32) -> i32;
}

#[link(name = "ntdll")]
extern "system" {
    fn NtSuspendProcess(process: *mut c_void) -> i32;
    fn NtResumeProcess(process: *mut c_void) -> i32;
}

#[link(name = "secur32")]
extern "system" {
    fn GetUserNameExW(format: i32, name: *mut u16, size: *mut u32) -> u8;
}

#[link(name = "advapi32")]
extern "system" {
    fn GetSecurityInfo(handle: *mut c_void, kind: u32, information: u32, owner: *mut *mut c_void, group: *mut *mut c_void,
        dacl: *mut *mut c_void, sacl: *mut *mut c_void, descriptor: *mut *mut c_void) -> u32;
    fn ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor: *mut c_void, revision: u32, information: u32, text: *mut *mut u16, length: *mut u32) -> i32;
}

const USAGE_EXIT: i32 = 97;
const WAIT_TIMEOUT_EXIT: i32 = 98;
const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;

fn usage(message: &str) -> ! {
    eprintln!("testkit: {}", message);
    exit(USAGE_EXIT);
}

fn need(rest: &[String], count: usize, form: &str) {
    if rest.len() != count {
        usage(&format!("usage: testkit {}", form));
    }
}

fn need_at_least(rest: &[String], count: usize, form: &str) {
    if rest.len() < count {
        usage(&format!("usage: testkit {}", form));
    }
}

fn number<T: std::str::FromStr>(text: &str, what: &str) -> T {
    text.parse().unwrap_or_else(|_| usage(&format!("{} is not a valid number: {}", what, text)))
}

/// A 32 bit code written in decimal or with a 0x prefix.
fn code(text: &str) -> u32 {
    let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => text.parse::<u32>(),
    };
    parsed.unwrap_or_else(|_| usage(&format!("not a 32 bit code: {}", text)))
}

/// A finite, non-negative number of seconds, small enough for a Duration.
fn seconds(text: &str) -> f64 {
    match text.parse::<f64>() {
        Ok(value) if value.is_finite() && (0.0..=1.0e7).contains(&value) => value,
        _ => usage(&format!("not a valid number of seconds: {}", text)),
    }
}

fn pause(value: f64) {
    sleep(Duration::from_secs_f64(value));
}

fn args_after(skip: usize) -> Vec<String> {
    std::env::args_os().skip(skip).map(|a| a.to_string_lossy().into_owned()).collect()
}

/// Compact JavaScript Object Notation (JSON) array of strings. Quote,
/// backslash and control characters are escaped; other text is written as it is.
fn json_array(items: &[String]) -> String {
    let mut out = String::from("[");
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('"');
        for c in item.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
    }
    out.push(']');
    out
}

/// Write `contents` beside `target` under a temporary name, then rename it into place.
fn publish(target: &Path, contents: &str) {
    let mut temporary = target.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    if let Err(error) = fs::write(&temporary, contents).and_then(|_| fs::rename(&temporary, target)) {
        eprintln!("testkit: cannot write {}: {}", target.display(), error);
        exit(1);
    }
}

fn publish_own_id(target: &Path) {
    publish(target, &std::process::id().to_string());
}

fn fail_spawn(error: &std::io::Error) -> ! {
    eprintln!("testkit: [WinError {}] {}", error.raw_os_error().unwrap_or(0), error);
    exit(1);
}

fn start(program: &OsStr, args: &[&str], flags: u32, quiet: bool) -> Child {
    let mut command = Command::new(program);
    command.args(args).creation_flags(flags);
    if quiet {
        command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    }
    command.spawn().unwrap_or_else(|error| fail_spawn(&error))
}

/// Start another copy of this executable with null standard streams.
fn start_self(args: &[&str]) -> Child {
    let me = std::env::current_exe().unwrap_or_else(|error| fail_spawn(&error));
    start(me.as_os_str(), args, 0, true)
}

/// The result of a request to the enclosing extendable run, as one line of text.
fn extension_line(result: Result<process_tree_guard::Grant, process_tree_guard::GuardError>) -> (String, bool) {
    match result {
        Ok(grant) => (format!("granted {}", grant.seconds), true),
        Err(error) => (format!("error {}", error), false),
    }
}

/// Open the channel `name` for reading and writing with exactly the rights its access list gives.
fn open_channel(name: &str, access: u32) -> std::io::Result<fs::File> {
    // 0x100183: read data, write data, read and write attributes, synchronize. The generic
    // write right is not asked for, because it includes a right the list leaves out.
    fs::OpenOptions::new().access_mode(access).security_qos_flags(0x0010_0000).open(name)
}

/// The channel a command names: the word `env` stands for the one this process was given.
fn channel_name(argument: &str) -> String {
    if argument == "env" {
        std::env::var(process_tree_guard::CHANNEL_VARIABLE).unwrap_or_else(|_| usage("no channel in the environment"))
    } else {
        argument.to_string()
    }
}

/// One request for `asked` seconds as the hold `token` of the caller, read after `delay` seconds:
/// `status S code C` (S 0 is a grant, 1 a refusal and C the reason), or what went wrong.
fn ask_slowly(name: &str, token: u64, asked: f64, delay: f64) -> String {
    let mut channel = match open_channel(name, 0x0010_0183) {
        Ok(channel) => channel,
        Err(error) => return format!("open failed {}", error.raw_os_error().unwrap_or(0)),
    };
    let mut request = Vec::new();
    request.extend_from_slice(b"PTGERQ01");
    request.extend_from_slice(&(1u64 | token << 8).to_le_bytes());
    request.extend_from_slice(&asked.to_bits().to_le_bytes());
    if let Err(error) = channel.write_all(&request) {
        return format!("write failed {}", error.raw_os_error().unwrap_or(0));
    }
    pause(delay);
    let mut reply = [0u8; 128];
    match channel.read(&mut reply) {
        Ok(0) => "read 0 bytes".to_string(),
        Ok(n) if n == 40 && &reply[..8] == b"PTGERP01" => {
            let word = |i: usize| u64::from_le_bytes(reply[8 * i..8 * i + 8].try_into().unwrap_or([0; 8]));
            format!("status {} code {}", word(1), word(2))
        }
        Ok(n) => format!("read {} bytes that are not a reply", n),
        Err(error) => format!("read failed {}", error.raw_os_error().unwrap_or(0)),
    }
}

/// Suspend the first thread (by creation time) of the process `id` for `hold` seconds and
/// resume it. The first thread of the guard is the supervisor: the others serve the channel.
fn suspend_first_thread(id: u32, hold: f64) {
    const THREADS: u32 = 4;
    const SUSPEND_RESUME_AND_QUERY: u32 = 0x2 | 0x800;
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(THREADS, 0);
        if snapshot as isize == -1 {
            usage("cannot list the threads");
        }
        let mut entry = ThreadEntry { size: std::mem::size_of::<ThreadEntry>() as u32, usage: 0, thread_id: 0, owner_process_id: 0, base_priority: 0, delta_priority: 0, flags: 0 };
        let mut first: Option<(u64, *mut c_void)> = None;
        let mut more = Thread32First(snapshot, &mut entry);
        while more != 0 {
            if entry.owner_process_id == id {
                let thread = OpenThread(SUSPEND_RESUME_AND_QUERY, 0, entry.thread_id);
                if !thread.is_null() {
                    let (mut created, mut exited, mut kernel, mut user) = (0u64, 0u64, 0u64, 0u64);
                    GetThreadTimes(thread, &mut created, &mut exited, &mut kernel, &mut user);
                    match first {
                        Some((earliest, _)) if earliest <= created => {
                            CloseHandle(thread);
                        }
                        Some((_, kept)) => {
                            CloseHandle(kept);
                            first = Some((created, thread));
                        }
                        None => first = Some((created, thread)),
                    }
                }
            }
            more = Thread32Next(snapshot, &mut entry);
        }
        CloseHandle(snapshot);
        let Some((_, thread)) = first else { usage("the process has no thread") };
        SuspendThread(thread);
        pause(hold);
        ResumeThread(thread);
        CloseHandle(thread);
    }
}

fn hex_bytes(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap_or_else(|_| usage("not hexadecimal"))).collect()
}

fn count_marker_files(dir: &Path) -> usize {
    fs::read_dir(dir)
        .map(|entries| entries.flatten().filter(|e| e.path().extension().map_or(false, |x| x == "pid")).count())
        .unwrap_or(0)
}

/// A file that exists, or a folder holding at least one marker file.
fn marker_present(path: &Path) -> bool {
    if path.is_dir() {
        count_marker_files(path) > 0
    } else {
        path.exists()
    }
}

/// The code of `hidden-station-guard` when the window station could not be made or is visible.
const NO_HIDDEN_STATION_EXIT: i32 = 96;

/// STARTUPINFOW.
#[repr(C)]
struct StartupInfo {
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
    std_input: *mut c_void,
    std_output: *mut c_void,
    std_error: *mut c_void,
}

#[repr(C)]
struct ProcessInfo {
    process: *mut c_void,
    thread: *mut c_void,
    process_id: u32,
    thread_id: u32,
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A command line from arguments, each in quotes when it has a space or is empty (no argument has a quote or a trailing backslash).
fn command_line(args: &[&str]) -> String {
    args.iter().map(|arg| if arg.is_empty() || arg.contains(' ') { format!("\"{}\"", arg) } else { arg.to_string() }).collect::<Vec<_>>().join(" ")
}

fn run_on_hidden_station(guard: &str, cap: &str, timeout: &str, child: &[String]) -> i32 {
    const GENERIC_ALL: u32 = 0x1000_0000;
    const UOI_FLAGS: i32 = 1;
    const UOI_NAME: i32 = 2;
    const WSF_VISIBLE: u32 = 1;
    const DETACHED_PROCESS: u32 = 0x8;
    const STARTF_USESTDHANDLES: u32 = 0x100;
    const HANDLE_FLAG_INHERIT: u32 = 1;
    // The refusal is immediate. A guard that is still there after this is not refusing, and may have put a prompt on
    // the screen: the wait is short so that, if it ever does, the prompt is gone within seconds.
    const WAIT_LIMIT_MS: u32 = 10_000;
    unsafe {
        // A station with no name of its own: the system names it, and a named one is refused to a process that is not a service.
        let station = CreateWindowStationW(std::ptr::null(), 0, GENERIC_ALL, std::ptr::null_mut());
        if station.is_null() || SetProcessWindowStation(station) == 0 {
            eprintln!("testkit: cannot make a window station [WinError {}]", GetLastError());
            return NO_HIDDEN_STATION_EXIT;
        }
        // USEROBJECTFLAGS: two Booleans, then the flags. The station that is current now must not be visible.
        let (mut flags, mut needed) = ([0u32; 3], 0u32);
        let current = GetProcessWindowStation();
        if current.is_null() || GetUserObjectInformationW(current, UOI_FLAGS, flags.as_mut_ptr() as *mut c_void, 12, &mut needed) == 0 || flags[2] & WSF_VISIBLE != 0 {
            eprintln!("testkit: the window station of this process is visible or cannot be read; nothing was started");
            return NO_HIDDEN_STATION_EXIT;
        }
        let desktop = CreateDesktopW(wide("hidden").as_ptr(), std::ptr::null(), std::ptr::null_mut(), 0, GENERIC_ALL, std::ptr::null_mut());
        if desktop.is_null() {
            eprintln!("testkit: cannot make a desktop [WinError {}]", GetLastError());
            return NO_HIDDEN_STATION_EXIT;
        }
        let mut station_name = [0u16; 256];
        if GetUserObjectInformationW(current, UOI_NAME, station_name.as_mut_ptr() as *mut c_void, 510, &mut needed) == 0 {
            eprintln!("testkit: cannot read the name of the window station [WinError {}]", GetLastError());
            return NO_HIDDEN_STATION_EXIT;
        }
        let station_name = String::from_utf16_lossy(&station_name[..station_name.iter().position(|unit| *unit == 0).unwrap_or(0)]);
        let mut desktop_name = wide(&format!("{}\\hidden", station_name));
        let mut args: Vec<&str> = vec![guard, "--extendable", "--max-extension", cap, "--timeout", timeout, "--"];
        args.extend(child.iter().map(String::as_str));
        let mut line = wide(&command_line(&args));
        let mut startup: StartupInfo = std::mem::zeroed();
        startup.cb = std::mem::size_of::<StartupInfo>() as u32;
        startup.desktop = desktop_name.as_mut_ptr();
        startup.flags = STARTF_USESTDHANDLES;
        for (which, slot) in [(-10i32, 0usize), (-11, 1), (-12, 2)] {
            let handle = GetStdHandle(which as u32);
            if !handle.is_null() && handle as isize != -1 {
                SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
            }
            match slot {
                0 => startup.std_input = handle,
                1 => startup.std_output = handle,
                _ => startup.std_error = handle,
            }
        }
        let mut info = ProcessInfo { process: std::ptr::null_mut(), thread: std::ptr::null_mut(), process_id: 0, thread_id: 0 };
        let started = CreateProcessW(std::ptr::null(), line.as_mut_ptr(), std::ptr::null_mut(), std::ptr::null_mut(), 1, DETACHED_PROCESS,
            std::ptr::null_mut(), std::ptr::null(), &mut startup, &mut info);
        if started == 0 {
            eprintln!("testkit: cannot start the guard [WinError {}]", GetLastError());
            return NO_HIDDEN_STATION_EXIT;
        }
        CloseHandle(info.thread);
        if WaitForSingleObject(info.process, WAIT_LIMIT_MS) != 0 {
            TerminateProcess(info.process, 1);
            eprintln!("testkit: the guard did not end within {} milliseconds", WAIT_LIMIT_MS);
            return WAIT_TIMEOUT_EXIT;
        }
        let mut status = 0u32;
        GetExitCodeProcess(info.process, &mut status);
        CloseHandle(info.process);
        status as i32
    }
}

/// STARTUPINFOEXW: the startup information and a list of attributes.
#[repr(C)]
struct StartupInfoEx {
    startup: StartupInfo,
    attributes: *mut c_void,
}

/// The code of `pty-guard` when no pseudo console could be made (before Windows 10 1809, or a host that refuses one).
const NO_PSEUDO_CONSOLE_EXIT: i32 = 95;

/// The text of terminal output without the escape sequences that move the cursor and set the
/// colours (a control sequence ends at a letter, an operating system command at a bell or a string
/// terminator), and with carriage returns left out.
fn plain_text(bytes: &[u8]) -> String {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            0x1b if bytes.get(i + 1) == Some(&b'[') => {
                i += 2;
                while i < bytes.len() && !(0x40..=0x7e).contains(&bytes[i]) {
                    i += 1;
                }
                i += 1;
            }
            0x1b if bytes.get(i + 1) == Some(&b']') => {
                i += 2;
                while i < bytes.len() && bytes[i] != 0x07 && !(bytes[i] == 0x1b && bytes.get(i + 1) == Some(&b'\\')) {
                    i += 1;
                }
                i += if bytes.get(i) == Some(&0x1b) { 2 } else { 1 };
            }
            0x0d => i += 1,
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// JOBOBJECT_BASIC_ACCOUNTING_INFORMATION: what a job has counted, with the number of its processes that are alive.
#[repr(C)]
#[derive(Default)]
struct JobAccounting {
    times: [i64; 4],
    page_faults: u32,
    total_processes: u32,
    active_processes: u32,
    terminated_processes: u32,
}

/// The number of processes of `job` that are alive, or None when that cannot be read.
fn active_processes(job: *mut c_void) -> Option<u32> {
    let mut information = JobAccounting::default();
    let read = unsafe {
        QueryInformationJobObject(job, 1, &mut information as *mut JobAccounting as *mut c_void,
            std::mem::size_of::<JobAccounting>() as u32, std::ptr::null_mut())
    };
    (read != 0).then_some(information.active_processes)
}

/// The time the process `id` was created, as the system counts it; None when it cannot be read.
fn started_at(id: u32) -> Option<u64> {
    unsafe {
        let handle = OpenProcess(0x1000, 0, id);
        if handle.is_null() {
            return None;
        }
        let (mut created, mut exited, mut kernel, mut user) = (0u64, 0u64, 0u64, 0u64);
        let read = GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user);
        CloseHandle(handle);
        (read != 0).then_some(created)
    }
}

/// The path of the file of the process `id`, in lower case; empty when it cannot be read.
fn image_of(id: u32) -> String {
    unsafe {
        let handle = OpenProcess(0x1000, 0, id);
        if handle.is_null() {
            return String::new();
        }
        let mut buffer = [0u16; 1024];
        let mut size = buffer.len() as u32;
        let read = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size);
        CloseHandle(handle);
        if read == 0 { String::new() } else { String::from_utf16_lossy(&buffer[..size as usize]).to_ascii_lowercase() }
    }
}

/// The Windows folder in lower case, without a final separator; empty when it cannot be read.
fn windows_folder() -> String {
    let mut buffer = [0u16; 512];
    let length = unsafe { GetSystemWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return String::new();
    }
    String::from_utf16_lossy(&buffer[..length]).trim_end_matches('\\').to_ascii_lowercase()
}

/// The file names, in lower case, of the live processes above this one, nearest first, walked by
/// the two rules of the walk of the guard that refuses a run that another guard started: each
/// parent must have started before its child (a reused process identifier is not a parent), and
/// the walk stops at the shell of the desktop and at system processes only when the file is in
/// the Windows folder (a copy of one of those names in another folder is walked past).
fn ancestor_names() -> Vec<String> {
    let windows = windows_folder();
    let mut table = std::collections::HashMap::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(2, 0);
        if snapshot as isize != -1 && !snapshot.is_null() {
            let mut entry: ProcessEntry = std::mem::zeroed();
            entry.size = std::mem::size_of::<ProcessEntry>() as u32;
            let mut more = Process32FirstW(snapshot, &mut entry);
            while more != 0 {
                let length = entry.exe_file.iter().position(|unit| *unit == 0).unwrap_or(entry.exe_file.len());
                table.insert(entry.process_id, (entry.parent_process_id, String::from_utf16_lossy(&entry.exe_file[..length]).to_ascii_lowercase()));
                more = Process32NextW(snapshot, &mut entry);
            }
            CloseHandle(snapshot);
        }
    }
    let (mut names, mut child) = (Vec::new(), unsafe { GetCurrentProcessId() });
    let mut child_started = started_at(child).unwrap_or(u64::MAX);
    for _ in 0..32 {
        let Some((parent, _)) = table.get(&child) else { break };
        let Some((_, name)) = table.get(parent) else { break };
        if *parent == 0 || *parent == 4 {
            break;
        }
        if ["explorer.exe", "services.exe", "wininit.exe", "winlogon.exe", "svchost.exe", "smss.exe"].contains(&name.as_str()) {
            let image = image_of(*parent);
            if !windows.is_empty() && image.strip_prefix(&windows).map_or(false, |rest| rest.starts_with('\\')) {
                break;
            }
        }
        let Some(started) = started_at(*parent) else { break };
        if started > child_started {
            break;
        }
        names.push(name.clone());
        child = *parent;
        child_started = started;
    }
    names
}

/// Run `guard args...` in a pseudo console: a console that is really one (standard input passes
/// the test for a console), with nothing shown on any desktop. With `type_enter`, an Enter is
/// typed every 300 milliseconds until the program ends, which answers a prompt with an empty user
/// name and an empty password for as long as it asks; without it nothing is typed, and a prompt
/// stays unanswered. Prints `exit CODE` and the text written to the console, which is collected
/// until every process that was started in it has ended (the program that was run is in a job
/// with them, and a program that it started may outlive it) and the console has been quiet for a second.
fn run_in_pseudo_console(limit: f64, guard: &str, args: &[String], type_enter: bool) -> i32 {
    const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
    const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE: usize = 0x0002_0016;
    // A run over the default cap by the desktop method would show a prompt on the desktop of whoever runs this (a pseudo
    // console does not hide the desktop). Only the options of the guard count, up to the first `--`: the arguments of
    // its command are not options, and an option given twice is read as the guard reads it, the last one winning.
    let options = &args[..args.iter().position(|arg| arg == "--").unwrap_or(args.len())];
    let method = options.iter().enumerate().rev().find_map(|(at, arg)| {
        if arg == "--authenticate" { options.get(at + 1).map(String::as_str) } else { arg.strip_prefix("--authenticate=") }
    });
    if method != Some("console") {
        usage("pty-guard runs a guard only with --authenticate console");
    }
    unsafe {
        let none = std::ptr::null_mut::<c_void>();
        let (mut input_read, mut input_write, mut output_read, mut output_write) = (none, none, none, none);
        if CreatePipe(&mut input_read, &mut input_write, std::ptr::null_mut(), 0) == 0 || CreatePipe(&mut output_read, &mut output_write, std::ptr::null_mut(), 0) == 0 {
            usage("cannot make a pipe");
        }
        // 2000 columns, so that no line of the guard wraps.
        let mut console: *mut c_void = std::ptr::null_mut();
        if CreatePseudoConsole(50 << 16 | 2000, input_read, output_write, 0, &mut console) < 0 {
            eprintln!("testkit: cannot make a pseudo console");
            return NO_PSEUDO_CONSOLE_EXIT;
        }
        CloseHandle(input_read);
        CloseHandle(output_write);
        let mut size = 0usize;
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size);
        let mut list = vec![0u64; size / 8 + 1];
        let list_pointer = list.as_mut_ptr() as *mut c_void;
        if InitializeProcThreadAttributeList(list_pointer, 1, 0, &mut size) == 0
            || UpdateProcThreadAttribute(list_pointer, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, console, std::mem::size_of::<*mut c_void>(),
                std::ptr::null_mut(), std::ptr::null_mut()) == 0 {
            usage(&format!("cannot attach the pseudo console [WinError {}]", GetLastError()));
        }
        // The console asks for the position of the cursor; a terminal answers it.
        let collected = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let (reader_output, reader_input, sink) = (output_read as usize, input_write as usize, collected.clone());
        let reader = std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            loop {
                let mut read = 0u32;
                if ReadFile(reader_output as *mut c_void, buffer.as_mut_ptr(), buffer.len() as u32, &mut read, std::ptr::null_mut()) == 0 || read == 0 {
                    break;
                }
                let chunk = &buffer[..read as usize];
                if chunk.windows(4).any(|window| window == b"\x1b[6n") {
                    let mut written = 0u32;
                    WriteFile(reader_input as *mut c_void, b"\x1b[1;1R".as_ptr(), 6, &mut written, std::ptr::null_mut());
                }
                sink.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).extend_from_slice(chunk);
            }
        });
        let mut startup: StartupInfoEx = std::mem::zeroed();
        startup.startup.cb = std::mem::size_of::<StartupInfoEx>() as u32;
        startup.attributes = list_pointer;
        // Standard handles that are asked for and null: the guard gets those of the pseudo console, not the ones this process was given.
        startup.startup.flags = 0x100;
        let mut all: Vec<&str> = vec![guard];
        all.extend(args.iter().map(String::as_str));
        let mut line = wide(&command_line(&all));
        let mut info = ProcessInfo { process: std::ptr::null_mut(), thread: std::ptr::null_mut(), process_id: 0, thread_id: 0 };
        // The program is started suspended and put in a job before it runs, so that every process it starts is in the job, and the
        // run is over only when the job is empty: a guard that a shell started and left behind still holds the lock of the prompts
        // of the session until it has ended, and the next test must not start before that.
        const CREATE_SUSPENDED: u32 = 0x4;
        if CreateProcessW(std::ptr::null(), line.as_mut_ptr(), std::ptr::null_mut(), std::ptr::null_mut(), 0, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
            std::ptr::null_mut(), std::ptr::null(), &mut startup as *mut StartupInfoEx as *mut StartupInfo, &mut info) == 0 {
            eprintln!("testkit: cannot start the guard [WinError {}]", GetLastError());
            return NO_PSEUDO_CONSOLE_EXIT;
        }
        let job = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
        if job.is_null() || AssignProcessToJobObject(job, info.process) == 0 {
            eprintln!("testkit: cannot put the guard in a job [WinError {}]", GetLastError());
            TerminateProcess(info.process, 1);
            return NO_PSEUDO_CONSOLE_EXIT;
        }
        ResumeThread(info.thread);
        CloseHandle(info.thread);
        let begun = Instant::now();
        let mut timed_out = false;
        while WaitForSingleObject(info.process, 300) != 0 {
            if begun.elapsed().as_secs_f64() > limit {
                TerminateJobObject(job, 1);
                timed_out = true;
                break;
            }
            if type_enter {
                let mut written = 0u32;
                WriteFile(input_write, b"\r".as_ptr(), 1, &mut written, std::ptr::null_mut());
            }
        }
        let mut status = 0u32;
        GetExitCodeProcess(info.process, &mut status);
        CloseHandle(info.process);
        // The processes that the program started: wait for them to end, within the same limit (a count that cannot be read is
        // taken as none, and the settling below is then all that waits).
        while !timed_out && active_processes(job).map_or(false, |alive| alive > 0) {
            if begun.elapsed().as_secs_f64() > limit {
                TerminateJobObject(job, 1);
                timed_out = true;
                break;
            }
            sleep(Duration::from_millis(100));
        }
        CloseHandle(job);
        // A program that was started in the console may outlive the one that was run (a starter that ended while the
        // guard it started goes on to refuse its run): the console stays open until it has been quiet for a second, at
        // most five seconds. The reader ends when the console is closed; closing it waits for the last of the output.
        let settling = Instant::now();
        let length = || collected.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).len();
        let (mut seen, mut changed) = (length(), Instant::now());
        while changed.elapsed() < Duration::from_millis(1000) && settling.elapsed() < Duration::from_secs(5) {
            sleep(Duration::from_millis(100));
            if length() != seen {
                seen = length();
                changed = Instant::now();
            }
        }
        ClosePseudoConsole(console);
        let _ = reader.join();
        CloseHandle(input_write);
        CloseHandle(output_read);
        DeleteProcThreadAttributeList(list_pointer);
        let text = plain_text(&collected.lock().unwrap_or_else(|poisoned| poisoned.into_inner()));
        println!("exit {}", if timed_out { -1 } else { status as i64 });
        println!("{}", text);
        if timed_out { WAIT_TIMEOUT_EXIT } else { 0 }
    }
}

fn main() {
    let args = args_after(1);
    let (name, rest) = match args.split_first() {
        Some((name, rest)) => (name.as_str(), rest),
        None => usage("a subcommand is required"),
    };
    match name {
        "sleep" => {
            need(rest, 1, "sleep SECONDS");
            pause(seconds(&rest[0]));
        }
        "exit" => {
            need(rest, 1, "exit CODE");
            exit(code(&rest[0]) as i32);
        }
        "print" => println!("{}", rest.join(" ")),
        "relay" => {
            need(rest, 1, "relay CODE");
            let mut data = Vec::new();
            let _ = std::io::stdin().read_to_end(&mut data);
            let mut out = std::io::stdout();
            let _ = out.write_all(&data);
            let _ = out.write_all(b"\n");
            let _ = out.flush();
            eprintln!("error-stream");
            exit(code(&rest[0]) as i32);
        }
        "cat" => {
            let (stdin, stdout) = (std::io::stdin(), std::io::stdout());
            let (mut input, mut output) = (stdin.lock(), stdout.lock());
            if std::io::copy(&mut input, &mut output).and_then(|_| output.flush()).is_err() {
                exit(1);
            }
        }
        "stdin-empty" => {
            let mut data = Vec::new();
            let _ = std::io::stdin().read_to_end(&mut data);
            println!("{}", if data.is_empty() { "True" } else { "False" });
        }
        "args-json" => println!("{}", json_array(rest)),
        "args-exit" => {
            need_at_least(rest, 1, "args-exit CODE ARGS...");
            let status = code(&rest[0]);
            println!("{}", json_array(&rest[1..]));
            exit(status as i32);
        }
        "arg-len" => {
            need(rest, 1, "arg-len ARG");
            println!("{}", rest[0].chars().count());
        }
        "mark" => {
            need(rest, 2, "mark FILE SECONDS");
            let wait = seconds(&rest[1]);
            publish_own_id(Path::new(&rest[0]));
            pause(wait);
        }
        "mark-dir" => {
            need(rest, 2, "mark-dir DIR SECONDS");
            let wait = seconds(&rest[1]);
            publish_own_id(&Path::new(&rest[0]).join(format!("{}.pid", std::process::id())));
            pause(wait);
        }
        "bloat" => {
            need(rest, 3, "bloat MEGABYTES FILE SECONDS");
            let megabytes: usize = number(&rest[0], "MEGABYTES");
            let wait = seconds(&rest[2]);
            // Touch every page, so the system has real memory to reclaim when this process ends.
            let mut block: Vec<u8> = Vec::new();
            block.resize(megabytes << 20, 1);
            publish_own_id(Path::new(&rest[1]));
            pause(wait);
            std::hint::black_box(&block);
        }
        "spawn" | "spawn-quiet" => {
            need_at_least(rest, 3, "spawn FLAGS HOLD PROGRAM [ARGS...]");
            let (flags, hold) = (code(&rest[0]), seconds(&rest[1]));
            let args: Vec<&str> = rest[3..].iter().map(String::as_str).collect();
            let _child = start(OsStr::new(&rest[2]), &args, flags, name == "spawn-quiet");
            pause(hold);
        }
        "spawn-marked" | "spawn-marked-quiet" => {
            // Hold until MARK appears (a file, or a folder that gains a marker file), so a
            // slow process start cannot make the caller give up early.
            need_at_least(rest, 4, "spawn-marked FLAGS MARK MAXSECONDS PROGRAM [ARGS...]");
            let (flags, limit) = (code(&rest[0]), seconds(&rest[2]));
            let args: Vec<&str> = rest[4..].iter().map(String::as_str).collect();
            let _child = start(OsStr::new(&rest[3]), &args, flags, name == "spawn-marked-quiet");
            let begun = Instant::now();
            while !marker_present(Path::new(&rest[1])) {
                if begun.elapsed().as_secs_f64() > limit {
                    eprintln!("testkit: no marker at {}", rest[1]);
                    exit(WAIT_TIMEOUT_EXIT);
                }
                sleep(Duration::from_millis(20));
            }
        }
        "lib-run" => {
            // The library call `run`, made after DELAY seconds, so the caller can decide
            // whether this process's parent is still there; the outcome is published.
            need_at_least(rest, 4, "lib-run RESULT SECONDS DELAY PROGRAM [ARGS...]");
            let (limit, delay) = (seconds(&rest[1]), seconds(&rest[2]));
            pause(delay);
            let outcome = match process_tree_guard::run(&rest[3..], limit) {
                Ok(code) => format!("ok {}", code),
                Err(error) => format!("error {}", error),
            };
            publish(Path::new(&rest[0]), &outcome);
        }
        "lib-run-repeat" => {
            // The library call `run` COUNT times in a row, each for at most SECONDS, in a process that
            // then holds for HOLD seconds. The outcome is published: how many calls returned 0, how
            // many did not, and the first reason or code of those that did not.
            need_at_least(rest, 5, "lib-run-repeat RESULT COUNT SECONDS HOLD PROGRAM [ARGS...]");
            let count: usize = number(&rest[1], "COUNT");
            let (limit, hold) = (seconds(&rest[2]), seconds(&rest[3]));
            let (mut done, mut others) = (0usize, Vec::new());
            for _ in 0..count {
                match process_tree_guard::run(&rest[4..], limit) {
                    Ok(0) => done += 1,
                    Ok(code) => others.push(format!("exit {}", code)),
                    Err(error) => others.push(format!("error {}", error)),
                }
            }
            publish(Path::new(&rest[0]), &format!("ok {} others {} {}", done, others.len(), others.first().map_or("", String::as_str)));
            pause(hold);
        }
        "lib-run-overlap" => {
            // The library call `extend` for EXTEND seconds, then two library calls `run` that overlap, from
            // two threads of this process: A (a deadline of A_LIMIT) runs a sleeper of A_SLEEP seconds at
            // once, and B (a deadline of B_LIMIT) runs a program that exits at once, after B_DELAY seconds.
            // Both outcomes are published ("a ok 0 b ok 0"), then this process stays alive.
            need(rest, 6, "lib-run-overlap RESULT A_LIMIT A_SLEEP B_DELAY B_LIMIT EXTEND");
            let (limit_a, delay_b, limit_b, extended) = (seconds(&rest[1]), seconds(&rest[3]), seconds(&rest[4]), seconds(&rest[5]));
            let me = std::env::current_exe().unwrap_or_else(|error| fail_spawn(&error)).to_string_lossy().into_owned();
            println!("{}", extension_line(process_tree_guard::extend(extended)).0);
            let outcome = |result: Result<u32, process_tree_guard::GuardError>| match result {
                Ok(code) => format!("ok {}", code),
                Err(error) => format!("error {}", error),
            };
            let a = {
                let command = vec![me.clone(), "sleep".to_string(), rest[2].clone()];
                std::thread::spawn(move || process_tree_guard::run(&command, limit_a))
            };
            pause(delay_b);
            let b = process_tree_guard::run(&[me, "exit".to_string(), "0".to_string()], limit_b);
            let a = a.join().unwrap_or_else(|_| usage("the first call panicked"));
            publish(Path::new(&rest[0]), &format!("a {} b {}", outcome(a), outcome(b)));
            pause(100.0);
        }
        "audit-reader" => {
            // Ask the enclosing extendable run for one second, wait until the audit file at PATH has the line
            // for it, then open the file for reading twice: sharing reading only (as .NET's File.OpenRead
            // does) and sharing reading and writing. Print what each did: "narrow denied 32" or "narrow opened",
            // "wide opened 1 lines" or "wide denied 32".
            need(rest, 1, "audit-reader PATH");
            let (line, _) = extension_line(process_tree_guard::extend(1.0));
            println!("{}", line);
            let path = Path::new(&rest[0]);
            let limit = Instant::now() + Duration::from_secs(10);
            while !fs::read_to_string(path).map_or(false, |text| text.contains("decision=granted")) {
                if Instant::now() > limit {
                    println!("no line in the file after 10 seconds");
                    exit(WAIT_TIMEOUT_EXIT);
                }
                sleep(Duration::from_millis(20));
            }
            match fs::OpenOptions::new().read(true).share_mode(1).open(path) {
                Ok(_) => println!("narrow opened"),
                Err(error) => println!("narrow denied {}", error.raw_os_error().unwrap_or(0)),
            }
            match fs::OpenOptions::new().read(true).share_mode(3).open(path).and_then(|mut file| {
                let mut text = String::new();
                file.read_to_string(&mut text).map(|_| text)
            }) {
                Ok(text) => println!("wide opened {} lines", text.lines().count()),
                Err(error) => println!("wide denied {}", error.raw_os_error().unwrap_or(0)),
            }
        }
        "lib-shell" => {
            // The library call `run_shell`, made at once; the outcome is published.
            need(rest, 4, "lib-shell RESULT SHELL SECONDS BASE64");
            let shell = process_tree_guard::Shell::from_name(&rest[1]).unwrap_or_else(|| usage(&format!("not a shell: {}", rest[1])));
            let outcome = match process_tree_guard::run_shell(shell, &rest[3], seconds(&rest[2])) {
                Ok(code) => format!("ok {}", code),
                Err(error) => format!("error {}", error),
            };
            publish(Path::new(&rest[0]), &outcome);
        }
        "lib-auto" => {
            // The library call `run_auto` with the remaining arguments; the outcome is published.
            need_at_least(rest, 2, "lib-auto RESULT ARGS...");
            let outcome = match process_tree_guard::run_auto(&rest[1..]) {
                Ok(code) => format!("ok {}", code),
                Err(error) => format!("error {}", error),
            };
            publish(Path::new(&rest[0]), &outcome);
        }
        "lib-hook" => {
            // The library call `run_hook` for VENDOR, with this process's standard input
            // and output; the exit code it returns is published.
            need(rest, 2, "lib-hook RESULT VENDOR");
            let code = process_tree_guard::run_hook(&rest[1]);
            publish(Path::new(&rest[0]), &format!("hook {}", code));
        }
        "env" => {
            // Print the value of an environment variable, or "unset".
            need(rest, 1, "env NAME");
            match std::env::var_os(&rest[0]) {
                Some(value) => println!("{}", value.to_string_lossy()),
                None => println!("unset"),
            }
        }
        "publish-env" => {
            // Publish the value of an environment variable (or "unset"), then hold.
            need(rest, 3, "publish-env FILE NAME SECONDS");
            let wait = seconds(&rest[2]);
            publish(Path::new(&rest[0]), &std::env::var_os(&rest[1]).map_or("unset".to_string(), |v| v.to_string_lossy().into_owned()));
            pause(wait);
        }
        "extend-self" => {
            // The library call `extend`; the answer is printed, 125 when refused. Then hold.
            need(rest, 2, "extend-self SECONDS HOLD");
            // Any number: the run decides what it will grant, and logs what it refuses.
            let asked: f64 = rest[0].parse().unwrap_or_else(|_| usage(&format!("not a number: {}", rest[0])));
            let (line, granted) = extension_line(process_tree_guard::extend(asked));
            println!("{}", line);
            pause(seconds(&rest[1]));
            exit(if granted { 0 } else { 125 });
        }
        "extend-then-exit" => {
            // Ask for a hold on this process, then end at once: the hold must end with the process.
            need(rest, 1, "extend-then-exit SECONDS");
            let (line, granted) = extension_line(process_tree_guard::extend(seconds(&rest[0])));
            println!("{}", line);
            exit(if granted { 0 } else { 125 });
        }
        "extend-loop" => {
            // COUNT requests of SECONDS each, one line of the answer per request.
            need(rest, 2, "extend-loop COUNT SECONDS");
            let count: usize = number(&rest[0], "COUNT");
            for _ in 0..count {
                println!("{}", extension_line(process_tree_guard::extend(seconds(&rest[1]))).0);
            }
        }
        "extend-flood" => {
            // COUNT requests of SECONDS each, as fast as the run answers; print how they were decided.
            need(rest, 2, "extend-flood COUNT SECONDS");
            let count: usize = number(&rest[0], "COUNT");
            let (mut granted, mut outside, mut limited, mut other) = (0, 0, 0, 0);
            for _ in 0..count {
                match process_tree_guard::extend(seconds(&rest[1])) {
                    Ok(_) => granted += 1,
                    Err(error) if error.message().contains("not in the job") => outside += 1,
                    Err(error) if error.message().contains("too many requests") => limited += 1,
                    Err(_) => other += 1,
                }
            }
            println!("granted {} outside {} limited {} other {}", granted, outside, limited, other);
        }
        "extend-steadily" => {
            // For DURATION seconds, one request of HOLD seconds every INTERVAL milliseconds: a process
            // that is never idle for a window of the rate limit. Prints how the requests were decided.
            need(rest, 3, "extend-steadily DURATION INTERVAL_MS HOLD");
            let (limit, hold): (f64, f64) = (seconds(&rest[0]), seconds(&rest[2]));
            let interval: u64 = number(&rest[1], "INTERVAL_MS");
            let begun = Instant::now();
            let (mut granted, mut limited, mut other) = (0, 0, 0);
            while begun.elapsed().as_secs_f64() < limit {
                match process_tree_guard::extend(hold) {
                    Ok(_) => granted += 1,
                    Err(error) if error.message().contains("too many requests") => limited += 1,
                    Err(_) => other += 1,
                }
                sleep(Duration::from_millis(interval));
            }
            println!("granted {} limited {} other {}", granted, limited, other);
        }
        "ask-and-exit" => {
            // Publish READY, wait until FROZEN exists, then write one request to the channel in the
            // environment (30 seconds, for this process) and exit at once without reading the reply:
            // a client that is gone by the time the run decides what to make of its request. With STAY,
            // it closes its end of the channel and then lives on for STAY seconds: the stand-in for a process
            // that has taken the identifier of a client that exited, which is alive and in the job but is
            // not the end of the pipe the request came on.
            need_at_least(rest, 3, "ask-and-exit READY FROZEN MAXSECONDS [STAY]");
            if rest.len() > 4 {
                usage("usage: testkit ask-and-exit READY FROZEN MAXSECONDS [STAY]");
            }
            let limit = seconds(&rest[2]);
            publish(Path::new(&rest[0]), "ready");
            let begun = Instant::now();
            while !Path::new(&rest[1]).exists() {
                if begun.elapsed().as_secs_f64() > limit {
                    eprintln!("testkit: no signal at {}", rest[1]);
                    exit(WAIT_TIMEOUT_EXIT);
                }
                sleep(Duration::from_millis(20));
            }
            let mut channel = open_channel(&channel_name("env"), 0x0010_0183).unwrap_or_else(|error| {
                println!("open failed {}", error.raw_os_error().unwrap_or(0));
                exit(1);
            });
            let mut request = Vec::new();
            request.extend_from_slice(b"PTGERQ01");
            request.extend_from_slice(&1u64.to_le_bytes());
            request.extend_from_slice(&30.0f64.to_bits().to_le_bytes());
            if let Err(error) = channel.write_all(&request) {
                println!("write failed {}", error.raw_os_error().unwrap_or(0));
                exit(1);
            }
            drop(channel);
            if let Some(stay) = rest.get(3) {
                pause(seconds(stay));
            }
            exit(0);
        }
        "freeze" => {
            // Suspend every thread of the process PID, publish FROZEN, hold for HOLD seconds, resume it.
            need(rest, 3, "freeze PID FROZEN HOLD");
            let hold = seconds(&rest[2]);
            unsafe {
                // PROCESS_SUSPEND_RESUME
                let process = OpenProcess(0x0800, 0, number(&rest[0], "PID"));
                if process.is_null() || NtSuspendProcess(process) != 0 {
                    usage("cannot suspend the process");
                }
                publish(Path::new(&rest[1]), "frozen");
                pause(hold);
                NtResumeProcess(process);
                CloseHandle(process);
            }
        }
        "forged-channel" => {
            // A channel served by something that is not the guard: it answers the first request with the
            // bytes REPLYHEX, whatever they are. FILE is published once the pipe exists.
            need(rest, 4, "forged-channel FILE NAME SECONDS REPLYHEX");
            let wait = seconds(&rest[2]);
            let reply = hex_bytes(&rest[3]);
            let name: Vec<u16> = rest[1].encode_utf16().chain(std::iter::once(0)).collect();
            // Message mode, blocking, one instance, the default access list.
            let pipe = unsafe { CreateNamedPipeW(name.as_ptr(), 3, 4 | 2, 1, 512, 512, 0, std::ptr::null_mut()) };
            if pipe as isize == -1 {
                println!("cannot make the pipe {}", unsafe { GetLastError() });
                exit(1);
            }
            publish(Path::new(&rest[0]), "ready");
            unsafe {
                ConnectNamedPipe(pipe, std::ptr::null_mut());
                let (mut buffer, mut count) = ([0u8; 64], 0u32);
                ReadFile(pipe, buffer.as_mut_ptr(), buffer.len() as u32, &mut count, std::ptr::null_mut());
                let mut written = 0u32;
                WriteFile(pipe, reply.as_ptr(), reply.len() as u32, &mut written, std::ptr::null_mut());
            }
            pause(wait);
            unsafe { CloseHandle(pipe) };
        }
        "flood-err" => {
            // Write to standard error until it can be written no more: with a reader that never reads, that is a full pipe.
            let chunk = vec![b'e'; 4096];
            let stderr = std::io::stderr();
            let mut err = stderr.lock();
            loop {
                if err.write_all(&chunk).and_then(|_| err.flush()).is_err() {
                    exit(1);
                }
            }
        }
        "fake-channel" => {
            // A channel that takes a client and never answers: FILE is published once the pipe exists.
            need(rest, 3, "fake-channel FILE NAME SECONDS");
            let wait = seconds(&rest[2]);
            let name: Vec<u16> = rest[1].encode_utf16().chain(std::iter::once(0)).collect();
            // Message mode, blocking, one instance, the default access list.
            let pipe = unsafe { CreateNamedPipeW(name.as_ptr(), 3, 4 | 2, 1, 512, 512, 0, std::ptr::null_mut()) };
            if pipe as isize == -1 {
                println!("cannot make the pipe {}", unsafe { GetLastError() });
                exit(1);
            }
            publish(Path::new(&rest[0]), "ready");
            unsafe { ConnectNamedPipe(pipe, std::ptr::null_mut()) };
            pause(wait);
            unsafe { CloseHandle(pipe) };
        }
        "suspend-main" => {
            // After DELAY seconds, suspend the first thread of process PID for HOLD seconds, then resume it.
            need(rest, 3, "suspend-main PID DELAY HOLD");
            pause(seconds(&rest[1]));
            suspend_first_thread(number(&rest[0], "PID"), seconds(&rest[2]));
        }
        "run-wait" => {
            // Run PROGRAM with the streams of this process and wait for it, hold, and exit with its code.
            need_at_least(rest, 2, "run-wait HOLD PROGRAM [ARGS...]");
            let hold = seconds(&rest[0]);
            let status = Command::new(&rest[1]).args(&rest[2..]).status().unwrap_or_else(|error| fail_spawn(&error));
            pause(hold);
            exit(status.code().unwrap_or(1));
        }
        "after" => {
            // Wait DELAY seconds, then run PROGRAM with the streams of this process and exit with its code.
            need_at_least(rest, 2, "after DELAY PROGRAM [ARGS...]");
            pause(seconds(&rest[0]));
            let status = Command::new(&rest[1]).args(&rest[2..]).status().unwrap_or_else(|error| fail_spawn(&error));
            exit(status.code().unwrap_or(1));
        }
        "par" | "par-loud" => {
            // Start several commands, separated by the token SEP, and hold. `par` gives them
            // null streams; `par-loud` gives them the streams of this process.
            need_at_least(rest, 3, "par HOLD SEP COMMAND [SEP COMMAND]...");
            let hold = seconds(&rest[0]);
            let mut children = Vec::new();
            for command in rest[2..].split(|word| *word == rest[1]).filter(|command| !command.is_empty()) {
                let args: Vec<&str> = command[1..].iter().map(String::as_str).collect();
                children.push(start(OsStr::new(&command[0]), &args, 0, name == "par"));
            }
            pause(hold);
        }
        "raw-send" => {
            // Send the bytes of a hexadecimal string, or nothing (stall), to a channel as one
            // message; print the reply as hexadecimal, or the error. SECONDS is how long to hold the connection.
            need(rest, 4, "raw-send CHANNEL HEX|stall SECONDS READ_REPLY");
            let hold = seconds(&rest[2]);
            let mut channel = open_channel(&channel_name(&rest[0]), 0x0010_0183).unwrap_or_else(|error| {
                println!("open failed {}", error.raw_os_error().unwrap_or(0));
                exit(1);
            });
            if rest[1] != "stall" {
                if let Err(error) = channel.write_all(&hex_bytes(&rest[1])) {
                    println!("write failed {}", error.raw_os_error().unwrap_or(0));
                    exit(1);
                }
            }
            if rest[3] == "yes" {
                let mut reply = [0u8; 128];
                match channel.read(&mut reply) {
                    Ok(n) => println!("reply {}", reply[..n].iter().map(|b| format!("{:02x}", b)).collect::<String>()),
                    Err(error) => println!("read failed {}", error.raw_os_error().unwrap_or(0)),
                }
            }
            pause(hold);
        }
        "late-reader" => {
            // Ask the channel for SECONDS as the hold TOKEN of the caller (what a library call does), wait DELAY
            // seconds, and only then read the reply: a client that is slow to take it. Prints what it got,
            // then holds for HOLD seconds, since a hold ends with its process.
            need(rest, 5, "late-reader CHANNEL TOKEN SECONDS DELAY HOLD");
            let (token, asked, delay): (u64, f64, f64) = (number(&rest[1], "TOKEN"), number(&rest[2], "SECONDS"), seconds(&rest[3]));
            println!("{}", ask_slowly(&channel_name(&rest[0]), token, asked, delay));
            pause(seconds(&rest[4]));
        }
        "hog" => {
            // COUNT requests of SECONDS each from this one process, each as a hold of its own (tokens 1 to
            // COUNT), then hold for HOLD seconds. Prints how each was decided and the reason code of the last refusal.
            need(rest, 4, "hog CHANNEL COUNT SECONDS HOLD");
            let (count, asked, wait): (u64, f64, f64) = (number(&rest[1], "COUNT"), number(&rest[2], "SECONDS"), seconds(&rest[3]));
            let (mut granted, mut refused, mut last) = (0, 0, 0);
            for token in 1..=count {
                let answer = ask_slowly(&channel_name(&rest[0]), token, asked, 0.0);
                match answer.split_whitespace().collect::<Vec<_>>()[..] {
                    ["status", "0", ..] => granted += 1,
                    ["status", "1", "code", code] => {
                        refused += 1;
                        last = code.parse().unwrap_or(0);
                    }
                    _ => println!("unexpected {}", answer),
                }
            }
            println!("granted {} refused {} last {}", granted, refused, last);
            pause(wait);
        }
        "pipe-info" => {
            // Print what the pipe says about its own type: GetNamedPipeInfo flags (4 is a message pipe, 1 the server end).
            need(rest, 1, "pipe-info CHANNEL");
            let channel = open_channel(&channel_name(&rest[0]), 0x0010_0183).unwrap_or_else(|error| {
                println!("open failed {}", error.raw_os_error().unwrap_or(0));
                exit(1);
            });
            let (mut flags, mut out_size, mut in_size, mut instances) = (0u32, 0u32, 0u32, 0u32);
            if unsafe { GetNamedPipeInfo(channel.as_raw_handle() as *mut c_void, &mut flags, &mut out_size, &mut in_size, &mut instances) } == 0 {
                println!("info failed {}", unsafe { GetLastError() });
                exit(1);
            }
            println!("flags {} type {} end {} instances {}", flags, if flags & 4 != 0 { "message" } else { "byte" }, if flags & 1 != 0 { "server" } else { "client" }, instances);
        }
        "stall-loop" => {
            // For SECONDS, connect to a channel, send nothing, and stay until the run lets go (it
            // closes the connection, or answers with a refusal), then connect again at once: a client
            // that stalls the channel again and again. Prints how many connections it held and the
            // longest one, in milliseconds.
            need(rest, 2, "stall-loop CHANNEL SECONDS");
            let (name, limit) = (channel_name(&rest[0]), seconds(&rest[1]));
            let begun = Instant::now();
            let (mut held, mut longest) = (0u32, 0u128);
            while begun.elapsed().as_secs_f64() < limit {
                let Ok(mut channel) = open_channel(&name, 0x0010_0183) else {
                    // Every instance is busy, or the run is gone: try again shortly.
                    sleep(Duration::from_millis(5));
                    continue;
                };
                let connected = Instant::now();
                let mut reply = [0u8; 64];
                let _ = channel.read(&mut reply);
                held += 1;
                longest = longest.max(connected.elapsed().as_millis());
                drop(channel);
                sleep(Duration::from_millis(2));
            }
            println!("held {} longest {}", held, longest);
        }
        "churn" => {
            // COUNT processes that each ask the enclosing run once, for SECONDS, and exit, BATCH at a
            // time: many short-lived requesters. Prints how many were granted and how many were not.
            need(rest, 3, "churn COUNT BATCH SECONDS");
            let (count, batch): (usize, usize) = (number(&rest[0], "COUNT"), number(&rest[1], "BATCH"));
            seconds(&rest[2]);
            let (mut done, mut granted, mut refused) = (0usize, 0usize, 0usize);
            while done < count {
                let size = batch.max(1).min(count - done);
                let mut children: Vec<Child> = (0..size).map(|_| start_self(&["extend-self", &rest[2], "0"])).collect();
                for child in children.iter_mut() {
                    match child.wait() {
                        Ok(status) if status.success() => granted += 1,
                        _ => refused += 1,
                    }
                }
                done += size;
            }
            println!("granted {} refused {}", granted, refused);
        }
        "run-closed-stderr" | "run-closed-stdout" => {
            // Run PROGRAM with a standard error (or, for run-closed-stdout, a standard output) whose
            // reader has already gone, with the other streams of this process, and print its exit code.
            need_at_least(rest, 1, "run-closed-stderr PROGRAM [ARGS...]");
            use std::os::windows::io::{FromRawHandle, OwnedHandle};
            let (mut read, mut write) = (std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());
            if unsafe { CreatePipe(&mut read, &mut write, std::ptr::null_mut(), 0) } == 0 {
                usage("cannot make a pipe");
            }
            unsafe { CloseHandle(read) };
            let closed = Stdio::from(unsafe { OwnedHandle::from_raw_handle(write) });
            let mut command = Command::new(&rest[0]);
            command.args(&rest[1..]);
            if name == "run-closed-stderr" {
                command.stderr(closed);
            } else {
                command.stdout(closed);
            }
            let status = command.status().unwrap_or_else(|error| fail_spawn(&error));
            println!("exit {}", status.code().map_or(-1, |code| code as i64 & 0xffff_ffff));
        }
        "run-message-stderr" => {
            // Run PROGRAM with a standard error that is a message mode pipe, and print what it wrote, one
            // message at a time: each write the program (or a program it starts) makes to standard error
            // is one message, so a line written in several calls shows as several. Then print its exit code.
            need_at_least(rest, 1, "run-message-stderr PROGRAM [ARGS...]");
            let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
            let pipe_name = format!("\\\\.\\pipe\\testkit-messages-{}-{}", std::process::id(), nanos);
            let wide_name: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
            // Inbound, message mode, one instance: the guard under test writes, this process reads.
            let server = unsafe { CreateNamedPipeW(wide_name.as_ptr(), 1, 4 | 2, 1, 65536, 65536, 0, std::ptr::null_mut()) };
            if server as isize == -1 {
                usage(&format!("cannot make the pipe {}", unsafe { GetLastError() }));
            }
            let writer = fs::OpenOptions::new().write(true).open(&pipe_name).unwrap_or_else(|error| fail_spawn(&error));
            let mut child = Command::new(&rest[0]).args(&rest[1..]).stderr(Stdio::from(writer)).spawn().unwrap_or_else(|error| fail_spawn(&error));
            let mut buffer = vec![0u8; 65536];
            loop {
                let mut read = 0u32;
                if unsafe { ReadFile(server, buffer.as_mut_ptr(), buffer.len() as u32, &mut read, std::ptr::null_mut()) } == 0 {
                    break;
                }
                let text = String::from_utf8_lossy(&buffer[..read as usize]).replace(char::from(13), "<CR>").replace(char::from(10), "<LF>");
                println!("message {}", text);
            }
            let status = child.wait().unwrap_or_else(|error| fail_spawn(&error));
            println!("exit {}", status.code().map_or(-1, |code| code as i64 & 0xffff_ffff));
            unsafe { CloseHandle(server) };
        }
        "pipe-squat" => {
            // Try to make another instance of the channel, with and without the first-instance
            // flag; print the Windows error of each (0 would mean it worked).
            need(rest, 1, "pipe-squat CHANNEL");
            let name: Vec<u16> = channel_name(&rest[0]).encode_utf16().chain(std::iter::once(0)).collect();
            for (label, mode) in [("first-instance", 3u32 | 0x0008_0000), ("plain", 3u32)] {
                let pipe = unsafe { CreateNamedPipeW(name.as_ptr(), mode, 4 | 2 | 8, 255, 512, 512, 0, std::ptr::null_mut()) };
                let error = if pipe as isize == -1 { unsafe { GetLastError() } } else { 0 };
                if pipe as isize != -1 {
                    unsafe { CloseHandle(pipe) };
                }
                println!("{} {}", label, error);
            }
        }
        "pipe-host" => {
            // Hold a named pipe open as a server for SECONDS, so that a path to a pipe exists and can be
            // opened by a client; print "ready" once it can be.
            need(rest, 2, "pipe-host NAME SECONDS");
            let name: Vec<u16> = format!(r"\\.\pipe\{}", rest[0]).encode_utf16().chain(std::iter::once(0)).collect();
            let pipes: Vec<_> = (0..4).map(|_| unsafe { CreateNamedPipeW(name.as_ptr(), 3, 0, 4, 512, 512, 0, std::ptr::null_mut()) }).collect();
            if pipes.iter().any(|pipe| *pipe as isize == -1) {
                println!("create failed {}", unsafe { GetLastError() });
                exit(1);
            }
            println!("ready");
            let _ = std::io::stdout().flush();
            pause(seconds(&rest[1]));
            for pipe in pipes {
                unsafe { CloseHandle(pipe) };
            }
        }
        "pipe-sddl" => {
            // Print the access list of the channel as text (Security Descriptor Definition Language).
            need(rest, 1, "pipe-sddl CHANNEL");
            // READ_CONTROL and SYNCHRONIZE only: the list grants both, and no data right is asked for.
            let channel = open_channel(&channel_name(&rest[0]), 0x0012_0000).unwrap_or_else(|error| {
                println!("open failed {}", error.raw_os_error().unwrap_or(0));
                exit(1);
            });
            unsafe {
                let mut descriptor: *mut c_void = std::ptr::null_mut();
                let mut dacl: *mut c_void = std::ptr::null_mut();
                let error = GetSecurityInfo(channel.as_raw_handle() as *mut c_void, 6, 4, std::ptr::null_mut(), std::ptr::null_mut(),
                    &mut dacl, std::ptr::null_mut(), &mut descriptor);
                if error != 0 {
                    println!("security failed {}", error);
                    exit(1);
                }
                let mut text: *mut u16 = std::ptr::null_mut();
                if ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, 4, &mut text, std::ptr::null_mut()) == 0 {
                    println!("convert failed {}", GetLastError());
                    exit(1);
                }
                let mut length = 0;
                while *text.add(length) != 0 {
                    length += 1;
                }
                println!("{}", String::from_utf16_lossy(std::slice::from_raw_parts(text, length)));
                LocalFree(text as *mut c_void);
                LocalFree(descriptor);
            }
        }
        "own-guard" => {
            // Start PROGRAM, publish its process identifier, and leave only once GO exists,
            // so the caller can open the program before its owner exits.
            need_at_least(rest, 4, "own-guard PIDFILE GO MAXSECONDS PROGRAM [ARGS...]");
            let limit = seconds(&rest[2]);
            let args: Vec<&str> = rest[4..].iter().map(String::as_str).collect();
            let child = start(OsStr::new(&rest[3]), &args, 0, true);
            publish(Path::new(&rest[0]), &child.id().to_string());
            let begun = Instant::now();
            while !Path::new(&rest[1]).exists() {
                if begun.elapsed().as_secs_f64() > limit {
                    eprintln!("testkit: no go signal at {}", rest[1]);
                    exit(WAIT_TIMEOUT_EXIT);
                }
                sleep(Duration::from_millis(20));
            }
        }
        "wide" => {
            need(rest, 4, "wide COUNT IDS CHILD_SECONDS HOLD_SECONDS");
            let count: usize = number(&rest[0], "COUNT");
            seconds(&rest[2]);
            let hold = seconds(&rest[3]);
            let mut children = Vec::with_capacity(count);
            let mut ids = String::new();
            for _ in 0..count {
                let child = start_self(&["sleep", &rest[2]]);
                ids.push_str(&format!("{}\n", child.id()));
                children.push(child);
            }
            publish(Path::new(&rest[1]), &ids);
            pause(hold);
        }
        "deep" => {
            need(rest, 4, "deep LEVEL MAX DIR SECONDS");
            let level: u32 = number(&rest[0], "LEVEL");
            let max: u32 = number(&rest[1], "MAX");
            let wait = seconds(&rest[3]);
            publish_own_id(&Path::new(&rest[2]).join(format!("{}.pid", level)));
            let _child = if level < max {
                Some(start_self(&["deep", &(level + 1).to_string(), &rest[1], &rest[2], &rest[3]]))
            } else {
                None
            };
            pause(wait);
        }
        "fan" | "fan-wait" => {
            need(rest, 3, "fan COUNT DIR HOLD | fan-wait COUNT DIR CODE");
            let count: usize = number(&rest[0], "COUNT");
            let children: Vec<Child> = (0..count).map(|_| start_self(&["mark-dir", &rest[1], "60"])).collect();
            if name == "fan" {
                pause(seconds(&rest[2]));
            } else {
                let status = code(&rest[2]);
                let begun = Instant::now();
                while count_marker_files(Path::new(&rest[1])) < count {
                    if begun.elapsed() > Duration::from_secs(30) {
                        eprintln!("testkit: markers did not appear");
                        exit(WAIT_TIMEOUT_EXIT);
                    }
                    sleep(Duration::from_millis(20));
                }
                exit(status as i32);
            }
            drop(children);
        }
        "out-bytes" => {
            need(rest, 1, "out-bytes N");
            let mut remaining: u64 = number(&rest[0], "N");
            let chunk = vec![b'x'; 1 << 20];
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            while remaining > 0 {
                let part = remaining.min(chunk.len() as u64) as usize;
                if out.write_all(&chunk[..part]).is_err() {
                    exit(1);
                }
                remaining -= part as u64;
            }
            if out.flush().is_err() {
                exit(1);
            }
        }
        "flood" => {
            let chunk = vec![b'y'; 65536];
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            loop {
                if out.write_all(&chunk).and_then(|_| out.flush()).is_err() {
                    exit(1);
                }
            }
        }
        "close-stdout-exit" => {
            need(rest, 1, "close-stdout-exit CODE");
            let status = code(&rest[0]);
            unsafe { CloseHandle(GetStdHandle(STD_OUTPUT_HANDLE)) };
            exit(status as i32);
        }
        "ancestors" => {
            // The file names of the live processes above this one, nearest first, one to a line: the tests use it to tell
            // whether a guard is above them, which makes a guard they start a run that another guard started.
            for name in ancestor_names() {
                println!("{}", name);
            }
        }
        "account-name" => {
            // The account this process runs as, as the system names it (DOMAIN\user, the form of
            // NameSamCompatible): the tests compare it with the account that a log line names.
            let mut name = [0u16; 1024];
            let mut size = name.len() as u32;
            if unsafe { GetUserNameExW(2, name.as_mut_ptr(), &mut size) } == 0 || size == 0 || size as usize >= name.len() {
                exit(1);
            }
            println!("{}", String::from_utf16_lossy(&name[..size as usize]));
        }
        "hidden-station-guard" => {
            // Run GUARD --extendable --max-extension CAP --timeout SECONDS -- CHILD... on a window
            // station that is not visible, with the default (desktop) method of asking, and exit
            // with its code. The guard must refuse at once, because it has no interactive window
            // station. If its test for that were defective, the real secure prompt could appear on
            // the desktop of whoever runs the tests; where it would appear is not established. The
            // station is made and checked first, and nothing starts if it cannot be.
            need_at_least(rest, 4, "hidden-station-guard GUARD CAP SECONDS CHILD...");
            exit(run_on_hidden_station(&rest[0], &rest[1], &rest[2], &rest[3..]));
        }
        "pty-guard" => {
            // Run GUARD ARGS... in a pseudo console for at most LIMIT seconds, typing an Enter every 300
            // milliseconds, and print `exit CODE` and what the guard wrote to the console. ARGS must
            // say `--authenticate console`. Exits 0 when the guard ended, 95 where no pseudo console can be made.
            need_at_least(rest, 3, "pty-guard LIMIT GUARD ARGS...");
            exit(run_in_pseudo_console(seconds(&rest[0]), &rest[1], &rest[2..], true));
        }
        "pty-guard-quiet" => {
            // `pty-guard` that types nothing, so that a prompt stays unanswered. The program may be a shell that starts the
            // guard and ends (`cmd.exe /d /c start /b "" GUARD ARGS... & ping ...`), the guard then being run by a starter that
            // exits; ARGS must still say `--authenticate console` among the options of the guard.
            need_at_least(rest, 3, "pty-guard-quiet LIMIT PROGRAM ARGS...");
            exit(run_in_pseudo_console(seconds(&rest[0]), &rest[1], &rest[2..], false));
        }
        _ => usage(&format!("unknown subcommand: {}", name)),
    }
}
