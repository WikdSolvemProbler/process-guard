// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! The Windows system calls the engine uses, declared directly: types,
//! constants and `extern` blocks. No crates are involved.

use crate::GuardError;
use std::ffi::c_void;

pub type Handle = *mut c_void;
pub type Bool = i32;

#[repr(C)]
pub struct StartupInfoW {
    pub cb: u32,
    pub reserved: *mut u16,
    pub desktop: *mut u16,
    pub title: *mut u16,
    pub x: u32,
    pub y: u32,
    pub x_size: u32,
    pub y_size: u32,
    pub x_count_chars: u32,
    pub y_count_chars: u32,
    pub fill_attribute: u32,
    pub flags: u32,
    pub show_window: u16,
    pub reserved2_size: u16,
    pub reserved2: *mut u8,
    pub std_input: Handle,
    pub std_output: Handle,
    pub std_error: Handle,
}

#[repr(C)]
pub struct ProcessInformation {
    pub process: Handle,
    pub thread: Handle,
    pub process_id: u32,
    pub thread_id: u32,
}

#[repr(C)]
#[derive(Default)]
pub struct BasicLimitInformation {
    pub per_process_user_time_limit: i64,
    pub per_job_user_time_limit: i64,
    pub limit_flags: u32,
    pub minimum_working_set_size: usize,
    pub maximum_working_set_size: usize,
    pub active_process_limit: u32,
    pub affinity: usize,
    pub priority_class: u32,
    pub scheduling_class: u32,
}

#[repr(C)]
#[derive(Default)]
pub struct IoCounters {
    pub counts: [u64; 6],
}

#[repr(C)]
#[derive(Default)]
pub struct ExtendedLimitInformation {
    pub basic: BasicLimitInformation,
    pub io: IoCounters,
    pub process_memory_limit: usize,
    pub job_memory_limit: usize,
    pub peak_process_memory_used: usize,
    pub peak_job_memory_used: usize,
}

#[repr(C)]
#[derive(Default)]
pub struct BasicAccountingInformation {
    pub times: [i64; 4],
    pub total_page_fault_count: u32,
    pub total_processes: u32,
    pub active_processes: u32,
    pub total_terminated_processes: u32,
}

#[repr(C)]
pub struct ProcessEntry32W {
    pub size: u32,
    pub usage: u32,
    pub process_id: u32,
    pub default_heap_id: usize,
    pub module_id: u32,
    pub threads: u32,
    pub parent_process_id: u32,
    pub priority_base: i32,
    pub flags: u32,
    pub exe_file: [u16; 260],
}

#[repr(C)]
pub struct ProcessBasicInformation {
    pub exit_status: i32,
    pub peb: *mut c_void,
    pub affinity: usize,
    pub base_priority: i32,
    pub unique_process_id: usize,
    pub parent_process_id: usize,
}

#[repr(C)]
pub struct SecurityAttributes {
    pub length: u32,
    pub descriptor: *mut c_void,
    pub inherit: Bool,
}

#[repr(C)]
pub struct Overlapped {
    pub internal: usize,
    pub internal_high: usize,
    pub offset: u32,
    pub offset_high: u32,
    pub event: Handle,
}

impl Overlapped {
    /// An operation that signals `event` when it completes.
    pub fn with_event(event: Handle) -> Overlapped {
        Overlapped { internal: 0, internal_high: 0, offset: 0, offset_high: 0, event }
    }
}

/// JOBOBJECT_ASSOCIATE_COMPLETION_PORT.
#[repr(C)]
pub struct AssociateCompletionPort {
    pub key: usize,
    pub port: Handle,
}

/// CREDUI_INFOW: what the sign-in prompt shows besides the fields.
#[repr(C)]
pub struct CredUiInfoW {
    pub size: u32,
    pub parent: Handle,
    pub message: *const u16,
    pub caption: *const u16,
    pub banner: Handle,
}

/// USEROBJECTFLAGS, the answer for `UOI_FLAGS`.
#[repr(C)]
#[derive(Default)]
pub struct UserObjectFlags {
    pub inherit: Bool,
    pub reserved: Bool,
    pub flags: u32,
}

#[link(name = "kernel32")]
extern "system" {
    pub fn CreateJobObjectW(attributes: *mut c_void, name: *const u16) -> Handle;
    pub fn SetInformationJobObject(job: Handle, class: i32, info: *mut c_void, length: u32) -> Bool;
    pub fn AssignProcessToJobObject(job: Handle, process: Handle) -> Bool;
    pub fn TerminateJobObject(job: Handle, code: u32) -> Bool;
    pub fn QueryInformationJobObject(job: Handle, class: i32, info: *mut c_void, length: u32, returned: *mut u32) -> Bool;
    pub fn Sleep(milliseconds: u32);
    pub fn CreateProcessW(
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
    pub fn ResumeThread(thread: Handle) -> u32;
    pub fn CloseHandle(handle: Handle) -> Bool;
    pub fn GetStdHandle(which: u32) -> Handle;
    pub fn GetCurrentProcess() -> Handle;
    pub fn GetCurrentProcessId() -> u32;
    pub fn DuplicateHandle(
        source_process: Handle,
        source: Handle,
        target_process: Handle,
        target: *mut Handle,
        access: u32,
        inherit: Bool,
        options: u32,
    ) -> Bool;
    pub fn OpenProcess(access: u32, inherit: Bool, process_id: u32) -> Handle;
    pub fn WaitForMultipleObjects(count: u32, handles: *const Handle, wait_all: Bool, milliseconds: u32) -> u32;
    pub fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    pub fn GetExitCodeProcess(process: Handle, code: *mut u32) -> Bool;
    pub fn TerminateProcess(process: Handle, code: u32) -> Bool;
    pub fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> Handle;
    pub fn Process32FirstW(snapshot: Handle, entry: *mut ProcessEntry32W) -> Bool;
    pub fn Process32NextW(snapshot: Handle, entry: *mut ProcessEntry32W) -> Bool;
    pub fn GetLastError() -> u32;
    pub fn GetConsoleWindow() -> Handle;
    pub fn GetConsoleMode(console: Handle, mode: *mut u32) -> Bool;
    pub fn SetConsoleMode(console: Handle, mode: u32) -> Bool;
    pub fn GetFileType(file: Handle) -> u32;
    pub fn WriteConsoleW(console: Handle, buffer: *const c_void, length: u32, written: *mut u32, reserved: *mut c_void) -> Bool;
    pub fn QueryFullProcessImageNameW(process: Handle, flags: u32, name: *mut u16, size: *mut u32) -> Bool;
    pub fn GetSystemWindowsDirectoryW(buffer: *mut u16, size: u32) -> u32;
    pub fn GetProcessTimes(process: Handle, creation: *mut u64, exit: *mut u64, kernel: *mut u64, user: *mut u64) -> Bool;
    pub fn IsProcessInJob(process: Handle, job: Handle, result: *mut Bool) -> Bool;
    pub fn GetTickCount64() -> u64;
    pub fn GetSystemTimePreciseAsFileTime(time: *mut u64);
    pub fn CreateNamedPipeW(
        name: *const u16,
        open_mode: u32,
        pipe_mode: u32,
        max_instances: u32,
        out_buffer: u32,
        in_buffer: u32,
        default_timeout: u32,
        attributes: *mut SecurityAttributes,
    ) -> Handle;
    pub fn ConnectNamedPipe(pipe: Handle, overlapped: *mut Overlapped) -> Bool;
    pub fn DisconnectNamedPipe(pipe: Handle) -> Bool;
    pub fn GetNamedPipeClientProcessId(pipe: Handle, id: *mut u32) -> Bool;
    pub fn PeekNamedPipe(pipe: Handle, buffer: *mut c_void, length: u32, read: *mut u32, available: *mut u32, left: *mut u32) -> Bool;
    pub fn WaitNamedPipeW(name: *const u16, milliseconds: u32) -> Bool;
    pub fn SetNamedPipeHandleState(pipe: Handle, mode: *mut u32, max_collection: *mut u32, timeout: *mut u32) -> Bool;
    pub fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        attributes: *mut c_void,
        disposition: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    pub fn ReadFile(file: Handle, buffer: *mut c_void, length: u32, read: *mut u32, overlapped: *mut Overlapped) -> Bool;
    pub fn WriteFile(file: Handle, buffer: *const c_void, length: u32, written: *mut u32, overlapped: *mut Overlapped) -> Bool;
    pub fn CancelIoEx(file: Handle, overlapped: *mut Overlapped) -> Bool;
    pub fn GetOverlappedResult(file: Handle, overlapped: *mut Overlapped, transferred: *mut u32, wait: Bool) -> Bool;
    pub fn CreateEventW(attributes: *mut c_void, manual_reset: Bool, initial: Bool, name: *const u16) -> Handle;
    pub fn SetEvent(event: Handle) -> Bool;
    pub fn ResetEvent(event: Handle) -> Bool;
    pub fn CreateIoCompletionPort(file: Handle, port: Handle, key: usize, threads: u32) -> Handle;
    pub fn GetQueuedCompletionStatus(port: Handle, transferred: *mut u32, key: *mut usize, overlapped: *mut *mut Overlapped, milliseconds: u32) -> Bool;
    pub fn PostQueuedCompletionStatus(port: Handle, transferred: u32, key: usize, overlapped: *mut Overlapped) -> Bool;
    pub fn LocalFree(memory: *mut c_void) -> *mut c_void;
    pub fn ProcessIdToSessionId(process_id: u32, session_id: *mut u32) -> Bool;
    pub fn GetNumberOfConsoleInputEvents(console: Handle, events: *mut u32) -> Bool;
    pub fn CreateMutexW(attributes: *mut c_void, initial_owner: Bool, name: *const u16) -> Handle;
    pub fn LoadLibraryExW(name: *const u16, file: Handle, flags: u32) -> Handle;
    pub fn GetProcAddress(module: Handle, name: *const u8) -> *const c_void;
}

#[link(name = "advapi32")]
extern "system" {
    pub fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> Bool;
    pub fn GetTokenInformation(token: Handle, class: u32, info: *mut c_void, length: u32, returned: *mut u32) -> Bool;
    pub fn ConvertSidToStringSidW(sid: *mut c_void, text: *mut *mut u16) -> Bool;
    pub fn ConvertStringSecurityDescriptorToSecurityDescriptorW(text: *const u16, revision: u32, descriptor: *mut *mut c_void, size: *mut u32) -> Bool;
    pub fn SetKernelObjectSecurity(object: Handle, information: u32, descriptor: *mut c_void) -> Bool;
    /// RtlGenRandom: bytes from the system random generator.
    pub fn SystemFunction036(buffer: *mut u8, length: u32) -> u8;
}

#[link(name = "ntdll")]
extern "system" {
    pub fn NtQueryInformationProcess(process: Handle, class: u32, info: *mut c_void, length: u32, returned: *mut u32) -> i32;
}

pub const INVALID_HANDLE: Handle = -1isize as Handle;
pub const FILE_TYPE_DISK: u32 = 1;
pub const FILE_TYPE_PIPE: u32 = 3;
pub const KILL_ON_JOB_CLOSE: u32 = 0x2000;
pub const EXTENDED_LIMIT_CLASS: i32 = 9;
pub const BASIC_ACCOUNTING_CLASS: i32 = 1;
pub const PROCESS_ID_LIST_CLASS: i32 = 3;
pub const STARTF_USESTDHANDLES: u32 = 0x100;
pub const STARTF_USESHOWWINDOW: u32 = 0x1;
pub const CREATE_SUSPENDED: u32 = 0x4;
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const DUPLICATE_SAME_ACCESS: u32 = 2;
pub const WAIT_TIMEOUT: u32 = 0x102;
pub const SNAPPROCESS: u32 = 0x2;
pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
pub const WAIT_OBJECT_0: u32 = 0;
pub const INFINITE: u32 = 0xFFFF_FFFF;
pub const CREATE_UNICODE_ENVIRONMENT: u32 = 0x400;
pub const ASSOCIATE_COMPLETION_PORT_CLASS: i32 = 7;
pub const JOB_OBJECT_MSG_EXIT_PROCESS: u32 = 7;
pub const JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS: u32 = 8;
pub const PIPE_ACCESS_DUPLEX: u32 = 3;
pub const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
/// The right to write the access list of the object.
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const DACL_SECURITY_INFORMATION: u32 = 4;
pub const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
pub const PIPE_TYPE_MESSAGE: u32 = 4;
pub const PIPE_READMODE_MESSAGE: u32 = 2;
pub const PIPE_REJECT_REMOTE_CLIENTS: u32 = 8;
pub const OPEN_EXISTING: u32 = 3;
pub const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
pub const TOKEN_QUERY: u32 = 8;
pub const TOKEN_USER_CLASS: u32 = 1;
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_MORE_DATA: u32 = 234;
pub const ERROR_PIPE_BUSY: u32 = 231;
pub const ERROR_PIPE_CONNECTED: u32 = 535;
pub const ERROR_IO_PENDING: u32 = 997;
pub const ERROR_ALREADY_EXISTS: u32 = 183;
pub const ERROR_CANCELLED: u32 = 1223;
pub const ERROR_LOGON_FAILURE: u32 = 1326;
/// The sign-in prompt shows only the accounts of the current user, on the secure desktop.
pub const CREDUIWIN_ENUMERATE_CURRENT_USER: u32 = 0x200;
pub const CREDUIWIN_SECURE_PROMPT: u32 = 0x1000;
/// Flags of the console prompt: the prompt is shown even when credentials for the target are
/// stored, no certificate or smart card, nothing is saved, and the credentials are generic (the
/// target names no server to check them against).
pub const CREDUI_FLAGS_DO_NOT_PERSIST: u32 = 0x2;
pub const CREDUI_FLAGS_EXCLUDE_CERTIFICATES: u32 = 0x8;
pub const CREDUI_FLAGS_ALWAYS_SHOW_UI: u32 = 0x80;
pub const CREDUI_FLAGS_GENERIC_CREDENTIALS: u32 = 0x40000;
/// The protection type `CredIsProtectedW` gives a password that is in clear text.
pub const CRED_UNPROTECTED: i32 = 0;
/// The most wide characters the message of the desktop sign-in prompt may have.
pub const CREDUI_MAX_MESSAGE_LENGTH: usize = 1024;
/// Sizes, in wide characters, of the buffers the sign-in prompt fills: the maximum lengths of the
/// system (CREDUI_MAX_USERNAME_LENGTH, CRED_MAX_DOMAIN_TARGET_NAME_LENGTH,
/// CREDUI_MAX_PASSWORD_LENGTH), which do not count the NUL, plus one for the NUL.
pub const CREDUI_USER_CHARS: usize = 514;
pub const CREDUI_DOMAIN_CHARS: usize = 338;
pub const CREDUI_PASSWORD_CHARS: usize = 257;
/// The form of a user name that `GetUserNameExW` writes as `DOMAIN\user`, read without a look up
/// that can leave the machine.
pub const NAME_SAM_COMPATIBLE: i32 = 2;
pub const UOI_FLAGS: i32 = 1;
pub const WSF_VISIBLE: u32 = 1;
pub const LOGON32_LOGON_INTERACTIVE: u32 = 2;
pub const LOGON32_PROVIDER_DEFAULT: u32 = 0;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const FILE_SHARE_READ_AND_WRITE: u32 = 3;
/// Load a library from the system folder only, never from the folder of the program or the current folder.
pub const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x800;

// ------------------------------------------------- the libraries of the sign-in prompt
//
// The sign-in prompt needs `credui.dll`, `user32.dll`, `ole32.dll` and `secur32.dll`, which only a run over the
// default cap uses. They are not linked: a program that links them loads them at start, for every
// command it guards, and cannot start where one cannot be loaded. They are loaded from the system
// folder when a prompt is first wanted, and a function that cannot be found makes the prompt
// unavailable (the run is refused) and nothing else. The same holds for `LogonUserW` and
// `LookupAccountNameW`, which the programs that can never ask must not import at all.

pub type GetProcessWindowStationFn = unsafe extern "system" fn() -> Handle;
pub type GetUserObjectInformationWFn = unsafe extern "system" fn(Handle, i32, *mut c_void, u32, *mut u32) -> Bool;
pub type CoTaskMemFreeFn = unsafe extern "system" fn(*mut c_void);
/// `GetUserNameExW` returns a BOOLEAN, one byte.
pub type GetUserNameExWFn = unsafe extern "system" fn(i32, *mut u16, *mut u32) -> u8;
pub type CredUiPromptForWindowsCredentialsWFn =
    unsafe extern "system" fn(*const CredUiInfoW, u32, *mut u32, *const c_void, u32, *mut *mut c_void, *mut u32, *mut Bool, u32) -> u32;
pub type CredUnPackAuthenticationBufferWFn =
    unsafe extern "system" fn(u32, *const c_void, u32, *mut u16, *mut u32, *mut u16, *mut u32, *mut u16, *mut u32) -> Bool;
pub type CredUiCmdLinePromptForCredentialsWFn =
    unsafe extern "system" fn(*const u16, *mut c_void, u32, *mut u16, u32, *mut u16, u32, *mut Bool, u32) -> u32;
/// The handler of a console control event (Ctrl+C, Ctrl+Break, closing the console, logging off, shutting down).
pub type ConsoleCtrlHandlerFn = unsafe extern "system" fn(u32) -> Bool;
/// `SetConsoleCtrlHandler(handler, add)`.
pub type SetConsoleCtrlHandlerFn = unsafe extern "system" fn(Option<ConsoleCtrlHandlerFn>, Bool) -> Bool;
/// `ExpungeConsoleCommandHistoryW(name of the program)`: clears the command history that the console keeps for a program.
pub type ExpungeConsoleCommandHistoryWFn = unsafe extern "system" fn(*const u16) -> Bool;
/// `CredIsProtectedW(credentials, protection type)`: whether a password is in a protected form.
pub type CredIsProtectedWFn = unsafe extern "system" fn(*mut u16, *mut i32) -> Bool;
/// `LogonUserW(user, domain, password, logon type, provider, token)`.
pub type LogonUserWFn = unsafe extern "system" fn(*const u16, *const u16, *const u16, u32, u32, *mut Handle) -> Bool;
/// `LookupAccountNameW(system, name, sid, sid size, domain, domain chars, kind)`.
pub type LookupAccountNameWFn =
    unsafe extern "system" fn(*const u16, *const u16, *mut c_void, *mut u32, *mut u16, *mut u32, *mut u32) -> Bool;

/// What the test for a person being present asks of `user32.dll`.
pub struct WindowStationApi {
    pub station: GetProcessWindowStationFn,
    pub information: GetUserObjectInformationWFn,
}

/// What the name of the account the guard runs as asks of `secur32.dll`.
pub struct NameApi {
    pub name: GetUserNameExWFn,
}

/// What the secure desktop prompt asks of `credui.dll`, `ole32.dll` and `advapi32.dll`.
pub struct DesktopApi {
    pub prompt: CredUiPromptForWindowsCredentialsWFn,
    pub unpack: CredUnPackAuthenticationBufferWFn,
    pub free: CoTaskMemFreeFn,
    pub protected: CredIsProtectedWFn,
}

/// What the check of the password asks of `advapi32.dll`. They are bound at run time, like the
/// rest of the prompt, so that the programs that can never ask (the contain role and the
/// automatic copies) have no import of a function that checks a credential.
pub struct LogonApi {
    pub logon: LogonUserWFn,
    pub lookup: LookupAccountNameWFn,
}

/// What the console prompt asks of `credui.dll` and `kernel32.dll`. The history call is not found
/// on every system; where it is missing the history is not cleared.
pub struct ConsoleApi {
    pub prompt: CredUiCmdLinePromptForCredentialsWFn,
    pub handler: SetConsoleCtrlHandlerFn,
    pub expunge: Option<ExpungeConsoleCommandHistoryWFn>,
}

/// The library `name`, from the system folder. It is never freed: the functions taken from it
/// are used for as long as the process lives, which is as long as a prompt can be wanted.
fn library(name: &str) -> Option<Handle> {
    let name = wide(name);
    let module = unsafe { LoadLibraryExW(name.as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    (!module.is_null()).then_some(module)
}

/// The function `name` (ended by a NUL) of `module`, as the function pointer type `T`.
///
/// # Safety
/// `T` must be the `extern "system"` function pointer type of the function that has that name.
unsafe fn function<T: Copy>(module: Handle, name: &[u8]) -> Option<T> {
    if name.last() != Some(&0) || std::mem::size_of::<T>() != std::mem::size_of::<*const c_void>() {
        return None;
    }
    let address = GetProcAddress(module, name.as_ptr());
    if address.is_null() { None } else { Some(std::mem::transmute_copy::<*const c_void, T>(&address)) }
}

pub fn window_station_api() -> Option<&'static WindowStationApi> {
    static API: std::sync::OnceLock<Option<WindowStationApi>> = std::sync::OnceLock::new();
    API.get_or_init(|| unsafe {
        let user32 = library("user32.dll")?;
        Some(WindowStationApi {
            station: function(user32, b"GetProcessWindowStation\0")?,
            information: function(user32, b"GetUserObjectInformationW\0")?,
        })
    }).as_ref()
}

pub fn name_api() -> Option<&'static NameApi> {
    static API: std::sync::OnceLock<Option<NameApi>> = std::sync::OnceLock::new();
    API.get_or_init(|| unsafe {
        let secur32 = library("secur32.dll")?;
        Some(NameApi { name: function(secur32, b"GetUserNameExW\0")? })
    }).as_ref()
}

pub fn desktop_api() -> Option<&'static DesktopApi> {
    static API: std::sync::OnceLock<Option<DesktopApi>> = std::sync::OnceLock::new();
    API.get_or_init(|| unsafe {
        let (credui, ole32, advapi32) = (library("credui.dll")?, library("ole32.dll")?, library("advapi32.dll")?);
        Some(DesktopApi {
            prompt: function(credui, b"CredUIPromptForWindowsCredentialsW\0")?,
            unpack: function(credui, b"CredUnPackAuthenticationBufferW\0")?,
            free: function(ole32, b"CoTaskMemFree\0")?,
            protected: function(advapi32, b"CredIsProtectedW\0")?,
        })
    }).as_ref()
}

pub fn logon_api() -> Option<&'static LogonApi> {
    static API: std::sync::OnceLock<Option<LogonApi>> = std::sync::OnceLock::new();
    API.get_or_init(|| unsafe {
        let advapi32 = library("advapi32.dll")?;
        Some(LogonApi {
            logon: function(advapi32, b"LogonUserW\0")?,
            lookup: function(advapi32, b"LookupAccountNameW\0")?,
        })
    }).as_ref()
}

pub fn console_api() -> Option<&'static ConsoleApi> {
    static API: std::sync::OnceLock<Option<ConsoleApi>> = std::sync::OnceLock::new();
    API.get_or_init(|| unsafe {
        let (credui, kernel32) = (library("credui.dll")?, library("kernel32.dll")?);
        Some(ConsoleApi {
            prompt: function(credui, b"CredUICmdLinePromptForCredentialsW\0")?,
            handler: function(kernel32, b"SetConsoleCtrlHandler\0")?,
            expunge: function(kernel32, b"ExpungeConsoleCommandHistoryW\0"),
        })
    }).as_ref()
}

pub fn os_error() -> GuardError {
    error_for(unsafe { GetLastError() })
}

/// The error for a Windows error code, in the form the guard reports it.
pub fn error_for(code: u32) -> GuardError {
    GuardError(format!("[WinError {}] {}", code, std::io::Error::from_raw_os_error(code as i32)))
}

pub fn checked(ok: Bool) -> Result<(), GuardError> {
    if ok == 0 { Err(os_error()) } else { Ok(()) }
}

pub fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}
