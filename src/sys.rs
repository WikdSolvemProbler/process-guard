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

/// WNDCLASSEXW: the class of the window that owns the Windows Hello request.
#[repr(C)]
pub struct WndClassExW {
    pub size: u32,
    pub style: u32,
    pub procedure: WindowProcFn,
    pub class_extra: i32,
    pub window_extra: i32,
    pub instance: Handle,
    pub icon: Handle,
    pub cursor: Handle,
    pub background: Handle,
    pub menu: *const u16,
    pub class_name: *const u16,
    pub icon_small: Handle,
}

/// MSG, what the message loop of a window reads.
#[repr(C)]
pub struct Msg {
    pub window: Handle,
    pub message: u32,
    pub w: usize,
    pub l: isize,
    pub time: u32,
    pub point: [i32; 2],
}

/// A GUID, in the layout the system uses for interface identifiers.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
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
    pub fn GetModuleHandleW(name: *const u16) -> Handle;
    pub fn GetCurrentThreadId() -> u32;
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
/// What a wait gives when it could not be made.
pub const WAIT_FAILED: u32 = 0xFFFF_FFFF;
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
pub const UOI_NAME: i32 = 2;
pub const WSF_VISIBLE: u32 = 1;
/// The right to read the name of a desktop, which is all the guard asks for of the desktop that receives the input.
pub const DESKTOP_READOBJECTS: u32 = 1;
pub const LOGON32_LOGON_INTERACTIVE: u32 = 2;
pub const LOGON32_PROVIDER_DEFAULT: u32 = 0;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const FILE_SHARE_READ_AND_WRITE: u32 = 3;
/// Load a library from the system folder only, never from the folder of the program or the current folder.
pub const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x800;
/// `GetLastError` after `RegisterClassExW` for a class that this process has made already.
pub const ERROR_CLASS_ALREADY_EXISTS: u32 = 1410;
/// The window that owns the request of Windows Hello is a tool window that is never shown and never takes the focus.
pub const WS_POPUP: u32 = 0x8000_0000;
pub const WS_EX_TOOLWINDOW: u32 = 0x80;
pub const WS_EX_NOACTIVATE: u32 = 0x0800_0000;
/// `PeekMessageW` removes the message it returns.
pub const PM_REMOVE: u32 = 1;
/// The timer messages. `DispatchMessageW` is documented to call the function that the `lParam` of such a message names.
pub const WM_TIMER: u32 = 0x0113;
pub const WM_SYSTIMER: u32 = 0x0118;
/// `MsgWaitForMultipleObjectsEx` wakes for a message of any kind, also one that was in the queue before the call.
pub const QS_ALLINPUT: u32 = 0x4ff;
pub const MWMO_INPUTAVAILABLE: u32 = 4;
/// What `WTSQuerySessionInformationW` is asked for: the user name and the domain of the user signed in to a session.
pub const WTS_USER_NAME: u32 = 5;
pub const WTS_DOMAIN_NAME: u32 = 7;
/// `RoInitialize` for a multithreaded apartment.
pub const RO_INIT_MULTITHREADED: i32 = 1;
/// The failures of the Windows Runtime that the guard makes up itself (HRESULTs).
pub const E_NOTIMPL: u32 = 0x8000_4001;
pub const E_FAIL: u32 = 0x8000_4005;
pub const E_UNEXPECTED: u32 = 0x8000_ffff;
pub const E_OUTOFMEMORY: u32 = 0x8007_000e;
pub const E_INVALIDARG: u32 = 0x8007_0057;

/// The HRESULT to report for a call that gave no object: the failure it gave, or `E_FAIL` when it said that it succeeded
/// (a success code is not a reason, and `0` would read as no failure at all).
pub fn failure_of(code: i32) -> u32 {
    if code < 0 { code as u32 } else { E_FAIL }
}
/// The states of an asynchronous operation of the Windows Runtime (`AsyncStatus`).
pub const ASYNC_STARTED: i32 = 0;
pub const ASYNC_COMPLETED: i32 = 1;
pub const ASYNC_CANCELED: i32 = 2;
pub const ASYNC_ERROR: i32 = 3;

// ------------------------------------------------ the interfaces of Windows Hello
//
// The consent of Windows Hello is asked through `Windows.Security.Credentials.UI.UserConsentVerifier`, a class of the Windows
// Runtime. Its interfaces are used through their v-tables, which are declared here: a slot is the index of a method, counting
// the three of `IUnknown` first (and, for an interface of the Windows Runtime, the three of `IInspectable`).

const fn guid(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Guid {
    Guid { data1, data2, data3, data4 }
}

/// `IUserConsentVerifierStatics`, which has `CheckAvailabilityAsync` (slot 6).
pub const IID_CONSENT_STATICS: Guid = guid(0xaf4f_3f91, 0x564c, 0x4ddc, [0xb8, 0xb5, 0x97, 0x34, 0x47, 0x62, 0x7c, 0x65]);
/// `IUserConsentVerifierInterop`, which has `RequestVerificationForWindowAsync` (slot 6).
pub const IID_CONSENT_INTEROP: Guid = guid(0x39e0_50c3, 0x4e74, 0x441a, [0x8d, 0xc0, 0xb8, 0x11, 0x04, 0xdf, 0x94, 0x9c]);
/// `IAsyncInfo`: the status (slot 7), the error (slot 8), `Cancel` (slot 9) and `Close` (slot 10) of an operation.
pub const IID_ASYNC_INFO: Guid = guid(0x0000_0036, 0x0000, 0x0000, [0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]);
/// `IAsyncOperation<UserConsentVerificationResult>`: its `GetResults` is slot 8. The identifier of a generic interface is
/// derived from its signature; a unit test computes it again, so that a typo cannot reach a release.
pub const IID_RESULT_OPERATION: Guid = guid(0xfd59_6ffd, 0x2318, 0x558f, [0x9d, 0xbe, 0xd2, 0x1d, 0xf4, 0x37, 0x64, 0xa5]);
/// `IAsyncOperation<UserConsentVerifierAvailability>`, computed again by the same test.
pub const IID_AVAILABILITY_OPERATION: Guid = guid(0xddd3_84f3, 0xd818, 0x5d83, [0xab, 0x4b, 0x32, 0x11, 0x9c, 0x28, 0x58, 0x7c]);

/// A string of the Windows Runtime (`HSTRING`).
pub type Hstring = *mut c_void;

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
/// `OpenInputDesktop(flags, inherit, access)`: the desktop that receives the input of the user, or null when it cannot be opened (the screen is locked).
pub type OpenInputDesktopFn = unsafe extern "system" fn(u32, Bool, u32) -> Handle;
/// `GetThreadDesktop(thread)`: the desktop of a thread, a handle that belongs to the process and is not closed.
pub type GetThreadDesktopFn = unsafe extern "system" fn(u32) -> Handle;
pub type CloseDesktopFn = unsafe extern "system" fn(Handle) -> Bool;
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
/// `CredUnprotectW(as self, protected, protected chars, password, password chars)`: the clear text of a password in a protected form.
pub type CredUnprotectWFn = unsafe extern "system" fn(Bool, *mut u16, u32, *mut u16, *mut u32) -> Bool;
/// The procedure of a window.
pub type WindowProcFn = unsafe extern "system" fn(Handle, u32, usize, isize) -> isize;
pub type RegisterClassExWFn = unsafe extern "system" fn(*const WndClassExW) -> u16;
pub type CreateWindowExWFn = unsafe extern "system" fn(u32, *const u16, *const u16, u32, i32, i32, i32, i32, Handle, Handle, Handle, *mut c_void) -> Handle;
pub type DestroyWindowFn = unsafe extern "system" fn(Handle) -> Bool;
pub type UnregisterClassWFn = unsafe extern "system" fn(*const u16, Handle) -> Bool;
pub type PeekMessageWFn = unsafe extern "system" fn(*mut Msg, Handle, u32, u32, u32) -> Bool;
pub type DispatchMessageWFn = unsafe extern "system" fn(*const Msg) -> isize;
/// `MsgWaitForMultipleObjectsEx(count, handles, milliseconds, wake mask, flags)`.
pub type MsgWaitForMultipleObjectsExFn = unsafe extern "system" fn(u32, *const Handle, u32, u32, u32) -> u32;
pub type RoInitializeFn = unsafe extern "system" fn(i32) -> i32;
pub type RoUninitializeFn = unsafe extern "system" fn();
/// `RoGetActivationFactory(class name, interface, factory)`.
pub type RoGetActivationFactoryFn = unsafe extern "system" fn(Hstring, *const Guid, *mut *mut c_void) -> i32;
pub type WindowsCreateStringFn = unsafe extern "system" fn(*const u16, u32, *mut Hstring) -> i32;
pub type WindowsDeleteStringFn = unsafe extern "system" fn(Hstring) -> i32;
/// `WTSQuerySessionInformationW(server, session, class, buffer, bytes)`.
pub type WtsQuerySessionInformationWFn = unsafe extern "system" fn(Handle, u32, u32, *mut *mut u16, *mut u32) -> Bool;
pub type WtsFreeMemoryFn = unsafe extern "system" fn(*mut c_void);
/// `IUnknown::QueryInterface(object, interface, found)`.
pub type QueryInterfaceFn = unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32;
/// `IUnknown::Release(object)`.
pub type ReleaseFn = unsafe extern "system" fn(*mut c_void) -> u32;
/// `IUserConsentVerifierStatics::CheckAvailabilityAsync(object, operation)`.
pub type CheckAvailabilityAsyncFn = unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32;
/// `IUserConsentVerifierInterop::RequestVerificationForWindowAsync(object, window, message, interface, operation)`.
pub type RequestVerificationForWindowAsyncFn = unsafe extern "system" fn(*mut c_void, Handle, Hstring, *const Guid, *mut *mut c_void) -> i32;
/// A method that gives one 32-bit value: `IAsyncInfo::get_Status` and `get_ErrorCode`, and `IAsyncOperation::GetResults`.
pub type GetValueFn = unsafe extern "system" fn(*mut c_void, *mut i32) -> i32;
/// A method with no argument: `IAsyncInfo::Cancel` and `Close`.
pub type CallFn = unsafe extern "system" fn(*mut c_void) -> i32;

/// What the test for a person being present asks of `user32.dll`.
pub struct WindowStationApi {
    pub station: GetProcessWindowStationFn,
    pub information: GetUserObjectInformationWFn,
    pub input_desktop: OpenInputDesktopFn,
    pub thread_desktop: GetThreadDesktopFn,
    pub close_desktop: CloseDesktopFn,
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
    pub unprotect: CredUnprotectWFn,
}

/// What the consent of Windows Hello asks of `combase.dll`: the Windows Runtime and its strings.
pub struct HelloApi {
    pub initialize: RoInitializeFn,
    pub uninitialize: RoUninitializeFn,
    pub factory: RoGetActivationFactoryFn,
    pub create: WindowsCreateStringFn,
    pub delete: WindowsDeleteStringFn,
}

/// What the window that owns the request of Windows Hello asks of `user32.dll`.
pub struct WindowApi {
    pub register: RegisterClassExWFn,
    pub create: CreateWindowExWFn,
    pub destroy: DestroyWindowFn,
    pub unregister: UnregisterClassWFn,
    pub peek: PeekMessageWFn,
    pub dispatch: DispatchMessageWFn,
    pub default_procedure: WindowProcFn,
    pub wait: MsgWaitForMultipleObjectsExFn,
}

/// What the look up of the user signed in to a session asks of `wtsapi32.dll`.
pub struct WtsApi {
    pub query: WtsQuerySessionInformationWFn,
    pub free: WtsFreeMemoryFn,
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
            input_desktop: function(user32, b"OpenInputDesktop\0")?,
            thread_desktop: function(user32, b"GetThreadDesktop\0")?,
            close_desktop: function(user32, b"CloseDesktop\0")?,
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
            unprotect: function(advapi32, b"CredUnprotectW\0")?,
        })
    }).as_ref()
}

pub fn hello_api() -> Option<&'static HelloApi> {
    static API: std::sync::OnceLock<Option<HelloApi>> = std::sync::OnceLock::new();
    API.get_or_init(|| unsafe {
        let combase = library("combase.dll")?;
        Some(HelloApi {
            initialize: function(combase, b"RoInitialize\0")?,
            uninitialize: function(combase, b"RoUninitialize\0")?,
            factory: function(combase, b"RoGetActivationFactory\0")?,
            create: function(combase, b"WindowsCreateString\0")?,
            delete: function(combase, b"WindowsDeleteString\0")?,
        })
    }).as_ref()
}

pub fn window_api() -> Option<&'static WindowApi> {
    static API: std::sync::OnceLock<Option<WindowApi>> = std::sync::OnceLock::new();
    API.get_or_init(|| unsafe {
        let user32 = library("user32.dll")?;
        Some(WindowApi {
            register: function(user32, b"RegisterClassExW\0")?,
            create: function(user32, b"CreateWindowExW\0")?,
            destroy: function(user32, b"DestroyWindow\0")?,
            unregister: function(user32, b"UnregisterClassW\0")?,
            peek: function(user32, b"PeekMessageW\0")?,
            dispatch: function(user32, b"DispatchMessageW\0")?,
            default_procedure: function(user32, b"DefWindowProcW\0")?,
            wait: function(user32, b"MsgWaitForMultipleObjectsEx\0")?,
        })
    }).as_ref()
}

pub fn wts_api() -> Option<&'static WtsApi> {
    static API: std::sync::OnceLock<Option<WtsApi>> = std::sync::OnceLock::new();
    API.get_or_init(|| unsafe {
        let wtsapi32 = library("wtsapi32.dll")?;
        Some(WtsApi {
            query: function(wtsapi32, b"WTSQuerySessionInformationW\0")?,
            free: function(wtsapi32, b"WTSFreeMemory\0")?,
        })
    }).as_ref()
}

/// The method at `index` of the v-table of `object`, as the function pointer type `T`.
///
/// # Safety
/// `object` must be a live interface pointer whose v-table has a method at `index` that has the type `T` (a function pointer
/// type, so the size of a pointer).
pub unsafe fn slot<T: Copy>(object: *mut c_void, index: usize) -> T {
    let table = *(object as *const *const *const c_void);
    let address = *table.add(index);
    std::mem::transmute_copy::<*const c_void, T>(&address)
}

/// An interface pointer of the Windows Runtime that is released when it goes away.
pub struct Com(pub *mut c_void);

impl Com {
    /// The same object through another interface (`QueryInterface`); the failure is the HRESULT.
    pub fn query(&self, interface: &Guid) -> Result<Com, u32> {
        let mut found: *mut c_void = std::ptr::null_mut();
        // SAFETY: `self` holds a live interface pointer, and slot 0 of every interface is `QueryInterface`.
        let code = unsafe { slot::<QueryInterfaceFn>(self.0, 0)(self.0, interface, &mut found) };
        if code < 0 || found.is_null() { Err(failure_of(code)) } else { Ok(Com(found)) }
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: slot 2 of every interface is `Release`, and this is the one reference that this value holds.
            unsafe { slot::<ReleaseFn>(self.0, 2)(self.0) };
        }
    }
}

/// A string of the Windows Runtime that is deleted when it goes away.
pub struct HString {
    pub raw: Hstring,
    delete: WindowsDeleteStringFn,
}

impl HString {
    /// The string of `text`. Never empty: the system gives an empty string no handle, and nothing here asks for one.
    pub fn new(api: &HelloApi, text: &str) -> Result<HString, u32> {
        let units: Vec<u16> = text.encode_utf16().collect();
        if units.is_empty() || units.len() > u32::MAX as usize {
            return Err(E_INVALIDARG);
        }
        let mut raw: Hstring = std::ptr::null_mut();
        let code = unsafe { (api.create)(units.as_ptr(), units.len() as u32, &mut raw) };
        if code < 0 || raw.is_null() { Err(failure_of(code)) } else { Ok(HString { raw, delete: api.delete }) }
    }
}

impl Drop for HString {
    fn drop(&mut self) {
        unsafe { (self.delete)(self.raw) };
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-1 of `data` (RFC 3174), for the identifiers of the generic interfaces.
    fn sha1(data: &[u8]) -> [u8; 20] {
        let mut state: [u32; 5] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0];
        let mut message = data.to_vec();
        message.push(0x80);
        while message.len() % 64 != 56 {
            message.push(0);
        }
        message.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
        for block in message.chunks(64) {
            let mut w = [0u32; 80];
            for (i, word) in block.chunks(4).enumerate() {
                w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
            }
            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }
            let [mut a, mut b, mut c, mut d, mut e] = state;
            for (i, word) in w.iter().enumerate() {
                let (f, k) = match i {
                    0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
                    20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                    _ => (b ^ c ^ d, 0xca62_c1d6u32),
                };
                let next = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*word);
                (e, d, c, b, a) = (d, c, b.rotate_left(30), a, next);
            }
            for (slot, add) in state.iter_mut().zip([a, b, c, d, e]) {
                *slot = slot.wrapping_add(add);
            }
        }
        let mut digest = [0u8; 20];
        for (bytes, word) in digest.chunks_mut(4).zip(state) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    /// The identifier of the generic interface with `signature`, as the Windows Runtime derives it: SHA-1 of the namespace
    /// identifier of the Windows Runtime and the signature, the first 16 bytes, with the version and variant bits set.
    fn derived(signature: &str) -> Guid {
        let mut data = vec![0x11, 0xf4, 0x7a, 0xd5, 0x7b, 0x73, 0x42, 0xc0, 0xab, 0xae, 0x87, 0x8b, 0x1e, 0x16, 0xad, 0xee];
        data.extend_from_slice(signature.as_bytes());
        let digest = sha1(&data);
        let mut data4 = [0u8; 8];
        data4.copy_from_slice(&digest[8..16]);
        data4[0] = (data4[0] & 0x3f) | 0x80;
        Guid {
            data1: u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]),
            data2: u16::from_be_bytes([digest[4], digest[5]]),
            data3: (u16::from_be_bytes([digest[6], digest[7]]) & 0x0fff) | 0x5000,
            data4,
        }
    }

    #[test]
    fn sha1_gives_the_published_digests() {
        let hex = |digest: [u8; 20]| digest.iter().map(|byte| format!("{:02x}", byte)).collect::<String>();
        assert_eq!(hex(sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(hex(sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(sha1(&[b'a'; 1_000])), "291e9a6c66994949b57ba5e650361e98fc36b1ba");
    }

    #[test]
    fn the_identifiers_of_the_generic_interfaces_are_the_ones_derived_from_their_signatures() {
        let operation = |enumeration: &str| derived(&format!("pinterface({{9fc2b0bb-e446-44e2-aa61-9cab8f636af2}};enum(Windows.Security.Credentials.UI.{};i4))", enumeration));
        assert_eq!(operation("UserConsentVerificationResult"), IID_RESULT_OPERATION);
        assert_eq!(operation("UserConsentVerifierAvailability"), IID_AVAILABILITY_OPERATION);
        // The method checks that the derivation is the right one: the identifier of a generic interface that is known by other means.
        assert_eq!(derived("pinterface({faa585ea-6214-4217-afda-7f46de5869b3};string)"), Guid {
            data1: 0xe2fc_c7c1, data2: 0x3bfc, data3: 0x5a0b, data4: [0xb2, 0xb0, 0x72, 0xe7, 0x69, 0xd1, 0xcb, 0x7e] }, "IIterable<String>");
    }

    #[test]
    fn a_call_that_gave_no_object_is_reported_with_a_failure_and_never_with_a_success_code() {
        assert_eq!(failure_of(0x8000_4002u32 as i32), 0x8000_4002, "the failure the call gave");
        assert_eq!(failure_of(0), E_FAIL, "a call that said it succeeded and gave nothing");
        assert_eq!(failure_of(1), E_FAIL, "S_FALSE and other success codes are no reason");
        // An empty string has no handle in the Windows Runtime, and is refused with a failure of its own.
        if let Some(api) = hello_api() {
            assert_eq!(HString::new(api, "").err(), Some(E_INVALIDARG));
        }
    }

    #[test]
    fn the_plain_interface_identifiers_are_the_published_ones() {
        let text = |guid: Guid| format!("{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}", guid.data1, guid.data2, guid.data3, guid.data4[0], guid.data4[1],
            guid.data4[2..].iter().map(|byte| format!("{:02x}", byte)).collect::<String>());
        assert_eq!(text(IID_CONSENT_STATICS), "af4f3f91-564c-4ddc-b8b5-973447627c65");
        assert_eq!(text(IID_CONSENT_INTEROP), "39e050c3-4e74-441a-8dc0-b81104df949c");
        assert_eq!(text(IID_ASYNC_INFO), "00000036-0000-0000-c000-000000000046");
        assert_eq!(text(IID_RESULT_OPERATION), "fd596ffd-2318-558f-9dbe-d21df43764a5");
        assert_eq!(text(IID_AVAILABILITY_OPERATION), "ddd384f3-d818-5d83-ab4b-32119c28587c");
    }
}
