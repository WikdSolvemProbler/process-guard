// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! The exception above the cap: the approval of the signed-in user, at the start of a run.
//!
//! A run started with `--extendable` and a `--max-extension` over the default cap (six hours)
//! is a per-run exception. Before the job is created and before the command starts, the guard
//! asks the signed-in user for approval. The default method (`--authenticate desktop`) asks for
//! the consent of Windows Hello (`UserConsentVerifier`: the Personal Identification Number
//! (PIN), fingerprint or face of the user, whose PIN guessing the Trusted Platform Module
//! limits), provided that the guard runs as the user who is signed in to its session. When
//! Windows Hello is not available (it is not set up, a policy disables it, or there is no
//! device) the same method shows the credential dialog of Windows instead and asks for the
//! password of the account the guard runs as. With `--authenticate console` the password is
//! asked for by a prompt on a console that is really there. A password is checked with
//! `LogonUserW`, and the user of the logon token must be the user the guard runs as.
//! A run that nobody is present to approve, or that is refused, exits with 125 and never starts
//! its command. At most three attempts at the password are made (Windows Hello is asked once),
//! each failed one counting toward account lockout, and every attempt is a line of the log. A
//! run that another guard started (the automatic wrapper, or a hook that wraps a line whole) is
//! refused before anything is shown: a command that an agent runs is such a run, and the agent
//! must not be able to summon the prompt.
//! Two tests make that refusal. The first looks at the file names of the live processes above the
//! guard, by the rule that `lib.rs` uses to select automatic mode; the search follows the parent
//! chain only while each parent is alive, so a parent that has exited, or one that a launcher
//! chose, ends it. The second looks at the job the process is in: every job a guard makes kills its
//! processes when it closes, so a descendant of a guard is in such a job however its chain of
//! parents looks, unless it has put itself in a job of its own (nested jobs are allowed, so any
//! process of the user can). The reason of the refusal names the test that fired and what it
//! found. The process that started the guard is watched while a prompt is open: if it
//! exits, nobody is waiting for the run and it is refused. A refusal after a prompt was shown
//! keeps the right to a prompt for ten seconds more, so that guards started in a loop do not put
//! one prompt after another on the screen. A prompt left open at its limit is the exception: the
//! process ends at once, which is expected to end the dialog or the read, so that nothing typed
//! into it is lost to a run that is already refused (step 5 of the manual check records whether
//! it does). A request for Windows Hello that is left open is cancelled
//! (`IAsyncInfo::Cancel`) before the process ends; steps 5 and 12 of the manual check record what
//! the system does with the prompt.
//!
//! Windows Hello verifies the user who is signed in to the session, not the account that the
//! guard runs as, so the consent is used only when the two are the same user (see
//! `session_user_matches`); a guard started as another account (`runas`) is refused, and does not
//! borrow the Windows Hello of the user at the screen. The request is made only on the desktop that
//! receives the input of that user (see `on_input_desktop`): a face can be matched with no act by the
//! user, so a request that is placed where nobody is looking is not made. One request is made for a
//! run, and Windows Hello keeps its own count of tries and its own lockout.
//!
//! The password lives only in buffers that are zeroed with volatile writes when they are
//! dropped, on every path, and is never put in a `String`, never logged and never echoed. The
//! release profile aborts on a panic without running destructors, so a panic hook zeroes every
//! buffer that is alive before the abort (see `install_panic_hook`). The exception resists
//! accidents and agents that lack the password (or the PIN, fingerprint or face of the user, though a
//! face can be matched with no act by the user); it does not resist a process of the same user that
//! can tamper with the guard itself (see `SECURITY.md`).
//!
//! The logic is behind three traits, `Prompt`, `Verifier` and `Consenter`, so that the unit tests
//! drive the attempt loop and the request for consent with stubs. The stubs exist only under
//! `cfg(test)`: no argument, environment variable or file selects one, so a release executable
//! has no way to skip the prompt. The Windows Runtime and the window that owns the request of
//! Windows Hello are reached through system calls bound at run time (`sys.rs`), so the programs
//! that can never ask import none of them.

use crate::engine::{format_seconds, image_path_of_handle, started_at};
use crate::extend::{current_user_sid, exception_line, hours_figure, image_of, now_ms, sid_text, token_user_sid, ExceptionRecord, Log, Settings, RECORD_MS};
use crate::sys::*;
use crate::GuardError;
use std::ffi::c_void;
use std::sync::atomic::{compiler_fence, AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The caption of the prompt, and the name the console prompt gives as its target: the product name.
pub(crate) const CAPTION: &str = "Process Tree Guard";

/// Attempts a run gets. Each failed `LogonUserW` counts toward the lockout of the account.
pub(crate) const MAX_ATTEMPTS: u32 = 3;

/// How long a prompt waits for an answer before the run is refused.
const PROMPT_TIMEOUT_MS: u64 = 300_000;

/// How long the check of the credentials waits for the system before the run is refused. A
/// domain controller that does not answer can keep `LogonUserW` for a minute or more.
const LOGON_TIMEOUT_MS: u64 = 60_000;

/// How often the process that started the guard is looked at while a wait goes on.
const OWNER_SLICE_MS: u64 = 250;

/// How long a name of the account, and a write to the console, wait for the system before the run is refused.
const SYSTEM_TIMEOUT_MS: u64 = 5_000;

/// How long the guard waits after a name or password that was not accepted before it asks again:
/// a loop that starts guards to guess a password pays this for every try. It slows such a loop and does not stop it.
const RETRY_DELAY_MS: u64 = 2_000;

/// How long a refusal after a prompt was shown keeps the right to a prompt before the guard returns,
/// so that a loop of guards over the cap cannot put one prompt after another on the screen. A guard
/// started in that time finds the right taken and is refused at once, without showing anything.
const COOL_DOWN_MS: u64 = 10_000;

/// The most characters each field of the prompt shows once its characters are written out:
/// reading stops before the first character that would take the field past its limit, so no field
/// is longer than this, whatever its characters are (the longest escape is ten characters,
/// `\u{10ffff}`). With the fixed text, the note and the words that say how much was cut, the
/// whole message stays under `CREDUI_MAX_MESSAGE_LENGTH`, the most the desktop dialog takes.
const COMMAND_LIMIT: usize = 140;
const PROGRAM_LIMIT: usize = 80;
const ACCOUNT_LIMIT: usize = 40;
const PARENT_LIMIT: usize = 80;

/// The message of the request for Windows Hello is shorter than that of the credential dialog: the most UTF-16 units it may have
/// (checked before the request is made; a longer text refuses the run and never reaches the system), and the limits of its
/// fields, in characters once written out, which are the largest the text starts with. A text that is longer than the
/// message limit with them is made again with smaller ones (`hello_text`). The limits are defaults; step 12 of the manual
/// check reads the whole text in the dialog, and they are adjusted if it is clipped.
const HELLO_MESSAGE_LIMIT: usize = 512;
const HELLO_COMMAND_LIMIT: usize = 100;
const HELLO_PROGRAM_LIMIT: usize = 40;
const HELLO_ACCOUNT_LIMIT: usize = 30;
const HELLO_PARENT_LIMIT: usize = 40;

/// How long the guard waits, after it asked a request for Windows Hello to cancel, for the system to say that it did.
const CANCEL_GRACE_MS: u64 = 3_000;

/// How often the state of an operation of the Windows Runtime is read, and the window that owns the request is served.
const POLL_MS: u32 = 100;

/// The most posted messages of the owner window that are dispatched between two looks at the state of the request. A message that
/// another process sends to the window is handled by the system when the queue is read and is not counted by this limit.
const PUMP_LIMIT: usize = 256;

/// What the result of an operation is set to before the system is asked for it: a value that is none of the results or
/// availabilities of Windows Hello, so that a call that succeeds and leaves it alone cannot read as `Verified` or `Available`,
/// which are 0 (Common Weakness Enumeration, CWE-636, not failing securely; Saltzer and Schroeder, fail-safe defaults).
const NO_RESULT: i32 = -1;

/// The most characters a password in a protected form may have (the form is longer than the password it holds).
const PROTECTED_LIMIT: usize = 4096;

/// The class of the Windows Runtime that asks for the consent of Windows Hello.
const CONSENT_CLASS: &str = "Windows.Security.Credentials.UI.UserConsentVerifier";

/// The class of the window that owns the request.
const OWNER_CLASS: &str = "ProcessTreeGuardConsentOwner";

/// The flags of the console prompt: the prompt is shown even when credentials for the target are
/// stored (without `CREDUI_FLAGS_ALWAYS_SHOW_UI` a generic credential kept under the name of the
/// product could be returned with no prompt), no certificate or smart card (a prompt on a console
/// takes none, and a call without this flag fails with `ERROR_INVALID_FLAGS`), nothing is saved,
/// and the credentials are generic: the target names no server to check them against.
const CONSOLE_PROMPT_FLAGS: u32 = CREDUI_FLAGS_ALWAYS_SHOW_UI | CREDUI_FLAGS_EXCLUDE_CERTIFICATES | CREDUI_FLAGS_DO_NOT_PERSIST | CREDUI_FLAGS_GENERIC_CREDENTIALS;

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NONE_MAPPED: u32 = 1332;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;

/// The code of a failure that has no Windows error: the account of the credentials could not be read.
const UNIDENTIFIED: u32 = 0;

/// Why a run started inside another run cannot have an exception.
const NESTED: &str = "an exception above the cap cannot be granted inside another run";

/// Why a run that another guard started is not asked.
const WRAPPED: &str = "an exception above the cap is not asked for by a run that another guard started (the automatic wrapper or a hook envelope) \
    or that runs inside a job that kills its processes when it closes, because a command that an agent runs is such a run; \
    start it from a terminal that is not under a guard";

/// What the reason of that refusal says when the names above the guard found a program of the
/// guard: the file name follows it.
pub(crate) const FOUND_ABOVE: &str = "found above the guard: ";

/// What the reason says when the job the guard is in kills its processes when it closes.
pub(crate) const JOB_KILLS: &str = "the job the guard is in kills its processes when it closes";

/// The file names, in lower case, of the programs of the guard that run a command: the full
/// command, the deadline role and the contain role, the name of the installed 1.x guard, and the
/// copies that are the automatic wrapper. Any other file name that ends in -auto is one too (see
/// `is_automatic_copy`).
const GUARD_PROGRAMS: [&str; 7] = [
    "process-tree-guard.exe", "process-guard.exe", "process-tree-guard-deadline.exe", "process-tree-guard-contain.exe",
    "process-tree-guard-auto.exe", "process-guard-auto.exe", "process-tree-guard-deadline-auto.exe",
];

/// Why a prompt cannot be shown where a library of it is missing.
const NOT_AVAILABLE: &str = "the sign-in prompt is not available on this system";

/// Why a run whose starter has gone is refused.
const OWNER_GONE: &str = "the process that started the run exited, so nobody is waiting for it";

/// The reason a user name or password that the system does not take is given: the same text for a
/// name that is unknown, a password that is wrong and an account that is not the guard's own, so
/// that the reason tells a typist nothing about which accounts exist.
const NOT_ACCEPTED: &str = "the user name or password was not accepted";

/// The reason an empty password is given. It is not a secret, so a reason of its own tells a typist
/// nothing, and the record must not say that the system rejected a credential when none was sent.
const EMPTY_PASSWORD: &str = "no password was entered, so no logon was tried";

/// The errors of `LogonUserW` that Windows gives only once the password was found to be right: an
/// account restriction, invalid logon hours, an invalid workstation, a disabled account, an
/// expired account, an expired password, an account without the right to log on at this computer
/// (1380 and 1385, which have the same text) and a password that must be changed. At the console
/// prompt, where a program can be the one that types, they are given the reason of a password
/// that is not accepted, so that the reason of a refusal does not tell it that a guess was right
/// (Common Weakness Enumeration, CWE-204). The desktop prompt cannot be answered by a program, so
/// there the error is shown.
const AFTER_PASSWORD_CHECKED: [u32; 9] = [1327, 1328, 1329, 1330, 1331, 1380, 1385, 1793, 1907];

/// How the approval of the signed-in user is asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// The consent of Windows Hello where it is available, and otherwise the credential dialog of Windows on the secure desktop.
    Desktop,
    /// A prompt on the console, accepted only when standard input is a real console.
    Console,
}

impl Method {
    /// The method named by `--authenticate`.
    pub fn from_name(name: &str) -> Option<Method> {
        match name {
            "desktop" => Some(Method::Desktop),
            "console" => Some(Method::Console),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Method::Desktop => "desktop",
            Method::Console => "console",
        }
    }
}

/// An exception above the cap: how to ask, and for which command line. The cap it is for is
/// the one the run is enforced against, `Settings::max_seconds`, and nothing else.
pub struct Exception {
    pub method: Method,
    /// The command line the prompt shows (for a shell, the command text).
    pub command: String,
    /// The deadline the run starts with (`--timeout`), in seconds, which the prompt shows beside the cap.
    pub timeout: f64,
}

// ------------------------------------------------------------------ secrets

/// Zero `buffer` with writes that the compiler may not drop or reorder past what follows.
fn wipe<T: Copy + Default>(buffer: &mut [T]) {
    for unit in buffer.iter_mut() {
        // SAFETY: the pointer comes from a unique reference to an initialised element.
        unsafe { std::ptr::write_volatile(unit as *mut T, T::default()) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
thread_local! {
    /// For each secret dropped on this thread: how many of its units were not zero before the
    /// wipe and after it, so that a test can see that a drop wipes on the path it takes.
    static WIPES: std::cell::RefCell<Vec<(usize, usize)>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Where a live secret is: its address, its size in bytes and the thread that made it.
type Placed = (usize, usize, std::thread::ThreadId);

/// The buffers that hold a secret right now. A destructor does not run when the release build
/// aborts on a panic, so the panic hook zeroes these (see `install_panic_hook`). A buffer is taken
/// out of this list before it is freed, so the hook never writes to memory that has gone.
fn live() -> std::sync::MutexGuard<'static, Vec<Placed>> {
    static LIVE: std::sync::Mutex<Vec<Placed>> = std::sync::Mutex::new(Vec::new());
    LIVE.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn register(pointer: *const u8, bytes: usize) {
    // A buffer is listed only once the hook that zeroes the list on a panic is in place, so that no path can hold a secret that
    // the abort of a release build leaves in the dump of the process (Common Weakness Enumeration, CWE-316, cleartext storage of
    // sensitive information in memory); the hook is installed once.
    install_panic_hook();
    live().push((pointer as usize, bytes, std::thread::current().id()));
}

fn unregister(pointer: *const u8) {
    live().retain(|placed| placed.0 != pointer as usize);
}

/// Set by the unit tests only: the hook then zeroes the buffers of the panicking thread alone, so
/// that a test that panics on purpose does not wipe the secrets of tests that run beside it.
#[cfg(test)]
static HOOK_FOR_THIS_THREAD: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The thread whose buffers the hook zeroes alone: in the unit tests the one a test has named,
/// and in a program none, so that the hook zeroes every buffer.
#[cfg(test)]
fn only_this_thread() -> Option<std::thread::ThreadId> {
    HOOK_FOR_THIS_THREAD.load(Ordering::SeqCst).then(|| std::thread::current().id())
}

#[cfg(not(test))]
fn only_this_thread() -> Option<std::thread::ThreadId> {
    None
}

/// Zero every buffer that holds a secret (those of one thread when `only` names it).
fn wipe_live(only: Option<std::thread::ThreadId>) {
    for (address, bytes, thread) in live().iter() {
        if only.map_or(true, |id| id == *thread) {
            for offset in 0..*bytes {
                // SAFETY: the memory is still allocated, because every owner takes its buffer out
                // of the list before it frees it and the lock of the list is held here. No
                // reference to it is formed, since another owner may hold one or be writing.
                unsafe { std::ptr::write_volatile((*address as *mut u8).add(offset), 0) };
            }
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Make a panic zero the secrets before anything else happens. The release profile aborts on a
/// panic and runs no destructor, so without this the password would stay in the dump that the
/// system writes for the process. The hook runs before the abort, then the previous hook. It is
/// installed by `register`, which every buffer that holds a secret passes through, and also by `decide`.
fn install_panic_hook() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            wipe_live(only_this_thread());
            previous(info);
        }));
    });
}

/// A buffer that is zeroed when it goes away, on every path.
struct Secret<B: AsMut<[u16]>>(B);

impl<B: AsMut<[u16]>> Drop for Secret<B> {
    fn drop(&mut self) {
        unregister(self.0.as_mut().as_ptr() as *const u8);
        #[cfg(test)]
        let before = self.0.as_mut().iter().filter(|unit| **unit != 0).count();
        wipe(self.0.as_mut());
        #[cfg(test)]
        {
            let after = self.0.as_mut().iter().filter(|unit| **unit != 0).count();
            let _ = WIPES.try_with(|wipes| wipes.borrow_mut().push((before, after)));
        }
    }
}

fn zeroed(chars: usize) -> Secret<Box<[u16]>> {
    let secret = Secret(vec![0u16; chars].into_boxed_slice());
    register(secret.0.as_ptr() as *const u8, chars * std::mem::size_of::<u16>());
    secret
}

/// What the sign-in prompt returns. The buffers are boxed, so a move copies a pointer and not
/// the secret, and the system call fills them where they stand. They are never grown: a name or
/// password that does not fit is a failure.
pub(crate) struct Credentials {
    user: Secret<Box<[u16]>>,
    domain: Secret<Box<[u16]>>,
    password: Secret<Box<[u16]>>,
}

fn text_before_nul(units: &[u16]) -> Option<String> {
    let end = units.iter().position(|unit| *unit == 0)?;
    Some(String::from_utf16_lossy(&units[..end]))
}

impl Credentials {
    fn new() -> Credentials {
        Credentials { user: zeroed(CREDUI_USER_CHARS), domain: zeroed(CREDUI_DOMAIN_CHARS), password: zeroed(CREDUI_PASSWORD_CHARS) }
    }

    /// The user name and the domain, which are not secret; None when one has no end.
    fn names(&self) -> Option<(String, String)> {
        Some((text_before_nul(&self.user.0)?, text_before_nul(&self.domain.0)?))
    }

    /// True when the password has its end inside the buffer.
    fn password_ends(&self) -> bool {
        self.password.0.contains(&0)
    }

    /// True when the password is empty. An empty password is never a secret: an account that has
    /// none could be approved by pressing Enter, and so by whoever drives the console.
    fn password_is_empty(&self) -> bool {
        self.password.0.first() == Some(&0)
    }

    fn password_pointer(&self) -> *const u16 {
        self.password.0.as_ptr()
    }

    /// Credentials for the tests of the attempt loop, with a password that is typed here.
    #[cfg(test)]
    fn with(user: &str, domain: &str, password: &str) -> Credentials {
        let mut credentials = Credentials::new();
        for (buffer, text) in [(&mut credentials.user, user), (&mut credentials.domain, domain), (&mut credentials.password, password)] {
            for (slot, unit) in buffer.0.iter_mut().zip(text.encode_utf16()) {
                *slot = unit;
            }
        }
        credentials
    }

    /// The password units up to the end, for the stub that checks them.
    #[cfg(test)]
    fn password_units(&self) -> Vec<u16> {
        self.password.0.iter().copied().take_while(|unit| *unit != 0).collect()
    }
}

/// The authentication buffer that the prompt returns: zeroed over its whole size, then freed
/// with the function that the system gave it by (`CoTaskMemFree`).
struct OutBuffer {
    pointer: *mut c_void,
    size: u32,
    free: CoTaskMemFreeFn,
}

impl Drop for OutBuffer {
    fn drop(&mut self) {
        unregister(self.pointer as *const u8);
        if !self.pointer.is_null() && self.size > 0 {
            // SAFETY: the system allocated `size` bytes at `pointer` and nothing else holds them.
            wipe(unsafe { std::slice::from_raw_parts_mut(self.pointer as *mut u8, self.size as usize) });
        }
        if !self.pointer.is_null() {
            unsafe { (self.free)(self.pointer) };
        }
    }
}

/// A handle that is closed when it goes away.
struct Token(Handle);

impl Drop for Token {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// The processes that started the guard, held by handle while a prompt is open. If one exits,
/// nobody is waiting for the run any more, and a process that takes its identifier must not be
/// taken for it: a process is taken only if it started before the guard did, as a parent must
/// have. They are opened before the first prompt and closed on every path, except those that
/// `into_handles` gives to the run, which watches the same handles for as long as it lasts.
pub(crate) struct Owners(Vec<Handle>);

/// True when a process created at `theirs` can be the parent of one created at `ours`: both
/// times are known, and it is not later. A parent that is gone, whose identifier was taken by a
/// process that started after the child, fails this.
fn started_before(theirs: Option<u64>, ours: Option<u64>) -> bool {
    matches!((theirs, ours), (Some(theirs), Some(ours)) if theirs <= ours)
}

impl Owners {
    /// Open each process of `ids`; the run is refused when one cannot be opened, or is not one
    /// that started before this process (its identifier was reused).
    pub(crate) fn open(ids: &[u32]) -> Result<Owners, GuardError> {
        let mut owners = Owners(Vec::new());
        let ours = started_at(unsafe { GetCurrentProcess() });
        for id in ids {
            let handle = unsafe { OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 0, *id) };
            if handle.is_null() {
                return Err(os_error());
            }
            // Closed with the others on every path from here.
            owners.0.push(handle);
            if !started_before(started_at(handle), ours) {
                return Err(GuardError("the process that started the run is gone and its identifier was reused".into()));
            }
        }
        Ok(owners)
    }

    /// No processes: nobody is watched.
    pub(crate) fn empty() -> Owners {
        Owners(Vec::new())
    }

    /// True when one of the processes has exited.
    fn gone(&self) -> bool {
        self.0.iter().any(|handle| unsafe { WaitForSingleObject(*handle, 0) } == WAIT_OBJECT_0)
    }

    /// The path of the file of the nearest process, read from the handle that is held; empty when it cannot be read.
    pub(crate) fn image(&self) -> String {
        self.0.first().map_or_else(String::new, |handle| image_path_of_handle(*handle))
    }

    /// The handles, which the caller must close: they are not closed with this value.
    pub(crate) fn into_handles(mut self) -> Vec<Handle> {
        std::mem::take(&mut self.0)
    }

    /// Watch the objects `handles`, which are closed with it; signalled means gone.
    #[cfg(test)]
    fn of(handles: Vec<Handle>) -> Owners {
        Owners(handles)
    }
}

impl Drop for Owners {
    fn drop(&mut self) {
        for handle in self.0.drain(..) {
            unsafe { CloseHandle(handle) };
        }
    }
}

/// The right to have a prompt open on this desktop session. A guard that finds another one's
/// prompt open does not add its own: several guards started together (an agent that starts
/// one per tool call) would otherwise stack prompts on the screen, each waiting for minutes. The
/// lock is a named object made by whoever comes first and gone when its last handle closes. A
/// guard that refuses a run after its prompt was shown keeps the lock for `COOL_DOWN_MS` more, so
/// that the prompts do not follow one another either.
struct PromptLock(Handle);

/// The name of the lock of the prompts of the guard in a session.
const PROMPT_LOCK_NAME: &str = "Local\\ProcessTreeGuardPrompt";

impl PromptLock {
    fn take() -> Result<PromptLock, &'static str> {
        PromptLock::take_named(PROMPT_LOCK_NAME)
    }

    /// The lock under `name`. A program of the same session that holds the name keeps every run
    /// from taking it, which is told apart from a real second prompt only by the reason given.
    fn take_named(name: &str) -> Result<PromptLock, &'static str> {
        let name = wide(name);
        unsafe {
            let handle = CreateMutexW(std::ptr::null_mut(), 0, name.as_ptr());
            // Nothing may come between the call and the error code it left.
            let existed = GetLastError() == ERROR_ALREADY_EXISTS;
            if handle.is_null() {
                return Err("the lock that keeps two sign-in prompts apart cannot be made");
            }
            if existed {
                CloseHandle(handle);
                return Err("another sign-in prompt of the guard is open or was refused less than 10 seconds ago, or another program holds its lock name");
            }
            Ok(PromptLock(handle))
        }
    }
}

impl Drop for PromptLock {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

// ------------------------------------------------------------------- the seam

/// What a prompt came back with.
pub(crate) enum Asked {
    Entered(Box<Credentials>),
    Cancelled,
    /// The prompt could not be started for this attempt, so nothing was shown for it; the reason
    /// says why. It is logged as the attempts made before it.
    NotShown(String),
    /// The prompt failed or went unanswered after it was shown; the reason says why.
    Unavailable(String),
    /// The prompt is still open and nobody answered within the time allowed: its thread is
    /// left at work, so the run is refused and the process ends at once, without the wait that
    /// follows another refusal, which is expected to end the dialog or the read.
    Abandoned(String),
    /// The prompt was answered, but what it returned cannot be read as a name and a password (a
    /// Personal Identification Number (PIN) or a smart card, or a name or password longer than the
    /// buffers). It uses an attempt like a wrong password, and no logon is tried for it.
    Rejected(String),
}

/// What checking credentials came to.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verified {
    Approved,
    /// The system does not accept the name and password, or the name is another account's.
    Wrong,
    /// The system accepts them, for an account other than the one the guard runs as.
    OtherUser,
    /// The failure is of the system, not of what was typed: a Windows error, or `UNIDENTIFIED`.
    Failed(u32),
    /// The process that started the guard exited while the check went on.
    OwnerGone,
}

/// What a run holds while its prompts are shown: the right to have one open.
pub(crate) struct Claim {
    _lock: Option<PromptLock>,
}

impl Claim {
    #[cfg(test)]
    fn none() -> Claim {
        Claim { _lock: None }
    }
}

pub(crate) trait Prompt {
    /// Check that the prompt can be shown at all, and take what it needs for the whole run (the
    /// right to have a prompt open, the console written to). `text` is what the prompt says. An
    /// error is the reason that nobody can be asked: nothing was shown, and no attempt was made.
    fn begin(&self, text: &str) -> Result<Claim, String>;

    /// The right to be asked at all, apart from what the dialog needs: that somebody is present and no other prompt of the
    /// guard is open. The desktop method takes it once, before it asks for Windows Hello, and keeps it if the dialog is shown
    /// after it. For a prompt that has nothing apart it is `begin`.
    fn seat(&self, text: &str) -> Result<Claim, String> {
        self.begin(text)
    }

    /// What the dialog itself needs, checked once the right is held and the dialog is to be shown. An error is the reason
    /// that nobody can be asked, as for `begin`.
    fn ready(&self, _text: &str) -> Result<(), String> {
        Ok(())
    }

    /// Ask for credentials. `last_error` is the error of the attempt before (`ERROR_LOGON_FAILURE`
    /// after a refusal, 0 on the first).
    fn ask(&self, attempt: u32, last_error: u32, text: &str) -> Asked;
}

pub(crate) trait Verifier {
    /// Check the credentials, which are wiped when this returns (or when the check that
    /// went on without it ends).
    fn verify(&self, credentials: Box<Credentials>) -> Verified;
}

// ----------------------------------------------------------------- the decision

/// The line for a refusal, in the log, and the error the run ends with. `attempt` is the
/// number of the attempt, or the attempts made before the refusal when nothing was shown for it
/// (0 for a run that was refused before any was made).
fn refuse(settings: &Settings, log: &Log, subject: &Subject, attempt: u32, reason: &str) -> GuardError {
    refuse_by(settings, log, subject, method_of(settings), attempt, reason)
}

/// `refuse` for a run that was asked by `method` (the word the log gives, which for the desktop method is `hello` once
/// the consent of Windows Hello has been chosen).
fn refuse_by(settings: &Settings, log: &Log, subject: &Subject, method: &str, attempt: u32, reason: &str) -> GuardError {
    log.push(&note(settings, subject, method, false, attempt, reason));
    GuardError(format!("exception refused: {}; the run did not start", reason))
}

/// The word the log gives for the method of the exception, as the launch arguments name it.
fn method_of(settings: &Settings) -> &'static str {
    settings.exception.as_ref().map_or("", |exception| exception.method.name())
}

/// The line of the log for a decision. It names what the decision is about: the account of the
/// guard (as the system writes it, not anything that was typed), the command line that was shown,
/// cut and written out as the prompt shows it, how the user was asked (`method`: `desktop` for the
/// credential dialog and for everything before Windows Hello was chosen, `hello`, or `console`),
/// the deadline the run starts with, and the nearest process that started the guard, as the prompt shows it. The message for
/// Windows Hello shows less of both than the credential dialog, so for that method they are cut as that message cuts them.
fn note(settings: &Settings, subject: &Subject, method: &str, approved: bool, attempt: u32, reason: &str) -> String {
    let pid = unsafe { GetCurrentProcessId() };
    let share = match settings.exception.as_ref() {
        Some(exception) if method == HELLO_METHOD => Some(hello_share(subject, exception, settings.max_seconds)),
        _ => None,
    };
    let (command, timeout) = settings.exception.as_ref().map_or_else(|| (String::new(), 0.0), |exception| {
        let command = match share {
            Some(percent) => shown(&exception.command, HELLO_COMMAND_LIMIT * percent / 100, Keep::Start),
            None => shown_command(&exception.command),
        };
        (command, exception.timeout)
    });
    let started_by = match share {
        _ if subject.parent.is_empty() => String::new(),
        Some(percent) => shown(subject.parent, HELLO_PARENT_LIMIT * percent / 100, Keep::End),
        None => shown(subject.parent, PARENT_LIMIT, Keep::End),
    };
    exception_line(&ExceptionRecord {
        unix_ms: now_ms(), pid, image: &image_of(pid), account: subject.account, command: &command, method, timeout, started_by: &started_by,
        requested: settings.max_seconds, approved, attempt, reason,
    })
}

/// The name of the account the guard runs as, read on a thread with a limit; empty when it cannot be read.
fn account_of_the_guard(owners: &Owners) -> String {
    bounded(Duration::from_millis(SYSTEM_TIMEOUT_MS), owners, own_account_name).ok().flatten().unwrap_or_default()
}

/// The refusal of a run whose starter cannot be watched (it cannot be read or opened, or its
/// identifier was reused): logged as a refusal before any attempt, like every other.
pub(crate) fn refuse_unwatched(settings: &Settings, log: &Log, reason: &str) -> GuardError {
    let account = account_of_the_guard(&Owners::empty());
    let subject = Subject { account: &account, parent: "", program: "" };
    refuse(settings, log, &subject, 0, &format!("the process that started the run cannot be watched: {}", reason))
}

/// The hours of a cap in seconds, as the prompt and the approval say it: rounded up, and with the
/// seconds beside it when the figure is not exact, so that it can never be less than the cap.
fn hours_phrase(seconds: f64) -> String {
    let text = hours_figure(seconds);
    let hours = if text == "1" { "1 hour".to_string() } else { format!("{} hours", text) };
    if (seconds / 36.0).fract() == 0.0 { hours } else { format!("{} ({} seconds)", hours, format_seconds(seconds)) }
}

/// The file name, in lower case, of the program at `image`, whichever way the path is written.
fn file_name_of(image: &str) -> String {
    image.rsplit(['\\', '/']).next().unwrap_or("").to_ascii_lowercase()
}

/// The first of `ancestors`, nearest first, that is a program of the guard that runs a command,
/// by its file name (the programs of the guard, and any file name that ends in -auto, which
/// selects automatic mode); None when none is. A run that one of them started is a run whose caller
/// chose the command: the automatic wrapper and the hooks that wrap a line whole start the guard
/// for every command that an agent runs, so a prompt would be one that an agent can summon, with
/// text it chooses, as often as it likes.
pub(crate) fn guard_above(ancestors: &[String]) -> Option<String> {
    ancestors.iter().map(|image| file_name_of(image)).find(|name| GUARD_PROGRAMS.contains(&name.as_str()) || is_automatic_copy(name))
}

/// Automatic mode is selected by a file stem that ends in -auto (lib.rs, entry_of), whatever the rest of the name.
fn is_automatic_copy(name: &str) -> bool {
    name.rsplit_once('.').map_or(name, |(stem, _)| stem).ends_with("-auto")
}

/// Decide on the exception of a run: refused inside another run or when another guard started it
/// (by the names above it, or by the job it is in), otherwise asked for with the method the launch
/// arguments name. `parent` is the image of the process that started the guard, which the prompt
/// names, `ancestors` are the images of the live processes above the guard
/// that the search of the parent chain reaches, nearest first, and `owners` are the processes that
/// are watched while a prompt is open. Ok(()) means the run may go on to create its job.
pub(crate) fn decide(settings: &Settings, held: bool, program: &str, parent: &str, ancestors: &[String], owners: &Owners, log: &Log) -> Result<(), GuardError> {
    let Some(exception) = settings.exception.as_ref() else { return Ok(()) };
    // The name is read on a thread with a limit: the system may have to ask a domain.
    let account = account_of_the_guard(owners);
    if held {
        let subject = Subject { account: &account, parent: "", program: "" };
        return Err(refuse(settings, log, &subject, 0, NESTED));
    }
    install_panic_hook();
    let subject = Subject { account: &account, parent, program };
    // For the unit tests of the engine only: a stub answers in place of the prompt, so that the run
    // that follows an approval is exercised. It exists under `cfg(test)` and nowhere else.
    #[cfg(test)]
    if let Some(approve) = seam::ANSWER.with(|answer| answer.get()) {
        return authorize(settings, &subject, &seam::SeamPrompt(approve), &seam::SeamVerifier, owners, log);
    }
    // Before any prompt, lock or logon: a run that another guard started is not asked. The job is
    // looked at as well as the names above, because a launcher can name its own parent or leave an
    // intermediate process to exit, which ends the search of the names.
    let above = guard_above(ancestors);
    if above.is_some() || in_guard_job() {
        let cause = match above {
            Some(name) => format!("{}{}", FOUND_ABOVE, shown_command(&name)),
            None => JOB_KILLS.to_string(),
        };
        return Err(refuse(settings, log, &subject, 0, &format!("{} ({})", WRAPPED, cause)));
    }
    let verifier = LogonVerifier { owners };
    match exception.method {
        Method::Desktop => authorize_desktop(settings, &subject, &HelloConsenter, &DesktopPrompt::new(owners), &verifier, owners, log),
        Method::Console => authorize(settings, &subject, &ConsolePrompt::new(owners), &verifier, owners, log),
    }
}

/// Wait `ms` milliseconds before the next attempt, looking at `owners` every `OWNER_SLICE_MS`:
/// false when one has exited, which ends the wait early.
fn pause(owners: &Owners, ms: u64) -> bool {
    let end = Instant::now() + Duration::from_millis(ms);
    loop {
        if owners.gone() {
            return false;
        }
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return true;
        }
        std::thread::sleep(left.min(Duration::from_millis(OWNER_SLICE_MS)));
    }
}

/// A wait of `normal` milliseconds: between attempts, or after a refusal (`cooling`).
#[cfg(not(test))]
fn wait_ms(normal: u64, _cooling: bool) -> u64 {
    normal
}

/// In the unit tests the wait is what a test sets, none by default, so that the attempt loop is not slow.
#[cfg(test)]
fn wait_ms(_normal: u64, cooling: bool) -> u64 {
    let counter = if cooling { &COOL_DOWNS } else { &RETRIES };
    counter.with(|count| count.set(count.get() + 1));
    RETRY_DELAY.with(|delay| delay.get())
}

fn retry_delay_ms() -> u64 {
    wait_ms(RETRY_DELAY_MS, false)
}

fn cool_down_ms() -> u64 {
    wait_ms(COOL_DOWN_MS, true)
}

#[cfg(test)]
thread_local! {
    static RETRY_DELAY: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// How many times the wait between attempts was asked for on this thread.
    static RETRIES: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    /// How many times the wait after a refusal was asked for on this thread.
    static COOL_DOWNS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Run the attempts. At most `MAX_ATTEMPTS`: a name or password the system does not accept, or
/// that is not the guard's own account's, or that is empty, or an answer that cannot be read as a
/// name and a password, is an attempt used (and the next prompt comes after a wait of
/// `RETRY_DELAY_MS`); a cancel, a prompt that cannot be shown, a starter that has gone and a
/// failure that more attempts cannot mend end it at once. Each attempt is one line of the log,
/// and the approval stands only if its line is recorded and the process that started the run is
/// still there. A refusal after a prompt was shown keeps the right to a prompt for `COOL_DOWN_MS`
/// more (the starter ending cuts it short), so guards started in that time are refused by the lock;
/// a prompt left open at its limit is refused at once and the process ends, which closes it.
pub(crate) fn authorize(settings: &Settings, subject: &Subject, prompt: &dyn Prompt, verifier: &dyn Verifier, owners: &Owners, log: &Log) -> Result<(), GuardError> {
    let Some(exception) = settings.exception.as_ref() else { return Ok(()) };
    if owners.gone() {
        return Err(refuse(settings, log, subject, 0, OWNER_GONE));
    }
    let text = prompt_text(subject, exception, settings.max_seconds);
    // Held until the attempts are over, so that no second prompt of the guard opens beside this one.
    let _claim = match prompt.begin(&text) {
        Ok(claim) => claim,
        Err(reason) => return Err(refuse(settings, log, subject, 0, &reason)),
    };
    attempts(settings, subject, prompt, verifier, owners, log, &text, "")
}

/// What stops an approval from standing once the user has given it.
enum NotRecorded {
    /// The process that started the run has exited, so nobody is waiting for it.
    OwnerGone,
    /// The audit file, or standard error when there is none, cannot take lines.
    Blocked,
    /// The line could not be written.
    Unwritten,
}

impl NotRecorded {
    /// The reason of the refusal.
    fn reason(&self) -> &'static str {
        match self {
            NotRecorded::OwnerGone => OWNER_GONE,
            NotRecorded::Blocked => "the audit file (or standard error, when there is no audit file) cannot take lines, so the approval could not be recorded",
            NotRecorded::Unwritten => "the approval could not be recorded",
        }
    }
}

/// Record the approval of `method` at `attempt`: it stands only if the starter is still there and its line is written.
fn record_approval(settings: &Settings, subject: &Subject, method: &str, attempt: u32, reason: &str, owners: &Owners, log: &Log) -> Result<(), NotRecorded> {
    if owners.gone() {
        return Err(NotRecorded::OwnerGone);
    }
    if log.blocked() {
        return Err(NotRecorded::Blocked);
    }
    if !log.record_decision(&note(settings, subject, method, true, attempt, reason), RECORD_MS) {
        return Err(NotRecorded::Unwritten);
    }
    Ok(())
}

/// The attempts at the password, with the right to a prompt already held by the caller and the checks that
/// `prompt` makes done. `why` ends the reason of every line of the record and of every refusal: empty, or the
/// words that say why the password is asked for where Windows Hello would have been (it was not available).
fn attempts(settings: &Settings, subject: &Subject, prompt: &dyn Prompt, verifier: &dyn Verifier, owners: &Owners, log: &Log, text: &str, why: &str) -> Result<(), GuardError> {
    let Some(exception) = settings.exception.as_ref() else { return Ok(()) };
    let method = method_of(settings);
    let said = |reason: &str| format!("{}{}", reason, why);
    let stop = |attempt: u32, reason: &str| refuse(settings, log, subject, attempt, &said(reason));
    // A refusal after the prompt was shown: the line is written at once and the right to a prompt is
    // kept for a while longer (it is dropped with the claim when the caller returns).
    let refuse_shown = |attempt: u32, reason: &str| {
        let error = stop(attempt, reason);
        pause(owners, cool_down_ms());
        error
    };
    let mut last_error = 0;
    for attempt in 1..=MAX_ATTEMPTS {
        // The credentials are dropped, and so wiped, as soon as they have been checked.
        let mut rejection: Option<String> = None;
        let verdict = match prompt.ask(attempt, last_error, text) {
            Asked::Entered(credentials) if credentials.password_is_empty() => {
                rejection = Some(EMPTY_PASSWORD.to_string());
                Verified::Wrong
            }
            Asked::Entered(credentials) => verifier.verify(credentials),
            Asked::Rejected(reason) => {
                rejection = Some(reason);
                Verified::Wrong
            }
            Asked::Cancelled => return Err(refuse_shown(attempt, "the prompt was cancelled")),
            Asked::NotShown(reason) => return Err(stop(attempt - 1, &reason)),
            Asked::Unavailable(reason) => return Err(refuse_shown(attempt, &reason)),
            // The prompt is still open: nothing may keep the process alive, or the person could type into a prompt
            // whose answer is never read.
            Asked::Abandoned(reason) => return Err(stop(attempt, &reason)),
        };
        let reason = match verdict {
            Verified::Approved => {
                let reason = format!("a cap of {} was approved: the password of the account the guard runs as was given at the {} prompt", hours_phrase(settings.max_seconds), exception.method.name());
                return match record_approval(settings, subject, method, attempt, &said(&reason), owners, log) {
                    Ok(()) => Ok(()),
                    Err(NotRecorded::OwnerGone) => Err(stop(attempt, OWNER_GONE)),
                    Err(unrecorded) => Err(refuse_shown(attempt, unrecorded.reason())),
                };
            }
            Verified::OwnerGone => return Err(stop(attempt, OWNER_GONE)),
            Verified::Wrong | Verified::OtherUser => rejection.unwrap_or_else(|| NOT_ACCEPTED.to_string()),
            Verified::Failed(code) if exception.method == Method::Console && AFTER_PASSWORD_CHECKED.contains(&code) => NOT_ACCEPTED.to_string(),
            Verified::Failed(UNIDENTIFIED) => return Err(refuse_shown(attempt, "the account of the credentials could not be identified")),
            Verified::Failed(code) => return Err(refuse_shown(attempt, &format!("the credentials could not be checked: {}", error_for(code).message()))),
        };
        if attempt == MAX_ATTEMPTS {
            return Err(refuse_shown(attempt, &format!("{}; no attempts are left", reason)));
        }
        log.push(&note(settings, subject, method, false, attempt, &said(&reason)));
        if !pause(owners, retry_delay_ms()) {
            return Err(stop(attempt, OWNER_GONE));
        }
        last_error = ERROR_LOGON_FAILURE;
    }
    Err(GuardError("exception refused: no attempt was made; the run did not start".into()))
}

/// What the prompt is told about the run: the account whose password it asks for (empty when it
/// cannot be read), the image of the process that started the guard (empty when it cannot be
/// read), and the program that will run.
pub(crate) struct Subject<'a> {
    pub account: &'a str,
    pub parent: &'a str,
    pub program: &'a str,
}

// --------------------------------------------------------------- Windows Hello

/// The word the log gives for a run that was approved or refused by the consent of Windows Hello.
const HELLO_METHOD: &str = "hello";

/// Why the consent of Windows Hello is not asked for where its libraries are missing.
const HELLO_MISSING: &str = "the Windows Runtime is not available on this system";

/// Whether Windows Hello can verify the user (`UserConsentVerifierAvailability`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Availability {
    Available,
    DeviceNotPresent,
    NotConfiguredForUser,
    DisabledByPolicy,
    DeviceBusy,
    Unknown(i32),
}

impl Availability {
    pub(crate) fn from_code(code: i32) -> Availability {
        match code {
            0 => Availability::Available,
            1 => Availability::DeviceNotPresent,
            2 => Availability::NotConfiguredForUser,
            3 => Availability::DisabledByPolicy,
            4 => Availability::DeviceBusy,
            other => Availability::Unknown(other),
        }
    }

    /// The name the record gives it.
    pub(crate) fn name(self) -> String {
        match self {
            Availability::Available => "Available".into(),
            Availability::DeviceNotPresent => "DeviceNotPresent".into(),
            Availability::NotConfiguredForUser => "NotConfiguredForUser".into(),
            Availability::DisabledByPolicy => "DisabledByPolicy".into(),
            Availability::DeviceBusy => "DeviceBusy".into(),
            Availability::Unknown(code) => format!("Unknown({})", code),
        }
    }
}

/// What a request for the consent of Windows Hello was answered with (`UserConsentVerificationResult`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Consent {
    Verified,
    DeviceNotPresent,
    NotConfiguredForUser,
    DisabledByPolicy,
    DeviceBusy,
    RetriesExhausted,
    Canceled,
    Unknown(i32),
}

impl Consent {
    pub(crate) fn from_code(code: i32) -> Consent {
        match code {
            0 => Consent::Verified,
            1 => Consent::DeviceNotPresent,
            2 => Consent::NotConfiguredForUser,
            3 => Consent::DisabledByPolicy,
            4 => Consent::DeviceBusy,
            5 => Consent::RetriesExhausted,
            6 => Consent::Canceled,
            other => Consent::Unknown(other),
        }
    }

    /// The name the record gives it.
    pub(crate) fn name(self) -> String {
        match self {
            Consent::Verified => "Verified".into(),
            Consent::DeviceNotPresent => "DeviceNotPresent".into(),
            Consent::NotConfiguredForUser => "NotConfiguredForUser".into(),
            Consent::DisabledByPolicy => "DisabledByPolicy".into(),
            Consent::DeviceBusy => "DeviceBusy".into(),
            Consent::RetriesExhausted => "RetriesExhausted".into(),
            Consent::Canceled => "Canceled".into(),
            Consent::Unknown(code) => format!("Unknown({})", code),
        }
    }
}

/// How a request for the consent of Windows Hello ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The system answered; the code is a `UserConsentVerificationResult`.
    Done(i32),
    /// The operation ended as cancelled, which nothing asked for here.
    Cancelled,
    /// The operation failed, with this HRESULT.
    Failed(u32),
    /// No answer came within the time allowed, and the request was cancelled.
    TimedOut,
    /// The process that started the guard exited while the request was open, and the request was cancelled.
    OwnerGone,
    /// The request was asked to cancel and did not end within the time given for it.
    CancelIgnored,
}

/// Windows Hello, as the decision uses it. The real one reaches the Windows Runtime; the unit tests give a scripted one.
pub(crate) trait Consenter {
    /// Whether Windows Hello can verify the user. It shows nothing. An error is the reason that it could not be found out
    /// (a library is missing, the call failed or took longer than `SYSTEM_TIMEOUT_MS`).
    fn availability(&self, owners: &Owners) -> Result<Availability, String>;

    /// Whether the guard runs as the user who is signed in to its session, which is the user whom Windows Hello verifies, and on
    /// the desktop that receives the input of that user, where the request can be read. An error is the reason that it cannot be
    /// said so.
    fn session_user(&self, owners: &Owners) -> Result<(), String>;

    /// Ask for the consent, showing `message`. It does not return before the request has ended or been cancelled, and watches
    /// `owners` while it waits.
    fn request(&self, message: &str, owners: &Owners) -> Outcome;
}

/// Decide on the exception of a run by the desktop method: the consent of Windows Hello where it is available, and otherwise the
/// credential dialog. In this order, which must not change: (1) the starter is still there; (2) somebody is present and no other
/// prompt of the guard is open, one right for the rest of the run; (3) Windows Hello is asked whether it is available, which shows
/// nothing; (4) if it is, the guard must run as the user signed in to the session, and then one request is made and its answer
/// decides; (5) in any other case, or when the question was not answered, the credential dialog asks for the password with its
/// three attempts, and every reason of the record ends with why Windows Hello was not used. A consent that was asked for and not
/// given never falls back to the dialog: that would let a refusal be answered by another door.
pub(crate) fn authorize_desktop(settings: &Settings, subject: &Subject, consenter: &dyn Consenter, prompt: &dyn Prompt, verifier: &dyn Verifier, owners: &Owners, log: &Log) -> Result<(), GuardError> {
    let Some(exception) = settings.exception.as_ref() else { return Ok(()) };
    if owners.gone() {
        return Err(refuse(settings, log, subject, 0, OWNER_GONE));
    }
    let text = prompt_text(subject, exception, settings.max_seconds);
    // Held for the rest of the run, whichever of the two asks, so that the lock is taken once.
    let _claim = match prompt.seat(&text) {
        Ok(claim) => claim,
        Err(reason) => return Err(refuse(settings, log, subject, 0, &reason)),
    };
    let availability = consenter.availability(owners);
    if owners.gone() {
        return Err(refuse(settings, log, subject, 0, OWNER_GONE));
    }
    match availability {
        Ok(Availability::Available) => hello(settings, subject, exception, consenter, owners, log, HELLO_MESSAGE_LIMIT),
        other => {
            let missing = match other {
                Ok(availability) => availability.name(),
                Err(reason) => reason,
            };
            let why = format!(" (Windows Hello was not available: {})", missing);
            if let Err(reason) = prompt.ready(&text) {
                return Err(refuse(settings, log, subject, 0, &format!("{}{}", reason, why)));
            }
            attempts(settings, subject, prompt, verifier, owners, log, &text, &why)
        }
    }
}

/// The consent of Windows Hello for a run: the check of the session user and the desktop, one more look at the starter, one
/// request, and what the answer decides. Only `Verified` approves. A refusal after the request was shown keeps the right to a
/// prompt for `COOL_DOWN_MS` more, as after any prompt; a request that had to be cancelled (no answer in time, the starter gone,
/// a cancel that was not taken) ends the process at once. A message of more than `limit` UTF-16 units is not sent.
fn hello(settings: &Settings, subject: &Subject, exception: &Exception, consenter: &dyn Consenter, owners: &Owners, log: &Log, limit: usize) -> Result<(), GuardError> {
    let stop = |attempt: u32, reason: &str| refuse_by(settings, log, subject, HELLO_METHOD, attempt, reason);
    let refuse_shown = |reason: &str| {
        let error = stop(1, reason);
        pause(owners, cool_down_ms());
        error
    };
    if let Err(reason) = consenter.session_user(owners) {
        return Err(stop(0, &reason));
    }
    let message = hello_text(subject, exception, settings.max_seconds);
    if message.encode_utf16().count() > limit {
        return Err(stop(0, "the message of the request for Windows Hello is longer than the system takes"));
    }
    // The starter may have left while the user and the message were looked at: no request is made for a run that nobody started.
    if owners.gone() {
        return Err(stop(0, OWNER_GONE));
    }
    match consenter.request(&message, owners) {
        Outcome::Done(code) => match Consent::from_code(code) {
            Consent::Verified => {
                let reason = format!("a cap of {} was approved: Windows Hello verified the signed-in user", hours_phrase(settings.max_seconds));
                match record_approval(settings, subject, HELLO_METHOD, 1, &reason, owners, log) {
                    Ok(()) => Ok(()),
                    Err(NotRecorded::OwnerGone) => Err(stop(1, OWNER_GONE)),
                    Err(unrecorded) => Err(refuse_shown(unrecorded.reason())),
                }
            }
            other => Err(refuse_shown(&format!("Windows Hello did not verify the user: {}", other.name()))),
        },
        Outcome::Cancelled => Err(refuse_shown("Windows Hello did not verify the user: the request was cancelled")),
        Outcome::Failed(code) => Err(refuse_shown(&format!("Windows Hello failed: 0x{:08x}", code))),
        Outcome::TimedOut => Err(stop(1, &format!("no answer within {} seconds, the request was cancelled", PROMPT_TIMEOUT_MS / 1000))),
        Outcome::OwnerGone => Err(stop(1, OWNER_GONE)),
        Outcome::CancelIgnored => Err(stop(1, "the request for Windows Hello was cancelled and did not end")),
    }
}

/// Whether the guard runs as the user who is signed in to its session. Windows Hello verifies the second, so the consent says
/// something about the first only when they are the same user: a guard started as another account (`runas`, a service account)
/// would otherwise borrow the Windows Hello of the user at the screen. `session` is the session of the guard, `signed_in` the
/// domain and the user name that the system gives for that session, `own` the name of the account the guard runs as
/// (`DOMAIN\user`), and `lookup` compares a name with the account of the guard when the two are not written alike (the same
/// look up as `account_check`: the security identifiers are compared). Nothing is approved when any of them is not known.
fn session_user_matches(session: Option<u32>, signed_in: Option<(String, String)>, own: Option<String>, lookup: impl FnOnce(&str) -> Option<Verified>) -> Result<(), String> {
    match session {
        None => return Err("the session of the guard cannot be read, so the user signed in to it is not known".into()),
        Some(0) => return Err("the guard runs in session 0, in which no user is signed in".into()),
        Some(_) => {}
    }
    let Some((domain, user)) = signed_in.filter(|(domain, user)| !domain.is_empty() && !user.is_empty()) else {
        return Err("the user signed in to this session cannot be read".into());
    };
    let Some(own) = own.filter(|own| !own.is_empty()) else {
        return Err("the account the guard runs as cannot be read".into());
    };
    let signed_in = format!("{}\\{}", domain, user);
    if own.eq_ignore_ascii_case(&signed_in) {
        return Ok(());
    }
    // The names are the system's, but they reach the reason of a refusal, so they are shown as the prompt shows a name: written out
    // where a character is not plain, and cut.
    let (own_shown, signed_in_shown) = (shown(&own, ACCOUNT_LIMIT, Keep::End), shown(&signed_in, ACCOUNT_LIMIT, Keep::End));
    match lookup(&signed_in) {
        None => Ok(()),
        Some(Verified::OtherUser) => Err(format!("the guard runs as {}, which is not the user signed in to this session ({}), and Windows Hello verifies only the second; \
            start the run as the signed-in user", own_shown, signed_in_shown)),
        Some(_) => Err(format!("the user signed in to this session ({}) cannot be compared with the account the guard runs as ({})", signed_in_shown, own_shown)),
    }
}

/// The two looks that stand before a request for Windows Hello, in this order: the guard runs as the user signed in to its session,
/// and on the desktop that receives the input of that user; the second is not made when the first refuses. What is read from the
/// system is given in (`signed_in` for the names of the session, `lookup` for the comparison of two accounts by their security
/// identifiers, `desktops` for the names of the two desktops), so that a unit test can give a user that is not the guard's and see that
/// it is refused. `HelloConsenter::session_user` is the only caller, with the real ones (G102 scans for it).
fn session_user_and_desktop(session: Option<u32>, signed_in: impl FnOnce(u32) -> Option<(String, String)>, own: Option<String>,
    lookup: impl FnOnce(&str) -> Option<Verified>, desktops: impl FnOnce() -> (Option<String>, Option<String>)) -> Result<(), String> {
    session_user_matches(session, session.and_then(signed_in), own, lookup)?;
    let (ours, input) = desktops();
    on_input_desktop(ours, input)
}

/// The domain and the user name of the user signed in to `session`, when the system gives them.
fn signed_in_names(session: u32) -> Option<(String, String)> {
    let api = wts_api()?;
    let read = |class: u32| -> Option<String> {
        let (mut buffer, mut bytes): (*mut u16, u32) = (std::ptr::null_mut(), 0);
        // A null server is this computer.
        if unsafe { (api.query)(std::ptr::null_mut(), session, class, &mut buffer, &mut bytes) } == 0 || buffer.is_null() {
            return None;
        }
        // SAFETY: the system allocated `bytes` bytes at `buffer`, and the memory is freed once it has been read.
        let units = unsafe { std::slice::from_raw_parts(buffer, bytes as usize / std::mem::size_of::<u16>()) };
        let end = units.iter().position(|unit| *unit == 0).unwrap_or(units.len());
        let name = String::from_utf16_lossy(&units[..end]);
        unsafe { (api.free)(buffer as *mut c_void) };
        Some(name)
    };
    Some((read(WTS_DOMAIN_NAME)?, read(WTS_USER_NAME)?))
}

/// The session of this process, when the system gives it.
fn own_session() -> Option<u32> {
    let mut session = 0u32;
    (unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) } != 0).then_some(session)
}

/// Whether the desktop that the guard runs on is the one that receives the input of the user, the one on the screen. The prompt of
/// Windows Hello is placed by the system, and a face can be matched with no act by the user, so a guard that a program of the
/// user started on a desktop that nobody is looking at (a desktop that the program made), or while the screen is locked or the
/// screen saver runs, would have the user verified without being shown what is asked (Common Weakness Enumeration, CWE-451, user
/// interface misrepresentation of critical information; National Institute of Standards and Technology (NIST) Special
/// Publication (SP) 800-63B-4, authentication intent). `ours` and `input` are the names of the two desktops, as the system gives
/// them; nothing is approved when one is not known.
fn on_input_desktop(ours: Option<String>, input: Option<String>) -> Result<(), String> {
    match (ours, input) {
        (Some(ours), Some(input)) if !ours.is_empty() && ours.eq_ignore_ascii_case(&input) => Ok(()),
        (Some(ours), Some(input)) => Err(format!("the guard runs on the desktop {}, and the desktop that receives the input of the user is {}; \
            start the run on the desktop that the user is looking at", shown(&ours, ACCOUNT_LIMIT, Keep::Start), shown(&input, ACCOUNT_LIMIT, Keep::Start))),
        (None, _) => Err("the desktop of the guard cannot be read, so nobody can be shown the request".into()),
        (_, None) => Err("the desktop that receives the input of the user cannot be opened (the screen may be locked), so nobody can be shown the request".into()),
    }
}

/// The name of `desktop` (`UOI_NAME`), when the system gives it.
fn desktop_name(api: &WindowStationApi, desktop: Handle) -> Option<String> {
    let mut name = vec![0u16; 256];
    let mut needed = 0u32;
    let read = unsafe { (api.information)(desktop, UOI_NAME, name.as_mut_ptr() as *mut c_void, (name.len() * std::mem::size_of::<u16>()) as u32, &mut needed) };
    if read == 0 {
        return None;
    }
    let end = name.iter().position(|unit| *unit == 0)?;
    Some(String::from_utf16_lossy(&name[..end]))
}

/// The names of the desktop of the calling thread and of the desktop that receives the input of the user, when the system gives them.
fn desktop_names() -> (Option<String>, Option<String>) {
    let Some(api) = window_station_api() else { return (None, None) };
    // The desktop of the thread belongs to the process and is not closed; the input desktop is opened for the read of its name and is.
    let ours = unsafe { (api.thread_desktop)(GetCurrentThreadId()) };
    let ours = if ours.is_null() { None } else { desktop_name(api, ours) };
    let input = unsafe { (api.input_desktop)(0, 0, DESKTOP_READOBJECTS) };
    let input = if input.is_null() {
        None
    } else {
        let name = desktop_name(api, input);
        unsafe { (api.close_desktop)(input) };
        name
    };
    (ours, input)
}

/// The real consent of Windows Hello, through the Windows Runtime. Nothing here is linked: the libraries are loaded from the
/// system folder when it is first wanted, and where they are missing it is not available.
pub(crate) struct HelloConsenter;

impl Consenter for HelloConsenter {
    fn availability(&self, owners: &Owners) -> Result<Availability, String> {
        match bounded(Duration::from_millis(SYSTEM_TIMEOUT_MS), owners, read_availability) {
            Ok(answer) => answer,
            Err(Unanswered::TimedOut) => Err(format!("no answer within {} seconds", SYSTEM_TIMEOUT_MS / 1000)),
            Err(Unanswered::OwnerGone) => Err(OWNER_GONE.into()),
            Err(_) => Err("the question could not be asked".into()),
        }
    }

    fn session_user(&self, owners: &Owners) -> Result<(), String> {
        let compared = bounded(Duration::from_millis(SYSTEM_TIMEOUT_MS), owners, || {
            session_user_and_desktop(own_session(), signed_in_names, own_account_name(), account_check, desktop_names)
        });
        match compared {
            Ok(answer) => answer,
            Err(Unanswered::TimedOut) => Err(format!("the user signed in to this session was not found within {} seconds", SYSTEM_TIMEOUT_MS / 1000)),
            Err(Unanswered::OwnerGone) => Err(OWNER_GONE.into()),
            Err(_) => Err("the user signed in to this session could not be looked up".into()),
        }
    }

    fn request(&self, message: &str, owners: &Owners) -> Outcome {
        let message = message.to_string();
        request_with(owners, Duration::from_millis(PROMPT_TIMEOUT_MS), Duration::from_millis(CANCEL_GRACE_MS), move |stop| consent_request(&message, stop))
    }
}

/// Run `work` on a thread of its own and wait for its outcome for at most `timeout`, looking at `owners` every
/// `OWNER_SLICE_MS`. When the time is up or a starter has exited, `work` is told to stop through the flag it is given (it is to
/// cancel the request) and is waited for `grace` more. The thread is left if it does not report, and ends with the process,
/// which the refusal that follows ends at once.
fn request_with(owners: &Owners, timeout: Duration, grace: Duration, work: impl FnOnce(&AtomicBool) -> Outcome + Send + 'static) -> Outcome {
    let stop = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = std::sync::mpsc::channel();
    let flag = stop.clone();
    let started = std::thread::Builder::new().name("consent".into()).spawn(move || {
        let _ = sender.send(work(&flag));
    });
    if started.is_err() {
        return Outcome::Failed(E_OUTOFMEMORY);
    }
    match wait_for(&receiver, timeout, owners) {
        Ok(outcome) => outcome,
        Err(Unanswered::Ended) | Err(Unanswered::NotStarted) => Outcome::Failed(E_FAIL),
        Err(cause) => {
            stop.store(true, Ordering::SeqCst);
            let late = receiver.recv_timeout(grace);
            match (cause, late) {
                (Unanswered::OwnerGone, _) => Outcome::OwnerGone,
                (_, Ok(Outcome::CancelIgnored)) | (_, Err(_)) => Outcome::CancelIgnored,
                _ => Outcome::TimedOut,
            }
        }
    }
}

/// An asynchronous operation of the Windows Runtime, as the loop that waits for it uses it. The real one reads the v-table of
/// `IAsyncInfo`; the unit tests give a scripted one.
trait Operation {
    /// The state of the operation (`AsyncStatus`); an error is the HRESULT of the call.
    fn status(&self) -> Result<i32, u32>;
    /// The HRESULT an operation in the state `ASYNC_ERROR` failed with.
    fn error(&self) -> u32;
    /// The result of an operation in the state `ASYNC_COMPLETED`; an error is the HRESULT of the call.
    fn result(&self) -> Result<i32, u32>;
    /// Ask the operation to cancel.
    fn cancel(&self);
}

/// Read the state of `operation` every time `step` returns, until it ends. `stop`, or the time `until`, makes the loop cancel
/// the operation, once, and wait `grace` for the state to leave `ASYNC_STARTED`. The outcome is `TimedOut` when the operation
/// reached `ASYNC_CANCELED` after it was asked to, `Cancelled` when it did so by itself, and `CancelIgnored` when it was
/// still started once the grace was over. A state that cannot be read, or is not one of the four, ends the loop with a failure
/// after one attempt to cancel, so that a refusal does not leave a request open that nothing watches any more (CWE-459,
/// incomplete cleanup).
fn drive(operation: &dyn Operation, stop: &AtomicBool, until: Option<Instant>, grace: Duration, step: &dyn Fn()) -> Outcome {
    let mut cancelled: Option<Instant> = None;
    loop {
        match operation.status() {
            Err(code) => {
                if cancelled.is_none() {
                    operation.cancel();
                }
                return Outcome::Failed(code);
            }
            Ok(ASYNC_COMPLETED) => {
                return match operation.result() {
                    Ok(code) => Outcome::Done(code),
                    Err(code) => Outcome::Failed(code),
                };
            }
            Ok(ASYNC_ERROR) => return Outcome::Failed(operation.error()),
            Ok(ASYNC_CANCELED) => return if cancelled.is_some() { Outcome::TimedOut } else { Outcome::Cancelled },
            Ok(ASYNC_STARTED) => {}
            Ok(_) => {
                if cancelled.is_none() {
                    operation.cancel();
                }
                return Outcome::Failed(E_UNEXPECTED);
            }
        }
        let stopping = stop.load(Ordering::SeqCst) || until.map_or(false, |until| Instant::now() >= until);
        match cancelled {
            None if stopping => {
                operation.cancel();
                cancelled = Some(Instant::now());
            }
            Some(at) if at.elapsed() >= grace => return Outcome::CancelIgnored,
            _ => {}
        }
        step();
    }
}

/// An operation of the Windows Runtime that is read through `IAsyncInfo`. Dropped, it is closed and released.
struct WinOperation {
    operation: Com,
    info: Com,
}

impl WinOperation {
    fn new(operation: Com) -> Result<WinOperation, u32> {
        let info = operation.query(&IID_ASYNC_INFO)?;
        Ok(WinOperation { operation, info })
    }
}

impl Operation for WinOperation {
    fn status(&self) -> Result<i32, u32> {
        let mut status = ASYNC_STARTED;
        // SAFETY: slot 7 of IAsyncInfo is get_Status.
        let code = unsafe { slot::<GetValueFn>(self.info.0, 7)(self.info.0, &mut status) };
        if code < 0 { Err(code as u32) } else { Ok(status) }
    }

    fn error(&self) -> u32 {
        let mut code = E_FAIL as i32;
        // SAFETY: slot 8 of IAsyncInfo is get_ErrorCode.
        unsafe { slot::<GetValueFn>(self.info.0, 8)(self.info.0, &mut code) };
        // A code that is no failure (0 or a success code) names none, as for a call that gave no object.
        failure_of(code)
    }

    fn result(&self) -> Result<i32, u32> {
        let mut result = NO_RESULT;
        // SAFETY: slot 8 of IAsyncOperation is GetResults, read only once the status is Completed.
        let code = unsafe { slot::<GetValueFn>(self.operation.0, 8)(self.operation.0, &mut result) };
        if code < 0 { Err(code as u32) } else { Ok(result) }
    }

    fn cancel(&self) {
        // SAFETY: slot 9 of IAsyncInfo is Cancel.
        unsafe { slot::<CallFn>(self.info.0, 9)(self.info.0) };
    }
}

impl Drop for WinOperation {
    fn drop(&mut self) {
        // SAFETY: slot 10 of IAsyncInfo is Close. It fails for an operation that is still started, which is left to the process.
        unsafe { slot::<CallFn>(self.info.0, 10)(self.info.0) };
    }
}

/// A Windows Runtime apartment on this thread, left when it is dropped (`RoInitialize` succeeds with S_OK and with S_FALSE, and
/// both need the call back).
struct Apartment(&'static HelloApi);

impl Apartment {
    fn enter(api: &'static HelloApi) -> Result<Apartment, u32> {
        let code = unsafe { (api.initialize)(RO_INIT_MULTITHREADED) };
        if code < 0 { Err(code as u32) } else { Ok(Apartment(api)) }
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe { (self.0.uninitialize)() };
    }
}

/// The activation factory of the class `class`, through the interface `interface`.
fn factory(api: &HelloApi, class: &HString, interface: &Guid) -> Result<Com, u32> {
    let mut found: *mut c_void = std::ptr::null_mut();
    let code = unsafe { (api.factory)(class.raw, interface, &mut found) };
    if code < 0 || found.is_null() { Err(failure_of(code)) } else { Ok(Com(found)) }
}

/// The HRESULT for a Windows error code.
fn hresult_of(code: u32) -> u32 {
    if code == 0 { E_FAIL } else { 0x8007_0000 | (code & 0xffff) }
}

/// The window that owns the request, which a program of the desktop needs: a tool window of zero size, with the procedure of
/// the system, that is never shown and never takes the focus. Whether Windows Hello puts its dialog in front of the windows
/// of the user with an owner that is not shown is recorded by step 12 of the manual check. Dropped, it is destroyed, and its
/// class is removed.
struct OwnerWindow {
    api: &'static WindowApi,
    handle: Handle,
    class: Vec<u16>,
    instance: Handle,
}

impl OwnerWindow {
    fn create(api: &'static WindowApi) -> Result<OwnerWindow, u32> {
        let class = wide(OWNER_CLASS);
        let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
        let description = WndClassExW {
            size: std::mem::size_of::<WndClassExW>() as u32,
            style: 0,
            procedure: api.default_procedure,
            class_extra: 0,
            window_extra: 0,
            instance,
            icon: std::ptr::null_mut(),
            cursor: std::ptr::null_mut(),
            background: std::ptr::null_mut(),
            menu: std::ptr::null(),
            class_name: class.as_ptr(),
            icon_small: std::ptr::null_mut(),
        };
        let registered = unsafe { (api.register)(&description) } != 0;
        let code = unsafe { GetLastError() };
        if !registered && code != ERROR_CLASS_ALREADY_EXISTS {
            return Err(hresult_of(code));
        }
        let caption = wide(CAPTION);
        let handle = unsafe {
            (api.create)(WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, class.as_ptr(), caption.as_ptr(), WS_POPUP, 0, 0, 0, 0,
                std::ptr::null_mut(), std::ptr::null_mut(), instance, std::ptr::null_mut())
        };
        if handle.is_null() {
            let code = unsafe { GetLastError() };
            unsafe { (api.unregister)(class.as_ptr(), instance) };
            return Err(hresult_of(code));
        }
        Ok(OwnerWindow { api, handle, class, instance })
    }

    /// Dispatch the messages that wait for the window, at most `PUMP_LIMIT` at a time: a program that floods the window with
    /// posted messages cannot keep the loop that waits for the request from looking at its stop flag and cancelling (CWE-834).
    /// A message that another process sends (not posts) is handled by the system when the queue is read and is not counted; a
    /// flood of those can delay the look at the request, and then the caller gives up on the cancel after its grace and refuses
    /// the run, so it costs availability and never approves. A message that is not `dispatchable` is taken from the queue and dropped.
    fn pump(&self) {
        let mut message = Msg { window: std::ptr::null_mut(), message: 0, w: 0, l: 0, time: 0, point: [0; 2] };
        for _ in 0..PUMP_LIMIT {
            if unsafe { (self.api.peek)(&mut message, std::ptr::null_mut(), 0, 0, PM_REMOVE) } == 0 {
                break;
            }
            if dispatchable(&message) {
                unsafe { (self.api.dispatch)(&message) };
            }
        }
    }

    /// Serve the window for `POLL_MS`, or until a message comes, and dispatch at most `PUMP_LIMIT` messages: the wait returns
    /// at once when a message is already in the queue, so one pass after it is all that a look at the request allows. A wait that
    /// fails (the desktop of the thread is gone, say) also returns at once, so the time is slept instead: the loop that waits for
    /// the request must not spin for up to 300 seconds, calling into another process on every turn (CWE-834).
    fn serve(&self) {
        if unsafe { (self.api.wait)(0, std::ptr::null(), POLL_MS, QS_ALLINPUT, MWMO_INPUTAVAILABLE) } == WAIT_FAILED {
            unsafe { Sleep(POLL_MS) };
        }
        self.pump();
    }
}

impl Drop for OwnerWindow {
    fn drop(&mut self) {
        unsafe {
            (self.api.destroy)(self.handle);
            (self.api.unregister)(self.class.as_ptr(), self.instance);
        }
    }
}

/// Whether a message that was taken from the queue of the thread that serves the owner window is dispatched. A timer message is
/// not: the thread sets no timer, so every one is from another program, and `DispatchMessageW` is documented to call the function
/// that the `lParam` of a timer message names, in this process, for a message to a window and for one to the thread (no window).
/// Any program of the same user can post either kind to another process (a "shatter" attack; Common Weakness Enumeration, CWE-422,
/// unprotected Windows messaging channel). The system itself did not call it for a timer that the thread did not set on Windows 11
/// (build 10.0.26200; the unit test of the owner window records it), so this is defence in depth. Every other message goes to
/// `DefWindowProcW`, or is ignored when it has no window.
fn dispatchable(message: &Msg) -> bool {
    message.message != WM_TIMER && message.message != WM_SYSTIMER
}

/// Ask Windows Hello whether it is available, on the worker, with its own limit: the operation is cancelled if it does not
/// answer in `SYSTEM_TIMEOUT_MS`, so that a worker that the caller has given up on ends. No window is made and nothing is shown.
fn read_availability() -> Result<Availability, String> {
    let failed = |code: u32| format!("the question failed: 0x{:08x}", code);
    let api = hello_api().ok_or_else(|| HELLO_MISSING.to_string())?;
    let _apartment = Apartment::enter(api).map_err(failed)?;
    let class = HString::new(api, CONSENT_CLASS).map_err(failed)?;
    let statics = factory(api, &class, &IID_CONSENT_STATICS).map_err(failed)?;
    let mut raw: *mut c_void = std::ptr::null_mut();
    // SAFETY: slot 6 of IUserConsentVerifierStatics is CheckAvailabilityAsync.
    let code = unsafe { slot::<CheckAvailabilityAsyncFn>(statics.0, 6)(statics.0, &mut raw) };
    if code < 0 || raw.is_null() {
        return Err(failed(failure_of(code)));
    }
    // The operation as the interface whose result is read: asking for it also checks that the answer is of the kind expected.
    let typed = Com(raw).query(&IID_AVAILABILITY_OPERATION).map_err(failed)?;
    let operation = WinOperation::new(typed).map_err(failed)?;
    let until = Instant::now() + Duration::from_millis(SYSTEM_TIMEOUT_MS);
    let wait = || unsafe { Sleep(POLL_MS) };
    match drive(&operation, &AtomicBool::new(false), Some(until), Duration::from_millis(CANCEL_GRACE_MS), &wait) {
        Outcome::Done(code) => Ok(Availability::from_code(code)),
        Outcome::Failed(code) => Err(failed(code)),
        _ => Err(format!("no answer within {} seconds", SYSTEM_TIMEOUT_MS / 1000)),
    }
}

/// Ask for the consent, on the worker, and say how the request ended; a failure to make it is `Failed` with its error code.
fn consent_request(message: &str, stop: &AtomicBool) -> Outcome {
    match consent_inner(message, stop) {
        Ok(outcome) => outcome,
        Err(code) => Outcome::Failed(code),
    }
}

/// The only place a request for Windows Hello is made (G102 scans for it). The window that owns the request is made first and
/// served while the request is open; the operation is cancelled when `stop` is set. Everything that was made is released on
/// every path, in the opposite order.
fn consent_inner(message: &str, stop: &AtomicBool) -> Result<Outcome, u32> {
    let (Some(api), Some(windows)) = (hello_api(), window_api()) else { return Err(E_NOTIMPL) };
    let _apartment = Apartment::enter(api)?;
    let owner = OwnerWindow::create(windows)?;
    let text = HString::new(api, message)?;
    let class = HString::new(api, CONSENT_CLASS)?;
    let interop = factory(api, &class, &IID_CONSENT_INTEROP)?;
    let mut raw: *mut c_void = std::ptr::null_mut();
    // SAFETY: slot 6 of IUserConsentVerifierInterop is RequestVerificationForWindowAsync.
    let code = unsafe { slot::<RequestVerificationForWindowAsyncFn>(interop.0, 6)(interop.0, owner.handle, text.raw, &IID_RESULT_OPERATION, &mut raw) };
    if code < 0 || raw.is_null() {
        return Err(failure_of(code));
    }
    let operation = WinOperation::new(Com(raw))?;
    Ok(drive(&operation, stop, None, Duration::from_millis(CANCEL_GRACE_MS), &|| owner.serve()))
}

// ------------------------------------------------------------------ the message

/// True when `c` is shown as it is: printable basic Latin other than the square brackets that
/// frame a field. Everything else is written out, every character outside basic Latin included:
/// the letters of other scripts that look like Latin ones (a Cyrillic o or c for the Latin one),
/// the blanks and spaces of other scripts, the combining marks that stack over the text beside
/// them, and the format and control characters. A name that is written out cannot pass for another.
fn shown_as_it_is(c: char) -> bool {
    c.is_ascii() && ((c.is_ascii_graphic() && c != '[' && c != ']') || c == ' ')
}

/// Which end of a field that is too long the prompt keeps: the start of a command line, which
/// names the program and the first arguments, and the end of a path or a name, which holds the
/// file name or the user.
#[derive(Clone, Copy)]
enum Keep {
    Start,
    End,
}

/// The text as the prompt shows it: no more than `limit` characters, with every character that is
/// not shown as it is written as `\u{..}` so that nothing in it can start a line of its own, pass
/// for a space or for another letter, or change how the rest is shown, the square brackets that
/// frame it written the same way so that it cannot close its own frame and imitate a label, and,
/// when it was cut, the number of characters left out: `... (and N more characters)` after a kept
/// start, `(N characters before) ...` before a kept end. Not `extend::escape`: that also escapes
/// quotes and backslashes, which would double every path.
fn shown(text: &str, limit: usize, keep: Keep) -> String {
    let mut pieces = Vec::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        // A backslash that begins what looks like a written-out character is itself written out, so that an
        // argument cannot imitate the form; any other backslash, as in a path, is shown as it is.
        let imitates = c == '\\' && {
            let mut ahead = chars.clone();
            ahead.next() == Some('u') && ahead.next() == Some('{')
        };
        pieces.push(if shown_as_it_is(c) && !imitates { c.to_string() } else { format!("\\u{{{:x}}}", c as u32) });
    }
    let fits = |pieces: &mut dyn Iterator<Item = &String>| {
        let mut used = 0;
        pieces.take_while(|piece| {
            used += piece.len();
            used <= limit
        }).count()
    };
    let kept = match keep {
        Keep::Start => fits(&mut pieces.iter()),
        Keep::End => fits(&mut pieces.iter().rev()),
    };
    let more = pieces.len() - kept;
    match keep {
        _ if pieces.is_empty() => "(none)".to_string(),
        _ if more == 0 => pieces.concat(),
        Keep::Start => format!("{}... (and {} more characters)", pieces[..kept].concat(), more),
        Keep::End => format!("({} characters before) ...{}", more, pieces[more..].concat()),
    }
}

/// The command line as the prompt and the log show it: its start, cut at `COMMAND_LIMIT`.
fn shown_command(command: &str) -> String {
    shown(command, COMMAND_LIMIT, Keep::Start)
}

/// What the prompt says, with what the person must check first: the command line as it was
/// given, the program that will run as the search found it, the account whose password it asks
/// for, and the parent process as the system reports it; then what the cap means, the deadline the run starts with and how to refuse. A dialog that
/// clips or scrolls long text loses the end first, so the end is the explanation and not a field.
/// The cap is the size of each request for time, not a bound on the run: the processes of the run
/// can renew without a total limit. The program is shown because the name in the command line is
/// looked for in the current folder first, so it can be another file than the one the user expects.
/// The parent is the one the launcher chose, so it is information, not proof of who started the
/// run. The command line keeps its start when it is cut, and the program, the account and the
/// parent keep their end, which holds the file name or the user. Each field is in square brackets, in which no bracket can appear, so that none can
/// imitate the others. How to refuse depends on the method: the desktop prompt has a cancel; the
/// console prompt is not known to have a cancel key, and is refused by not answering or by closing
/// the console.
pub(crate) fn prompt_text(subject: &Subject, exception: &Exception, seconds: f64) -> String {
    let field = |text: &str, limit| if text.is_empty() { "(unknown)".to_string() } else { shown(text, limit, Keep::End) };
    let refusal = match exception.method {
        Method::Desktop => "cancel to refuse the run".to_string(),
        Method::Console => format!("leave the prompt unanswered for {} seconds, or close this console, to refuse the run", PROMPT_TIMEOUT_MS / 1000),
    };
    // Said when a field above has a character that is written out, so that the form is not a puzzle.
    let written_out = [subject.account, subject.program, subject.parent, exception.command.as_str()].into_iter()
        .any(|text| !text.is_ascii() || text.contains("\\u{"));
    let note = if written_out { " Note: \\u{..} is a character written out; check each field letter by letter." } else { "" };
    format!("{} is asked to run: Command line: [{}] Program: [{}] Account: [{}] Parent process, as the system reports it: [{}] \
        The processes of the run may each ask to keep it alive for up to {} at a time, and may renew without a total limit. \
        The run starts with a deadline of {} seconds. Enter the password of the account above to allow it, or {}.{}",
        CAPTION, shown_command(&exception.command), shown(subject.program, PROGRAM_LIMIT, Keep::End), field(subject.account, ACCOUNT_LIMIT),
        field(subject.parent, PARENT_LIMIT), hours_phrase(seconds), format_seconds(exception.timeout), refusal, note)
}

/// What the request for Windows Hello says, with the same fields as the credential dialog, cut shorter: it starts with how to
/// refuse, so that a clipped end still shows it, and names the run (the command line first); then the cap and the deadline the run
/// starts with, and it ends with how to refuse again, as the credential dialog does. The limits of the fields
/// (`HELLO_COMMAND_LIMIT` and the others) are those of a text that is as long as the message may be; a text that is longer once
/// the characters are written out is made again with a smaller share of each, down to none, so that it fits
/// `HELLO_MESSAGE_LIMIT` whatever the fields hold (what is left out is counted, as in the credential dialog).
fn hello_text(subject: &Subject, exception: &Exception, seconds: f64) -> String {
    hello_made(subject, exception, seconds, hello_share(subject, exception, seconds))
}

/// The share, in percent, of the limits of the fields that the message for Windows Hello is made with: the largest of 100, 75, 50
/// and 25 that keeps it within `HELLO_MESSAGE_LIMIT`, and 0 when none does. The record of a run that Windows Hello decided cuts
/// the command line and the starter by the same share, so that it never shows more than the user was shown.
fn hello_share(subject: &Subject, exception: &Exception, seconds: f64) -> usize {
    [100, 75, 50, 25].into_iter()
        .find(|percent| hello_made(subject, exception, seconds, *percent).encode_utf16().count() <= HELLO_MESSAGE_LIMIT)
        .unwrap_or(0)
}

/// The message for Windows Hello with the limits of its fields at `percent` of their defaults. The parent keeps the words
/// "as reported" of the credential dialog: the launcher chooses it, so it is information and not proof of who started the run
/// (Common Weakness Enumeration, CWE-451, user interface misrepresentation of critical information).
fn hello_made(subject: &Subject, exception: &Exception, seconds: f64, percent: usize) -> String {
    let field = |text: &str, limit: usize| if text.is_empty() { "(unknown)".to_string() } else { shown(text, limit, Keep::End) };
    // Said when a field has a character that is written out, so that the form is not a puzzle.
    let written_out = [subject.account, subject.program, subject.parent, exception.command.as_str()].into_iter()
        .any(|text| !text.is_ascii() || text.contains("\\u{"));
    let note = if written_out { " Note: \\u{..} is a character written out; check each field letter by letter." } else { "" };
    let at = |limit: usize| limit * percent / 100;
    format!("{} asks Windows Hello to allow this run; cancel to refuse it. Command line: [{}] Program: [{}] Account: [{}] Parent process, as reported: [{}] \
        Allows a cap of {}, renewable without a total limit; the run starts with a deadline of {} seconds.{} Cancel to refuse it.",
        CAPTION, shown(&exception.command, at(HELLO_COMMAND_LIMIT), Keep::Start), shown(subject.program, at(HELLO_PROGRAM_LIMIT), Keep::End),
        field(subject.account, at(HELLO_ACCOUNT_LIMIT)), field(subject.parent, at(HELLO_PARENT_LIMIT)), hours_phrase(seconds), format_seconds(exception.timeout), note)
}

// --------------------------------------------------------------------- names

/// The domain and the user for `LogonUserW`. A name with a backslash is split at the first
/// one; otherwise a name with an at sign is a user principal name, which takes no domain
/// (None); otherwise the domain the prompt returned, and when there is none the local
/// account database (`.`). The prompt does not need `CredUIParseUserNameW` for this: the
/// forms it returns are these.
fn split_name(name: &str, domain: &str) -> (Option<String>, String) {
    if let Some((domain, user)) = name.split_once('\\') {
        (Some(domain.to_string()), user.to_string())
    } else if name.contains('@') {
        (None, name.to_string())
    } else if !domain.is_empty() {
        (Some(domain.to_string()), name.to_string())
    } else {
        (Some(".".to_string()), name.to_string())
    }
}

/// The name as `LookupAccountNameW` takes it: `DOMAIN\user`, a user principal name as it is, and
/// a name in the local database as it is.
fn full_name(domain: Option<&str>, user: &str) -> String {
    match domain {
        Some(domain) if domain != "." => format!("{}\\{}", domain, user),
        _ => user.to_string(),
    }
}

/// The name of the account this process runs as, `DOMAIN\user`, as the system writes it for the
/// account that is signed in (`GetUserNameExW`, not a look up of the security identifier, which
/// can ask a domain controller); None when it cannot be read.
fn own_account_name() -> Option<String> {
    let api = name_api()?;
    let mut name = vec![0u16; 1024];
    let mut chars = name.len() as u32;
    // The size is in characters, and on success it is the length without the end.
    if unsafe { (api.name)(NAME_SAM_COMPATIBLE, name.as_mut_ptr(), &mut chars) } == 0 || chars == 0 || chars as usize >= name.len() {
        return None;
    }
    Some(String::from_utf16_lossy(&name[..chars as usize]))
}

/// What a failed look up of an account comes to: no such account is a name that is not accepted;
/// anything else is a failure of the system.
fn classify_lookup_error(code: u32) -> Verified {
    if code == ERROR_NONE_MAPPED { Verified::Wrong } else { Verified::Failed(code) }
}

/// Before any logon is tried with `name`: the verdict when it cannot be the account the guard
/// runs as, None when it can. Every logon with a wrong password counts toward the lockout of the
/// account it was tried for, so a name that is another account's, or no account's, is turned away
/// here and `LogonUserW` is not called for it. The security identifier of the token of a logon
/// that is made is still compared afterwards: this look up only decides what is not tried.
fn account_check(name: &str) -> Option<Verified> {
    if own_account_name().map_or(false, |own| own.eq_ignore_ascii_case(name)) {
        return None;
    }
    let Some(api) = logon_api() else { return Some(Verified::Failed(UNIDENTIFIED)) };
    let text = wide(name);
    let (mut sid_size, mut domain_chars, mut kind) = (0u32, 0u32, 0u32);
    unsafe {
        (api.lookup)(std::ptr::null(), text.as_ptr(), std::ptr::null_mut(), &mut sid_size, std::ptr::null_mut(), &mut domain_chars, &mut kind);
        let code = GetLastError();
        if code != ERROR_INSUFFICIENT_BUFFER {
            return Some(classify_lookup_error(code));
        }
        let mut sid = vec![0u64; (sid_size as usize + 7) / 8 + 1];
        let mut domain = vec![0u16; domain_chars as usize + 1];
        if (api.lookup)(std::ptr::null(), text.as_ptr(), sid.as_mut_ptr() as *mut c_void, &mut sid_size, domain.as_mut_ptr(), &mut domain_chars, &mut kind) == 0 {
            return Some(classify_lookup_error(GetLastError()));
        }
        match (sid_text(sid.as_mut_ptr() as *mut c_void), current_user_sid()) {
            (Ok(theirs), Ok(ours)) if !theirs.is_empty() && theirs == ours => None,
            (Ok(_), Ok(_)) => Some(Verified::OtherUser),
            _ => Some(Verified::Failed(UNIDENTIFIED)),
        }
    }
}

// ------------------------------------------------------------------ presence

/// Whether a prompt can be shown to someone: not in session 0, which has no desktop, and with
/// an interactive (visible) window station. The reason is the distinct text for each case.
pub(crate) fn present(session: Option<u32>, flags: Option<u32>) -> Result<(), &'static str> {
    match (session, flags) {
        (None, _) => Err("the session of the process cannot be read, so nobody can be asked"),
        (Some(0), _) => Err("the process runs in session 0, which has no desktop to show the prompt on"),
        (_, None) => Err("the window station of the process cannot be read, so nobody can be asked"),
        (_, Some(flags)) if flags & WSF_VISIBLE == 0 => Err("the process has no interactive window station to show the prompt on"),
        _ => Ok(()),
    }
}

/// The session of this process and the flags of its window station, when they can be read.
fn detect() -> (Option<u32>, Option<u32>) {
    let session = own_session();
    let flags = window_station_api().and_then(|api| unsafe {
        // The handle belongs to the process and is not closed.
        let station = (api.station)();
        if station.is_null() {
            return None;
        }
        let mut info = UserObjectFlags::default();
        let mut needed = 0u32;
        let read = (api.information)(station, UOI_FLAGS, &mut info as *mut _ as *mut c_void, std::mem::size_of::<UserObjectFlags>() as u32, &mut needed);
        (read != 0).then_some(info.flags)
    });
    (session, flags)
}

/// True when the job this process is in (the innermost one, where jobs are nested) kills its
/// processes when it closes. Every job the guard makes does (`KILL_ON_JOB_CLOSE`, engine.rs), so
/// every descendant of a guard is in such a job whatever its chain of parents looks like, unless it
/// has put itself in a job of its own, which replaces the innermost job that is read here. A host
/// that puts its terminal in a job of that kind is taken for a guard as well. A process in no job,
/// or a job that cannot be read, is not.
fn in_guard_job() -> bool {
    let mut limits = ExtendedLimitInformation::default();
    let read = unsafe {
        QueryInformationJobObject(std::ptr::null_mut(), EXTENDED_LIMIT_CLASS, &mut limits as *mut _ as *mut c_void,
            std::mem::size_of::<ExtendedLimitInformation>() as u32, std::ptr::null_mut())
    };
    read != 0 && limits.basic.limit_flags & KILL_ON_JOB_CLOSE != 0
}

/// True when standard input is a console input buffer: never a pipe, a file or the null
/// device, which an agent controls.
pub(crate) fn console_stdin() -> bool {
    stdin_handle().map_or(false, is_console_input)
}

/// True when `handle` is a console input buffer. `GetConsoleMode` alone is not enough: it also
/// succeeds on the screen buffer of a console, which is no input, so `GetNumberOfConsoleInputEvents`
/// must succeed too.
fn is_console_input(handle: Handle) -> bool {
    let (mut mode, mut events) = (0u32, 0u32);
    unsafe { GetConsoleMode(handle, &mut mode) != 0 && GetNumberOfConsoleInputEvents(handle, &mut events) != 0 }
}

// ------------------------------------------------------------ bounded waits

/// Why work that was run in the background gave no answer.
#[derive(Debug, PartialEq, Eq)]
enum Unanswered {
    NotStarted,
    TimedOut,
    Ended,
    /// A process that started the guard exited while it was waited for.
    OwnerGone,
}

/// Wait for an answer on `receiver` for at most `timeout`, looking at `owners` every
/// `OWNER_SLICE_MS`.
fn wait_for<T>(receiver: &std::sync::mpsc::Receiver<T>, timeout: Duration, owners: &Owners) -> Result<T, Unanswered> {
    let end = Instant::now() + timeout;
    loop {
        let left = end.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(left.min(Duration::from_millis(OWNER_SLICE_MS))) {
            Ok(answer) => return Ok(answer),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Err(Unanswered::Ended),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if owners.gone() {
                    return Err(Unanswered::OwnerGone);
                }
                if Instant::now() >= end {
                    return Err(Unanswered::TimedOut);
                }
            }
        }
    }
}

/// Run `work` on a thread and wait for its answer for at most `timeout`, looking at `owners`
/// every `OWNER_SLICE_MS`. A thread that is still at work when the wait ends is left, and ends
/// with the process (the run is refused, so the process is about to). An answer that comes after
/// that is dropped by the thread, which wipes it.
fn bounded<T: Send + 'static>(timeout: Duration, owners: &Owners, work: impl FnOnce() -> T + Send + 'static) -> Result<T, Unanswered> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::Builder::new().name("prompt".into()).spawn(move || {
        let _ = sender.send(work());
    }).map_err(|_| Unanswered::NotStarted)?;
    wait_for(&receiver, timeout, owners)
}

/// What a prompt that was waited for came to.
fn asked_from(answer: Result<Asked, Unanswered>) -> Asked {
    match answer {
        Ok(asked) => asked,
        Err(Unanswered::NotStarted) => Asked::NotShown("the prompt could not be started".into()),
        Err(Unanswered::TimedOut) => Asked::Abandoned(format!("no answer within {} seconds", PROMPT_TIMEOUT_MS / 1000)),
        Err(Unanswered::Ended) => Asked::Unavailable("the prompt ended without an answer".into()),
        Err(Unanswered::OwnerGone) => Asked::Unavailable(OWNER_GONE.into()),
    }
}

// ------------------------------------------------------------ the desktop prompt

/// The credential dialog of the desktop method, used where Windows Hello is not available:
/// `CredUIPromptForWindowsCredentialsW` showing only the accounts of the current user, then
/// `CredUnPackAuthenticationBufferW`. The user whose sign-in is a Personal Identification Number
/// (PIN) gets the password in a protected form, which is unprotected (`CredUnprotectW`) into a
/// buffer that is wiped like any other secret. It is refused without showing anything when the
/// process has no interactive window station or runs in session 0.
pub(crate) struct DesktopPrompt<'a> {
    owners: &'a Owners,
    /// The thread that makes every call of the prompt of this run, made when the first is asked.
    worker: std::cell::RefCell<Option<PromptWorker>>,
}

impl<'a> DesktopPrompt<'a> {
    pub(crate) fn new(owners: &'a Owners) -> DesktopPrompt<'a> {
        DesktopPrompt { owners, worker: std::cell::RefCell::new(None) }
    }
}

impl Prompt for DesktopPrompt<'_> {
    fn begin(&self, text: &str) -> Result<Claim, String> {
        self.ready(text)?;
        self.seat(text)
    }

    fn seat(&self, _text: &str) -> Result<Claim, String> {
        if window_station_api().is_none() {
            return Err(NOT_AVAILABLE.into());
        }
        let (session, flags) = detect();
        present(session, flags)?;
        Ok(Claim { _lock: Some(PromptLock::take()?) })
    }

    fn ready(&self, text: &str) -> Result<(), String> {
        if desktop_api().is_none() || window_station_api().is_none() {
            return Err(NOT_AVAILABLE.into());
        }
        // The field limits keep the message under the most the dialog takes; a message that is not
        // refuses the run rather than reach a dialog that would clip the way to refuse it.
        if text.encode_utf16().count() >= CREDUI_MAX_MESSAGE_LENGTH {
            return Err("the message of the prompt is longer than the dialog takes".into());
        }
        Ok(())
    }

    fn ask(&self, _attempt: u32, last_error: u32, text: &str) -> Asked {
        let Some(api) = desktop_api() else { return Asked::NotShown(NOT_AVAILABLE.into()) };
        let (message, caption) = (wide(text), wide(CAPTION));
        let mut slot = self.worker.borrow_mut();
        if slot.is_none() {
            *slot = PromptWorker::start();
        }
        let Some(worker) = slot.as_ref() else { return Asked::NotShown("the prompt could not be started".into()) };
        worker.ask(self.owners, Duration::from_millis(PROMPT_TIMEOUT_MS), move || desktop_dialog(api, &message, &caption, last_error))
    }
}

fn desktop_dialog(api: &DesktopApi, message: &[u16], caption: &[u16], last_error: u32) -> Asked {
    let info = CredUiInfoW {
        size: std::mem::size_of::<CredUiInfoW>() as u32,
        parent: std::ptr::null_mut(),
        message: message.as_ptr(),
        caption: caption.as_ptr(),
        banner: std::ptr::null_mut(),
    };
    let (mut package, mut save) = (0u32, 0);
    let mut out = OutBuffer { pointer: std::ptr::null_mut(), size: 0, free: api.free };
    let status = unsafe {
        (api.prompt)(&info, last_error, &mut package, std::ptr::null(), 0,
            &mut out.pointer, &mut out.size, &mut save, CREDUIWIN_SECURE_PROMPT | CREDUIWIN_ENUMERATE_CURRENT_USER)
    };
    match status {
        0 => {}
        ERROR_CANCELLED => return Asked::Cancelled,
        code => return Asked::Unavailable(format!("the prompt failed: {}", error_for(code).message())),
    }
    if !out.pointer.is_null() && out.size > 0 {
        register(out.pointer as *const u8, out.size as usize);
    }
    read_credentials(api, out.pointer, out.size)
}

/// Read the name, the domain and the password out of the authentication buffer that the dialog returned. The password buffer
/// is the size of a password; one that is not large enough holds a password in a protected form, which is longer than the
/// password it holds, and the unpacking is made again with a buffer of the size the system asked for (at most
/// `PROTECTED_LIMIT`). A password in a protected form is then unprotected into a buffer of the size of a password. Every buffer
/// is a registered secret, wiped when it goes, on every path.
fn read_credentials(api: &DesktopApi, buffer: *const c_void, size: u32) -> Asked {
    let mut credentials = Box::new(Credentials::new());
    let (mut user_chars, mut domain_chars, mut password_chars) = (CREDUI_USER_CHARS as u32, CREDUI_DOMAIN_CHARS as u32, CREDUI_PASSWORD_CHARS as u32);
    let mut unpacked = unsafe {
        (api.unpack)(0, buffer, size,
            credentials.user.0.as_mut_ptr(), &mut user_chars,
            credentials.domain.0.as_mut_ptr(), &mut domain_chars,
            credentials.password.0.as_mut_ptr(), &mut password_chars)
    };
    let mut code = if unpacked == 0 { unsafe { GetLastError() } } else { 0 };
    if unpacked == 0 && code == ERROR_INSUFFICIENT_BUFFER && password_chars as usize > CREDUI_PASSWORD_CHARS {
        if password_chars as usize > PROTECTED_LIMIT {
            return Asked::Rejected("the password is longer than the guard takes".into());
        }
        // The old buffer is wiped and taken out of the list as the new one takes its place.
        credentials.password = zeroed(password_chars as usize);
        (user_chars, domain_chars, password_chars) = (CREDUI_USER_CHARS as u32, CREDUI_DOMAIN_CHARS as u32, credentials.password.0.len() as u32);
        unpacked = unsafe {
            (api.unpack)(0, buffer, size,
                credentials.user.0.as_mut_ptr(), &mut user_chars,
                credentials.domain.0.as_mut_ptr(), &mut domain_chars,
                credentials.password.0.as_mut_ptr(), &mut password_chars)
        };
        code = if unpacked == 0 { unsafe { GetLastError() } } else { 0 };
    }
    if unpacked == 0 {
        // The prompt was answered with something that is not a name and a password (a smart card may be so), or with a name or
        // password that is too long: an attempt used, with no logon tried, and the user is asked again. The buffers are wiped
        // when `credentials` goes.
        return Asked::Rejected(if code == ERROR_INSUFFICIENT_BUFFER {
            "the name or password is longer than the prompt allows".into()
        } else {
            format!("the answer of the prompt could not be read as a user name and password: {}", error_for(code).message())
        });
    }
    // A password that the system hands back in a protected (encrypted) form is not the text that was typed: sent to `LogonUserW`
    // it would fail as a wrong password and count toward the lockout of the account. It is unprotected first; one that cannot
    // be uses an attempt of its own, with a reason of its own, and no logon is tried for it.
    if password_is_protected(api, &mut credentials.password.0) {
        match unprotect(api, &mut credentials.password.0) {
            // The protected form is wiped as the clear one takes its place.
            Ok(clear) => credentials.password = clear,
            Err(reason) => return Asked::Rejected(reason),
        }
    }
    Asked::Entered(credentials)
}

/// The clear text of `protected`, a password in a protected form that ends with a NUL inside the slice (`CredUnprotectW`, for
/// the user whose sign-in it is), in a registered buffer of the size of a password. The size is asked for first, and a password
/// that would not fit is refused. The clear password is in memory from here until the credentials are dropped.
fn unprotect(api: &DesktopApi, protected: &mut [u16]) -> Result<Secret<Box<[u16]>>, String> {
    let failed = |code: u32| format!("the protected form of the password could not be unprotected: {}", error_for(code).message());
    let Some(end) = protected.iter().position(|unit| *unit == 0) else { return Err(failed(ERROR_INSUFFICIENT_BUFFER)) };
    // The length counts the NUL, as the call that makes a protected form counts it.
    let length = end as u32 + 1;
    let mut needed = 0u32;
    let sized = unsafe { (api.unprotect)(0, protected.as_mut_ptr(), length, std::ptr::null_mut(), &mut needed) };
    let code = unsafe { GetLastError() };
    if sized != 0 || code != ERROR_INSUFFICIENT_BUFFER {
        return Err(failed(if sized != 0 { UNIDENTIFIED } else { code }));
    }
    if needed as usize > CREDUI_PASSWORD_CHARS {
        return Err("the password is longer than the guard takes".into());
    }
    let mut clear = zeroed(CREDUI_PASSWORD_CHARS);
    let mut chars = CREDUI_PASSWORD_CHARS as u32;
    if unsafe { (api.unprotect)(0, protected.as_mut_ptr(), length, clear.0.as_mut_ptr(), &mut chars) } == 0 {
        return Err(failed(unsafe { GetLastError() }));
    }
    Ok(clear)
}

/// True when `password`, which ends with a NUL inside the slice (the unpacking that filled it
/// succeeded), is in a protected form (`CredIsProtectedW`) and not clear text.
fn password_is_protected(api: &DesktopApi, password: &mut [u16]) -> bool {
    let mut kind = CRED_UNPROTECTED;
    unsafe { (api.protected)(password.as_mut_ptr(), &mut kind) != 0 && kind != CRED_UNPROTECTED }
}

// ------------------------------------------------------------ the console prompt

/// The console prompt: `CredUICmdLinePromptForCredentialsW`, accepted only when standard input
/// is a real console. The prompt reads the console itself, so redirected standard input would
/// not feed it, and an agent that controls standard input must never be able to answer. What
/// the user is approving is written to the console first, once. A console that a process of the
/// same user made (a pseudo console) also passes the test; see `SECURITY.md`.
pub(crate) struct ConsolePrompt<'a> {
    owners: &'a Owners,
    /// The thread that makes every call of the prompt of this run, made when the first is asked.
    worker: std::cell::RefCell<Option<PromptWorker>>,
}

impl<'a> ConsolePrompt<'a> {
    pub(crate) fn new(owners: &'a Owners) -> ConsolePrompt<'a> {
        ConsolePrompt { owners, worker: std::cell::RefCell::new(None) }
    }
}

/// What the worker of a prompt is given to do.
type Job = Box<dyn FnOnce() -> Asked + Send>;

/// One thread that makes all the calls of the prompt of a run, desktop or console, and lives for
/// as long as they are asked. A console prompt that is made on a thread of its own each time is
/// answered at once with a cancel from the second call on, with nothing shown (G97 shows it in a
/// pseudo console): the functions of `credui.dll` that read the console keep state that
/// goes with the thread that first called them. The desktop prompt is the same library, and
/// makes its calls in the same way, so that a second and a third attempt are shown and are not
/// cancelled at once, which the guard would read as the user refusing the run.
struct PromptWorker {
    jobs: std::sync::mpsc::Sender<Job>,
    answers: std::sync::mpsc::Receiver<Asked>,
}

impl PromptWorker {
    fn start() -> Option<PromptWorker> {
        let (jobs, job_receiver) = std::sync::mpsc::channel::<Job>();
        let (answer_sender, answers) = std::sync::mpsc::channel::<Asked>();
        std::thread::Builder::new().name("prompt worker".into()).spawn(move || {
            while let Ok(job) = job_receiver.recv() {
                if answer_sender.send(job()).is_err() {
                    break;
                }
            }
        }).ok()?;
        Some(PromptWorker { jobs, answers })
    }

    /// Give `job` to the thread and wait for what it comes back with, for at most `timeout`, with
    /// `owners` watched. A job that is still at work when the wait ends is left, and ends with the
    /// process (the run is refused, so the process is about to).
    fn ask(&self, owners: &Owners, timeout: Duration, job: impl FnOnce() -> Asked + Send + 'static) -> Asked {
        if self.jobs.send(Box::new(job)).is_err() {
            return Asked::Unavailable("the prompt ended without an answer".into());
        }
        asked_from(wait_for(&self.answers, timeout, owners))
    }
}

impl Prompt for ConsolePrompt<'_> {
    fn begin(&self, text: &str) -> Result<Claim, String> {
        if !console_stdin() {
            return Err("standard input is not an interactive console; the console prompt is never read from a pipe, a file or the null device".into());
        }
        if console_api().is_none() {
            return Err(NOT_AVAILABLE.into());
        }
        let lock = PromptLock::take()?;
        // A console that does not take the text (a selection is being made in it, or nobody reads
        // it) must not hold the guard, with the lock, for ever.
        let text = text.to_string();
        write_bounded(self.owners, Duration::from_millis(SYSTEM_TIMEOUT_MS), move || write_console(&text))?;
        Ok(Claim { _lock: Some(lock) })
    }

    fn ask(&self, _attempt: u32, last_error: u32, _text: &str) -> Asked {
        let Some(api) = console_api() else { return Asked::NotShown(NOT_AVAILABLE.into()) };
        let mut slot = self.worker.borrow_mut();
        if slot.is_none() {
            *slot = PromptWorker::start();
        }
        let Some(worker) = slot.as_ref() else { return Asked::NotShown("the prompt could not be started".into()) };
        // The prompt reads with echo off. When the prompt returns, or the wait gives up on a read
        // that goes on, the console is put back as it was, so the shell is not left with no echo.
        // While the prompt reads, a control event that ends the guard (Ctrl+C, Ctrl+Break, closing
        // the console) puts it back too, before the default action ends the process. Nothing can
        // do it when the guard is ended from outside (Task Manager). The name of the account is
        // read inside the same limit as the prompt.
        let echo = EchoGuard::new(api, console_mode());
        let asked = worker.ask(self.owners, Duration::from_millis(PROMPT_TIMEOUT_MS), move || console_dialog(api, last_error, own_account_name()));
        drop(echo);
        // The line that was typed may have reached the command history that the console keeps for
        // the program: clear it, whatever the prompt came back with.
        expunge_history(api);
        if matches!(asked, Asked::Unavailable(_) | Asked::Abandoned(_)) {
            // The prompt line is left open when nobody answers (the starter exits, or the time is up): end it, so that the
            // refusal that follows is a line of its own in the record on the console.
            let _ = write_bounded(self.owners, Duration::from_millis(SYSTEM_TIMEOUT_MS), || write_console(""));
        }
        asked
    }
}

/// A write to the console, with a limit and the owner watched.
fn write_bounded(owners: &Owners, limit: Duration, write: impl FnOnce() -> bool + Send + 'static) -> Result<(), String> {
    match bounded(limit, owners, write) {
        Ok(true) => Ok(()),
        Ok(false) => Err("the console cannot be written to, so the user cannot be shown what is asked".into()),
        Err(Unanswered::OwnerGone) => Err(OWNER_GONE.into()),
        Err(_) => Err("the console did not take what is asked within the time allowed, so the user cannot be shown it".into()),
    }
}

/// The handle of standard input, when there is one.
fn stdin_handle() -> Option<Handle> {
    let handle = unsafe { GetStdHandle(-10i32 as u32) };
    (!handle.is_null() && handle != INVALID_HANDLE).then_some(handle)
}

/// The mode of the console that standard input is, when it is one.
fn console_mode() -> Option<u32> {
    let mut mode = 0u32;
    (unsafe { GetConsoleMode(stdin_handle()?, &mut mode) } != 0).then_some(mode)
}

/// The mode of the console that a control event puts back: `NO_MODE` when there is none to put back.
static MODE_TO_RESTORE: AtomicU64 = AtomicU64::new(NO_MODE);
const NO_MODE: u64 = u64::MAX;

/// The handler of the control events while a console prompt reads: it puts the mode back and
/// returns false, so that the default action still ends the guard.
unsafe extern "system" fn restore_on_control_event(_event: u32) -> Bool {
    let mode = MODE_TO_RESTORE.load(Ordering::SeqCst);
    if mode != NO_MODE {
        restore_console_mode(Some(mode as u32));
    }
    0
}

/// Puts the console mode back when it is dropped, and for as long as it lives puts it back on a
/// control event that ends the guard.
struct EchoGuard {
    saved: Option<u32>,
    handler: SetConsoleCtrlHandlerFn,
}

impl EchoGuard {
    fn new(api: &ConsoleApi, saved: Option<u32>) -> EchoGuard {
        if let Some(mode) = saved {
            MODE_TO_RESTORE.store(mode as u64, Ordering::SeqCst);
            unsafe { (api.handler)(Some(restore_on_control_event), 1) };
        }
        EchoGuard { saved, handler: api.handler }
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        if self.saved.is_some() {
            unsafe { (self.handler)(Some(restore_on_control_event), 0) };
            MODE_TO_RESTORE.store(NO_MODE, Ordering::SeqCst);
        }
        restore_console_mode(self.saved);
    }
}

/// Clear the command history that the console keeps for the file name of this program. The
/// result is ignored: a system without the call, or a console without a history, has nothing to clear.
fn expunge_history(api: &ConsoleApi) {
    let Some(expunge) = api.expunge else { return };
    let image = image_of(unsafe { GetCurrentProcessId() });
    let name = image.rsplit(['\\', '/']).next().unwrap_or("");
    if name.is_empty() {
        return;
    }
    unsafe { expunge(wide(name).as_ptr()) };
}

/// Put the mode of the console back to `saved`, if it was read.
fn restore_console_mode(saved: Option<u32>) {
    if let (Some(mode), Some(handle)) = (saved, stdin_handle()) {
        unsafe { SetConsoleMode(handle, mode) };
    }
}

/// Write `text` and a line end to the console itself (`CONOUT$`), whatever standard output is.
fn write_console(text: &str) -> bool {
    unsafe {
        let name = wide("CONOUT$");
        let console = CreateFileW(name.as_ptr(), GENERIC_WRITE, FILE_SHARE_READ_AND_WRITE, std::ptr::null_mut(), OPEN_EXISTING, 0, std::ptr::null_mut());
        if console == INVALID_HANDLE {
            return false;
        }
        let units: Vec<u16> = format!("{}\r\n", text).encode_utf16().collect();
        let mut written = 0u32;
        let ok = WriteConsoleW(console, units.as_ptr() as *const c_void, units.len() as u32, &mut written, std::ptr::null_mut()) != 0;
        CloseHandle(console);
        ok
    }
}

/// The prompt, with the name of the account the guard runs as already in the user field, so that
/// it asks for the password alone (the name cannot be changed there). Only when the guard cannot
/// read its own account name does the prompt ask for a name too, and a name that is typed is looked
/// up before a logon is tried (see `account_check`). The flags are `CONSOLE_PROMPT_FLAGS`:
/// `CREDUI_FLAGS_EXCLUDE_CERTIFICATES` is required (a prompt on a console takes no certificate or
/// smart card, and any call without it fails with `ERROR_INVALID_FLAGS`), the prompt is always
/// shown, nothing is saved, and the credentials are generic: the target names no server to check
/// them against.
fn console_dialog(api: &ConsoleApi, last_error: u32, own_name: Option<String>) -> Asked {
    let mut credentials = Box::new(Credentials::new());
    if let Some(name) = own_name {
        for (slot, unit) in credentials.user.0.iter_mut().zip(name.encode_utf16().take(CREDUI_USER_CHARS - 1)) {
            *slot = unit;
        }
    }
    let target = wide(CAPTION);
    let mut save = 0;
    let status = unsafe {
        (api.prompt)(target.as_ptr(), std::ptr::null_mut(), last_error,
            credentials.user.0.as_mut_ptr(), CREDUI_USER_CHARS as u32,
            credentials.password.0.as_mut_ptr(), CREDUI_PASSWORD_CHARS as u32,
            &mut save, CONSOLE_PROMPT_FLAGS)
    };
    match status {
        0 => Asked::Entered(credentials),
        ERROR_CANCELLED => Asked::Cancelled,
        code => Asked::Unavailable(format!("the console prompt failed: {}", error_for(code).message())),
    }
}

// ----------------------------------------------------------------- verification

/// Checks credentials with `LogonUserW`, as an interactive logon (`LOGON32_LOGON_INTERACTIVE`,
/// the default provider). That is the check Windows sign-in itself makes, and the logon itself
/// works for a domain account with cached credentials. The look up of the name before it is local
/// when the name is the guard's own account name as the system writes it; a name in another form
/// (a user principal name of a domain account) may contact a domain controller, and where none
/// answers the run is refused with the error of the system. An account that lacks the right to
/// log on locally fails with 1385 and cannot approve.
/// The cost is a logon session (event 4624, logon type 2) that closing the token ends at once, and
/// that an interactive logon caches the logon information as a sign-in does. The security
/// identifier of the token's user must equal that of the guard's own token, so the password of
/// another account that the system accepts does not approve anything, and a name that is not the
/// guard's own account is turned away before any logon is tried for it. The check runs on a
/// thread, and a system that does not answer within `LOGON_TIMEOUT_MS` refuses the run.
pub(crate) struct LogonVerifier<'a> {
    owners: &'a Owners,
}

impl Verifier for LogonVerifier<'_> {
    fn verify(&self, credentials: Box<Credentials>) -> Verified {
        if !credentials.password_ends() {
            return Verified::Failed(ERROR_INSUFFICIENT_BUFFER);
        }
        // Nothing is tried for an empty password: it is not a secret, and it would use an attempt of the lockout.
        if credentials.password_is_empty() {
            return Verified::Wrong;
        }
        check_bounded(Duration::from_millis(LOGON_TIMEOUT_MS), self.owners, credentials, logon)
    }
}

/// Run `work` on the credentials with a limit, and say what it came to.
fn check_bounded(limit: Duration, owners: &Owners, credentials: Box<Credentials>, work: impl FnOnce(Box<Credentials>) -> Verified + Send + 'static) -> Verified {
    match bounded(limit, owners, move || work(credentials)) {
        Ok(verdict) => verdict,
        Err(Unanswered::NotStarted) => Verified::Failed(ERROR_NOT_ENOUGH_MEMORY),
        Err(Unanswered::TimedOut) => Verified::Failed(WAIT_TIMEOUT),
        Err(Unanswered::Ended) => Verified::Failed(UNIDENTIFIED),
        Err(Unanswered::OwnerGone) => Verified::OwnerGone,
    }
}

/// What a failed `LogonUserW` with the error `code` comes to: the error for a wrong name or
/// password is a name or password that is not accepted; any other is a failure of the system (a
/// locked or disabled account, an expired password, an account without the right to log on
/// locally, a domain that cannot be reached), which another try cannot mend.
fn classify_logon_error(code: u32) -> Verified {
    if code == ERROR_LOGON_FAILURE { Verified::Wrong } else { Verified::Failed(code) }
}

fn logon(credentials: Box<Credentials>) -> Verified {
    let Some((name, domain)) = credentials.names() else { return Verified::Failed(ERROR_INSUFFICIENT_BUFFER) };
    let (domain, user) = split_name(&name, &domain);
    if let Some(verdict) = account_check(&full_name(domain.as_deref(), &user)) {
        return verdict;
    }
    let Some(api) = logon_api() else { return Verified::Failed(UNIDENTIFIED) };
    let (user, domain) = (wide(&user), domain.map(|domain| wide(&domain)));
    let mut handle: Handle = std::ptr::null_mut();
    let logged_on = unsafe {
        (api.logon)(user.as_ptr(), domain.as_ref().map_or(std::ptr::null(), |domain| domain.as_ptr()), credentials.password_pointer(),
            LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &mut handle)
    };
    if logged_on == 0 {
        return classify_logon_error(unsafe { GetLastError() });
    }
    let token = Token(handle);
    same_user(token_user_sid(token.0), current_user_sid())
}

/// Approved when the user of the logon token is the user the guard runs as: the text forms of
/// their security identifiers are equal. If either cannot be read, nothing is approved.
fn same_user(theirs: Result<String, GuardError>, ours: Result<String, GuardError>) -> Verified {
    match (theirs, ours) {
        (Ok(theirs), Ok(ours)) if !theirs.is_empty() && theirs == ours => Verified::Approved,
        (Ok(_), Ok(_)) => Verified::OtherUser,
        _ => Verified::Failed(UNIDENTIFIED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extend::{is_format, DEFAULT_MAX_EXTENSION};
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};

    /// What the stub prompt does on each call, in order.
    enum Answer {
        Password(&'static str),
        Cancel,
        Unavailable(&'static str),
        Abandoned(&'static str),
        NotShown(&'static str),
    }

    /// A prompt that answers from a script, and keeps what it was asked.
    struct StubPrompt {
        answers: Mutex<VecDeque<Answer>>,
        asked: Mutex<Vec<(u32, u32, String)>>,
        /// The reason `begin` gives for refusing, if it does.
        closed: Option<&'static str>,
    }

    impl StubPrompt {
        fn new(answers: Vec<Answer>) -> StubPrompt {
            StubPrompt { answers: Mutex::new(answers.into()), asked: Mutex::new(Vec::new()), closed: None }
        }

        fn asked(&self) -> Vec<(u32, u32, String)> {
            self.asked.lock().unwrap().clone()
        }
    }

    impl Prompt for StubPrompt {
        fn begin(&self, _text: &str) -> Result<Claim, String> {
            match self.closed {
                Some(reason) => Err(reason.into()),
                None => Ok(Claim::none()),
            }
        }

        fn ask(&self, attempt: u32, last_error: u32, text: &str) -> Asked {
            self.asked.lock().unwrap().push((attempt, last_error, text.to_string()));
            match self.answers.lock().unwrap().pop_front().expect("the prompt was asked more often than the test allows") {
                Answer::Password(password) => Asked::Entered(Box::new(Credentials::with("me", "", password))),
                Answer::Cancel => Asked::Cancelled,
                Answer::Unavailable(reason) => Asked::Unavailable(reason.into()),
                Answer::Abandoned(reason) => Asked::Abandoned(reason.into()),
                Answer::NotShown(reason) => Asked::NotShown(reason.into()),
            }
        }
    }

    /// A verifier that accepts one password, for the account of the guard or for another, or fails.
    struct StubVerifier {
        right: &'static str,
        same_user: bool,
        failure: Option<u32>,
    }

    impl Verifier for StubVerifier {
        fn verify(&self, credentials: Box<Credentials>) -> Verified {
            if let Some(code) = self.failure {
                return Verified::Failed(code);
            }
            if credentials.password_units() != self.right.encode_utf16().collect::<Vec<u16>>() {
                Verified::Wrong
            } else if self.same_user {
                Verified::Approved
            } else {
                Verified::OtherUser
            }
        }
    }

    fn settings(command: &str) -> Settings {
        Settings {
            max_seconds: 86_400.0,
            log_path: None,
            exception: Some(Exception { method: Method::Console, command: command.into(), timeout: 20.0 }),
        }
    }

    /// The parent the prompt is told in the tests.
    const STARTER: &str = "starter.exe";

    /// `authorize` with no owner to watch and the same names every time.
    fn authorize_with(settings: &Settings, prompt: &dyn Prompt, verifier: &dyn Verifier, log: &Log) -> Result<(), GuardError> {
        authorize_owned(settings, prompt, verifier, &Owners::empty(), log)
    }

    fn authorize_owned(settings: &Settings, prompt: &dyn Prompt, verifier: &dyn Verifier, owners: &Owners, log: &Log) -> Result<(), GuardError> {
        authorize(settings, &Subject { account: "PC\\me", parent: STARTER, program: "prog.exe" }, prompt, verifier, owners, log)
    }

    fn lines_of(lines: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
        lines.lock().unwrap().clone()
    }

    fn decisions(lines: &[String]) -> Vec<&str> {
        lines.iter().map(|line| if line.contains("decision=exception-approved") { "approved" } else if line.contains("decision=exception-refused") { "refused" } else { "other" }).collect()
    }

    /// An event that is signalled, or is not; a process handle stands in for it in the tests of the owner.
    fn event(signalled: bool) -> Handle {
        let handle = unsafe { CreateEventW(std::ptr::null_mut(), 1, signalled as Bool, std::ptr::null()) };
        assert!(!handle.is_null());
        handle
    }

    #[test]
    fn the_right_password_of_the_signed_in_user_approves_and_the_line_is_the_record() {
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let prompt = StubPrompt::new(vec![Answer::Password("correct horse")]);
        let verifier = StubVerifier { right: "correct horse", same_user: true, failure: None };
        assert!(authorize_with(&settings("C:\\tools\\run.exe --all"), &prompt, &verifier, &log).is_ok());
        log.finish(1_000);
        let lines = lines_of(&kept);
        assert_eq!(decisions(&lines), ["approved"], "{:?}", lines);
        assert!(lines[0].contains("requested=86400 hours=24 granted=0 decision=exception-approved attempt=1 reason=\"a cap of 24 hours was approved"), "{}", lines[0]);
        assert!(lines[0].starts_with("PROCESS_TREE_GUARD_EXTENSION: time=") && !lines[0].contains("correct horse") && !lines[0].contains("user="), "{}", lines[0]);
        let asked = prompt.asked();
        assert_eq!(asked.len(), 1);
        assert_eq!((asked[0].0, asked[0].1), (1, 0), "the first attempt has no error before it");
        assert!(asked[0].2.contains("Command line: [C:\\tools\\run.exe --all] Program: [prog.exe] Account: [PC\\me] Parent process, as the system reports it: [starter.exe] ")
            && asked[0].2.contains("up to 24 hours at a time"), "{}", asked[0].2);
        // The record says what was approved and for which account: the command line as the prompt shows it, and the guard's own account.
        assert!(lines[0].contains("account=\"PC\\\\me\" command=\"C:\\\\tools\\\\run.exe --all\" method=\"console\" timeout=20 started_by=\"starter.exe\" requested=86400"), "{}", lines[0]);
        assert!(lines[0].contains("the password of the account the guard runs as was given at the console prompt") && !lines[0].contains("signed-in user gave"), "the approval says what the guard knows: {}", lines[0]);
    }

    #[test]
    fn a_wrong_password_is_an_attempt_used_and_the_prompt_says_why_the_next_time() {
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let prompt = StubPrompt::new(vec![Answer::Password("wrong"), Answer::Password("right")]);
        let verifier = StubVerifier { right: "right", same_user: true, failure: None };
        assert!(authorize_with(&settings("x"), &prompt, &verifier, &log).is_ok());
        log.finish(1_000);
        let lines = lines_of(&kept);
        assert_eq!(decisions(&lines), ["refused", "approved"], "{:?}", lines);
        assert!(lines[0].contains("attempt=1 ") && lines[0].contains("the user name or password was not accepted") && !lines[0].contains("no attempts are left"), "{}", lines[0]);
        assert!(lines[1].contains("attempt=2 "), "{}", lines[1]);
        let asked = prompt.asked();
        assert_eq!((asked[1].0, asked[1].1), (2, ERROR_LOGON_FAILURE), "the second prompt is told the logon failed");
        assert!(lines.iter().all(|line| !line.contains("wrong") && !line.contains("right\"")), "no password is in the log: {:?}", lines);
    }

    #[test]
    fn a_password_of_another_account_does_not_approve_counts_and_is_not_told_apart_from_a_wrong_one() {
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let prompt = StubPrompt::new(vec![Answer::Password("theirs"), Answer::Password("theirs"), Answer::Password("theirs")]);
        let verifier = StubVerifier { right: "theirs", same_user: false, failure: None };
        let error = authorize_with(&settings("x"), &prompt, &verifier, &log).expect_err("another account's password is refused");
        log.finish(1_000);
        let lines = lines_of(&kept);
        assert_eq!(decisions(&lines), ["refused", "refused", "refused"], "{:?}", lines);
        assert!(lines.iter().all(|line| line.contains("reason=\"the user name or password was not accepted")), "the reason is the same text as for a wrong password: {:?}", lines);
        assert!(error.message().contains("exception refused") && error.message().contains("the run did not start"), "{}", error);
    }

    #[test]
    fn three_failures_end_the_attempts_and_a_fourth_is_never_asked() {
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        // A fourth answer is scripted, and the stub panics if it is not left unasked: it is left in the queue.
        let prompt = StubPrompt::new(vec![Answer::Password("a"), Answer::Password("b"), Answer::Password("c"), Answer::Password("right")]);
        let verifier = StubVerifier { right: "right", same_user: true, failure: None };
        let error = authorize_with(&settings("x"), &prompt, &verifier, &log).expect_err("three wrong passwords end the run");
        log.finish(1_000);
        let lines = lines_of(&kept);
        assert_eq!(prompt.asked().len(), 3, "the prompt is asked three times and no more");
        assert_eq!(decisions(&lines), ["refused", "refused", "refused"], "{:?}", lines);
        assert!(lines[0].contains("attempt=1 ") && lines[1].contains("attempt=2 ") && lines[2].contains("attempt=3 "), "{:?}", lines);
        assert!(!lines[1].contains("no attempts are left") && lines[2].contains("no attempts are left"), "{:?}", lines);
        assert!(error.message().contains("no attempts are left"), "{}", error);
    }

    #[test]
    fn an_empty_password_is_never_checked_and_never_approves() {
        // A verifier that would approve anything: the empty password does not reach it.
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let prompt = StubPrompt::new(vec![Answer::Password(""), Answer::Password(""), Answer::Password(""), Answer::Password("")]);
        let verifier = StubVerifier { right: "", same_user: true, failure: None };
        let error = authorize_with(&settings("x"), &prompt, &verifier, &log).expect_err("an empty password is refused three times");
        log.finish(1_000);
        let lines = lines_of(&kept);
        assert_eq!(prompt.asked().len(), 3, "an empty password uses an attempt like any other");
        assert_eq!(decisions(&lines), ["refused", "refused", "refused"], "{:?}", lines);
        assert!(error.message().contains("no attempts are left") && !lines.iter().any(|line| line.contains("exception-approved")), "{} {:?}", error, lines);
        assert!(lines.iter().all(|line| line.contains(EMPTY_PASSWORD) && !line.contains(NOT_ACCEPTED)), "the record does not say that the system rejected a credential when none was sent: {:?}", lines);
        // And the system verifier turns it away before it calls the system.
        let owners = Owners::empty();
        assert_eq!(LogonVerifier { owners: &owners }.verify(Box::new(Credentials::with("me", "", ""))), Verified::Wrong);
        assert!(Credentials::with("me", "", "").password_is_empty() && !Credentials::with("me", "", "x").password_is_empty());
    }

    #[test]
    fn a_cancel_ends_the_attempts_at_once() {
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let prompt = StubPrompt::new(vec![Answer::Password("wrong"), Answer::Cancel, Answer::Password("right")]);
        let verifier = StubVerifier { right: "right", same_user: true, failure: None };
        let error = authorize_with(&settings("x"), &prompt, &verifier, &log).expect_err("a cancel refuses the run");
        log.finish(1_000);
        let lines = lines_of(&kept);
        assert_eq!(prompt.asked().len(), 2, "nothing is asked after the cancel");
        assert_eq!(decisions(&lines), ["refused", "refused"], "{:?}", lines);
        assert!(lines[1].contains("attempt=2 ") && lines[1].contains("the prompt was cancelled"), "{}", lines[1]);
        assert!(error.message().contains("cancelled"), "{}", error);
    }

    /// A prompt that takes a lock of this test's own as its right to be open, and cancels when asked.
    struct HoldsALock(String);

    impl Prompt for HoldsALock {
        fn begin(&self, _text: &str) -> Result<Claim, String> {
            Ok(Claim { _lock: Some(PromptLock::take_named(&self.0)?) })
        }

        fn ask(&self, _attempt: u32, _last_error: u32, _text: &str) -> Asked {
            Asked::Cancelled
        }
    }

    #[test]
    fn a_refusal_after_a_prompt_was_shown_keeps_the_right_to_a_prompt_for_a_while_and_other_ends_do_not() {
        COOL_DOWNS.with(|count| count.set(0));
        RETRY_DELAY.with(|delay| delay.set(600));
        // A name of this test's own, so that a prompt of a real guard in the same session is not touched.
        let name = format!("Local\\ProcessTreeGuardCoolDown{}", std::process::id());
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        // Another thread tries to take the right as soon as the refusal is in the log, while the cool-down goes on.
        let watcher = {
            let (kept, name) = (kept.clone(), name.clone());
            std::thread::spawn(move || {
                let end = Instant::now() + Duration::from_secs(10);
                while kept.lock().unwrap().is_empty() && Instant::now() < end {
                    std::thread::sleep(Duration::from_millis(5));
                }
                PromptLock::take_named(&name).is_ok()
            })
        };
        let started = Instant::now();
        let verifier = StubVerifier { right: "right", same_user: true, failure: None };
        assert!(authorize_with(&settings("x"), &HoldsALock(name.clone()), &verifier, &log).is_err(), "the cancel refuses the run");
        assert!(started.elapsed() >= Duration::from_millis(600), "the right is kept after the refusal: {:?}", started.elapsed());
        log.finish(1_000);
        assert!(!watcher.join().unwrap(), "a guard started in that time finds the right taken and is refused at once");
        assert_eq!(COOL_DOWNS.with(|count| count.replace(0)), 1);
        assert!(PromptLock::take_named(&name).is_ok(), "the right returns when the guard has returned");
        // The same for a prompt that fails after it was shown, a failure of the system, and three names or passwords that were not accepted.
        for answers in [vec![Answer::Unavailable("the prompt failed")], vec![Answer::Password("right")], vec![Answer::Password("a"), Answer::Password("b"), Answer::Password("c")]] {
            let failing = StubVerifier { right: "other", same_user: true, failure: if answers.len() == 1 && matches!(answers[0], Answer::Password(_)) { Some(1909) } else { None } };
            let log = Log::capture(Arc::new(Mutex::new(Vec::new())), None);
            assert!(authorize_with(&settings("x"), &StubPrompt::new(answers), &failing, &log).is_err());
            log.finish(1_000);
            assert_eq!(COOL_DOWNS.with(|count| count.replace(0)), 1, "one cool-down for each refusal after a prompt");
        }
        // Not after an approval, a prompt that was never shown, a starter that has gone, or a prompt left open at its limit (the process
        // ends at once, which is expected to end the dialog or the read): nobody is shown a prompt that follows.
        let log = Log::capture(Arc::new(Mutex::new(Vec::new())), None);
        assert!(authorize_with(&settings("x"), &StubPrompt::new(vec![Answer::Abandoned("no answer within 300 seconds")]), &verifier, &log).is_err());
        assert!(authorize_with(&settings("x"), &StubPrompt::new(vec![Answer::Password("right")]), &verifier, &log).is_ok());
        let mut closed = StubPrompt::new(vec![]);
        closed.closed = Some("nobody is present");
        assert!(authorize_with(&settings("x"), &closed, &verifier, &log).is_err());
        assert!(authorize_with(&settings("x"), &StubPrompt::new(vec![Answer::NotShown("the prompt could not be started")]), &verifier, &log).is_err());
        assert!(authorize_owned(&settings("x"), &StubPrompt::new(vec![Answer::Password("right")]), &verifier, &Owners::of(vec![event(true)]), &log).is_err());
        log.finish(1_000);
        assert_eq!(COOL_DOWNS.with(|count| count.replace(0)), 0);
        RETRY_DELAY.with(|delay| delay.set(0));
    }

    #[test]
    fn a_prompt_that_cannot_be_shown_is_refused_before_any_attempt_and_says_why() {
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let mut prompt = StubPrompt::new(vec![]);
        prompt.closed = Some("standard input is not an interactive console");
        let verifier = StubVerifier { right: "right", same_user: true, failure: None };
        let error = authorize_with(&settings("x"), &prompt, &verifier, &log).expect_err("nobody can be asked");
        log.finish(1_000);
        let lines = lines_of(&kept);
        assert_eq!(decisions(&lines), ["refused"], "{:?}", lines);
        assert!(lines[0].contains("attempt=0 ") && lines[0].contains("standard input is not an interactive console"), "{}", lines[0]);
        assert!(error.message().contains("standard input is not an interactive console") && prompt.asked().is_empty(), "{}", error);
    }

    #[test]
    fn a_prompt_that_fails_after_it_was_shown_is_an_attempt_and_one_that_never_started_is_not() {
        // Unanswered after it was shown: the attempt it was.
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let prompt = StubPrompt::new(vec![Answer::Abandoned("no answer within 300 seconds")]);
        let verifier = StubVerifier { right: "right", same_user: true, failure: None };
        assert!(authorize_with(&settings("x"), &prompt, &verifier, &log).is_err());
        log.finish(1_000);
        assert!(lines_of(&kept)[0].contains("attempt=1 ") && lines_of(&kept)[0].contains("no answer within 300 seconds"), "{:?}", lines_of(&kept));
        // Not started for the first attempt: none was made. Not started for the second: one was.
        for (answers, attempt) in [(vec![Answer::NotShown("the prompt could not be started")], 0), (vec![Answer::Password("wrong"), Answer::NotShown("the prompt could not be started")], 1)] {
            let kept = Arc::new(Mutex::new(Vec::new()));
            let log = Log::capture(kept.clone(), None);
            let prompt = StubPrompt::new(answers);
            assert!(authorize_with(&settings("x"), &prompt, &verifier, &log).is_err());
            log.finish(1_000);
            let last = lines_of(&kept).last().cloned().unwrap_or_default();
            assert!(last.contains(&format!("attempt={} ", attempt)) && last.contains("the prompt could not be started"), "{}", last);
        }
    }

    #[test]
    fn a_failure_that_more_attempts_cannot_mend_ends_them_and_names_the_error() {
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let prompt = StubPrompt::new(vec![Answer::Password("right")]);
        let locked_out = StubVerifier { right: "right", same_user: true, failure: Some(1909) };
        let error = authorize_with(&settings("x"), &prompt, &locked_out, &log).expect_err("a locked out account is refused");
        log.finish(1_000);
        let lines = lines_of(&kept);
        assert_eq!(prompt.asked().len(), 1);
        assert!(lines[0].contains("[WinError 1909]") && error.message().contains("[WinError 1909]"), "{:?} {}", lines, error);
        // An account that may not log on locally is the same kind of failure, shown at the desktop prompt.
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let prompt = StubPrompt::new(vec![Answer::Password("right")]);
        let no_right = StubVerifier { right: "right", same_user: true, failure: Some(1385) };
        let mut desktop = settings("x");
        if let Some(exception) = desktop.exception.as_mut() {
            exception.method = Method::Desktop;
        }
        assert!(authorize_with(&desktop, &prompt, &no_right, &log).is_err());
        log.finish(1_000);
        assert!(lines_of(&kept)[0].contains("[WinError 1385]") && prompt.asked().len() == 1, "{:?}", lines_of(&kept));
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let unknown = StubVerifier { right: "right", same_user: true, failure: Some(UNIDENTIFIED) };
        let prompt = StubPrompt::new(vec![Answer::Password("right")]);
        assert!(authorize_with(&settings("x"), &prompt, &unknown, &log).is_err());
        log.finish(1_000);
        assert!(lines_of(&kept)[0].contains("could not be identified"), "{:?}", lines_of(&kept));
    }

    #[test]
    fn at_the_console_an_error_given_only_for_a_right_password_is_not_told_apart_from_a_wrong_one() {
        // 1380 and 1385 have the same text in the system, so both are in the list.
        assert!(AFTER_PASSWORD_CHECKED.contains(&1380) && AFTER_PASSWORD_CHECKED.contains(&1385));
        for code in AFTER_PASSWORD_CHECKED {
            let kept = Arc::new(Mutex::new(Vec::new()));
            let log = Log::capture(kept.clone(), None);
            let prompt = StubPrompt::new(vec![Answer::Password("right"), Answer::Password("right"), Answer::Password("right")]);
            let verifier = StubVerifier { right: "right", same_user: true, failure: Some(code) };
            let error = authorize_with(&settings("x"), &prompt, &verifier, &log).expect_err("the run is refused");
            log.finish(1_000);
            let lines = lines_of(&kept);
            assert_eq!(prompt.asked().len(), 3, "{}: a program that types is given the answer of a wrong password, attempts included", code);
            assert_eq!(lines.len(), 3, "{:?}", lines);
            assert!(lines.iter().all(|line| line.contains(NOT_ACCEPTED) && !line.contains(&format!("WinError {}", code))), "{}: {:?}", code, lines);
            assert!(!error.message().contains("WinError"), "{}: {}", code, error);
        }
        // Another failure of the system is still named.
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let prompt = StubPrompt::new(vec![Answer::Password("right")]);
        let verifier = StubVerifier { right: "right", same_user: true, failure: Some(1909) };
        assert!(authorize_with(&settings("x"), &prompt, &verifier, &log).is_err());
        log.finish(1_000);
        assert!(lines_of(&kept)[0].contains("[WinError 1909]"), "{:?}", lines_of(&kept));
    }

    #[test]
    fn an_approval_that_no_record_holds_does_not_stand() {
        let fail = Arc::new(AtomicBool::new(true));
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), Some(fail.clone()));
        let prompt = StubPrompt::new(vec![Answer::Password("right")]);
        let verifier = StubVerifier { right: "right", same_user: true, failure: None };
        let error = authorize_with(&settings("x"), &prompt, &verifier, &log).expect_err("an approval that cannot be written is not one");
        assert!(error.message().contains("could not be recorded"), "{}", error);
        log.finish(1_000);
        // The same log with a standard error that works records the approval and the run goes on.
        fail.store(false, Ordering::SeqCst);
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), Some(fail));
        let prompt = StubPrompt::new(vec![Answer::Password("right")]);
        assert!(authorize_with(&settings("x"), &prompt, &verifier, &log).is_ok());
        log.finish(1_000);
        assert_eq!(decisions(&lines_of(&kept)), ["approved"]);
    }

    #[test]
    fn an_approval_that_the_audit_file_could_not_take_does_not_stand() {
        let folder = std::env::temp_dir().join(format!("ptg-approval-{}", std::process::id()));
        std::fs::create_dir_all(&folder).expect("make a folder");
        let verifier = StubVerifier { right: "right", same_user: true, failure: None };
        // A file in a folder that is not there takes no line: the run is refused, as for a standard error that takes none.
        let bad = Log::start(Some(folder.join("missing").join("audit.log")), 1 << 20).expect("start a log whose file cannot be written");
        let error = authorize_with(&settings("x"), &StubPrompt::new(vec![Answer::Password("right")]), &verifier, &bad).expect_err("an approval that no file holds is not one");
        bad.finish(1_000);
        assert!(error.message().contains("could not be recorded"), "{}", error);
        // A file that takes lines holds the approval, and the run goes on.
        let path = folder.join("audit.log");
        let good = Log::start(Some(path.clone()), 1 << 20).expect("start a log with a file");
        assert!(authorize_with(&settings("x"), &StubPrompt::new(vec![Answer::Password("right")]), &verifier, &good).is_ok());
        good.finish(1_000);
        let contents = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(contents.contains("decision=exception-approved") && contents.contains("account=\"PC\\\\me\""), "{}", contents);
        let _ = std::fs::remove_dir_all(&folder);
    }

    #[test]
    fn a_panic_zeroes_the_secrets_that_are_alive_before_the_process_would_abort() {
        // The hook of the tests zeroes the buffers of the panicking thread only, so a panic here does not wipe a test beside this one.
        HOOK_FOR_THIS_THREAD.store(true, Ordering::SeqCst);
        install_panic_hook();
        let credentials = Credentials::with("me", "DOM", "hunter2");
        let address = credentials.password.0.as_ptr() as usize;
        assert!(live().iter().any(|placed| placed.0 == address), "a buffer that holds a secret is listed while it is alive");
        assert_eq!(credentials.password_units().len(), 7);
        // The destructor does not run for this value (it is outside the closure that panics), as in a release build that aborts.
        let panicked = std::panic::catch_unwind(|| -> () { panic!("a panic while a password is alive") }).is_err();
        assert!(panicked);
        assert!(credentials.password_units().is_empty() && credentials.names() == Some((String::new(), String::new())), "the hook zeroed every buffer");
        drop(credentials);
        assert!(!live().iter().any(|placed| placed.0 == address), "a buffer that was dropped is no longer listed, so the hook never writes to freed memory");
        // The authentication buffer of the prompt is listed and zeroed in the same way.
        unsafe extern "system" fn keep(_memory: *mut c_void) {}
        let mut raw = [0xffu8; 24];
        register(raw.as_mut_ptr(), raw.len());
        let _ = std::panic::catch_unwind(|| -> () { panic!("a panic while the buffer of the prompt is alive") });
        assert!(raw.iter().all(|byte| *byte == 0), "the buffer the prompt returned is zero after a panic");
        // Dropping the buffer takes it out of the list again, so the list does not keep an address that was freed.
        drop(OutBuffer { pointer: raw.as_mut_ptr() as *mut c_void, size: raw.len() as u32, free: keep });
        assert!(!live().iter().any(|placed| placed.0 == raw.as_ptr() as usize));
    }

    /// Set in the environment of the copy of this test executable in which no test has installed the panic hook.
    const HOOK_CHILD: &str = "PROCESS_TREE_GUARD_UNIT_TEST_PANIC_HOOK_CHILD";

    #[test]
    fn making_a_buffer_for_a_secret_is_enough_to_have_the_hook_that_zeroes_it_on_a_panic() {
        if std::env::var_os(HOOK_CHILD).is_some() {
            // The copy: nothing here installs the hook by name, as `decide` does in a program. A buffer for a secret is made and filled,
            // and a panic is caught while it is alive, as the abort of a release build leaves it.
            HOOK_FOR_THIS_THREAD.store(true, Ordering::SeqCst);
            let mut secret = zeroed(8);
            secret.0.iter_mut().for_each(|unit| *unit = 0x5a5a);
            let _ = std::panic::catch_unwind(|| -> () { panic!("a panic while a secret is alive") });
            println!("HOOK {}", if secret.0.iter().all(|unit| *unit == 0) { "zeroed" } else { "left" });
            return;
        }
        // The hook is installed once for the whole process, so the check needs a copy of this executable in which no other test has done it.
        let output = std::process::Command::new(std::env::current_exe().expect("the path of this test executable"))
            .args(["making_a_buffer_for_a_secret_is_enough_to_have_the_hook", "--nocapture", "--test-threads=1"])
            .env(HOOK_CHILD, "1").stdin(std::process::Stdio::null()).output().expect("run the copy");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(output.status.success() && stdout.contains("HOOK zeroed"), "a secret must not be alive without the hook that zeroes it: {}", stdout);
    }

    #[test]
    fn the_credential_dialog_is_refused_a_message_longer_than_it_takes_and_checking_that_shows_nothing() {
        // `ready` loads the libraries and measures the message; the dialog is not called. The limit counts UTF-16 units, as the dialog does.
        if desktop_api().is_none() || window_station_api().is_none() {
            eprintln!("NOT ASSERTED: the libraries of the credential dialog cannot be loaded here");
            return;
        }
        let owners = Owners::empty();
        let prompt = DesktopPrompt::new(&owners);
        assert!(prompt.ready("short").is_ok());
        assert!(prompt.ready(&"x".repeat(CREDUI_MAX_MESSAGE_LENGTH - 1)).is_ok(), "one unit under the limit is taken");
        let reason = prompt.ready(&"x".repeat(CREDUI_MAX_MESSAGE_LENGTH)).expect_err("a message at the limit is not taken");
        assert!(reason.contains("longer than the dialog takes"), "{}", reason);
        let wide_characters = "\u{1d11e}".repeat(CREDUI_MAX_MESSAGE_LENGTH / 2);
        assert!(wide_characters.chars().count() < CREDUI_MAX_MESSAGE_LENGTH && prompt.ready(&wide_characters).is_err(), "each character outside the basic plane is two units");
    }

    #[test]
    fn the_console_mode_is_put_back_on_a_control_event_only_while_a_mode_was_read_and_the_guard_is_not_ended_by_the_handler() {
        use std::sync::atomic::AtomicU32;
        static CALLS: AtomicU32 = AtomicU32::new(0);
        unsafe extern "system" fn count(_handler: Option<ConsoleCtrlHandlerFn>, _add: Bool) -> Bool {
            CALLS.fetch_add(1, Ordering::SeqCst);
            1
        }
        // With no mode read there is nothing to put back: the handler is not registered, and a control event restores nothing.
        let api = ConsoleApi { prompt: unused_prompt, handler: count, expunge: None };
        drop(EchoGuard::new(&api, None));
        assert_eq!(CALLS.load(Ordering::SeqCst), 0, "no handler is added or removed when there is no mode to put back");
        assert_eq!(MODE_TO_RESTORE.load(Ordering::SeqCst), NO_MODE);
        // The handler never claims the event, so that the default action still ends the guard.
        assert_eq!(unsafe { restore_on_control_event(0) }, 0);
        assert_eq!(unsafe { restore_on_control_event(2) }, 0);
        // Where the call to clear the history is missing nothing happens.
        expunge_history(&api);
    }

    unsafe extern "system" fn unused_prompt(_target: *const u16, _context: *mut c_void, _error: u32, _user: *mut u16, _user_chars: u32,
        _password: *mut u16, _password_chars: u32, _save: *mut Bool, _flags: u32) -> u32 {
        ERROR_CANCELLED
    }

    #[test]
    fn a_run_inside_another_run_is_refused_without_asking() {
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let error = decide(&settings("x"), true, "prog.exe", STARTER, &[], &Owners::empty(), &log).expect_err("an exception cannot be granted inside another run");
        log.finish(1_000);
        let lines = lines_of(&kept);
        assert_eq!(decisions(&lines), ["refused"]);
        assert!(lines[0].contains("attempt=0 ") && lines[0].contains(NESTED) && error.message().contains(NESTED), "{:?} {}", lines, error);
        assert!(lines[0].contains("method=\"console\" timeout=20 started_by=\"\" requested="), "the refusal names the method and the deadline: {}", lines[0]);
        // A run with no exception has nothing to decide, held or not.
        let plain = Settings { max_seconds: DEFAULT_MAX_EXTENSION, log_path: None, exception: None };
        assert!(decide(&plain, true, "prog.exe", STARTER, &[], &Owners::empty(), &Log::capture(Arc::new(Mutex::new(Vec::new())), None)).is_ok());
        // Inside another run comes first: the guard that holds the run is above this one too.
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let above = vec!["C:\\tools\\process-tree-guard.exe".to_string()];
        let error = decide(&settings("x"), true, "prog.exe", STARTER, &above, &Owners::empty(), &log).expect_err("nested");
        log.finish(1_000);
        assert!(error.message().contains(NESTED) && !error.message().contains("another guard started"), "{}", error);
    }

    #[test]
    fn a_run_that_another_guard_started_is_refused_before_any_prompt_and_says_so() {
        let names = ["process-tree-guard.exe", "process-guard.exe", "process-tree-guard-deadline.exe", "process-tree-guard-contain.exe",
            "process-tree-guard-auto.exe", "process-guard-auto.exe", "process-tree-guard-deadline-auto.exe"];
        for name in names {
            for image in [format!("C:\\Program Files\\Guard\\{}", name), format!("c:/tools/{}", name.to_ascii_uppercase()), name.to_string()] {
                let chain = vec!["C:\\Windows\\System32\\cmd.exe".to_string(), image.clone(), "C:\\Windows\\explorer.exe".to_string()];
                assert_eq!(guard_above(&chain), Some(name.to_string()), "{}", image);
                let kept = Arc::new(Mutex::new(Vec::new()));
                let log = Log::capture(kept.clone(), None);
                // The real prompt would be reached if this were not refused first, and nothing here can be answered.
                let error = decide(&settings("x"), false, "prog.exe", STARTER, &chain, &Owners::empty(), &log).expect_err("a run that a guard started is not asked");
                log.finish(1_000);
                let lines = lines_of(&kept);
                assert_eq!(decisions(&lines), ["refused"], "{:?}", lines);
                assert!(lines[0].contains("attempt=0 ") && lines[0].contains("reason=\"an exception above the cap is not asked for by a run that another guard started")
                    && lines[0].contains("started_by=\"starter.exe\""), "{}", lines[0]);
                // The reason names the test that made the refusal, and what it found.
                assert!(lines[0].contains(&format!("({}{})", FOUND_ABOVE, name)) && !lines[0].contains(JOB_KILLS), "{}", lines[0]);
                assert!(error.message().contains(&format!("{}{}", FOUND_ABOVE, name)), "{}", error);
                assert!(error.message().contains("start it from a terminal that is not under a guard") && error.message().contains("the run did not start"), "{}", error);
            }
        }
        // A file name whose stem ends in -auto selects automatic mode, whatever the rest of the name, so a host can name its wrapper freely.
        for (image, name) in [("C:\\hosts\\harness-auto.exe", "harness-auto.exe"), ("C:\\x\\Host-Auto.EXE", "host-auto.exe"), ("tool-auto", "tool-auto"), ("D:/a/b.c-auto.exe", "b.c-auto.exe")] {
            let chain = vec!["C:\\Windows\\System32\\cmd.exe".to_string(), image.to_string()];
            assert_eq!(guard_above(&chain), Some(name.to_string()), "{}", image);
        }
        // Only a program of the guard counts, by its file name and not by a folder or a part of it.
        for chain in [vec![], vec![String::new()], vec!["C:\\tools\\other.exe".to_string(), "C:\\process-tree-guard.exe\\cmd.exe".to_string()],
            vec!["C:\\tools\\my-process-tree-guard.exe".to_string(), "C:\\tools\\process-tree-guard-gate.exe".to_string(), "C:\\tools\\testkit.exe".to_string()],
            vec!["C:\\tools\\auto.exe".to_string(), "C:\\tools\\automatic.exe".to_string(), "C:\\auto-x\\cmd.exe".to_string(), "C:\\tools\\x-auto.exe\\cmd.exe".to_string()]] {
            assert_eq!(guard_above(&chain), None, "{:?}", chain);
        }
        // The nearest is the one named, and a guard far above counts as much as the parent.
        let far: Vec<String> = (0..30).map(|n| format!("C:\\tools\\p{}.exe", n)).chain(std::iter::once("C:\\x\\Process-Guard-Auto.exe".to_string())).collect();
        assert_eq!(guard_above(&far), Some("process-guard-auto.exe".to_string()));
    }

    #[test]
    fn a_run_whose_starter_has_exited_is_refused_not_approved() {
        // The starter is gone before the first prompt: nothing is shown and no attempt is made.
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let prompt = StubPrompt::new(vec![Answer::Password("right")]);
        let verifier = StubVerifier { right: "right", same_user: true, failure: None };
        let gone = Owners::of(vec![event(true)]);
        let error = authorize_owned(&settings("x"), &prompt, &verifier, &gone, &log).expect_err("a run nobody started is refused");
        log.finish(1_000);
        assert!(prompt.asked().is_empty() && lines_of(&kept)[0].contains("attempt=0 ") && error.message().contains("nobody is waiting for it"), "{:?} {}", lines_of(&kept), error);
        // The prompt reports the starter gone while it was open.
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let prompt = StubPrompt::new(vec![Answer::Unavailable(OWNER_GONE)]);
        assert!(authorize_with(&settings("x"), &prompt, &verifier, &log).is_err());
        log.finish(1_000);
        assert!(lines_of(&kept)[0].contains("attempt=1 ") && lines_of(&kept)[0].contains(OWNER_GONE), "{:?}", lines_of(&kept));
        // A right password given just as the starter exits is not an approval, and no approval is logged.
        let starter = event(false);
        struct ExitsWhileAsked(Handle);
        impl Prompt for ExitsWhileAsked {
            fn begin(&self, _text: &str) -> Result<Claim, String> {
                Ok(Claim::none())
            }
            fn ask(&self, _attempt: u32, _last_error: u32, _text: &str) -> Asked {
                unsafe { SetEvent(self.0) };
                Asked::Entered(Box::new(Credentials::with("me", "", "right")))
            }
        }
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let owners = Owners::of(vec![starter]);
        let error = authorize_owned(&settings("x"), &ExitsWhileAsked(starter), &verifier, &owners, &log).expect_err("the starter exited");
        log.finish(1_000);
        let lines = lines_of(&kept);
        assert!(decisions(&lines) == ["refused"] && error.message().contains("nobody is waiting for it"), "{:?} {}", lines, error);
    }

    /// The text of the prompt of `method` for an account, a parent, the program and the command, for
    /// a run that starts with a deadline of 20 seconds.
    fn text_for(method: Method, account: &str, parent: &str, program: &str, command: &str, seconds: f64) -> String {
        prompt_text(&Subject { account, parent, program }, &Exception { method, command: command.into(), timeout: 20.0 }, seconds)
    }

    /// The text of the desktop prompt for a parent, the program and the command, in the account `PC\me`.
    fn text_of(parent: &str, program: &str, command: &str, seconds: f64) -> String {
        text_for(Method::Desktop, "PC\\me", parent, program, command, seconds)
    }

    #[test]
    fn the_message_names_the_product_what_the_cap_means_the_account_the_parent_and_the_command_with_nothing_that_can_forge_a_line() {
        let text = text_of("C:\\Apps\\host.exe", "C:\\Windows\\prog.exe", "C:\\Program Files\\tool.exe \"quoted\" --flag", 86_400.0);
        assert!(text.starts_with("Process Tree Guard is asked to run: Command line: [C:\\Program Files\\tool.exe \"quoted\" --flag] Program: [C:\\Windows\\prog.exe] Account: [PC\\me] Parent process, as the system reports it: [C:\\Apps\\host.exe] "),
            "the fields to check come first, and paths and quotes are shown as they are, not doubled: {}", text);
        assert!(text.ends_with("The processes of the run may each ask to keep it alive for up to 24 hours at a time, and may renew without a total limit. \
            The run starts with a deadline of 20 seconds. Enter the password of the account above to allow it, or cancel to refuse the run."), "{}", text);
        assert!(!text.contains("for up to 24 hours.") && !text.contains("run a command for up to") && !text.contains("signed-in user") && !text.contains("Started by"), "the cap is not described as a bound on the run: {}", text);
        // The deadline the run starts with is shown as it is (a fraction too), apart from the cap.
        let started = |timeout: f64| prompt_text(&Subject { account: "PC\\me", parent: "", program: "p" }, &Exception { method: Method::Desktop, command: "x".into(), timeout }, 86_400.0);
        assert!(started(86_400.0).contains("The run starts with a deadline of 86400 seconds."), "{}", started(86_400.0));
        assert!(started(0.5).contains("The run starts with a deadline of 0.5 seconds."), "{}", started(0.5));
        assert!(text_of("s", "p", "x", 3_600.0).contains("up to 1 hour at a time"), "one hour is not hours");
        assert!(text_of("s", "p", "x", 23_400.0).contains("up to 6.5 hours at a time"));
        // Rounded up and with the seconds beside it, so that the figure is never less than the cap and a cap just over the default shows.
        assert!(text_of("s", "p", "x", 21_601.0).contains("up to 6.01 hours (21601 seconds) at a time"), "{}", text_of("s", "p", "x", 21_601.0));
        assert!(text_of("s", "p", "x", 25_000.0).contains("up to 6.95 hours (25000 seconds) at a time"));
        // A parent or an account that cannot be read is said so.
        assert!(text_of("", "p", "x", 86_400.0).contains("Parent process, as the system reports it: [(unknown)] The processes"), "a parent that cannot be read is said so");
        assert!(text_for(Method::Desktop, "", "s", "p", "x", 86_400.0).contains("Account: [(unknown)]"), "an account that cannot be read is said so");
        // Controls, line separators and format characters are escaped; nothing can start another line or reorder the rest.
        let hostile = text_of("s", "p", "a\r\nb\u{85}c\u{2028}d\u{202e}e\u{200b}f\0g\ttab", 86_400.0);
        assert!(hostile.contains("Command line: [a\\u{d}\\u{a}b\\u{85}c\\u{2028}d\\u{202e}e\\u{200b}f\\u{0}g\\u{9}tab] Program: [p]"), "{}", hostile);
        assert!(!hostile.chars().any(|c| c.is_control() || c == '\u{2028}' || is_format(c)), "{}", hostile);
        // A command cannot close its own frame and write a label of its own: the brackets in it are escaped.
        let forged = text_of("s", "p", "x] Program: [C:\\Windows\\System32\\winver.exe", 86_400.0);
        assert!(forged.contains("Command line: [x\\u{5d} Program: \\u{5b}C:\\Windows\\System32\\winver.exe] Program: [p] Account:"), "{}", forged);
        assert_eq!(forged.matches('[').count(), 4);
        assert_eq!(forged.matches(']').count(), 4);
        // So can no name of an account: each field is framed alone.
        let account = text_for(Method::Desktop, "me] Parent process, as the system reports it: [C:\\Windows\\explorer.exe", "s", "p", "x", 86_400.0);
        assert_eq!(account.matches('[').count(), 4, "{}", account);
        assert_eq!(shown_command(""), "(none)");
    }

    #[test]
    fn the_message_says_how_to_refuse_for_the_method_that_asks_and_the_console_has_no_cancel() {
        let desktop = text_for(Method::Desktop, "PC\\me", "s", "p", "x", 86_400.0);
        let console = text_for(Method::Console, "PC\\me", "s", "p", "x", 86_400.0);
        assert!(desktop.ends_with("to allow it, or cancel to refuse the run."), "the desktop prompt has a cancel: {}", desktop);
        assert!(console.ends_with("to allow it, or leave the prompt unanswered for 300 seconds, or close this console, to refuse the run."), "{}", console);
        assert!(!console.contains("cancel"), "the console prompt has no cancel key and must not tell the user to cancel: {}", console);
        // Everything else is the same text.
        assert_eq!(desktop.replace("cancel to refuse the run", "X"), console.replace("leave the prompt unanswered for 300 seconds, or close this console, to refuse the run", "X"));
    }

    #[test]
    fn a_name_in_another_script_is_written_out_and_said_so_and_a_plain_one_has_no_note() {
        const NOTE: &str = " Note: \\u{..} is a character written out; check each field letter by letter.";
        // A Cyrillic es and o for the Latin c and o: the program looks like cmd.exe and is not.
        let program = "C:\\Windows\\System32\\\u{441}md.exe";
        let spoofed = text_for(Method::Desktop, "PC\\me", "C:\\Apps\\host.exe", program, "x", 86_400.0);
        assert!(spoofed.contains("Program: [C:\\Windows\\System32\\\\u{441}md.exe]"), "the look-alike letter is written out: {}", spoofed);
        assert!(spoofed.ends_with(NOTE), "{}", spoofed);
        assert!(!spoofed.contains('\u{441}'), "no letter of another script reaches the dialog: {}", spoofed);
        // Any of the fields can carry it: the account, the parent, the program and the command line.
        for (account, parent, program, command) in [("PC\\\u{43c}e", "s", "p", "x"), ("PC\\me", "\u{440}.exe", "p", "x"), ("PC\\me", "s", "\u{440}", "x"), ("PC\\me", "s", "p", "\u{3b1}")] {
            let text = text_for(Method::Desktop, account, parent, program, command, 86_400.0);
            assert!(text.ends_with(NOTE), "{}", text);
        }
        // Plain Latin has no note.
        let plain = text_of("C:\\Apps\\host.exe", "C:\\Windows\\System32\\cmd.exe", "cmd /c echo hello", 86_400.0);
        assert!(!plain.contains("Note:"), "{}", plain);
        // A command that holds the written-out form of a character has the note too, and an ordinary backslash has none.
        let imitating = text_of("C:\\Apps\\host.exe", "C:\\Windows\\System32\\cmd.exe", "echo a\\u{200b}b", 86_400.0);
        assert!(imitating.contains("Command line: [echo a\\u{5c}u{200b}b]") && imitating.ends_with(NOTE), "{}", imitating);
        // The note comes after the fields and the command line is the first of them.
        assert!(spoofed.starts_with("Process Tree Guard is asked to run: Command line: [x] Program: ["), "{}", spoofed);
    }

    #[test]
    fn the_command_keeps_its_start_and_a_path_keeps_its_end_and_each_says_how_much_was_left_out() {
        let exact = "a".repeat(COMMAND_LIMIT);
        assert_eq!(shown_command(&exact), exact, "a command of exactly the limit is shown whole");
        let over = "b".repeat(COMMAND_LIMIT + 1);
        assert_eq!(shown_command(&over), format!("{}... (and 1 more characters)", "b".repeat(COMMAND_LIMIT)), "one more character cuts it and says so");
        let tail = format!("{}{}{}", "ok ".repeat(10), " ".repeat(COMMAND_LIMIT), "evil".repeat(75));
        assert!(shown_command(&tail).ends_with(&format!("... (and {} more characters)", tail.chars().count() - COMMAND_LIMIT)),
            "a short prefix, blank padding and a long tail do not look like a short command: {}", shown_command(&tail));
        // A long path keeps its end, so the file name stays in view, and says how much came before it.
        let program = format!("C:\\{}\\tool.exe", "d\\".repeat(200));
        let shown_program = shown(&program, PROGRAM_LIMIT, Keep::End);
        let before = program.chars().count() - PROGRAM_LIMIT;
        assert!(shown_program.starts_with(&format!("({} characters before) ...", before)) && shown_program.ends_with("\\tool.exe"), "{}", shown_program);
        let text = text_of(&program, &program, "x", 86_400.0);
        assert!(text.contains("\\tool.exe] Account:") && text.contains("\\tool.exe] The processes"), "the program and the parent end with their file name: {}", text);
        // Characters, not bytes: a character outside basic Latin is written out, so it takes the room of its escape.
        let wide_text = "\u{4e2d}".repeat(COMMAND_LIMIT + 5);
        let kept = COMMAND_LIMIT / "\\u{4e2d}".len();
        assert_eq!(shown_command(&wide_text), format!("{}... (and {} more characters)", "\\u{4e2d}".repeat(kept), COMMAND_LIMIT + 5 - kept));
        // The escapes are the worst case: a field of the longest escapes (ten characters, `\u{10ffff}`) stays within its limit.
        for limit in [COMMAND_LIMIT, PROGRAM_LIMIT, ACCOUNT_LIMIT, PARENT_LIMIT] {
            for keep in [Keep::Start, Keep::End] {
                let field = shown(&format!("{}{}{}", "\u{10ffff}".repeat(39), "a".repeat(3), "\u{10ffff}".repeat(10)), limit, keep);
                let body = field.split("... (and").next().unwrap_or("").rsplit(") ...").next().unwrap_or("");
                assert!(body.len() <= limit, "a field is never longer than its limit once written out: {} {}", body.len(), limit);
            }
        }
    }

    #[test]
    fn the_whole_message_stays_under_the_limit_of_the_dialog_whatever_the_fields_hold() {
        // The largest the message can be: every field is as long as a field can be and is made of the longest escapes, the
        // account holds a backslash before u{ as well, the hours phrase is the longest, the deadline has a fraction and the most
        // digits, and the method is the one with the longest way to refuse.
        let longest = |escaped: &str| escaped.repeat(40_000);
        for escaped in ["\u{202e}", "\u{10ffff}", "\u{e0020}", "\\u{"] {
            let field = longest(escaped);
            let account = format!("{}\u{202e}", "\\u{".repeat(40_000));
            for method in [Method::Desktop, Method::Console] {
                let text = prompt_text(&Subject { account: &account, parent: &field, program: &field },
                    &Exception { method, command: field.clone(), timeout: 86_399.5 }, 21_601.5);
                assert!(text.encode_utf16().count() < CREDUI_MAX_MESSAGE_LENGTH, "the message stays under the limit of the dialog: {}", text.len());
            }
        }
        // The command line is the field the user most needs and it is first, so that a dialog that clips text keeps it.
        let hostile = "\u{202e}".repeat(10_000);
        let text = text_for(Method::Console, &hostile, &hostile, &hostile, &hostile, 21_601.0);
        let (kept, left) = (COMMAND_LIMIT / "\\u{202e}".len(), 10_000 - COMMAND_LIMIT / "\\u{202e}".len());
        assert!(text.starts_with(&format!("Process Tree Guard is asked to run: Command line: [{}... (and {} more characters)] Program: [", "\\u{202e}".repeat(kept), left)),
            "the command line is the first field: {}", text);
    }

    #[test]
    fn what_looks_like_a_blank_or_stacks_over_the_text_or_looks_like_a_letter_is_written_out() {
        for c in ['\u{a0}', '\u{3164}', '\u{115f}', '\u{1160}', '\u{ffa0}', '\u{2800}', '\u{34f}', '\u{301}', '\u{fe0f}', '\u{2003}', '\u{3000}', '\u{7f}'] {
            assert_eq!(shown_command(&format!("a{}b", c)), format!("a\\u{{{:x}}}b", c as u32), "U+{:04x}", c as u32);
        }
        assert_eq!(shown_command("a b\\c:d/e\"f'g&&h%PATH%i"), "a b\\c:d/e\"f'g&&h%PATH%i", "printable basic Latin is shown as it is, the ampersand and the percent sign included");
        // Letters and digits of other scripts are written out too: a Cyrillic es, o and er, a Greek alpha, a mathematical bold a.
        for c in ['\u{441}', '\u{43e}', '\u{440}', '\u{3b1}', '\u{1d41a}', '\u{e9}', '\u{4e2d}', '\u{661}', '\u{ff21}'] {
            assert_eq!(shown_command(&format!("a{}b", c)), format!("a\\u{{{:x}}}b", c as u32), "U+{:04x}: a letter that can pass for a Latin one", c as u32);
            assert!(!shown_as_it_is(c));
        }
        assert_eq!(shown_command("C:\\tools\\\u{440}ython.exe"), "C:\\tools\\\\u{440}ython.exe", "a program that is not python.exe cannot look like it");
        // The written-out form cannot be imitated: the text of six characters and the character itself are shown differently.
        let imitation = shown_command("a\\u{200b}b");
        let real = shown_command("a\u{200b}b");
        assert_eq!(imitation, "a\\u{5c}u{200b}b");
        assert_eq!(real, "a\\u{200b}b");
        assert_ne!(imitation, real, "an argument cannot pass for a character that is written out");
        // A backslash before anything else, and one at the end, is shown as it is, so paths are not doubled.
        assert_eq!(shown_command("C:\\u\\v\\u{x"), "C:\\u\\v\\u{5c}u{x");
        assert_eq!(shown_command("C:\\dir\\"), "C:\\dir\\");
        assert_eq!(shown_command("\\u"), "\\u");
        assert_eq!(shown_command("\\"), "\\");
    }

    #[test]
    fn hours_are_shown_rounded_up_to_two_decimals_and_never_less_than_the_cap() {
        for (seconds, phrase) in [(86_400.0, "24 hours"), (3_600.0, "1 hour"), (23_400.0, "6.5 hours"), (44_100.0, "12.25 hours"),
            (25_000.0, "6.95 hours (25000 seconds)"), (21_601.0, "6.01 hours (21601 seconds)"), (21_600.5, "6.01 hours (21600.5 seconds)"), (21_636.0, "6.01 hours")] {
            assert_eq!(hours_phrase(seconds), phrase, "{}", seconds);
        }
    }

    #[test]
    fn a_user_name_is_split_for_the_logon_by_its_form() {
        assert_eq!(split_name("DOMAIN\\alice", ""), (Some("DOMAIN".into()), "alice".into()));
        assert_eq!(split_name("PC\\a\\b", ""), (Some("PC".into()), "a\\b".into()), "the first backslash splits");
        assert_eq!(split_name("MicrosoftAccount\\a@b.example", ""), (Some("MicrosoftAccount".into()), "a@b.example".into()));
        assert_eq!(split_name("alice@corp.example", ""), (None, "alice@corp.example".into()), "a principal name takes no domain");
        assert_eq!(split_name("alice@corp.example", "IGNORED"), (None, "alice@corp.example".into()));
        assert_eq!(split_name("alice", ""), (Some(".".into()), "alice".into()), "a bare name is a local account");
        assert_eq!(split_name("alice", "CORP"), (Some("CORP".into()), "alice".into()), "the domain the prompt returned is used when the name has none");
        assert_eq!(split_name("DOMAIN\\alice", "OTHER"), (Some("DOMAIN".into()), "alice".into()), "the name decides over the domain field");
        // The name for the look up of the account.
        assert_eq!(full_name(Some("CORP"), "alice"), "CORP\\alice");
        assert_eq!(full_name(Some("."), "alice"), "alice", "the local database is looked in with the bare name");
        assert_eq!(full_name(None, "alice@corp.example"), "alice@corp.example");
    }

    #[test]
    fn nobody_is_present_without_a_session_and_a_visible_window_station() {
        assert_eq!(present(Some(1), Some(WSF_VISIBLE)), Ok(()));
        assert_eq!(present(Some(2), Some(WSF_VISIBLE | 0x4)), Ok(()), "other flags do not matter");
        let reasons = [
            present(Some(0), Some(WSF_VISIBLE)).unwrap_err(),
            present(None, Some(WSF_VISIBLE)).unwrap_err(),
            present(Some(1), None).unwrap_err(),
            present(Some(1), Some(0)).unwrap_err(),
            present(Some(1), Some(0x2)).unwrap_err(),
        ];
        assert!(reasons[0].contains("session 0") && reasons[1].contains("session of the process") && reasons[2].contains("window station of the process cannot be read")
            && reasons[3].contains("no interactive window station") && reasons[3] == reasons[4], "{:?}", reasons);
        for (i, a) in reasons[..4].iter().enumerate() {
            for b in &reasons[i + 1..4] {
                assert_ne!(a, b, "each case has a reason of its own");
            }
        }
        assert_eq!(present(Some(0), None).unwrap_err(), reasons[0], "session 0 is reported first");
    }

    #[test]
    fn detect_reads_this_process() {
        // It shows nothing: it reads the session of this process and the flags of its window station.
        let (session, flags) = detect();
        assert!(session.is_some() && flags.is_some(), "{:?} {:?}", session, flags);
        // Where this runs is not asserted: a shell over Secure Shell (SSH), a service, a scheduled task or a build agent has no session with a
        // desktop or a visible window station, and the guard is right to refuse there. What holds everywhere is that somebody
        // is present exactly when the session is not 0 and the window station is visible.
        assert_eq!(present(session, flags).is_ok(), session.map_or(false, |session| session != 0) && flags.map_or(false, |flags| flags & WSF_VISIBLE != 0), "{:?} {:?}", session, flags);
        // The libraries the prompts ask for are on every Windows with a desktop; loading them shows nothing.
        assert!(window_station_api().is_some());
    }

    #[link(name = "user32")]
    extern "system" {
        fn CreateWindowStationW(name: *const u16, flags: u32, access: u32, attributes: *mut c_void) -> Handle;
        fn SetProcessWindowStation(station: Handle) -> Bool;
    }

    /// Set in the environment of the copy of this test executable that `detect` is tried in.
    const DETECT_CHILD: &str = "PROCESS_TREE_GUARD_UNIT_TEST_HIDDEN_STATION_CHILD";

    #[test]
    fn detect_reports_a_window_station_that_is_not_visible_so_that_no_prompt_is_shown_on_one() {
        const GENERIC_ALL: u32 = 0x1000_0000;
        if std::env::var_os(DETECT_CHILD).is_some() {
            // The copy: it makes a window station of its own, which is not visible, makes it the station of the process, and says what
            // `detect` reads and `present` makes of it. Nothing is shown; no prompt is made.
            let station = unsafe { CreateWindowStationW(std::ptr::null(), 0, GENERIC_ALL, std::ptr::null_mut()) };
            if station.is_null() || unsafe { SetProcessWindowStation(station) } == 0 {
                println!("DETECTED no window station could be made [WinError {}]", unsafe { GetLastError() });
                return;
            }
            let (session, flags) = detect();
            println!("DETECTED flags={:?} {}", flags.map(|flags| flags & WSF_VISIBLE), match present(session, flags) {
                Ok(()) => "Ok".to_string(),
                Err(reason) => format!("Err {}", reason),
            });
            // The seat of the credential dialog, which the desktop method takes first, looks at the same thing before it takes the lock or
            // shows anything; it is what G95 and G103 see end to end, and those two run only where the variable that allows them is set.
            let owners = Owners::empty();
            println!("SEATED {}", match DesktopPrompt::new(&owners).seat("text") {
                Ok(_) => "accepted".to_string(),
                Err(reason) => format!("refused: {}", reason),
            });
            return;
        }
        // This copy cannot change its own window station without affecting the tests beside it, so a copy of the executable is run for
        // this test alone, with the marker in its environment (only this module reads it).
        let output = std::process::Command::new(std::env::current_exe().expect("the path of this test executable"))
            .args(["detect_reports_a_window_station_that_is_not_visible", "--nocapture", "--test-threads=1"])
            .env(DETECT_CHILD, "1").stdin(std::process::Stdio::null()).output().expect("run the copy");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        // The harness writes the name of the test before the line, so the report is found inside a line and not at its start.
        let said = stdout.lines().find_map(|line| line.find("DETECTED ").map(|at| line[at + "DETECTED ".len()..].to_string())).unwrap_or_default();
        if said.starts_with("no window station could be made") {
            // Some hosts refuse a process that is not a service a window station of its own; the manual check and G95 cover the path there.
            assert!(std::env::var_os("PROCESS_TREE_GUARD_REQUIRE_WINDOW_STATION").map_or(true, |value| value.is_empty()), "{}", said);
            eprintln!("NOT ASSERTED: {}", said);
            return;
        }
        assert!(output.status.success() && said.contains("flags=Some(0) Err ")
            && (said.contains("no interactive window station") || said.contains("session 0")), "detect must report a window station that is not visible: {} / {}", said, stdout);
        let seated = stdout.lines().find_map(|line| line.find("SEATED ").map(|at| line[at + "SEATED ".len()..].to_string())).unwrap_or_default();
        assert!(seated.starts_with("refused: ") && (seated.contains("no interactive window station") || seated.contains("session 0")),
            "the seat of the credential dialog must refuse on a window station that is not visible, before the lock is taken: {} / {}", seated, stdout);
    }

    /// Set in the environment of the copy of this test executable that the console prompt is begun in.
    const BEGIN_CHILD: &str = "PROCESS_TREE_GUARD_UNIT_TEST_CONSOLE_BEGIN_CHILD";

    #[test]
    fn the_console_prompt_is_refused_before_anything_is_written_when_standard_input_is_not_a_console() {
        if std::env::var_os(BEGIN_CHILD).is_some() {
            // The copy: its standard input is the null device. With it `begin` returns at the first check, before the lock is taken
            // or anything is written, so nothing can be shown.
            let owners = Owners::empty();
            match ConsolePrompt::new(&owners).begin("text") {
                Err(reason) => println!("BEGIN refused: {}", reason),
                Ok(_) => println!("BEGIN accepted"),
            }
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().expect("the path of this test executable"))
            .args(["the_console_prompt_is_refused_before_anything_is_written", "--nocapture", "--test-threads=1"])
            .env(BEGIN_CHILD, "1").stdin(std::process::Stdio::null()).output().expect("run the copy");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(output.status.success() && stdout.contains("BEGIN refused: standard input is not an interactive console"), "{}", stdout);
    }

    /// Set in the environment of the copy of this test executable that puts itself in a job; its value is `kill` or `plain`.
    const JOB_CHILD: &str = "PROCESS_TREE_GUARD_UNIT_TEST_JOB_CHILD";

    #[test]
    fn a_process_is_in_a_guard_job_when_the_job_it_is_in_kills_its_processes_when_it_closes() {
        if let Some(mode) = std::env::var_os(JOB_CHILD) {
            // The copy: it makes a job of its own, with the limit of a job of the guard or with none, and is put in it (nested in
            // whatever job it is in already). It says what `in_guard_job` reads.
            unsafe {
                let job = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
                let mut limits = ExtendedLimitInformation::default();
                if mode == "kill" {
                    limits.basic.limit_flags = KILL_ON_JOB_CLOSE;
                }
                let set = SetInformationJobObject(job, EXTENDED_LIMIT_CLASS, &mut limits as *mut _ as *mut c_void, std::mem::size_of::<ExtendedLimitInformation>() as u32);
                let assigned = !job.is_null() && set != 0 && AssignProcessToJobObject(job, GetCurrentProcess()) != 0;
                println!("JOBBED assigned={} in_guard_job={}", assigned, in_guard_job());
            }
            return;
        }
        // This copy cannot change its own job without affecting the tests beside it, so a copy of the executable is run for each case.
        for (mode, expected) in [("plain", false), ("kill", true)] {
            let output = std::process::Command::new(std::env::current_exe().expect("the path of this test executable"))
                .args(["a_process_is_in_a_guard_job_when_the_job_it_is_in", "--nocapture", "--test-threads=1"])
                .env(JOB_CHILD, mode).stdin(std::process::Stdio::null()).output().expect("run the copy");
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let said = stdout.lines().find_map(|line| line.find("JOBBED ").map(|at| line[at + "JOBBED ".len()..].to_string())).unwrap_or_default();
            if said.starts_with("assigned=false") {
                // A host whose job does not take a nested job: the integration tests (G100) cover the path there.
                eprintln!("NOT ASSERTED: the copy ({}) could not be put in a job of its own", mode);
                continue;
            }
            assert!(output.status.success() && said.trim() == format!("assigned=true in_guard_job={}", expected), "{}: {} / {}", mode, said, stdout);
        }
    }

    const GENERIC_READ: u32 = 0x8000_0000;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreatePipe(read: *mut Handle, write: *mut Handle, attributes: *mut c_void, size: u32) -> Bool;
    }

    #[test]
    fn only_a_console_input_buffer_is_taken_for_a_console_and_the_screen_buffer_of_a_console_is_not() {
        use std::os::windows::io::AsRawHandle;
        // The null device, a pipe and a file are what a program that starts the guard can give it for standard input.
        let null = std::fs::File::open("NUL").expect("open the null device");
        assert!(!is_console_input(null.as_raw_handle() as Handle), "the null device is not a console");
        let (mut read, mut write): (Handle, Handle) = (std::ptr::null_mut(), std::ptr::null_mut());
        assert_ne!(unsafe { CreatePipe(&mut read, &mut write, std::ptr::null_mut(), 0) }, 0, "make a pipe");
        assert!(!is_console_input(read) && !is_console_input(write), "neither end of a pipe is a console");
        unsafe {
            CloseHandle(read);
            CloseHandle(write);
        }
        let path = std::env::temp_dir().join(format!("ptg-console-input-{}", std::process::id()));
        let file = std::fs::File::create(&path).expect("make a file");
        assert!(!is_console_input(file.as_raw_handle() as Handle), "a file is not a console");
        drop(file);
        let _ = std::fs::remove_file(&path);
        // Where this run has a console: its screen buffer takes `GetConsoleMode` too and is still no input, which only the
        // second call tells; its input buffer is one. A run with no console (a build agent, a pipe-hosted shell) skips this part.
        if unsafe { GetConsoleWindow() }.is_null() {
            return;
        }
        let open = |name: &str| unsafe { CreateFileW(wide(name).as_ptr(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ_AND_WRITE, std::ptr::null_mut(), OPEN_EXISTING, 0, std::ptr::null_mut()) };
        let (screen, input) = (open("CONOUT$"), open("CONIN$"));
        let mut mode = 0u32;
        if screen != INVALID_HANDLE {
            assert_ne!(unsafe { GetConsoleMode(screen, &mut mode) }, 0, "the screen buffer answers GetConsoleMode, which is why that call alone is not the test");
            assert!(!is_console_input(screen), "the screen buffer of a console is not a console input");
            unsafe { CloseHandle(screen) };
        }
        if input != INVALID_HANDLE {
            assert!(is_console_input(input), "the input buffer of a console is");
            unsafe { CloseHandle(input) };
        }
    }

    #[test]
    fn two_prompts_of_the_guard_are_not_open_at_once() {
        // A name of this test's own, so that a prompt of a real guard in the same session is neither refused by this test nor refuses it.
        let name = format!("Local\\ProcessTreeGuardTest{}", std::process::id());
        let first = PromptLock::take_named(&name).expect("the first prompt may open");
        let refusal = PromptLock::take_named(&name).err().expect("a second one is refused while the first is open");
        assert!(refusal.contains("is open or was refused less than 10 seconds ago, or another program holds its lock name"), "{}", refusal);
        assert_eq!(COOL_DOWN_MS, 10_000, "the figure the reason names");
        drop(first);
        assert!(PromptLock::take_named(&name).is_ok(), "the right returns when the first prompt is gone");
        assert_eq!(PROMPT_LOCK_NAME, "Local\\ProcessTreeGuardPrompt", "the name that the guard takes, which a test never takes");
    }

    #[test]
    fn a_wait_ends_at_its_limit_when_the_starter_goes_and_when_the_answer_comes() {
        let none = Owners::empty();
        let started = Instant::now();
        let slow = bounded(Duration::from_millis(50), &none, || {
            std::thread::sleep(Duration::from_millis(1_500));
            7
        });
        assert_eq!(slow, Err(Unanswered::TimedOut));
        assert!(started.elapsed() < Duration::from_millis(1_000), "the wait ends at its limit, not when the thread does");
        assert_eq!(bounded(Duration::from_secs(10), &none, || 5), Ok(5));
        // A starter that has exited ends the wait at once, long before the limit.
        let gone = Owners::of(vec![event(true)]);
        let started = Instant::now();
        let waiting = bounded(Duration::from_secs(60), &gone, || {
            std::thread::sleep(Duration::from_millis(3_000));
            7
        });
        assert_eq!(waiting, Err(Unanswered::OwnerGone));
        assert!(started.elapsed() < Duration::from_millis(2_000), "{:?}", started.elapsed());
        // One that is still there does not.
        let there = Owners::of(vec![event(false)]);
        assert_eq!(bounded(Duration::from_secs(10), &there, || 5), Ok(5));
        assert_eq!(bounded(Duration::from_millis(30), &there, || { std::thread::sleep(Duration::from_millis(1_000)); 5 }), Err(Unanswered::TimedOut));
        // The same for a prompt: the answer of a prompt that is waited for is Unavailable with the reason.
        assert_eq!(match ask_bounded_for(&gone) { Asked::Unavailable(reason) => reason, _ => String::new() }, OWNER_GONE);
    }

    /// The worker of a prompt over a prompt that never answers, for an owner that has gone.
    fn ask_bounded_for(owners: &Owners) -> Asked {
        PromptWorker::start().expect("the thread of the prompt").ask(owners, Duration::from_secs(60), || {
            std::thread::sleep(Duration::from_millis(3_000));
            Asked::Cancelled
        })
    }

    #[test]
    fn the_check_of_the_credentials_is_bounded_and_watches_the_starter() {
        let owners = Owners::empty();
        let slow = check_bounded(Duration::from_millis(50), &owners, Box::new(Credentials::with("me", "", "x")), |_| {
            std::thread::sleep(Duration::from_millis(1_500));
            Verified::Approved
        });
        assert_eq!(slow, Verified::Failed(WAIT_TIMEOUT), "a system that does not answer refuses the run and does not approve it");
        assert_eq!(check_bounded(Duration::from_secs(10), &owners, Box::new(Credentials::with("me", "", "x")), |_| Verified::Approved), Verified::Approved);
        let gone = Owners::of(vec![event(true)]);
        let waiting = check_bounded(Duration::from_secs(60), &gone, Box::new(Credentials::with("me", "", "x")), |_| {
            std::thread::sleep(Duration::from_millis(3_000));
            Verified::Approved
        });
        assert_eq!(waiting, Verified::OwnerGone);
    }

    #[test]
    fn the_buffers_are_zeroed_when_they_are_dropped_on_every_path() {
        let mut units = [0x5a5au16; 16];
        wipe(&mut units);
        assert!(units.iter().all(|unit| *unit == 0));
        let mut bytes = [0xa5u8; 33];
        wipe(&mut bytes);
        assert!(bytes.iter().all(|byte| *byte == 0));
        // A secret over storage that the test keeps: after the drop the storage is zero.
        let mut storage = [0x1234u16; 8];
        drop(Secret(&mut storage[..]));
        assert!(storage.iter().all(|unit| *unit == 0), "dropping a secret zeroes it");
        // The credentials: the typed password is there, and then the drop of the three buffers finds it and wipes it.
        let credentials = Credentials::with("me", "DOM", "hunter2");
        assert_eq!(credentials.password_units(), "hunter2".encode_utf16().collect::<Vec<u16>>());
        assert_eq!(credentials.names(), Some(("me".into(), "DOM".into())));
        WIPES.with(|wipes| wipes.borrow_mut().clear());
        drop(credentials);
        let dropped = WIPES.with(|wipes| wipes.borrow().clone());
        assert_eq!(dropped, [(2, 0), (3, 0), (7, 0)], "the user, the domain and the password were there, and are zero");
        // The buffer the prompt returns: dropping it zeroes it over its whole size before it is freed (here nothing is).
        unsafe extern "system" fn keep(_memory: *mut c_void) {}
        let mut raw = [0xffu8; 40];
        let buffer = OutBuffer { pointer: raw.as_mut_ptr() as *mut c_void, size: raw.len() as u32, free: keep };
        drop(buffer);
        assert!(raw.iter().all(|byte| *byte == 0), "the authentication buffer is zero after its drop");
    }

    #[test]
    fn the_credentials_are_wiped_on_the_path_of_every_verdict() {
        // The drop is the path of every verdict: approved, a wrong password, another account's, a failure and an empty password.
        for (name, verifier, password) in [
            ("approved", StubVerifier { right: "hunter2", same_user: true, failure: None }, "hunter2"),
            ("wrong", StubVerifier { right: "other", same_user: true, failure: None }, "hunter2"),
            ("another account", StubVerifier { right: "hunter2", same_user: false, failure: None }, "hunter2"),
            ("failed", StubVerifier { right: "hunter2", same_user: true, failure: Some(1909) }, "hunter2"),
        ] {
            WIPES.with(|wipes| wipes.borrow_mut().clear());
            let log = Log::capture(Arc::new(Mutex::new(Vec::new())), None);
            let prompt = StubPrompt::new(vec![Answer::Password(password), Answer::Password(password), Answer::Password(password)]);
            let _ = authorize_with(&settings("x"), &prompt, &verifier, &log);
            log.finish(1_000);
            let dropped = WIPES.with(|wipes| wipes.borrow().clone());
            let asked = prompt.asked().len();
            assert_eq!(dropped.len(), 3 * asked, "{}: three buffers for each set of credentials that was asked for", name);
            assert!(dropped.iter().all(|(_, after)| *after == 0), "{}: {:?}", name, dropped);
            assert_eq!(dropped.iter().filter(|(before, _)| *before == 7).count(), asked, "{}: the password was in each set before its drop: {:?}", name, dropped);
        }
        // An empty password never reaches a verifier, and its buffers are wiped just the same.
        WIPES.with(|wipes| wipes.borrow_mut().clear());
        let log = Log::capture(Arc::new(Mutex::new(Vec::new())), None);
        let prompt = StubPrompt::new(vec![Answer::Password(""), Answer::Password(""), Answer::Password("")]);
        let _ = authorize_with(&settings("x"), &prompt, &StubVerifier { right: "", same_user: true, failure: None }, &log);
        log.finish(1_000);
        let dropped = WIPES.with(|wipes| wipes.borrow().clone());
        assert_eq!(dropped.len(), 9);
        assert!(dropped.iter().all(|(_, after)| *after == 0));
    }

    #[test]
    fn only_the_security_identifier_of_the_guards_own_user_approves() {
        let sid = |text: &str| Ok::<String, GuardError>(text.to_string());
        let mine = "S-1-5-21-1111111111-2222222222-3333333333-1001";
        assert_eq!(same_user(sid(mine), sid(mine)), Verified::Approved);
        assert_eq!(same_user(sid("S-1-5-21-1111111111-2222222222-3333333333-1002"), sid(mine)), Verified::OtherUser, "another account of the same machine");
        assert_eq!(same_user(sid("S-1-5-21-4444444444-2222222222-3333333333-1001"), sid(mine)), Verified::OtherUser, "the same relative identifier on another machine");
        assert_eq!(same_user(sid(&mine.to_lowercase()), sid(mine)), Verified::OtherUser, "the text form is compared as it is");
        assert_eq!(same_user(sid("S-1-5-18"), sid(mine)), Verified::OtherUser);
        let unreadable = || Err::<String, GuardError>(GuardError("cannot read".into()));
        assert_eq!(same_user(unreadable(), sid(mine)), Verified::Failed(UNIDENTIFIED), "a token that cannot be read approves nothing");
        assert_eq!(same_user(sid(mine), unreadable()), Verified::Failed(UNIDENTIFIED));
        assert_eq!(same_user(unreadable(), unreadable()), Verified::Failed(UNIDENTIFIED));
        assert_eq!(same_user(sid(""), sid("")), Verified::OtherUser, "two empty identifiers are not the same user");
    }

    #[test]
    fn what_the_system_says_to_a_logon_and_to_a_look_up_is_sorted_into_wrong_and_failed() {
        // The mapping alone: the system is not called, so no failed logon is written to the audit log of the machine.
        assert_eq!(classify_logon_error(ERROR_LOGON_FAILURE), Verified::Wrong);
        for code in [1909, 1385, 1327, ERROR_INSUFFICIENT_BUFFER, 1328, 1331] {
            assert_eq!(classify_logon_error(code), Verified::Failed(code), "{}", code);
        }
        assert_eq!(classify_lookup_error(ERROR_NONE_MAPPED), Verified::Wrong, "no such account is a name that is not accepted");
        assert_eq!(classify_lookup_error(1722), Verified::Failed(1722), "a domain that cannot be reached is a failure of the system");
    }

    #[test]
    fn a_name_that_is_not_the_guards_own_account_is_turned_away_before_any_logon() {
        let own = own_account_name().expect("the name of the account this test runs as");
        assert!(!own.is_empty(), "{}", own);
        assert!(account_check(&own).is_none(), "the account itself goes on to the logon: {}", own);
        assert!(account_check(&own.to_uppercase()).is_none(), "in any letter case: {}", own);
        // A well known account of the local system, which is looked up with no network and is the account of no user: it is another account.
        // Its name is asked of the system by its security identifier, since it is spelled differently on a localized Windows.
        let system_name = name_of_well_known_account("S-1-5-18").expect("the name of the local system account");
        let ours = current_user_sid().expect("the user of this process");
        let system = account_check(&system_name);
        if ours == "S-1-5-18" {
            assert!(system.is_none(), "{}", system_name);
        } else {
            assert_eq!(system, Some(Verified::OtherUser), "another account is turned away without a logon: {}", system_name);
        }
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertStringSidToSidW(text: *const u16, sid: *mut *mut c_void) -> Bool;
        fn LookupAccountSidW(system: *const u16, sid: *mut c_void, name: *mut u16, name_chars: *mut u32, domain: *mut u16, domain_chars: *mut u32, kind: *mut u32) -> Bool;
        fn CredProtectW(as_self: Bool, credentials: *const u16, chars: u32, protected: *mut u16, protected_chars: *mut u32, kind: *mut i32) -> Bool;
    }

    /// The name, `DOMAIN\name`, that the system gives the account with the security identifier `text` (looked up locally).
    fn name_of_well_known_account(text: &str) -> Option<String> {
        unsafe {
            let mut sid: *mut c_void = std::ptr::null_mut();
            if ConvertStringSidToSidW(wide(text).as_ptr(), &mut sid) == 0 {
                return None;
            }
            let (mut name, mut domain) = (vec![0u16; 256], vec![0u16; 256]);
            let (mut name_chars, mut domain_chars, mut kind) = (name.len() as u32, domain.len() as u32, 0u32);
            let found = LookupAccountSidW(std::ptr::null(), sid, name.as_mut_ptr(), &mut name_chars, domain.as_mut_ptr(), &mut domain_chars, &mut kind) != 0;
            LocalFree(sid);
            found.then(|| format!("{}\\{}", String::from_utf16_lossy(&domain[..domain_chars as usize]), String::from_utf16_lossy(&name[..name_chars as usize])))
        }
    }

    #[test]
    fn a_password_in_a_protected_form_is_told_from_one_in_clear_text() {
        // Loading the libraries shows nothing; the function is the one the desktop prompt asks.
        let api = desktop_api().expect("the libraries of the desktop prompt");
        let mut plain = Credentials::with("me", "", "hunter2");
        assert!(!password_is_protected(api, &mut plain.password.0), "a password in clear text is not protected");
        // A password protected for the current user, as the system can hand one back.
        let clear: Vec<u16> = "hunter2".encode_utf16().chain(std::iter::once(0)).collect();
        let (mut size, mut kind) = (0u32, 0i32);
        unsafe { CredProtectW(0, clear.as_ptr(), clear.len() as u32, std::ptr::null_mut(), &mut size, &mut kind) };
        assert!(size > 0, "the size of the protected form is asked for first");
        let mut blob = vec![0u16; size as usize];
        assert_ne!(unsafe { CredProtectW(0, clear.as_ptr(), clear.len() as u32, blob.as_mut_ptr(), &mut size, &mut kind) }, 0, "protect a password for the test");
        assert!(password_is_protected(api, &mut blob), "a protected password is not sent to the logon");
        wipe(&mut blob);
    }

    #[test]
    fn credentials_have_the_sizes_the_prompt_fills_and_a_password_that_ends() {
        let credentials = Credentials::new();
        assert_eq!((credentials.user.0.len(), credentials.domain.0.len(), credentials.password.0.len()), (514, 338, 257));
        assert!(credentials.password_ends(), "a zeroed buffer ends");
        let mut full = Credentials::new();
        for unit in full.password.0.iter_mut() {
            *unit = 0x41;
        }
        assert!(!full.password_ends(), "a password with no end is not passed to the system");
        let owners = Owners::empty();
        assert_eq!(LogonVerifier { owners: &owners }.verify(Box::new(full)), Verified::Failed(ERROR_INSUFFICIENT_BUFFER));
    }

    /// A verifier that must not be called: for answers that never reach a logon.
    struct NoLogon;

    impl Verifier for NoLogon {
        fn verify(&self, _credentials: Box<Credentials>) -> Verified {
            panic!("a logon was tried");
        }
    }

    /// A prompt that gives `Rejected` each time it is asked, and keeps how often it was asked.
    struct RejectsEvery(Mutex<Vec<(u32, u32)>>);

    impl Prompt for RejectsEvery {
        fn begin(&self, _text: &str) -> Result<Claim, String> {
            Ok(Claim::none())
        }
        fn ask(&self, attempt: u32, last_error: u32, _text: &str) -> Asked {
            self.0.lock().unwrap().push((attempt, last_error));
            Asked::Rejected("the answer of the prompt could not be read as a user name and password: smart card".into())
        }
    }

    #[test]
    fn an_answer_that_is_not_a_name_and_a_password_is_an_attempt_used_with_no_logon_and_ends_after_three() {
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let prompt = RejectsEvery(Mutex::new(Vec::new()));
        let error = authorize_with(&settings("x"), &prompt, &NoLogon, &log).expect_err("three answers that cannot be read end the run");
        log.finish(1_000);
        let lines = lines_of(&kept);
        assert_eq!(*prompt.0.lock().unwrap(), [(1, 0), (2, ERROR_LOGON_FAILURE), (3, ERROR_LOGON_FAILURE)], "the prompt is asked three times and told that the logon failed");
        assert_eq!(decisions(&lines), ["refused", "refused", "refused"], "{:?}", lines);
        assert!(lines.iter().all(|line| line.contains("smart card")) && lines[2].contains("attempt=3 ") && lines[2].contains("no attempts are left"), "{:?}", lines);
        assert!(error.message().contains("no attempts are left"), "{}", error);
        // A good answer after one of them still approves.
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        struct RejectsThenAnswers(Mutex<u32>);
        impl Prompt for RejectsThenAnswers {
            fn begin(&self, _text: &str) -> Result<Claim, String> {
                Ok(Claim::none())
            }
            fn ask(&self, _attempt: u32, _last_error: u32, _text: &str) -> Asked {
                let mut asked = self.0.lock().unwrap();
                *asked += 1;
                if *asked == 1 { Asked::Rejected("not a password".into()) } else { Asked::Entered(Box::new(Credentials::with("me", "", "right"))) }
            }
        }
        let verifier = StubVerifier { right: "right", same_user: true, failure: None };
        assert!(authorize_with(&settings("x"), &RejectsThenAnswers(Mutex::new(0)), &verifier, &log).is_ok());
        log.finish(1_000);
        assert_eq!(decisions(&lines_of(&kept)), ["refused", "approved"], "{:?}", lines_of(&kept));
    }

    #[test]
    fn a_wrong_answer_is_followed_by_a_wait_that_the_starter_ending_cuts_short() {
        assert_eq!(RETRY_DELAY_MS, 2_000, "the wait that makes a loop of guesses cost time");
        let verifier = StubVerifier { right: "right", same_user: true, failure: None };
        RETRY_DELAY.with(|delay| delay.set(400));
        let waits = || RETRIES.with(|retries| retries.replace(0));
        waits();
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let started = Instant::now();
        assert!(authorize_with(&settings("x"), &StubPrompt::new(vec![Answer::Password("wrong"), Answer::Password("right")]), &verifier, &log).is_ok());
        log.finish(1_000);
        assert!(started.elapsed() >= Duration::from_millis(400) && waits() == 1, "the second prompt comes after the wait: {:?}", started.elapsed());
        // Nothing is waited for after an approval, or after the last attempt: three attempts are two waits.
        let log = Log::capture(Arc::new(Mutex::new(Vec::new())), None);
        assert!(authorize_with(&settings("x"), &StubPrompt::new(vec![Answer::Password("right")]), &verifier, &log).is_ok());
        log.finish(1_000);
        assert_eq!(waits(), 0);
        let log = Log::capture(Arc::new(Mutex::new(Vec::new())), None);
        assert!(authorize_with(&settings("x"), &StubPrompt::new(vec![Answer::Password("a"), Answer::Password("b"), Answer::Password("c")]), &verifier, &log).is_err());
        log.finish(1_000);
        assert_eq!(waits(), 2);
        // A starter that exits during the wait ends it at once, and the run is refused.
        RETRY_DELAY.with(|delay| delay.set(30_000));
        let starter = event(false);
        struct ExitsDuringTheWait(Handle, Mutex<u32>);
        impl Prompt for ExitsDuringTheWait {
            fn begin(&self, _text: &str) -> Result<Claim, String> {
                Ok(Claim::none())
            }
            fn ask(&self, _attempt: u32, _last_error: u32, _text: &str) -> Asked {
                *self.1.lock().unwrap() += 1;
                let handle = self.0 as usize;
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(300));
                    unsafe { SetEvent(handle as Handle) };
                });
                Asked::Entered(Box::new(Credentials::with("me", "", "wrong")))
            }
        }
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let prompt = ExitsDuringTheWait(starter, Mutex::new(0));
        let started = Instant::now();
        let error = authorize_owned(&settings("x"), &prompt, &verifier, &Owners::of(vec![starter]), &log).expect_err("the starter went");
        log.finish(1_000);
        assert!(started.elapsed() < Duration::from_secs(3) && *prompt.1.lock().unwrap() == 1 && error.message().contains("nobody is waiting for it"), "{:?} {}", started.elapsed(), error);
        assert!(!pause(&Owners::of(vec![event(true)]), 30_000) && pause(&Owners::empty(), 20));
        RETRY_DELAY.with(|delay| delay.set(0));
    }

    #[test]
    fn the_starter_is_taken_only_if_it_started_before_the_guard_and_its_handle_is_the_one_that_is_kept() {
        assert!(started_before(Some(5), Some(5)) && started_before(Some(4), Some(5)));
        assert!(!started_before(Some(6), Some(5)) && !started_before(None, Some(5)) && !started_before(Some(5), None) && !started_before(None, None));
        // The parent of this process started before it, and its handle watches it: alive, so not signalled.
        let parent = crate::engine::parent_process_id().expect("the parent of the test run");
        let owners = Owners::open(&[parent]).expect("the parent of this process is a starter");
        assert!(!owners.gone() && !owners.image().is_empty(), "the image is read from the handle: {:?}", owners.image());
        // The handles are given on and not closed with the value: the one used for the wait is the one opened for the prompt.
        let handles = owners.into_handles();
        assert_eq!(handles.len(), 1);
        assert_eq!(unsafe { WaitForSingleObject(handles[0], 0) }, WAIT_TIMEOUT, "the handle is still open and the parent is alive");
        assert!(started_at(handles[0]).is_some());
        assert_eq!(Owners::of(handles.clone()).into_handles(), handles, "the same handles come out as went in");
        unsafe { CloseHandle(handles[0]) };
        // A process that started after this one cannot be its parent: a reused identifier is refused.
        let mut later = std::process::Command::new("cmd").args(["/d", "/c", "ping -n 6 127.0.0.1 >nul"]).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).spawn().expect("start a later process");
        let refusal = Owners::open(&[later.id()]).err().expect("a process that started later is not a starter");
        assert!(refusal.message().contains("its identifier was reused"), "{}", refusal);
        let _ = later.kill();
        let _ = later.wait();
        // A process that cannot be opened is refused too.
        assert!(Owners::open(&[0xffff_fff0]).is_err());
    }

    #[test]
    fn a_run_whose_starter_cannot_be_watched_is_refused_with_a_line_before_any_attempt() {
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let error = refuse_unwatched(&settings("x"), &log, "[WinError 5] Access is denied.");
        log.finish(1_000);
        let lines = lines_of(&kept);
        assert_eq!(decisions(&lines), ["refused"], "{:?}", lines);
        assert!(lines[0].contains("attempt=0 ") && lines[0].contains("decision=exception-refused") && lines[0].contains("cannot be watched: [WinError 5] Access is denied."), "{}", lines[0]);
        assert!(error.message().contains("exception refused") && error.message().contains("the run did not start"), "{}", error);
    }

    #[test]
    fn a_write_to_the_console_is_bounded_and_watches_the_starter() {
        let none = Owners::empty();
        assert_eq!(write_bounded(&none, Duration::from_secs(5), || true), Ok(()));
        assert!(write_bounded(&none, Duration::from_secs(5), || false).unwrap_err().contains("cannot be written to"));
        let started = Instant::now();
        let blocked = write_bounded(&none, Duration::from_millis(60), || {
            std::thread::sleep(Duration::from_millis(1_500));
            true
        });
        assert!(blocked.unwrap_err().contains("within the time allowed") && started.elapsed() < Duration::from_millis(1_000), "{:?}", started.elapsed());
        let gone = Owners::of(vec![event(true)]);
        let started = Instant::now();
        let blocked = write_bounded(&gone, Duration::from_secs(60), || {
            std::thread::sleep(Duration::from_millis(3_000));
            true
        });
        assert_eq!(blocked, Err(OWNER_GONE.to_string()));
        assert!(started.elapsed() < Duration::from_millis(2_000), "{:?}", started.elapsed());
    }

    #[test]
    fn the_name_of_the_account_is_read_inside_the_limit_of_the_prompt_and_every_call_is_made_on_one_thread() {
        // A look up that does not come back is waited for by the same bounded wait as the prompt, with the owner watched.
        let worker = PromptWorker::start().expect("the thread of the prompt");
        let gone = Owners::of(vec![event(true)]);
        let started = Instant::now();
        let asked = worker.ask(&gone, Duration::from_secs(60), || {
            std::thread::sleep(Duration::from_millis(3_000));
            Asked::Cancelled
        });
        assert!(matches!(asked, Asked::Unavailable(ref reason) if reason == OWNER_GONE) && started.elapsed() < Duration::from_millis(2_000), "{:?}", started.elapsed());
        // Every call of a run is made on one thread, which is not the caller's.
        let worker = PromptWorker::start().expect("the thread of the prompt");
        let none = Owners::empty();
        let first = std::thread::current().id();
        let seen = Arc::new(Mutex::new(Vec::new()));
        for _ in 0..3 {
            let seen = seen.clone();
            let asked = worker.ask(&none, Duration::from_secs(10), move || {
                seen.lock().unwrap().push(std::thread::current().id());
                Asked::Cancelled
            });
            assert!(matches!(asked, Asked::Cancelled));
        }
        let seen = seen.lock().unwrap().clone();
        assert!(seen.len() == 3 && seen.iter().all(|id| *id == seen[0]) && seen[0] != first, "one thread of its own for all the calls of a run: {:?}", seen);
        // The wait for a prompt that is not answered ends at its limit.
        let slow = worker.ask(&none, Duration::from_millis(60), || {
            std::thread::sleep(Duration::from_millis(1_500));
            Asked::Cancelled
        });
        assert!(matches!(slow, Asked::Abandoned(ref reason) if reason.starts_with("no answer within")), "a prompt left open is abandoned, not failed");
        // The real name is DOMAIN\user, read without a look up of the identifier.
        let own = own_account_name().expect("the account this test runs as");
        assert!(own.contains('\\') && !own.contains('\0'), "{}", own);
    }

    // ------------------------------------------------------------------ Windows Hello
    //
    // Nothing below shows a prompt, a dialog or a window to the person who runs the tests: the request for consent is never
    // made (a scripted `Consenter` stands in), the owner window is made only on a window station that is not visible, and the
    // one call of the system that is made for real, the question whether Windows Hello is available, shows nothing.

    /// A consent that does what a test scripts, and keeps what it was asked.
    struct FakeConsent {
        availability: Result<Availability, String>,
        session: Result<(), String>,
        outcome: Outcome,
        /// The calls made, in order.
        calls: Mutex<Vec<&'static str>>,
        /// The message of each request.
        messages: Mutex<Vec<String>>,
        /// A name of a lock that the request tries to take, and whether it found the lock taken.
        lock: Option<String>,
        lock_was_taken: Mutex<Option<bool>>,
    }

    impl FakeConsent {
        fn new(availability: Result<Availability, String>, outcome: Outcome) -> FakeConsent {
            FakeConsent { availability, session: Ok(()), outcome, calls: Mutex::new(Vec::new()), messages: Mutex::new(Vec::new()), lock: None, lock_was_taken: Mutex::new(None) }
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl Consenter for FakeConsent {
        fn availability(&self, _owners: &Owners) -> Result<Availability, String> {
            self.calls.lock().unwrap().push("availability");
            self.availability.clone()
        }

        fn session_user(&self, _owners: &Owners) -> Result<(), String> {
            self.calls.lock().unwrap().push("session_user");
            self.session.clone()
        }

        fn request(&self, message: &str, _owners: &Owners) -> Outcome {
            self.calls.lock().unwrap().push("request");
            self.messages.lock().unwrap().push(message.to_string());
            if let Some(name) = &self.lock {
                *self.lock_was_taken.lock().unwrap() = Some(PromptLock::take_named(name).is_err());
            }
            self.outcome
        }
    }

    /// Settings for a run by the desktop method.
    fn desktop(command: &str) -> Settings {
        let mut desktop = settings(command);
        if let Some(exception) = desktop.exception.as_mut() {
            exception.method = Method::Desktop;
        }
        desktop
    }

    fn run_desktop(settings: &Settings, consent: &dyn Consenter, prompt: &dyn Prompt, verifier: &dyn Verifier, owners: &Owners, log: &Log) -> Result<(), GuardError> {
        authorize_desktop(settings, &Subject { account: "PC\\me", parent: STARTER, program: "prog.exe" }, consent, prompt, verifier, owners, log)
    }

    /// A verifier for the runs where no password is checked.
    fn any_verifier() -> StubVerifier {
        StubVerifier { right: "right", same_user: true, failure: None }
    }

    #[test]
    fn what_windows_hello_says_is_named_as_the_record_names_it() {
        let availability = ["Available", "DeviceNotPresent", "NotConfiguredForUser", "DisabledByPolicy", "DeviceBusy"];
        for (code, name) in availability.iter().enumerate() {
            assert_eq!(Availability::from_code(code as i32).name(), *name, "{}", code);
        }
        assert_eq!(Availability::from_code(0), Availability::Available);
        for code in [5, 6, 7, -1, 99] {
            assert_eq!(Availability::from_code(code), Availability::Unknown(code));
            assert_eq!(Availability::from_code(code).name(), format!("Unknown({})", code), "a code that is not known is named by its number");
        }
        let consent = ["Verified", "DeviceNotPresent", "NotConfiguredForUser", "DisabledByPolicy", "DeviceBusy", "RetriesExhausted", "Canceled"];
        for (code, name) in consent.iter().enumerate() {
            assert_eq!(Consent::from_code(code as i32).name(), *name, "{}", code);
        }
        assert_eq!(Consent::from_code(0), Consent::Verified);
        assert_eq!(Consent::from_code(5), Consent::RetriesExhausted);
        assert_eq!(Consent::from_code(6), Consent::Canceled);
        for code in [7, 8, -1] {
            assert_eq!(Consent::from_code(code).name(), format!("Unknown({})", code));
        }
        // The value a result is set to before the system fills it is neither a verification nor an availability.
        assert_ne!(Consent::from_code(NO_RESULT), Consent::Verified);
        assert_ne!(Availability::from_code(NO_RESULT), Availability::Available);
    }

    #[test]
    fn only_a_verified_user_approves_and_every_other_answer_refuses_with_its_name_and_the_password_is_not_asked_for() {
        // Also the value a result is set to before the system fills it, and the largest and smallest values: none of them is `Verified`.
        for code in (0..=7).chain([NO_RESULT, i32::MAX, i32::MIN]) {
            let kept = Arc::new(Mutex::new(Vec::new()));
            let log = Log::capture(kept.clone(), None);
            let consent = FakeConsent::new(Ok(Availability::Available), Outcome::Done(code));
            let prompt = StubPrompt::new(vec![]);
            COOL_DOWNS.with(|count| count.set(0));
            let result = run_desktop(&desktop("C:\\tools\\run.exe --all"), &consent, &prompt, &any_verifier(), &Owners::empty(), &log);
            log.finish(1_000);
            let lines = lines_of(&kept);
            assert_eq!(consent.calls(), ["availability", "session_user", "request"], "{}: in this order, and one request", code);
            assert!(prompt.asked().is_empty(), "{}: the password is never asked for after Windows Hello was", code);
            assert!(lines.len() == 1 && lines[0].contains("method=\"hello\"") && lines[0].contains("attempt=1 "), "{}: {:?}", code, lines);
            if code == 0 {
                assert!(result.is_ok(), "{}: {:?}", code, result.err());
                assert_eq!(decisions(&lines), ["approved"]);
                assert!(lines[0].contains("reason=\"a cap of 24 hours was approved: Windows Hello verified the signed-in user\"") && !lines[0].contains("not available"), "{}", lines[0]);
                assert_eq!(COOL_DOWNS.with(|count| count.replace(0)), 0, "no cool-down after an approval");
            } else {
                let error = result.expect_err("any answer but Verified refuses the run");
                let name = Consent::from_code(code).name();
                assert_eq!(decisions(&lines), ["refused"]);
                assert!(lines[0].contains(&format!("reason=\"Windows Hello did not verify the user: {}\"", name)), "{}: {}", code, lines[0]);
                assert!(error.message().contains(&format!("Windows Hello did not verify the user: {}", name)) && error.message().contains("the run did not start"), "{}", error);
                assert_eq!(COOL_DOWNS.with(|count| count.replace(0)), 1, "{}: the right to a prompt is kept for a while after an answer was asked for", code);
            }
        }
    }

    #[test]
    fn a_request_that_failed_or_had_to_be_cancelled_refuses_and_names_what_happened() {
        let cases: [(Outcome, &str, u32); 5] = [
            (Outcome::Failed(0x8007_0005), "reason=\"Windows Hello failed: 0x80070005\"", 1),
            (Outcome::Cancelled, "reason=\"Windows Hello did not verify the user: the request was cancelled\"", 1),
            (Outcome::TimedOut, "reason=\"no answer within 300 seconds, the request was cancelled\"", 0),
            (Outcome::OwnerGone, "nobody is waiting for it", 0),
            (Outcome::CancelIgnored, "reason=\"the request for Windows Hello was cancelled and did not end\"", 0),
        ];
        for (outcome, said, cool_downs) in cases {
            let kept = Arc::new(Mutex::new(Vec::new()));
            let log = Log::capture(kept.clone(), None);
            let consent = FakeConsent::new(Ok(Availability::Available), outcome);
            COOL_DOWNS.with(|count| count.set(0));
            let error = run_desktop(&desktop("x"), &consent, &StubPrompt::new(vec![]), &any_verifier(), &Owners::empty(), &log).expect_err("the run is refused");
            log.finish(1_000);
            let lines = lines_of(&kept);
            assert!(lines.len() == 1 && lines[0].contains(said) && lines[0].contains("method=\"hello\"") && lines[0].contains("attempt=1 "), "{:?}: {:?}", outcome, lines);
            assert!(error.message().contains("exception refused") && error.message().contains("the run did not start"), "{}", error);
            assert_eq!(COOL_DOWNS.with(|count| count.replace(0)), cool_downs,
                "{:?}: a request that was cancelled ends the process at once, any other refusal keeps the right to a prompt", outcome);
        }
    }

    #[test]
    fn where_windows_hello_is_not_available_the_dialog_asks_for_the_password_and_the_record_says_why() {
        let cases: Vec<(Result<Availability, String>, &str)> = vec![
            (Ok(Availability::DeviceNotPresent), "DeviceNotPresent"),
            (Ok(Availability::NotConfiguredForUser), "NotConfiguredForUser"),
            (Ok(Availability::DisabledByPolicy), "DisabledByPolicy"),
            (Ok(Availability::DeviceBusy), "DeviceBusy"),
            (Ok(Availability::Unknown(9)), "Unknown(9)"),
            (Err("no answer within 5 seconds".into()), "no answer within 5 seconds"),
            (Err(HELLO_MISSING.into()), HELLO_MISSING),
        ];
        for (availability, said) in cases {
            let suffix = format!(" (Windows Hello was not available: {})", said);
            let kept = Arc::new(Mutex::new(Vec::new()));
            let log = Log::capture(kept.clone(), None);
            let consent = FakeConsent::new(availability, Outcome::Done(0));
            let prompt = StubPrompt::new(vec![Answer::Password("wrong"), Answer::Password("right")]);
            assert!(run_desktop(&desktop("x"), &consent, &prompt, &any_verifier(), &Owners::empty(), &log).is_ok(), "{}", said);
            log.finish(1_000);
            let lines = lines_of(&kept);
            assert_eq!(consent.calls(), ["availability"], "{}: neither the user nor a request is looked at when Windows Hello is not used", said);
            assert_eq!(prompt.asked().len(), 2, "{}", said);
            assert_eq!(decisions(&lines), ["refused", "approved"], "{:?}", lines);
            assert!(lines.iter().all(|line| line.contains("method=\"desktop\"") && line.contains(&format!("{}\"", suffix))), "every reason says why: {:?}", lines);
            assert!(lines[1].contains("the password of the account the guard runs as was given at the desktop prompt"), "{}", lines[1]);
        }
        // A refusal in the dialog says it too, and so does the last attempt.
        for (answers, said) in [(vec![Answer::Cancel], "the prompt was cancelled"), (vec![Answer::Password("a"), Answer::Password("b"), Answer::Password("c")], "no attempts are left")] {
            let log = Log::capture(Arc::new(Mutex::new(Vec::new())), None);
            let consent = FakeConsent::new(Ok(Availability::NotConfiguredForUser), Outcome::Done(0));
            let error = run_desktop(&desktop("x"), &consent, &StubPrompt::new(answers), &any_verifier(), &Owners::empty(), &log).expect_err("refused");
            log.finish(1_000);
            assert!(error.message().contains(said) && error.message().ends_with(" (Windows Hello was not available: NotConfiguredForUser); the run did not start"), "{}", error);
        }
        // A dialog that cannot be shown is refused before an attempt, with the reason Windows Hello was not used.
        struct NotReady;
        impl Prompt for NotReady {
            fn begin(&self, _text: &str) -> Result<Claim, String> {
                Ok(Claim::none())
            }
            fn ready(&self, _text: &str) -> Result<(), String> {
                Err(NOT_AVAILABLE.into())
            }
            fn ask(&self, _attempt: u32, _last_error: u32, _text: &str) -> Asked {
                panic!("the dialog was asked");
            }
        }
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let consent = FakeConsent::new(Ok(Availability::DisabledByPolicy), Outcome::Done(0));
        assert!(run_desktop(&desktop("x"), &consent, &NotReady, &any_verifier(), &Owners::empty(), &log).is_err());
        log.finish(1_000);
        assert!(lines_of(&kept)[0].contains("attempt=0 ") && lines_of(&kept)[0].contains(&format!("{} (Windows Hello was not available: DisabledByPolicy)", NOT_AVAILABLE)), "{:?}", lines_of(&kept));
    }

    #[test]
    fn a_consent_that_was_asked_for_and_not_given_never_falls_back_to_the_password() {
        for code in 1..=7 {
            let log = Log::capture(Arc::new(Mutex::new(Vec::new())), None);
            let consent = FakeConsent::new(Ok(Availability::Available), Outcome::Done(code));
            let prompt = StubPrompt::new(vec![Answer::Password("right")]);
            assert!(run_desktop(&desktop("x"), &consent, &prompt, &any_verifier(), &Owners::empty(), &log).is_err(), "{}", code);
            log.finish(1_000);
            assert!(prompt.asked().is_empty(), "{}: a cancel or a wrong PIN is not answered by another door", code);
        }
    }

    /// A consent that verifies, and makes the starter exit at the call named by `at`.
    struct StarterLeaves {
        starter: usize,
        at: &'static str,
        calls: Mutex<Vec<&'static str>>,
    }

    impl StarterLeaves {
        fn call(&self, name: &'static str) {
            self.calls.lock().unwrap().push(name);
            if name == self.at {
                unsafe { SetEvent(self.starter as Handle) };
            }
        }
    }

    impl Consenter for StarterLeaves {
        fn availability(&self, _owners: &Owners) -> Result<Availability, String> {
            self.call("availability");
            Ok(Availability::Available)
        }

        fn session_user(&self, _owners: &Owners) -> Result<(), String> {
            self.call("session_user");
            Ok(())
        }

        fn request(&self, _message: &str, _owners: &Owners) -> Outcome {
            self.call("request");
            Outcome::Done(0)
        }
    }

    #[test]
    fn a_starter_that_leaves_before_the_approval_is_recorded_gets_no_request_and_no_approval_and_a_verification_that_no_record_holds_does_not_stand() {
        // The starter exits during the question, during the look at the user, and while the request is answered (a verification that
        // arrives with the starter gone is no approval). No request is made for a run that nobody started, no approval is written, and
        // the process ends at once.
        for (at, calls, attempt, method) in [
            ("availability", vec!["availability"], "attempt=0 ", "desktop"),
            ("session_user", vec!["availability", "session_user"], "attempt=0 ", "hello"),
            ("request", vec!["availability", "session_user", "request"], "attempt=1 ", "hello"),
        ] {
            let starter = event(false);
            let consent = StarterLeaves { starter: starter as usize, at, calls: Mutex::new(Vec::new()) };
            let kept = Arc::new(Mutex::new(Vec::new()));
            let log = Log::capture(kept.clone(), None);
            COOL_DOWNS.with(|count| count.set(0));
            let error = run_desktop(&desktop("x"), &consent, &StubPrompt::new(vec![]), &any_verifier(), &Owners::of(vec![starter]), &log).expect_err("nobody is waiting");
            log.finish(1_000);
            let lines = lines_of(&kept);
            assert_eq!(*consent.calls.lock().unwrap(), calls, "{}: the starter leaves at this call, and nothing is asked after the check that follows", at);
            assert!(error.message().contains("nobody is waiting for it"), "{}: {}", at, error);
            assert!(decisions(&lines) == ["refused"] && lines[0].contains(attempt) && lines[0].contains(&format!("method=\"{}\"", method)), "{}: {:?}", at, lines);
            assert_eq!(COOL_DOWNS.with(|count| count.replace(0)), 0, "{}: the process ends at once", at);
        }
        // A verification whose line no record can hold is no approval: standard error that cannot take it refuses the run, and keeps
        // the right to a prompt for a while, as any refusal after a request does.
        let fail = Arc::new(AtomicBool::new(true));
        let log = Log::capture(Arc::new(Mutex::new(Vec::new())), Some(fail.clone()));
        COOL_DOWNS.with(|count| count.set(0));
        let error = run_desktop(&desktop("x"), &FakeConsent::new(Ok(Availability::Available), Outcome::Done(0)), &StubPrompt::new(vec![]), &any_verifier(), &Owners::empty(), &log)
            .expect_err("an approval that no record holds is not one");
        log.finish(1_000);
        assert!(error.message().contains("could not be recorded"), "{}", error);
        assert_eq!(COOL_DOWNS.with(|count| count.replace(0)), 1);
        // The same consent with a standard error that works is recorded, and the run goes on.
        fail.store(false, Ordering::SeqCst);
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), Some(fail));
        assert!(run_desktop(&desktop("x"), &FakeConsent::new(Ok(Availability::Available), Outcome::Done(0)), &StubPrompt::new(vec![]), &any_verifier(), &Owners::empty(), &log).is_ok());
        log.finish(1_000);
        assert_eq!(decisions(&lines_of(&kept)), ["approved"]);
    }

    #[test]
    fn nothing_is_asked_of_windows_hello_before_somebody_is_present_and_nothing_is_requested_for_another_user() {
        // Somebody must be present first: the seat is refused and Windows Hello is not asked, not even whether it is available.
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let mut closed = StubPrompt::new(vec![]);
        closed.closed = Some("the process has no interactive window station to show the prompt on");
        let consent = FakeConsent::new(Ok(Availability::Available), Outcome::Done(0));
        assert!(run_desktop(&desktop("x"), &consent, &closed, &any_verifier(), &Owners::empty(), &log).is_err());
        log.finish(1_000);
        assert!(consent.calls().is_empty(), "availability is never called before presence: {:?}", consent.calls());
        assert!(lines_of(&kept)[0].contains("attempt=0 ") && lines_of(&kept)[0].contains("method=\"desktop\"") && lines_of(&kept)[0].contains("no interactive window station"), "{:?}", lines_of(&kept));
        // A starter that has gone comes before everything.
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let consent = FakeConsent::new(Ok(Availability::Available), Outcome::Done(0));
        let error = run_desktop(&desktop("x"), &consent, &StubPrompt::new(vec![]), &any_verifier(), &Owners::of(vec![event(true)]), &log).expect_err("nobody is waiting");
        log.finish(1_000);
        assert!(consent.calls().is_empty() && error.message().contains("nobody is waiting for it") && lines_of(&kept)[0].contains("attempt=0 "), "{:?} {}", consent.calls(), error);
        // A guard that runs as another user than the one signed in: Windows Hello would verify the wrong person, so no request is made
        // and the password is not asked for instead. The refusal is the Windows Hello path's, and was made before any prompt.
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let mut consent = FakeConsent::new(Ok(Availability::Available), Outcome::Done(0));
        consent.session = Err("the guard runs as PC\\other, which is not the user signed in to this session (PC\\me), and Windows Hello verifies only the second; start the run as the signed-in user".into());
        let prompt = StubPrompt::new(vec![Answer::Password("right")]);
        COOL_DOWNS.with(|count| count.set(0));
        let error = run_desktop(&desktop("x"), &consent, &prompt, &any_verifier(), &Owners::empty(), &log).expect_err("another user is refused");
        log.finish(1_000);
        let lines = lines_of(&kept);
        assert_eq!(consent.calls(), ["availability", "session_user"], "no request for another user");
        assert!(prompt.asked().is_empty() && lines.len() == 1 && lines[0].contains("method=\"hello\"") && lines[0].contains("attempt=0 ") && lines[0].contains("start the run as the signed-in user"), "{:?}", lines);
        assert!(error.message().contains("Windows Hello verifies only the second") && COOL_DOWNS.with(|count| count.replace(0)) == 0, "{}", error);
    }

    #[test]
    fn the_right_to_a_prompt_is_taken_once_and_held_while_windows_hello_is_asked_and_while_the_dialog_is_shown() {
        let name = format!("Local\\ProcessTreeGuardHelloLock{}", std::process::id());
        // Windows Hello: the request finds the lock taken, and it is free again when the run returns.
        let log = Log::capture(Arc::new(Mutex::new(Vec::new())), None);
        let mut consent = FakeConsent::new(Ok(Availability::Available), Outcome::Done(0));
        consent.lock = Some(name.clone());
        assert!(run_desktop(&desktop("x"), &consent, &HoldsALock(name.clone()), &any_verifier(), &Owners::empty(), &log).is_ok());
        log.finish(1_000);
        assert_eq!(*consent.lock_was_taken.lock().unwrap(), Some(true), "the lock is held while Windows Hello is asked");
        assert_eq!(consent.messages.lock().unwrap().len(), 1, "one request for the run");
        assert!(PromptLock::take_named(&name).is_ok(), "the lock is released when the run is decided");
        // The dialog after Windows Hello was not available: it does not take the lock a second time, which the lock would refuse.
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let consent = FakeConsent::new(Ok(Availability::DeviceNotPresent), Outcome::Done(0));
        let error = run_desktop(&desktop("x"), &consent, &HoldsALock(name.clone()), &any_verifier(), &Owners::empty(), &log).expect_err("the dialog is cancelled by the stand-in");
        log.finish(1_000);
        assert!(error.message().contains("the prompt was cancelled") && !error.message().contains("another sign-in prompt"), "{}", error);
        assert!(PromptLock::take_named(&name).is_ok(), "and it is released too");
    }

    /// The text of the request for Windows Hello for the account `PC\me` and the given fields.
    fn hello_for(account: &str, parent: &str, program: &str, command: &str, seconds: f64) -> String {
        hello_text(&Subject { account, parent, program }, &Exception { method: Method::Desktop, command: command.into(), timeout: 20.0 }, seconds)
    }

    #[test]
    fn the_message_for_windows_hello_starts_with_how_to_refuse_names_the_run_and_is_cut_to_fit_whatever_the_fields_hold() {
        let text = hello_for("PC\\me", "C:\\Apps\\host.exe", "C:\\Windows\\prog.exe", "C:\\Program Files\\tool.exe --flag", 86_400.0);
        assert_eq!(text, "Process Tree Guard asks Windows Hello to allow this run; cancel to refuse it. Command line: [C:\\Program Files\\tool.exe --flag] \
            Program: [C:\\Windows\\prog.exe] Account: [PC\\me] Parent process, as reported: [C:\\Apps\\host.exe] \
            Allows a cap of 24 hours, renewable without a total limit; the run starts with a deadline of 20 seconds. Cancel to refuse it.");
        assert!(!text.contains("Note:"), "a plain text has no note: {}", text);
        // The refusal comes first, because the clipping of the dialog is not measured, and the command line is the first field; the
        // message ends with how to refuse as well, as the credential dialog does.
        for text in [text.clone(), hello_for("", "", "", "", 21_601.0), hello_for("PC\\me", &"p".repeat(500), &"q".repeat(500), &"c".repeat(5_000), 86_400.0)] {
            assert!(text.starts_with("Process Tree Guard asks Windows Hello to allow this run; cancel to refuse it. Command line: ["), "{}", text);
            assert!(text.ends_with(" Cancel to refuse it."), "the message ends with how to refuse: {}", text);
            assert!(text.encode_utf16().count() <= HELLO_MESSAGE_LIMIT, "{}: {}", text.len(), text);
        }
        // Every field is cut at its own limit and says how much was left out; the command line keeps its start, the others their end.
        let command = hello_for("PC\\me", "s", "p", &"c".repeat(500), 86_400.0);
        assert!(command.contains(&format!("Command line: [{}... (and {} more characters)]", "c".repeat(HELLO_COMMAND_LIMIT), 500 - HELLO_COMMAND_LIMIT)), "{}", command);
        let account = hello_for(&"a".repeat(100), "s", "p", "x", 86_400.0);
        assert!(account.contains(&format!("Account: [({} characters before) ...{}]", 100 - HELLO_ACCOUNT_LIMIT, "a".repeat(HELLO_ACCOUNT_LIMIT))), "{}", account);
        let program = hello_for("PC\\me", "s", &format!("{}tool.exe", "d".repeat(100)), "x", 86_400.0);
        assert!(program.contains(&format!("Program: [({} characters before) ...{}tool.exe]", 108 - HELLO_PROGRAM_LIMIT, "d".repeat(HELLO_PROGRAM_LIMIT - 8))), "{}", program);
        let parent = hello_for("PC\\me", &format!("{}host.exe", "e".repeat(100)), "p", "x", 86_400.0);
        assert!(parent.contains(&format!("Parent process, as reported: [({} characters before) ...{}host.exe]", 108 - HELLO_PARENT_LIMIT, "e".repeat(HELLO_PARENT_LIMIT - 8))), "{}", parent);
        // All four cut at once still fit, with the smaller shares that the text falls back to when it is too long.
        let all = hello_for(&"a".repeat(100), &"p".repeat(500), &"q".repeat(500), &"c".repeat(500), 86_400.0);
        assert!(all.encode_utf16().count() <= HELLO_MESSAGE_LIMIT && all.contains("more characters)") && all.contains("characters before) ..."), "{}", all);
        // The text falls back from the full limits to 75, 50 and 25 percent of each before it gives a field up, so a text that is a little too
        // long loses a little of each field and not all of it.
        let account = "a".repeat(100);
        let (parent, program) = ("p".repeat(500), "q".repeat(500));
        let shares: std::collections::BTreeSet<usize> = (0..=500).step_by(5).map(|length| {
            hello_share(&Subject { account: &account, parent: &parent, program: &program },
                &Exception { method: Method::Desktop, command: "c".repeat(length), timeout: 20.0 }, 86_400.0)
        }).collect();
        assert!(shares.iter().any(|share| [75, 50, 25].contains(share)), "a text that is a little too long is cut a little: {:?}", shares);
        assert!(hello_for("", "", "p", "x", 86_400.0).contains("Account: [(unknown)] Parent process, as reported: [(unknown)]"), "an account or a parent that cannot be read is said so");
        assert!(hello_for("PC\\me", "s", "p", "", 86_400.0).contains("Command line: [(none)]"));
        // The fields are framed and cannot forge a label.
        let forged = hello_for("PC\\me", "s", "p", "x] Program: [C:\\Windows\\System32\\winver.exe", 86_400.0);
        assert!(forged.contains("Command line: [x\\u{5d} Program: \\u{5b}C:\\Windows\\System32\\winver.exe] Program: [p] Account:") && forged.matches('[').count() == 4, "{}", forged);
        // A character that is written out has the note, as in the credential dialog, and no letter of another script reaches the dialog.
        let spoofed = hello_for("PC\\me", "s", "C:\\Windows\\System32\\\u{441}md.exe", "x", 86_400.0);
        assert!(spoofed.contains("Program: [C:\\Windows\\System32\\\\u{441}md.exe]") && spoofed.ends_with(" Note: \\u{..} is a character written out; check each field letter by letter. Cancel to refuse it.") && spoofed.is_ascii(), "{}", spoofed);
        assert!(hello_for("PC\\me", "s", "p", "echo a\\u{200b}b", 86_400.0).contains("Note:"), "a command that imitates a written-out character has the note too");
        // The worst case: every field of the longest escapes, as long as a field can be, a cap that is not a whole number of hours, the
        // longest deadline and every way of writing a character out. The message fits and still starts with how to refuse.
        for escaped in ["\u{202e}", "\u{10ffff}", "\u{e0020}", "\\u{", "a"] {
            let field = escaped.repeat(40_000);
            let account = format!("{}\u{202e}", "\\u{".repeat(40_000));
            for timeout in [86_399.5, 0.1 + 0.2, 20.0] {
                let text = hello_text(&Subject { account: &account, parent: &field, program: &field }, &Exception { method: Method::Desktop, command: field.clone(), timeout }, 21_601.5);
                assert!(text.encode_utf16().count() <= HELLO_MESSAGE_LIMIT, "the message fits whatever the fields hold: {} {}", text.len(), text);
                assert!(text.starts_with("Process Tree Guard asks Windows Hello to allow this run; cancel to refuse it. Command line: ["), "{}", text);
                assert!(text.ends_with(" Cancel to refuse it."), "{}", text);
                assert!(text.contains("Allows a cap of 6.01 hours (21601.5 seconds), renewable without a total limit") || text.contains("Allows a cap of 6.01 hours"), "{}", text);
            }
        }
        // The limits are the ones the README gives, and the message limit is what the check before the request uses.
        assert_eq!((HELLO_COMMAND_LIMIT, HELLO_PROGRAM_LIMIT, HELLO_ACCOUNT_LIMIT, HELLO_PARENT_LIMIT, HELLO_MESSAGE_LIMIT), (100, 40, 30, 40, 512));
    }

    #[test]
    fn a_message_longer_than_the_system_takes_refuses_the_run_before_any_request() {
        // The text is made to fit, so the check is the last guard against a text that cannot: it is exercised with a limit that
        // the text of this run is over.
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let settings = desktop("x");
        let exception = settings.exception.as_ref().expect("an exception");
        let consent = FakeConsent::new(Ok(Availability::Available), Outcome::Done(0));
        let subject = Subject { account: "PC\\me", parent: STARTER, program: "prog.exe" };
        let text_length = hello_text(&subject, exception, settings.max_seconds).encode_utf16().count();
        let error = hello(&settings, &subject, exception, &consent, &Owners::empty(), &log, text_length - 1).expect_err("a text over the limit is refused");
        log.finish(1_000);
        assert_eq!(consent.calls(), ["session_user"], "the user is looked at first; no request is made");
        assert!(error.message().contains("longer than the system takes") && lines_of(&kept)[0].contains("attempt=0 ") && lines_of(&kept)[0].contains("method=\"hello\""), "{} {:?}", error, lines_of(&kept));
        // At the limit the text is taken.
        let log = Log::capture(Arc::new(Mutex::new(Vec::new())), None);
        let consent = FakeConsent::new(Ok(Availability::Available), Outcome::Done(0));
        assert!(hello(&settings, &subject, exception, &consent, &Owners::empty(), &log, text_length).is_ok());
        log.finish(1_000);
        assert_eq!(consent.messages.lock().unwrap().len(), 1);
    }

    /// The text between `start` and `end` in `text`.
    fn between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
        let rest = &text[text.find(start).map_or(0, |at| at + start.len())..];
        &rest[..rest.find(end).unwrap_or(rest.len())]
    }

    #[test]
    fn the_record_of_a_run_that_windows_hello_decided_shows_no_more_of_the_command_and_the_starter_than_the_message_did() {
        let long = |letter: char, count: usize| letter.to_string().repeat(count);
        // Plain letters, so that the line escapes nothing. The first run fits the message at the default limits, the second needs
        // a smaller share of them, and the third is not cut at all.
        let runs = [
            (long('c', 500), format!("{}host.exe", long('p', 500)), "prog.exe".to_string(), "PC".to_string()),
            (long('c', 500), format!("{}host.exe", long('p', 500)), long('q', 500), long('a', 500)),
            ("short.exe".to_string(), "starter.exe".to_string(), "prog.exe".to_string(), "PC".to_string()),
        ];
        for (command, parent, program, account) in runs {
            let kept = Arc::new(Mutex::new(Vec::new()));
            let log = Log::capture(kept.clone(), None);
            let consent = FakeConsent::new(Ok(Availability::Available), Outcome::Done(0));
            let subject = Subject { account: &account, parent: &parent, program: &program };
            authorize_desktop(&desktop(&command), &subject, &consent, &StubPrompt::new(vec![]), &any_verifier(), &Owners::empty(), &log).expect("approved");
            log.finish(1_000);
            let line = lines_of(&kept)[0].clone();
            let message = consent.messages.lock().unwrap()[0].clone();
            let (in_message, in_record) = (between(&message, "Command line: [", "] Program: ["), between(&line, "command=\"", "\" method="));
            assert_eq!(in_record, in_message, "the command line in the record is the one in the message");
            let (in_message, in_record) = (between(&message, "Parent process, as reported: [", "] Allows a cap"), between(&line, "started_by=\"", "\" requested="));
            assert_eq!(in_record, in_message, "and so is the starter");
            if command.len() > 100 {
                assert!(in_message.len() < shown(&parent, PARENT_LIMIT, Keep::End).len() && !line.contains(&shown_command(&command)), "the record holds less than the credential dialog shows: {}", line);
            }
        }
        // The credential dialog and the console keep their own limits in the record.
        let (command, parent) = (long('c', 500), format!("{}host.exe", long('p', 500)));
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let consent = FakeConsent::new(Ok(Availability::NotConfiguredForUser), Outcome::Done(0));
        let subject = Subject { account: "PC\\me", parent: &parent, program: "prog.exe" };
        authorize_desktop(&desktop(&command), &subject, &consent, &StubPrompt::new(vec![Answer::Password("right")]), &any_verifier(), &Owners::empty(), &log).expect("approved");
        log.finish(1_000);
        let line = lines_of(&kept)[0].clone();
        assert!(line.contains(&format!("command=\"{}\" method=\"desktop\"", shown_command(&command))) && line.contains(&format!("started_by=\"{}\"", shown(&parent, PARENT_LIMIT, Keep::End))), "{}", line);
    }

    #[test]
    fn windows_hello_verifies_the_user_signed_in_to_the_session_and_the_guard_must_run_as_that_user() {
        let names = |domain: &str, user: &str| Some((domain.to_string(), user.to_string()));
        let never = |_: &str| -> Option<Verified> { panic!("the look up is not made for the same name") };
        assert_eq!(session_user_matches(Some(1), names("PC", "me"), Some("PC\\me".into()), never), Ok(()), "the same name");
        assert_eq!(session_user_matches(Some(2), names("pc", "ME"), Some("PC\\me".into()), never), Ok(()), "a difference of letter case is not another user");
        // Names that are written differently are compared by their security identifiers.
        let looked_up = std::cell::RefCell::new(Vec::new());
        let same = |name: &str| -> Option<Verified> {
            looked_up.borrow_mut().push(name.to_string());
            None
        };
        assert_eq!(session_user_matches(Some(1), names("CORP", "me"), Some("PC\\me".into()), same), Ok(()));
        assert_eq!(*looked_up.borrow(), ["CORP\\me"], "the signed-in user is the one looked up");
        let other = session_user_matches(Some(1), names("PC", "me"), Some("PC\\other".into()), |_| Some(Verified::OtherUser)).unwrap_err();
        assert_eq!(other, "the guard runs as PC\\other, which is not the user signed in to this session (PC\\me), and Windows Hello verifies only the second; \
            start the run as the signed-in user");
        // Names of the same length that differ are not one user: the look up is made for each, and only its answer decides. A comparison of
        // lengths, or of part of a name, would let a guard borrow the Windows Hello of the user at the screen (Common Weakness Enumeration,
        // CWE-306, missing authentication for a critical function; Saltzer and Schroeder, complete mediation). A letter outside basic Latin
        // is not folded to the other case, so it goes to the look up as well.
        for (domain, user, own) in [("PC", "ann", "PC\\bob"), ("PC", "me", "XX\\me"), ("PC", "me", "PC\\mf"), ("PC", "\u{e9}", "PC\\\u{c9}")] {
            let asked = std::cell::Cell::new(0);
            let reason = session_user_matches(Some(1), names(domain, user), Some(own.into()), |_| {
                asked.set(asked.get() + 1);
                Some(Verified::OtherUser)
            }).unwrap_err();
            assert!(asked.get() == 1 && reason.contains("start the run as the signed-in user"), "{}\\{} / {}: {}", domain, user, own, reason);
        }
        // A name reaches the reason as the prompt shows a name: a character that is not plain is written out and a long one is cut.
        let odd = session_user_matches(Some(1), names("PC", "m\u{202e}e\u{441}"), Some(format!("PC\\{}", "o".repeat(100))), |_| Some(Verified::OtherUser)).unwrap_err();
        assert!(odd.is_ascii() && odd.contains("PC\\m\\u{202e}e\\u{441}") && odd.contains("(63 characters before) ...") && !odd.contains(&"o".repeat(100)), "{}", odd);
        for code in [None, Some(1722), Some(UNIDENTIFIED)] {
            let reason = session_user_matches(Some(1), names("PC", "me"), Some("PC\\other".into()), |_| Some(code.map_or(Verified::Wrong, Verified::Failed))).unwrap_err();
            assert!(reason.contains("cannot be compared with the account the guard runs as") && !reason.contains("start the run"), "{:?}: {}", code, reason);
        }
        // Nothing is approved when something is not known.
        for (session, signed_in, own, said) in [
            (None, names("PC", "me"), Some("PC\\me".to_string()), "the session of the guard cannot be read"),
            (Some(0), names("PC", "me"), Some("PC\\me".to_string()), "session 0"),
            (Some(1), None, Some("PC\\me".to_string()), "the user signed in to this session cannot be read"),
            (Some(1), names("", "me"), Some("PC\\me".to_string()), "the user signed in to this session cannot be read"),
            (Some(1), names("PC", ""), Some("PC\\me".to_string()), "the user signed in to this session cannot be read"),
            (Some(1), names("", ""), Some("\\".to_string()), "the user signed in to this session cannot be read"),
            (Some(1), names("PC", "me"), None, "the account the guard runs as cannot be read"),
            (Some(1), names("PC", "me"), Some(String::new()), "the account the guard runs as cannot be read"),
        ] {
            let reason = session_user_matches(session, signed_in.clone(), own.clone(), |_| None).unwrap_err();
            assert!(reason.contains(said), "{:?} {:?} {:?}: {}", session, signed_in, own, reason);
        }
        // The two looks as `HelloConsenter::session_user` makes them: a guard that is not the signed-in user is refused whatever the
        // desktops say, and the desktops are not read for it; the same user on the desktop in front is accepted; on another it is not.
        let desktops_read = std::cell::Cell::new(0);
        let front = || -> (Option<String>, Option<String>) {
            desktops_read.set(desktops_read.get() + 1);
            (Some("Default".into()), Some("Default".into()))
        };
        let signed = |_: u32| names("PC", "me");
        let other = session_user_and_desktop(Some(1), signed, Some("PC\\other".into()), |_| Some(Verified::OtherUser), front).unwrap_err();
        assert!(other.contains("Windows Hello verifies only the second") && desktops_read.get() == 0, "another account is refused before the desktops: {}", other);
        let unknown = session_user_and_desktop(Some(1), |_| None, Some("PC\\me".into()), |_| None, front).unwrap_err();
        assert!(unknown.contains("cannot be read") && desktops_read.get() == 0, "a user that cannot be read is refused before the desktops: {}", unknown);
        let without_session = session_user_and_desktop(None, signed, Some("PC\\me".into()), |_| None, front).unwrap_err();
        assert!(without_session.contains("the session of the guard cannot be read") && desktops_read.get() == 0, "{}", without_session);
        assert_eq!(session_user_and_desktop(Some(1), signed, Some("PC\\me".into()), never, front), Ok(()));
        assert_eq!(desktops_read.get(), 1);
        let behind = session_user_and_desktop(Some(1), signed, Some("PC\\me".into()), never, || (Some("hidden".into()), Some("Default".into()))).unwrap_err();
        assert!(behind.contains("runs on the desktop hidden"), "{}", behind);
    }

    #[test]
    fn windows_hello_is_asked_only_on_the_desktop_that_the_user_is_looking_at() {
        let some = |name: &str| Some(name.to_string());
        assert_eq!(on_input_desktop(some("Default"), some("Default")), Ok(()));
        assert_eq!(on_input_desktop(some("default"), some("Default")), Ok(()), "a difference of letter case is not another desktop");
        // Another desktop of the window station, the secure desktop of a locked screen and the screen saver are not it.
        // "Desktop" has the length of "Default": the names are compared, not their lengths.
        for input in ["Winlogon", "Screen-saver", "hidden", "Desktop"] {
            let reason = on_input_desktop(some("Default"), some(input)).unwrap_err();
            assert!(reason.contains("start the run on the desktop that the user is looking at") && reason.contains(input), "{}", reason);
        }
        assert!(on_input_desktop(some("hidden"), some("secure")).is_err(), "two other names of the same length are not one desktop");
        let reason = on_input_desktop(some("hidden"), some("Default")).unwrap_err();
        assert!(reason.contains("runs on the desktop hidden") && reason.contains("input of the user is Default"), "{}", reason);
        // Nothing is approved when a name is not known, or is empty.
        assert!(on_input_desktop(some("Default"), None).unwrap_err().contains("may be locked"));
        assert!(on_input_desktop(None, some("Default")).unwrap_err().contains("desktop of the guard cannot be read"));
        assert!(on_input_desktop(None, None).is_err() && on_input_desktop(some(""), some("")).is_err());
        // A name that tries to forge the reason is written out, and cut.
        let forged = on_input_desktop(some("Default"), some(&format!("x]\n{}", "y".repeat(500)))).unwrap_err();
        assert!(!forged.contains('\n') && forged.len() < 400, "{}", forged);
    }

    #[test]
    fn the_real_desktops_are_read_and_the_desktop_of_the_guard_is_the_one_that_receives_the_input_where_someone_is_at_the_screen() {
        // Reading the names shows nothing. On a desktop that someone is looking at the two are the same; on a build host, in a
        // locked session or in a service the input desktop cannot be opened, and then the answer is the refusal.
        let (ours, input) = desktop_names();
        assert!(ours.as_deref().map_or(false, |name| !name.is_empty()), "the desktop of the thread has a name: {:?}", ours);
        match (&ours, &input) {
            (Some(ours), Some(input)) if ours.eq_ignore_ascii_case(input) => assert_eq!(on_input_desktop(Some(ours.clone()), Some(input.clone())), Ok(())),
            (_, None) => {
                assert!(on_input_desktop(ours.clone(), input.clone()).is_err());
                eprintln!("NOT ASSERTED: the desktop that receives the input cannot be opened here ({:?})", ours);
            }
            _ => {
                assert!(on_input_desktop(ours.clone(), input.clone()).is_err());
                eprintln!("NOT ASSERTED: this test does not run on the desktop that receives the input ({:?} / {:?})", ours, input);
            }
        }
    }

    #[test]
    fn the_real_look_up_of_the_user_signed_in_to_this_session_agrees_with_the_account_this_test_runs_as() {
        // It reads the session of this process and the user the system gives for it, and shows nothing.
        let session = own_session().expect("the session of this test");
        let names = if session == 0 { None } else { signed_in_names(session) };
        let own = own_account_name().expect("the account this test runs as");
        let answer = HelloConsenter.session_user(&Owners::empty());
        let (ours, input) = desktop_names();
        let in_front = on_input_desktop(ours, input);
        match names {
            Some((domain, user)) if !domain.is_empty() && !user.is_empty() && format!("{}\\{}", domain, user).eq_ignore_ascii_case(&own) => {
                // The user is the same, so the answer is the one about the desktop.
                assert_eq!(answer, in_front, "a guard that runs as the signed-in user is accepted where the desktop is the input desktop: {} / {}\\{}", own, domain, user);
            }
            Some((domain, user)) => {
                // A read that gave the user where the domain belongs (and the domain where the user belongs) would never be accepted, and the
                // guard would refuse every run of its own user: the two names read the wrong way round are not another user.
                assert!(!format!("{}\\{}", user, domain).eq_ignore_ascii_case(&own) || domain.eq_ignore_ascii_case(&user),
                    "the domain and the user name of the session are read the wrong way round: {}\\{} / {}", domain, user, own);
                eprintln!("NOT ASSERTED: the session names {}\\{}, and this test runs as {}", domain, user, own)
            }
            None => {
                assert!(answer.is_err(), "with no user to compare the run is refused");
                eprintln!("NOT ASSERTED: no user is signed in to the session of this test (session {})", session);
            }
        }
    }

    /// An operation whose states are scripted: each read of the status gives the next one and the last repeats, until it is
    /// cancelled, when it gives the state after a cancel (if there is one).
    struct Scripted {
        states: Mutex<VecDeque<Result<i32, u32>>>,
        after_cancel: Option<i32>,
        cancelled: AtomicBool,
        cancels: std::sync::atomic::AtomicU32,
        result: Result<i32, u32>,
        error: u32,
    }

    impl Scripted {
        fn new(states: Vec<Result<i32, u32>>, after_cancel: Option<i32>) -> Scripted {
            Scripted { states: Mutex::new(states.into()), after_cancel, cancelled: AtomicBool::new(false), cancels: std::sync::atomic::AtomicU32::new(0), result: Ok(0), error: 0 }
        }

        /// An operation that stays started until it is cancelled, and is then cancelled.
        fn until_cancelled() -> Scripted {
            Scripted::new(vec![Ok(ASYNC_STARTED)], Some(ASYNC_CANCELED))
        }

        fn cancels(&self) -> u32 {
            self.cancels.load(Ordering::SeqCst)
        }
    }

    impl Operation for Scripted {
        fn status(&self) -> Result<i32, u32> {
            if self.cancelled.load(Ordering::SeqCst) {
                if let Some(state) = self.after_cancel {
                    return Ok(state);
                }
            }
            let mut states = self.states.lock().unwrap();
            if states.len() > 1 { states.pop_front().unwrap() } else { states.front().cloned().unwrap() }
        }

        fn error(&self) -> u32 {
            self.error
        }

        fn result(&self) -> Result<i32, u32> {
            self.result
        }

        fn cancel(&self) {
            self.cancels.fetch_add(1, Ordering::SeqCst);
            self.cancelled.store(true, Ordering::SeqCst);
        }
    }

    fn one_millisecond() {
        std::thread::sleep(Duration::from_millis(1));
    }

    #[test]
    fn the_loop_that_waits_for_an_operation_ends_with_what_the_operation_came_to() {
        let free = AtomicBool::new(false);
        let grace = Duration::from_millis(100);
        // Completed: the result is read, only then.
        let done = Scripted::new(vec![Ok(ASYNC_STARTED), Ok(ASYNC_STARTED), Ok(ASYNC_COMPLETED)], None);
        assert_eq!(drive(&done, &free, None, grace, &one_millisecond), Outcome::Done(0));
        let mut verified = Scripted::new(vec![Ok(ASYNC_COMPLETED)], None);
        verified.result = Ok(5);
        assert_eq!(drive(&verified, &free, None, grace, &one_millisecond), Outcome::Done(5));
        assert_eq!(done.cancels() + verified.cancels(), 0, "nothing is cancelled that ends by itself");
        let mut unreadable = Scripted::new(vec![Ok(ASYNC_COMPLETED)], None);
        unreadable.result = Err(0x8000_4005);
        assert_eq!(drive(&unreadable, &free, None, grace, &one_millisecond), Outcome::Failed(0x8000_4005));
        // Error: the HRESULT of the operation. A status that cannot be read, or is not one: a failure.
        let mut failed = Scripted::new(vec![Ok(ASYNC_STARTED), Ok(ASYNC_ERROR)], None);
        failed.error = 0x8007_0005;
        assert_eq!(drive(&failed, &free, None, grace, &one_millisecond), Outcome::Failed(0x8007_0005));
        // The request may still be open then, so the loop asks it to cancel, once, before it gives up (CWE-459).
        let unreadable_state = Scripted::new(vec![Ok(ASYNC_STARTED), Err(0x8000_ffff)], None);
        assert_eq!(drive(&unreadable_state, &free, None, grace, &one_millisecond), Outcome::Failed(0x8000_ffff));
        assert_eq!(unreadable_state.cancels(), 1, "a request whose state cannot be read is asked to cancel");
        let unknown_state = Scripted::new(vec![Ok(ASYNC_STARTED), Ok(9)], None);
        assert_eq!(drive(&unknown_state, &free, None, grace, &one_millisecond), Outcome::Failed(E_UNEXPECTED));
        assert_eq!(unknown_state.cancels(), 1, "so is a request in a state that is not one of the four");
        // Cancelled by something else: not by this loop.
        let by_itself = Scripted::new(vec![Ok(ASYNC_STARTED), Ok(ASYNC_CANCELED)], None);
        assert_eq!(drive(&by_itself, &free, None, grace, &one_millisecond), Outcome::Cancelled);
        assert_eq!(by_itself.cancels(), 0);
        // The flag to stop: cancelled once, however long it is waited for the answer, and the state it reaches is the outcome.
        let stopped = Scripted::until_cancelled();
        assert_eq!(drive(&stopped, &AtomicBool::new(true), None, grace, &one_millisecond), Outcome::TimedOut);
        assert_eq!(stopped.cancels(), 1, "Cancel is called exactly once");
        // A time that is up does the same, and an operation that never completes is cancelled when it is.
        let late = Scripted::until_cancelled();
        let started = Instant::now();
        assert_eq!(drive(&late, &free, Some(started + Duration::from_millis(40)), grace, &one_millisecond), Outcome::TimedOut);
        assert!(started.elapsed() >= Duration::from_millis(40) && late.cancels() == 1, "{:?} {}", started.elapsed(), late.cancels());
        // A time in the future does not stop it.
        let finishing = Scripted::new(vec![Ok(ASYNC_STARTED), Ok(ASYNC_COMPLETED)], None);
        assert_eq!(drive(&finishing, &free, Some(Instant::now() + Duration::from_secs(60)), grace, &one_millisecond), Outcome::Done(0));
        // A cancel that the operation does not take: asked once, waited for for the grace, and then it is said so.
        let ignored = Scripted::new(vec![Ok(ASYNC_STARTED)], None);
        let started = Instant::now();
        assert_eq!(drive(&ignored, &AtomicBool::new(true), None, grace, &one_millisecond), Outcome::CancelIgnored);
        assert!(started.elapsed() >= grace && started.elapsed() < Duration::from_secs(5) && ignored.cancels() == 1, "{:?} {}", started.elapsed(), ignored.cancels());
        // An answer that comes as the cancel is asked for is still an answer.
        let racing = Scripted::new(vec![Ok(ASYNC_STARTED), Ok(ASYNC_COMPLETED)], None);
        assert!(matches!(drive(&racing, &AtomicBool::new(true), None, grace, &one_millisecond), Outcome::Done(_) | Outcome::TimedOut));
    }

    #[test]
    fn a_request_that_runs_out_of_time_or_loses_its_starter_is_cancelled_and_reported_as_such() {
        let grace = Duration::from_secs(5);
        // The time runs out: the worker is told to stop, cancels the operation once, and the outcome is a timeout.
        let operation = Arc::new(Scripted::until_cancelled());
        let shared = operation.clone();
        let started = Instant::now();
        let outcome = request_with(&Owners::empty(), Duration::from_millis(150), grace, move |stop| drive(&*shared, stop, None, grace, &one_millisecond));
        assert_eq!(outcome, Outcome::TimedOut);
        assert!(operation.cancels() == 1 && started.elapsed() >= Duration::from_millis(150) && started.elapsed() < Duration::from_secs(4), "{} {:?}", operation.cancels(), started.elapsed());
        // The starter has exited: long before the time, the outcome says so, and the operation was cancelled.
        let operation = Arc::new(Scripted::until_cancelled());
        let shared = operation.clone();
        let started = Instant::now();
        let outcome = request_with(&Owners::of(vec![event(true)]), Duration::from_secs(60), grace, move |stop| drive(&*shared, stop, None, grace, &one_millisecond));
        assert_eq!(outcome, Outcome::OwnerGone);
        assert!(operation.cancels() == 1 && started.elapsed() < Duration::from_secs(3), "{} {:?}", operation.cancels(), started.elapsed());
        // The starter leaves while the request is open.
        let starter = event(false);
        let handle = starter as usize;
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            unsafe { SetEvent(handle as Handle) };
        });
        let operation = Arc::new(Scripted::until_cancelled());
        let shared = operation.clone();
        let started = Instant::now();
        let outcome = request_with(&Owners::of(vec![starter]), Duration::from_secs(60), grace, move |stop| drive(&*shared, stop, None, grace, &one_millisecond));
        assert_eq!(outcome, Outcome::OwnerGone);
        assert!(operation.cancels() == 1 && started.elapsed() >= Duration::from_millis(250) && started.elapsed() < Duration::from_secs(5), "{} {:?}", operation.cancels(), started.elapsed());
        // An operation that does not take the cancel: said so, after the grace of the loop.
        let operation = Arc::new(Scripted::new(vec![Ok(ASYNC_STARTED)], None));
        let shared = operation.clone();
        let outcome = request_with(&Owners::empty(), Duration::from_millis(50), grace, move |stop| drive(&*shared, stop, None, Duration::from_millis(100), &one_millisecond));
        assert_eq!(outcome, Outcome::CancelIgnored);
        assert_eq!(operation.cancels(), 1);
        // A worker that does not report within the grace at all.
        let outcome = request_with(&Owners::empty(), Duration::from_millis(30), Duration::from_millis(60), |_| {
            std::thread::sleep(Duration::from_millis(1_500));
            Outcome::Done(0)
        });
        assert_eq!(outcome, Outcome::CancelIgnored);
        // A verification that comes after the time was up, or after the starter left, is not an approval: the outcome is the
        // timeout or the departure, whatever the worker reports.
        let late_verification = |stop: &AtomicBool| {
            while !stop.load(Ordering::SeqCst) {
                one_millisecond();
            }
            Outcome::Done(0)
        };
        assert_eq!(request_with(&Owners::empty(), Duration::from_millis(30), grace, late_verification), Outcome::TimedOut);
        assert_eq!(request_with(&Owners::of(vec![event(true)]), Duration::from_secs(60), grace, late_verification), Outcome::OwnerGone);
        // An answer in time is passed on, and so is a worker that ends without one.
        assert_eq!(request_with(&Owners::empty(), Duration::from_secs(10), grace, |_| Outcome::Done(0)), Outcome::Done(0));
        assert_eq!(request_with(&Owners::empty(), Duration::from_secs(10), grace, |_| Outcome::Failed(E_FAIL)), Outcome::Failed(E_FAIL));
    }

    /// A consent whose request is the real wait (`request_with`) over a scripted operation, so that the cancel is recorded.
    struct WaitsOnAnOperation {
        operation: Arc<Scripted>,
        timeout: Duration,
    }

    impl Consenter for WaitsOnAnOperation {
        fn availability(&self, _owners: &Owners) -> Result<Availability, String> {
            Ok(Availability::Available)
        }

        fn session_user(&self, _owners: &Owners) -> Result<(), String> {
            Ok(())
        }

        fn request(&self, _message: &str, owners: &Owners) -> Outcome {
            let operation = self.operation.clone();
            request_with(owners, self.timeout, Duration::from_secs(5), move |stop| drive(&*operation, stop, None, Duration::from_secs(5), &one_millisecond))
        }
    }

    #[test]
    fn a_request_that_times_out_or_loses_its_starter_is_cancelled_and_the_run_is_refused_at_once() {
        // The time runs out (a short one stands in for the 300 seconds): the operation is cancelled once, the reason says so, and the process
        // does not wait out the cool-down that follows another refusal.
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let operation = Arc::new(Scripted::until_cancelled());
        let consent = WaitsOnAnOperation { operation: operation.clone(), timeout: Duration::from_millis(100) };
        COOL_DOWNS.with(|count| count.set(0));
        let error = run_desktop(&desktop("x"), &consent, &StubPrompt::new(vec![]), &any_verifier(), &Owners::empty(), &log).expect_err("no answer");
        log.finish(1_000);
        assert_eq!(operation.cancels(), 1, "the request is cancelled exactly once");
        assert!(error.message().contains("no answer within 300 seconds, the request was cancelled"), "{}", error);
        assert!(lines_of(&kept).len() == 1 && lines_of(&kept)[0].contains("method=\"hello\"") && lines_of(&kept)[0].contains("attempt=1 "), "{:?}", lines_of(&kept));
        assert_eq!(COOL_DOWNS.with(|count| count.replace(0)), 0, "the process ends at once");
        // The starter exits while the request is open: it is cancelled long before the time, and the run is refused for that.
        let starter = event(false);
        let handle = starter as usize;
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(250));
            unsafe { SetEvent(handle as Handle) };
        });
        let kept = Arc::new(Mutex::new(Vec::new()));
        let log = Log::capture(kept.clone(), None);
        let operation = Arc::new(Scripted::until_cancelled());
        let consent = WaitsOnAnOperation { operation: operation.clone(), timeout: Duration::from_secs(60) };
        let started = Instant::now();
        let error = run_desktop(&desktop("x"), &consent, &StubPrompt::new(vec![]), &any_verifier(), &Owners::of(vec![starter]), &log).expect_err("the starter is gone");
        log.finish(1_000);
        assert!(started.elapsed() < Duration::from_secs(5) && operation.cancels() == 1 && error.message().contains("nobody is waiting for it"), "{:?} {} {}", started.elapsed(), operation.cancels(), error);
        assert!(lines_of(&kept).len() == 1 && lines_of(&kept)[0].contains("attempt=1 "), "{:?}", lines_of(&kept));
        assert_eq!(COOL_DOWNS.with(|count| count.replace(0)), 0);
    }

    // ---- an operation of the Windows Runtime made here, read through the slots of its interfaces

    /// What a stand-in operation does and what was asked of it.
    struct Facts {
        /// The state it gives, and the HRESULT with which reading the state fails when that is not zero.
        status: std::sync::atomic::AtomicI32,
        status_fails: std::sync::atomic::AtomicI32,
        /// What `get_ErrorCode` writes.
        error: std::sync::atomic::AtomicI32,
        /// What `GetResults` writes; with None it succeeds and writes nothing.
        result: Option<i32>,
        /// Whether `Cancel` moves the state to cancelled.
        cancel_takes: bool,
        cancels: std::sync::atomic::AtomicU32,
        closes: std::sync::atomic::AtomicU32,
        releases: std::sync::atomic::AtomicU32,
        /// Calls of a slot that the guard has no business with.
        strays: std::sync::atomic::AtomicU32,
        asked_for: Mutex<Vec<Guid>>,
    }

    /// An interface pointer as the system lays out an object: the first field is the table of methods.
    #[repr(C)]
    struct Object {
        table: *const *const c_void,
        facts: *const Facts,
        /// The pointer of the other interface of the same operation (`IAsyncOperation` and `IAsyncInfo`).
        other: *const Object,
        is_info: bool,
    }

    /// An operation with the two interfaces that the guard reads, and the tables of their methods (slots 0 to 2 of both are those of
    /// `IUnknown`, 3 to 5 those of `IInspectable`; the rest are the methods of the interface, and the other slots count as strays).
    struct Fake {
        facts: Box<Facts>,
        operation: Box<Object>,
        _info: Box<Object>,
        _tables: [Vec<*const c_void>; 2],
    }

    unsafe fn facts_of<'a>(this: *mut c_void) -> &'a Facts {
        &*(*(this as *const Object)).facts
    }

    unsafe extern "system" fn fake_query(this: *mut c_void, interface: *const Guid, found: *mut *mut c_void) -> i32 {
        let object = &*(this as *const Object);
        facts_of(this).asked_for.lock().unwrap().push(*interface);
        let (operation, info) = if object.is_info { (object.other, this as *const Object) } else { (this as *const Object, object.other) };
        if *interface == IID_ASYNC_INFO {
            *found = info as *mut c_void;
        } else if *interface == IID_RESULT_OPERATION {
            *found = operation as *mut c_void;
        } else {
            *found = std::ptr::null_mut();
            return 0x8000_4002u32 as i32;
        }
        0
    }

    unsafe extern "system" fn fake_add_ref(_this: *mut c_void) -> u32 {
        1
    }

    unsafe extern "system" fn fake_release(this: *mut c_void) -> u32 {
        facts_of(this).releases.fetch_add(1, Ordering::SeqCst);
        1
    }

    unsafe extern "system" fn fake_stray(this: *mut c_void) -> i32 {
        facts_of(this).strays.fetch_add(1, Ordering::SeqCst);
        E_NOTIMPL as i32
    }

    unsafe extern "system" fn fake_status(this: *mut c_void, status: *mut i32) -> i32 {
        let facts = facts_of(this);
        let failure = facts.status_fails.load(Ordering::SeqCst);
        if failure != 0 {
            return failure;
        }
        *status = facts.status.load(Ordering::SeqCst);
        0
    }

    unsafe extern "system" fn fake_error(this: *mut c_void, code: *mut i32) -> i32 {
        *code = facts_of(this).error.load(Ordering::SeqCst);
        0
    }

    unsafe extern "system" fn fake_cancel(this: *mut c_void) -> i32 {
        let facts = facts_of(this);
        facts.cancels.fetch_add(1, Ordering::SeqCst);
        if facts.cancel_takes {
            facts.status.store(ASYNC_CANCELED, Ordering::SeqCst);
        }
        0
    }

    unsafe extern "system" fn fake_close(this: *mut c_void) -> i32 {
        facts_of(this).closes.fetch_add(1, Ordering::SeqCst);
        0
    }

    unsafe extern "system" fn fake_results(this: *mut c_void, result: *mut i32) -> i32 {
        if let Some(value) = facts_of(this).result {
            *result = value;
        }
        0
    }

    impl Fake {
        fn new(status: i32, result: Option<i32>, cancel_takes: bool) -> Fake {
            let facts = Box::new(Facts {
                status: std::sync::atomic::AtomicI32::new(status), status_fails: std::sync::atomic::AtomicI32::new(0), error: std::sync::atomic::AtomicI32::new(0x8007_0005u32 as i32), result, cancel_takes,
                cancels: std::sync::atomic::AtomicU32::new(0), closes: std::sync::atomic::AtomicU32::new(0), releases: std::sync::atomic::AtomicU32::new(0),
                strays: std::sync::atomic::AtomicU32::new(0), asked_for: Mutex::new(Vec::new()),
            });
            let stray = fake_stray as *const c_void;
            let unknown = [fake_query as *const c_void, fake_add_ref as *const c_void, fake_release as *const c_void];
            // IAsyncOperation<T>: put_Completed (6), get_Completed (7), GetResults (8).
            let mut operation_table: Vec<*const c_void> = unknown.to_vec();
            operation_table.extend([stray; 5]);
            operation_table.push(fake_results as *const c_void);
            // IAsyncInfo: get_Id (6), get_Status (7), get_ErrorCode (8), Cancel (9), Close (10).
            let mut info_table: Vec<*const c_void> = unknown.to_vec();
            info_table.extend([stray; 4]);
            info_table.extend([fake_status as *const c_void, fake_error as *const c_void, fake_cancel as *const c_void, fake_close as *const c_void]);
            let mut operation = Box::new(Object { table: operation_table.as_ptr(), facts: &*facts, other: std::ptr::null(), is_info: false });
            let mut info = Box::new(Object { table: info_table.as_ptr(), facts: &*facts, other: std::ptr::null(), is_info: true });
            operation.other = &*info;
            info.other = &*operation;
            Fake { facts, operation, _info: info, _tables: [operation_table, info_table] }
        }

        /// The pointer of the operation, as the call that makes a request gives it.
        fn com(&self) -> Com {
            Com(&*self.operation as *const Object as *mut c_void)
        }

        fn counts(&self) -> (u32, u32, u32, u32) {
            let facts = &self.facts;
            (facts.cancels.load(Ordering::SeqCst), facts.closes.load(Ordering::SeqCst), facts.releases.load(Ordering::SeqCst), facts.strays.load(Ordering::SeqCst))
        }
    }

    #[test]
    fn an_operation_is_read_and_cancelled_through_the_slots_of_its_interfaces_and_a_result_that_is_not_written_is_not_a_verification() {
        let free = AtomicBool::new(false);
        let grace = Duration::from_millis(150);
        // Each read is made through the interface and the slot that has it: the state, the error, the cancel and the close through
        // `IAsyncInfo`, the result through `IAsyncOperation`, and the other interface is asked for once.
        let fake = Fake::new(ASYNC_COMPLETED, Some(6), true);
        {
            let operation = WinOperation::new(fake.com()).expect("an operation that has IAsyncInfo");
            assert_eq!(operation.status(), Ok(ASYNC_COMPLETED));
            assert_eq!(operation.result(), Ok(6), "the result is the one GetResults wrote, from the interface of the operation and not of the information");
            assert_eq!(operation.error(), 0x8007_0005);
            assert_eq!(fake.counts(), (0, 0, 0, 0), "nothing is cancelled, closed or released while the operation is read");
            operation.cancel();
            assert_eq!(fake.counts(), (1, 0, 0, 0), "Cancel is slot 9 of IAsyncInfo");
            assert_eq!(operation.status(), Ok(ASYNC_CANCELED), "a cancel that the operation takes moves its state");
        }
        assert_eq!(fake.counts(), (1, 1, 2, 0), "Close is slot 10, called once, and both interface pointers are released; no other slot was called");
        assert_eq!(*fake.facts.asked_for.lock().unwrap(), [IID_ASYNC_INFO], "the information is the only other interface that is asked for");
        // An operation that failed but whose error code is no failure (0, or a success code) is reported with a failure of its own: a
        // reason such as `Windows Hello failed: 0x00000000` would name no failure at all.
        let failed = Fake::new(ASYNC_ERROR, None, false);
        let operation = WinOperation::new(failed.com()).expect("an operation that has IAsyncInfo");
        for (written, said) in [(0x8007_0005u32 as i32, 0x8007_0005), (0, E_FAIL), (1, E_FAIL), (i32::MAX, E_FAIL)] {
            failed.facts.error.store(written, Ordering::SeqCst);
            assert_eq!(operation.error(), said, "an error code of {:#x}", written);
            assert_eq!(drive(&operation, &free, None, grace, &one_millisecond), Outcome::Failed(said));
        }
        assert_eq!(failed.counts().3, 0, "no stray slot was called");
        // The system succeeds and writes nothing: the result is the value that is none of the results, and is not a verification.
        let silent = Fake::new(ASYNC_COMPLETED, None, true);
        let operation = WinOperation::new(silent.com()).expect("an operation that has IAsyncInfo");
        assert_eq!(operation.result(), Ok(NO_RESULT));
        let outcome = drive(&operation, &free, None, grace, &one_millisecond);
        assert_eq!(outcome, Outcome::Done(NO_RESULT));
        assert!(matches!(outcome, Outcome::Done(code) if Consent::from_code(code) != Consent::Verified && Availability::from_code(code) != Availability::Available));
        // A state that cannot be read: the request is asked to cancel, once, and the failure is the one the system gave.
        let unreadable = Fake::new(ASYNC_STARTED, Some(0), true);
        unreadable.facts.status_fails.store(0x8000_4005u32 as i32, Ordering::SeqCst);
        let operation = WinOperation::new(unreadable.com()).expect("an operation that has IAsyncInfo");
        assert_eq!(operation.status(), Err(0x8000_4005));
        assert_eq!(drive(&operation, &free, None, grace, &one_millisecond), Outcome::Failed(0x8000_4005));
        assert_eq!(unreadable.counts().0, 1, "a request whose state cannot be read is asked to cancel");
        // The flag to stop: the operation is cancelled once, and the outcome is a timeout where it took the cancel and a cancel that was
        // ignored where it did not, however it went on to answer.
        let takes = Fake::new(ASYNC_STARTED, Some(0), true);
        let operation = WinOperation::new(takes.com()).expect("an operation that has IAsyncInfo");
        assert_eq!(drive(&operation, &AtomicBool::new(true), None, grace, &one_millisecond), Outcome::TimedOut);
        assert_eq!(takes.counts().0, 1);
        let ignores = Fake::new(ASYNC_STARTED, Some(0), false);
        let operation = WinOperation::new(ignores.com()).expect("an operation that has IAsyncInfo");
        assert_eq!(drive(&operation, &AtomicBool::new(true), None, grace, &one_millisecond), Outcome::CancelIgnored);
        assert_eq!(ignores.counts().0, 1, "Cancel is asked once and the grace is waited for");
        drop(operation);
        assert_eq!(ignores.counts().3, 0, "no stray slot was called on any path");
        assert_eq!((takes.counts().3, unreadable.counts().3, silent.counts().3), (0, 0, 0));
    }

    // ---- the password in a protected form, with a stand-in for the calls of the system

    #[link(name = "kernel32")]
    extern "system" {
        fn SetLastError(code: u32);
    }

    /// What the stand-ins for the calls of the dialog do.
    #[derive(Default)]
    struct Script {
        /// The password as the dialog returns it, with its NUL, and the clear text it is unprotected to.
        packed: Vec<u16>,
        clear: Vec<u16>,
        unpack_fails: Option<u32>,
        unprotect_fails: Option<u32>,
        unpack_calls: u32,
        unprotect_calls: u32,
        /// The size of the password buffer of each call of the unpacking.
        buffers: Vec<u32>,
    }

    thread_local! {
        static SCRIPT: std::cell::RefCell<Script> = std::cell::RefCell::new(Script::default());
    }

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    unsafe extern "system" fn fake_unpack(_flags: u32, _buffer: *const c_void, _size: u32, user: *mut u16, user_chars: *mut u32,
        domain: *mut u16, domain_chars: *mut u32, password: *mut u16, password_chars: *mut u32) -> Bool {
        SCRIPT.with(|script| {
            let mut script = script.borrow_mut();
            script.unpack_calls += 1;
            script.buffers.push(*password_chars);
            if let Some(code) = script.unpack_fails {
                SetLastError(code);
                return 0;
            }
            if (*password_chars as usize) < script.packed.len() {
                *password_chars = script.packed.len() as u32;
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return 0;
            }
            for (at, unit) in units("me").iter().enumerate() {
                *user.add(at) = *unit;
            }
            *user_chars = 3;
            *domain = 0;
            *domain_chars = 1;
            for (at, unit) in script.packed.iter().enumerate() {
                *password.add(at) = *unit;
            }
            1
        })
    }

    /// A password that begins with `@` is in a protected form.
    unsafe extern "system" fn fake_protected(password: *mut u16, kind: *mut i32) -> Bool {
        *kind = if *password == '@' as u16 { 1 } else { CRED_UNPROTECTED };
        1
    }

    unsafe extern "system" fn fake_unprotect(_as_self: Bool, _protected: *mut u16, _length: u32, clear: *mut u16, chars: *mut u32) -> Bool {
        SCRIPT.with(|script| {
            let mut script = script.borrow_mut();
            script.unprotect_calls += 1;
            if let Some(code) = script.unprotect_fails {
                SetLastError(code);
                return 0;
            }
            if clear.is_null() || (*chars as usize) < script.clear.len() {
                *chars = script.clear.len() as u32;
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return 0;
            }
            for (at, unit) in script.clear.iter().enumerate() {
                *clear.add(at) = *unit;
            }
            1
        })
    }

    unsafe extern "system" fn fake_free(_memory: *mut c_void) {}

    unsafe extern "system" fn fake_prompt(_info: *const CredUiInfoW, _error: u32, _package: *mut u32, _in: *const c_void, _in_size: u32,
        _out: *mut *mut c_void, _out_size: *mut u32, _save: *mut Bool, _flags: u32) -> u32 {
        ERROR_CANCELLED
    }

    fn fake_api() -> DesktopApi {
        DesktopApi { prompt: fake_prompt, unpack: fake_unpack, free: fake_free, protected: fake_protected, unprotect: fake_unprotect }
    }

    /// Script the dialog and read the credentials it returns; the wipes of the buffers that were dropped on the way are cleared first.
    fn read_with(script: Script) -> (Asked, Script) {
        SCRIPT.with(|slot| *slot.borrow_mut() = script);
        WIPES.with(|wipes| wipes.borrow_mut().clear());
        let asked = read_credentials(&fake_api(), std::ptr::null(), 0);
        (asked, SCRIPT.with(|slot| std::mem::take(&mut *slot.borrow_mut())))
    }

    fn rejected(asked: Asked) -> String {
        match asked {
            Asked::Rejected(reason) => reason,
            Asked::Entered(_) => "(entered)".into(),
            _ => "(something else)".into(),
        }
    }

    #[test]
    fn a_password_in_a_clear_form_is_taken_as_it_is_and_one_in_a_protected_form_is_unprotected_into_a_buffer_that_is_wiped() {
        // Clear text: no unprotecting.
        let (asked, script) = read_with(Script { packed: units("hunter2"), ..Script::default() });
        let Asked::Entered(credentials) = asked else { panic!("a clear password is taken") };
        assert_eq!(credentials.password_units(), "hunter2".encode_utf16().collect::<Vec<u16>>());
        assert_eq!((script.unpack_calls, script.unprotect_calls), (1, 0));
        drop(credentials);
        // A protected form that fits the buffer of a password: unprotected into one of the same size.
        let (asked, script) = read_with(Script { packed: units(&format!("@{}", "B".repeat(200))), clear: units("hunter2"), ..Script::default() });
        let Asked::Entered(credentials) = asked else { panic!("a protected form that can be unprotected is taken") };
        assert_eq!(credentials.password_units(), "hunter2".encode_utf16().collect::<Vec<u16>>(), "the clear form is what is checked");
        assert!(credentials.password_ends() && credentials.password.0.len() == CREDUI_PASSWORD_CHARS && (script.unpack_calls, script.unprotect_calls) == (1, 2), "{}", script.unprotect_calls);
        drop(credentials);
        let wiped = WIPES.with(|wipes| wipes.borrow().clone());
        assert!(wiped.iter().all(|(_, after)| *after == 0), "every buffer that was alive is zero once dropped: {:?}", wiped);
        assert!(wiped.iter().any(|(before, _)| *before == 201) && wiped.iter().any(|(before, _)| *before == 7), "the protected form and the clear password were each there and were wiped: {:?}", wiped);
    }

    #[test]
    fn a_protected_form_longer_than_a_password_is_read_with_a_larger_buffer_and_no_larger_than_the_limit() {
        // The dialog returns a form of 400 characters: the buffer of a password is too small, and the unpacking is made again with the
        // size the system asked for. The password it holds is then 7 characters, which fit the buffer of a password.
        let (asked, script) = read_with(Script { packed: units(&format!("@{}", "B".repeat(399))), clear: units("hunter2"), ..Script::default() });
        let Asked::Entered(credentials) = asked else { panic!("a long protected form is taken") };
        assert_eq!(credentials.password_units(), "hunter2".encode_utf16().collect::<Vec<u16>>());
        assert_eq!(script.buffers, [CREDUI_PASSWORD_CHARS as u32, 401], "asked with the buffer of a password, then with the size that was asked for");
        assert_eq!((script.unpack_calls, script.unprotect_calls), (2, 2));
        assert_eq!(credentials.password.0.len(), CREDUI_PASSWORD_CHARS, "the password is held in a buffer of the size of a password");
        drop(credentials);
        let wiped = WIPES.with(|wipes| wipes.borrow().clone());
        assert!(wiped.iter().all(|(_, after)| *after == 0) && wiped.iter().any(|(before, _)| *before == 400), "the larger buffer was wiped: {:?}", wiped);
        // At the limit it is taken, over it the dialog's answer is turned away (an attempt used, no logon), after one call.
        let at_limit = Script { packed: units(&format!("@{}", "B".repeat(PROTECTED_LIMIT - 2))), clear: units("x"), ..Script::default() };
        assert!(matches!(read_with(at_limit).0, Asked::Entered(_)), "the limit itself is taken");
        let (asked, script) = read_with(Script { packed: units(&format!("@{}", "B".repeat(PROTECTED_LIMIT))), clear: units("x"), ..Script::default() });
        assert_eq!(rejected(asked), "the password is longer than the guard takes");
        assert_eq!((script.unpack_calls, script.unprotect_calls), (1, 0));
        assert!(WIPES.with(|wipes| wipes.borrow().iter().all(|(_, after)| *after == 0)));
    }

    #[test]
    fn a_password_that_cannot_be_unprotected_or_read_uses_an_attempt_and_leaves_nothing_in_memory() {
        // The system fails to unprotect.
        let (asked, script) = read_with(Script { packed: units("@protected"), clear: units("hunter2"), unprotect_fails: Some(5), ..Script::default() });
        let reason = rejected(asked);
        assert!(reason.starts_with("the protected form of the password could not be unprotected: ") && reason.contains("[WinError 5]"), "{}", reason);
        assert_eq!(script.unprotect_calls, 1);
        assert!(WIPES.with(|wipes| wipes.borrow().iter().all(|(_, after)| *after == 0)), "the protected form was wiped");
        // The clear password would be longer than a password can be.
        let (asked, script) = read_with(Script { packed: units("@protected"), clear: units(&"p".repeat(CREDUI_PASSWORD_CHARS)), ..Script::default() });
        assert_eq!(rejected(asked), "the password is longer than the guard takes");
        assert_eq!(script.unprotect_calls, 1, "the clear text is not asked for");
        // The size is asked for and the system fills nothing: the first call does not fail with the error for the size.
        let (asked, _) = read_with(Script { packed: units("@protected"), clear: units("x"), unprotect_fails: Some(ERROR_NONE_MAPPED), ..Script::default() });
        assert!(rejected(asked).contains("could not be unprotected"));
        // The dialog's answer cannot be read at all, or the name is too long: as before.
        let (asked, _) = read_with(Script { unpack_fails: Some(1168), ..Script::default() });
        assert!(rejected(asked).starts_with("the answer of the prompt could not be read as a user name and password: "));
        let (asked, script) = read_with(Script { unpack_fails: Some(ERROR_INSUFFICIENT_BUFFER), ..Script::default() });
        assert_eq!(rejected(asked), "the name or password is longer than the prompt allows");
        assert_eq!(script.unpack_calls, 1, "a size that did not grow is not asked again");
        assert!(WIPES.with(|wipes| wipes.borrow().iter().all(|(_, after)| *after == 0)));
    }

    #[test]
    fn a_password_protected_by_the_system_is_unprotected_by_the_system() {
        // The real calls: a password protected for the test with `CredProtectW` and given back by `CredUnprotectW`. Neither shows anything.
        let api = desktop_api().expect("the libraries of the desktop prompt");
        let clear: Vec<u16> = "hunter2".encode_utf16().chain(std::iter::once(0)).collect();
        let (mut size, mut kind) = (0u32, 0i32);
        unsafe { CredProtectW(0, clear.as_ptr(), clear.len() as u32, std::ptr::null_mut(), &mut size, &mut kind) };
        let mut blob = vec![0u16; size as usize];
        assert_ne!(unsafe { CredProtectW(0, clear.as_ptr(), clear.len() as u32, blob.as_mut_ptr(), &mut size, &mut kind) }, 0, "protect a password for the test");
        assert!(password_is_protected(api, &mut blob));
        match unprotect(api, &mut blob) {
            Ok(back) => assert_eq!(text_before_nul(&back.0).as_deref(), Some("hunter2")),
            Err(reason) => panic!("{}", reason),
        }
        wipe(&mut blob);
    }

    // ---- the calls of the Windows Runtime, for real, where they show nothing

    #[test]
    fn the_class_and_the_interfaces_that_the_request_uses_are_there_and_whether_windows_hello_is_available_is_answered_without_showing_anything() {
        let api = hello_api().expect("combase.dll");
        let _apartment = Apartment::enter(api).expect("a Windows Runtime apartment");
        let class = HString::new(api, CONSENT_CLASS).expect("a string of the Windows Runtime");
        // The two interfaces of the class that are used: the code to ask for the request is slot 6 of the second, and a request is never made here.
        match factory(api, &class, &IID_CONSENT_INTEROP) {
            Ok(interop) => assert!(interop.query(&IID_CONSENT_INTEROP).is_ok() && !interop.0.is_null()),
            // A system without the class (0x80040154) or without the interop interface (an edition of Windows older than 1703 or a server edition).
            Err(code) if code == 0x8004_0154 || code == 0x8000_4002 => eprintln!("NOT ASSERTED: the class or the interop interface of Windows Hello is not there (0x{:08x})", code),
            Err(code) => panic!("the interop interface of the class: 0x{:08x}", code),
        }
        if let Ok(statics) = factory(api, &class, &IID_CONSENT_STATICS) {
            assert!(!statics.0.is_null());
        }
        // The question: it shows nothing, and the answer is one of the names that are logged.
        match HelloConsenter.availability(&Owners::empty()) {
            Ok(answer) => {
                let name = answer.name();
                assert!(["Available", "DeviceNotPresent", "NotConfiguredForUser", "DisabledByPolicy", "DeviceBusy"].contains(&name.as_str()) || name.starts_with("Unknown("), "{}", name);
                eprintln!("Windows Hello on this machine: {}", name);
            }
            Err(reason) => eprintln!("NOT ASSERTED: the question was not answered here: {}", reason),
        }
        // A starter that has gone ends the question early, with its reason, unless the system answered first; either way it returns
        // within the limit of the question, and an answer is one of the names that are logged.
        let gone = Owners::of(vec![event(true)]);
        let started = Instant::now();
        match HelloConsenter.availability(&gone) {
            Ok(answer) => assert!(["Available", "DeviceNotPresent", "NotConfiguredForUser", "DisabledByPolicy", "DeviceBusy"].contains(&answer.name().as_str()) || answer.name().starts_with("Unknown(")),
            Err(reason) => assert!(!reason.is_empty(), "a question that is not answered says why"),
        }
        assert!(started.elapsed() < Duration::from_millis(SYSTEM_TIMEOUT_MS + 2_000), "{:?}", started.elapsed());
    }

    #[link(name = "user32")]
    extern "system" {
        fn CreateDesktopW(name: *const u16, device: *const u16, devmode: *mut c_void, flags: u32, access: u32, attributes: *mut c_void) -> Handle;
        fn SetThreadDesktop(desktop: Handle) -> Bool;
        fn PostMessageW(window: Handle, message: u32, w: usize, l: isize) -> Bool;
        fn PostThreadMessageW(thread: u32, message: u32, w: usize, l: isize) -> Bool;
    }

    /// Set by the function that a timer message posted to the owner window names, if it is ever called.
    static TIMER_FUNCTION_CALLED: AtomicBool = AtomicBool::new(false);

    unsafe extern "system" fn timer_function(_window: Handle, _message: u32, _id: usize, _time: u32) {
        TIMER_FUNCTION_CALLED.store(true, Ordering::SeqCst);
    }

    #[test]
    fn a_question_about_windows_hello_that_is_cancelled_ends_cancelled_through_the_cancel_slot_of_the_system() {
        // The question shows nothing, and it is the one real operation of the Windows Runtime that can be cancelled here: the request is
        // never made. Cancel is slot 9 of `IAsyncInfo`; only a system that lays the table out as the guard declares ends the operation
        // as cancelled, which the stand-in operations cannot show. The loop that waits for an operation cancels it when its flag is set.
        let Some(api) = hello_api() else { return eprintln!("NOT ASSERTED: combase.dll is not there") };
        let (mut cancelled, mut asked) = (0, 0);
        for _ in 0..20 {
            let Ok(_apartment) = Apartment::enter(api) else { return eprintln!("NOT ASSERTED: no apartment of the Windows Runtime") };
            let Ok(class) = HString::new(api, CONSENT_CLASS) else { return eprintln!("NOT ASSERTED: no string of the Windows Runtime") };
            let Ok(statics) = factory(api, &class, &IID_CONSENT_STATICS) else { return eprintln!("NOT ASSERTED: the class of Windows Hello is not there") };
            let mut raw: *mut c_void = std::ptr::null_mut();
            // SAFETY: slot 6 of IUserConsentVerifierStatics is CheckAvailabilityAsync.
            let code = unsafe { slot::<CheckAvailabilityAsyncFn>(statics.0, 6)(statics.0, &mut raw) };
            assert!(code >= 0 && !raw.is_null(), "the question is asked: 0x{:08x}", code);
            let typed = Com(raw).query(&IID_AVAILABILITY_OPERATION).expect("the operation as the interface whose result is read");
            let operation = WinOperation::new(typed).expect("an operation that has IAsyncInfo");
            asked += 1;
            match drive(&operation, &AtomicBool::new(true), None, Duration::from_secs(5), &one_millisecond) {
                Outcome::TimedOut => cancelled += 1,
                // The answer came before the loop looked at its flag: an answer is an answer.
                Outcome::Done(code) => assert!(!matches!(Availability::from_code(code), Availability::Unknown(_)), "an availability that is known: {}", code),
                other => panic!("a question that is cancelled ends as cancelled or answered, not {:?}", other),
            }
        }
        assert!(cancelled > 0, "no question of {} ended as cancelled: Cancel (slot 9) does not reach the operation", asked);
    }

    #[test]
    fn only_a_message_the_window_can_have_asked_for_is_dispatched() {
        let (own, none) = (0x1000usize as Handle, std::ptr::null_mut());
        let message = |window: Handle, message: u32, l: isize| Msg { window, message, w: 1, l, time: 0, point: [0; 2] };
        // A timer message is never dispatched, for the window or for the thread, with a function named or none: the thread sets no timer.
        for kind in [WM_TIMER, WM_SYSTIMER] {
            for window in [own, none] {
                assert!(!dispatchable(&message(window, kind, timer_function as *const () as usize as isize)), "{}: the function it names is never called", kind);
                assert!(!dispatchable(&message(window, kind, 0)), "{}: and nor is one that names none", kind);
            }
        }
        // Everything else is.
        assert!(dispatchable(&message(own, 0, 0)) && dispatchable(&message(own, 0x0010, 0)) && dispatchable(&message(none, 0x0400, 0)), "WM_NULL, WM_CLOSE and a message of the thread");
    }

    thread_local! {
        /// What the stand-in for the wait of the owner window gives.
        static WAIT_GIVES: std::cell::Cell<u32> = const { std::cell::Cell::new(WAIT_OBJECT_0) };
    }

    unsafe extern "system" fn fake_wait(_count: u32, _handles: *const Handle, _milliseconds: u32, _mask: u32, _flags: u32) -> u32 {
        WAIT_GIVES.with(|gives| gives.get())
    }

    unsafe extern "system" fn fake_register(_class: *const WndClassExW) -> u16 {
        1
    }

    unsafe extern "system" fn fake_create(_ex: u32, _class: *const u16, _name: *const u16, _style: u32, _x: i32, _y: i32, _width: i32, _height: i32,
        _parent: Handle, _menu: Handle, _instance: Handle, _parameter: *mut c_void) -> Handle {
        std::ptr::null_mut()
    }

    unsafe extern "system" fn fake_destroy(_window: Handle) -> Bool {
        1
    }

    unsafe extern "system" fn fake_unregister(_class: *const u16, _instance: Handle) -> Bool {
        1
    }

    unsafe extern "system" fn fake_peek(_message: *mut Msg, _window: Handle, _first: u32, _last: u32, _flags: u32) -> Bool {
        0
    }

    unsafe extern "system" fn fake_dispatch(_message: *const Msg) -> isize {
        0
    }

    unsafe extern "system" fn fake_procedure(_window: Handle, _message: u32, _w: usize, _l: isize) -> isize {
        0
    }

    #[test]
    fn a_wait_for_the_owner_window_that_fails_sleeps_the_time_and_does_not_spin() {
        let api: &'static WindowApi = Box::leak(Box::new(WindowApi {
            register: fake_register, create: fake_create, destroy: fake_destroy, unregister: fake_unregister, peek: fake_peek,
            dispatch: fake_dispatch, default_procedure: fake_procedure, wait: fake_wait,
        }));
        let window = OwnerWindow { api, handle: std::ptr::null_mut(), class: wide("none"), instance: std::ptr::null_mut() };
        // A wait that could not be made returns at once, which the loop that waits for the request would turn into a spin: the time is slept.
        WAIT_GIVES.with(|gives| gives.set(WAIT_FAILED));
        let started = Instant::now();
        window.serve();
        assert!(started.elapsed() >= Duration::from_millis(POLL_MS as u64 - 20), "{:?}", started.elapsed());
        // A wait that ended because of a message, or because the time was up, is not slept again.
        for gives in [WAIT_OBJECT_0, WAIT_TIMEOUT] {
            WAIT_GIVES.with(|slot| slot.set(gives));
            window.serve();
        }
    }

    /// Set in the environment of the copy of this test executable that makes the owner window.
    const OWNER_CHILD: &str = "PROCESS_TREE_GUARD_UNIT_TEST_OWNER_WINDOW_CHILD";

    #[test]
    fn the_window_that_owns_the_request_is_made_served_and_destroyed_on_a_window_station_that_is_not_visible() {
        const GENERIC_ALL: u32 = 0x1000_0000;
        if std::env::var_os(OWNER_CHILD).is_some() {
            // The copy: it makes a window station of its own, which is not visible, and a desktop on it, makes them its own and makes the
            // window on that desktop, so that no window is ever on the desktop of whoever runs the tests. It is served once and
            // destroyed, twice, to see that the class can be made again.
            let station = unsafe { CreateWindowStationW(std::ptr::null(), 0, GENERIC_ALL, std::ptr::null_mut()) };
            if station.is_null() || unsafe { SetProcessWindowStation(station) } == 0 {
                println!("OWNER no window station could be made [WinError {}]", unsafe { GetLastError() });
                return;
            }
            let desktop = unsafe { CreateDesktopW(wide("hidden").as_ptr(), std::ptr::null(), std::ptr::null_mut(), 0, GENERIC_ALL, std::ptr::null_mut()) };
            if desktop.is_null() || unsafe { SetThreadDesktop(desktop) } == 0 {
                println!("OWNER no desktop could be made [WinError {}]", unsafe { GetLastError() });
                return;
            }
            // The real read of the two desktops from a desktop that does not receive the input of anyone: it is not accepted.
            let (ours, input) = desktop_names();
            println!("OWNER desktops ours={} input={:?} accepted={}", ours.as_deref().unwrap_or("(none)"), input, on_input_desktop(ours.clone(), input.clone()).is_ok());
            let api = window_api().expect("user32.dll");
            for round in 1..=2 {
                match OwnerWindow::create(api) {
                    Ok(window) => {
                        window.serve();
                        println!("OWNER round {} made and served", round);
                        // With nothing in its queue the window waits for the poll and does not return at once, which would turn the loop that
                        // waits for the request into a spin that reads the operation on every turn (CWE-834).
                        for pass in 0..4 {
                            let before = Instant::now();
                            window.serve();
                            println!("OWNER round {} idle serve {} {}", round, pass, before.elapsed().as_millis());
                        }
                        // One look at the request serves what waits for the window: the loop that waits for the request serves the window nowhere
                        // else, so a few posted messages are gone after it.
                        let mut seen = Msg { window: std::ptr::null_mut(), message: 0, w: 0, l: 0, time: 0, point: [0; 2] };
                        unsafe {
                            for _ in 0..3 {
                                PostMessageW(window.handle, 0, 0, 0);
                            }
                        }
                        window.serve();
                        println!("OWNER round {} serve drains {}", round, unsafe { (window.api.peek)(&mut seen, std::ptr::null_mut(), 0, 0, 0) } == 0);
                        // A program of the same user can post to the window and to its thread: a timer message that names a function
                        // to each, then more messages than one look at the queue takes. One look serves no more than PUMP_LIMIT of them and calls no
                        // function, and a few looks empty the queue.
                        let mut probe = Msg { window: std::ptr::null_mut(), message: 0, w: 0, l: 0, time: 0, point: [0; 2] };
                        unsafe {
                            PostMessageW(window.handle, WM_TIMER, 1, timer_function as *const () as usize as isize);
                            PostThreadMessageW(GetCurrentThreadId(), WM_TIMER, 2, timer_function as *const () as usize as isize);
                            for _ in 0..PUMP_LIMIT * 2 {
                                PostMessageW(window.handle, 0, 0, 0);
                            }
                        }
                        window.pump();
                        let left = unsafe { (window.api.peek)(&mut probe, std::ptr::null_mut(), 0, 0, 0) } != 0;
                        for _ in 0..4 {
                            window.pump();
                        }
                        let drained = unsafe { (window.api.peek)(&mut probe, std::ptr::null_mut(), 0, 0, 0) } == 0;
                        // A pass of `serve`, which is what a look at the request allows, dispatches no more than that either.
                        unsafe {
                            for _ in 0..PUMP_LIMIT * 2 {
                                PostMessageW(window.handle, 0, 0, 0);
                            }
                        }
                        window.serve();
                        let left_by_serve = unsafe { (window.api.peek)(&mut probe, std::ptr::null_mut(), 0, 0, 0) } != 0;
                        for _ in 0..4 {
                            window.pump();
                        }
                        println!("OWNER round {} flood left_after_one_look={} drained={} left_after_serve={} timer_function_called={}", round, left, drained, left_by_serve,
                            TIMER_FUNCTION_CALLED.load(Ordering::SeqCst));
                        // What the system itself does with such a message, dispatched without the filter: recorded and not asserted, because
                        // the guard does not rely on it and it may differ between systems.
                        TIMER_FUNCTION_CALLED.store(false, Ordering::SeqCst);
                        unsafe { PostMessageW(window.handle, WM_TIMER, 3, timer_function as *const () as usize as isize) };
                        while unsafe { (window.api.peek)(&mut probe, std::ptr::null_mut(), 0, 0, PM_REMOVE) } != 0 {
                            if probe.message == WM_TIMER {
                                unsafe { (window.api.dispatch)(&probe) };
                            }
                        }
                        println!("OWNER round {} the system calls the function of a timer message from outside: {}", round, TIMER_FUNCTION_CALLED.load(Ordering::SeqCst));
                        TIMER_FUNCTION_CALLED.store(false, Ordering::SeqCst);
                    }
                    Err(code) => {
                        println!("OWNER round {} failed 0x{:08x}", round, code);
                        return;
                    }
                }
            }
            println!("OWNER ok");
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().expect("the path of this test executable"))
            .args(["the_window_that_owns_the_request_is_made_served_and_destroyed", "--nocapture", "--test-threads=1"])
            .env(OWNER_CHILD, "1").stdin(std::process::Stdio::null()).output().expect("run the copy");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let said: Vec<String> = stdout.lines().filter_map(|line| line.find("OWNER ").map(|at| line[at + "OWNER ".len()..].to_string())).collect();
        if said.iter().any(|line| line.starts_with("no window station") || line.starts_with("no desktop")) {
            assert!(std::env::var_os("PROCESS_TREE_GUARD_REQUIRE_WINDOW_STATION").map_or(true, |value| value.is_empty()), "{:?}", said);
            eprintln!("NOT ASSERTED: {:?}", said);
            return;
        }
        assert!(output.status.success() && said.last().map(String::as_str) == Some("ok"), "{:?} / {}", said, stdout);
        assert!(said.iter().any(|line| line.starts_with("desktops ours=hidden ") && line.ends_with(" accepted=false")),
            "a desktop of a window station that is not visible is not the one that receives the input of the user: {:?}", said);
        for round in 1..=2 {
            assert!(said.iter().any(|line| *line == format!("round {} flood left_after_one_look=true drained=true left_after_serve=true timer_function_called=false", round)),
                "round {}: a flood is served in parts and a timer message calls nothing: {:?}", round, said);
            assert!(said.iter().any(|line| *line == format!("round {} serve drains true", round)), "round {}: one look at the request serves the messages that wait: {:?}", round, said);
            // A message that the system sends to a window can end one wait early, so three of the four idle waits must last about the poll.
            let prefix = format!("round {} idle serve ", round);
            let waits: Vec<u128> = said.iter().filter_map(|line| line.strip_prefix(prefix.as_str())).filter_map(|rest| rest.split_whitespace().nth(1)?.parse().ok()).collect();
            assert!(waits.len() == 4 && waits.iter().filter(|ms| **ms >= POLL_MS as u128 / 2).count() >= 3 && waits.iter().all(|ms| *ms < 5_000),
                "round {}: a window with nothing in its queue waits for the poll and does not spin: {:?}", round, waits);
        }
        for line in said.iter().filter(|line| line.contains("the system calls the function")) {
            eprintln!("Recorded, not asserted: {}", line);
        }
    }
}

/// The answers a unit test of the engine can give in place of the prompt, so that the run an
/// approval starts is exercised end to end. Only `decide` looks at them, and only under `cfg(test)`.
#[cfg(test)]
pub(crate) mod seam {
    use super::*;
    use std::cell::Cell;

    thread_local! {
        /// Some(true): the right password is given. Some(false): the prompt is cancelled. None: the real prompt.
        pub(crate) static ANSWER: Cell<Option<bool>> = const { Cell::new(None) };
    }

    pub(super) struct SeamPrompt(pub bool);

    impl Prompt for SeamPrompt {
        fn begin(&self, _text: &str) -> Result<Claim, String> {
            Ok(Claim { _lock: None })
        }

        fn ask(&self, _attempt: u32, _last_error: u32, _text: &str) -> Asked {
            if self.0 { Asked::Entered(Box::new(Credentials::with("me", "", "right"))) } else { Asked::Cancelled }
        }
    }

    pub(super) struct SeamVerifier;

    impl Verifier for SeamVerifier {
        fn verify(&self, credentials: Box<Credentials>) -> Verified {
            if credentials.password_units() == "right".encode_utf16().collect::<Vec<u16>>() { Verified::Approved } else { Verified::Wrong }
        }
    }
}
