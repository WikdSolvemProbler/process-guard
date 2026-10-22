// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! The exception above the cap: the password of the account the guard runs as, at the start of a run.
//!
//! A run started with `--extendable` and a `--max-extension` over the default cap (six hours)
//! is a per-run exception. Before the job is created and before the command starts, the guard
//! asks the account the guard runs as (the signed-in user in the usual case) for the password,
//! by the secure desktop prompt (the default) or, with `--authenticate console`, by a prompt on
//! a console that is really there. The credentials are
//! checked with `LogonUserW`, and the user of the logon token must be the user the guard runs as.
//! A run that nobody is present to approve, or that is refused, exits with 125 and never starts
//! its command. At most three attempts are made, each failed one counting toward account
//! lockout, and every attempt is a line of the log. A run that another guard started (the
//! automatic wrapper, or a hook that wraps a line whole) is refused before anything is shown: a
//! command that an agent runs is such a run, and the agent must not be able to summon the prompt.
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
//! it does).
//!
//! The password lives only in buffers that are zeroed with volatile writes when they are
//! dropped, on every path, and is never put in a `String`, never logged and never echoed. The
//! release profile aborts on a panic without running destructors, so a panic hook zeroes every
//! buffer that is alive before the abort (see `install_panic_hook`). The exception resists
//! accidents and agents that lack the password; it does not resist a process of the same user that
//! can tamper with the guard itself (see `SECURITY.md`).
//!
//! The logic is behind two traits, `Prompt` and `Verifier`, so that the unit tests drive the
//! attempt loop with stubs. The stubs exist only under `cfg(test)`: no argument, environment
//! variable or file selects one, so a release executable has no way to skip the prompt.

use crate::engine::{format_seconds, image_path_of_handle, started_at};
use crate::extend::{current_user_sid, exception_line, hours_figure, image_of, now_ms, sid_text, token_user_sid, ExceptionRecord, Log, Settings, RECORD_MS};
use crate::sys::*;
use crate::GuardError;
use std::ffi::c_void;
use std::sync::atomic::{compiler_fence, AtomicU64, Ordering};
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

/// How the password of the account the guard runs as is asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// The secure desktop prompt of Windows.
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
/// system writes for the process. The hook runs before the abort, then the previous hook.
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
    log.push(&note(settings, subject, false, attempt, reason));
    GuardError(format!("exception refused: {}; the run did not start", reason))
}

/// The line of the log for a decision. It names what the decision is about: the account of the
/// guard (as the system writes it, not anything that was typed), the command line that was shown,
/// cut and written out as the prompt shows it, how the user was asked, the deadline the run starts
/// with, and the nearest process that started the guard, as the prompt shows it.
fn note(settings: &Settings, subject: &Subject, approved: bool, attempt: u32, reason: &str) -> String {
    let pid = unsafe { GetCurrentProcessId() };
    let (command, method, timeout) = settings.exception.as_ref()
        .map_or_else(|| (String::new(), "", 0.0), |exception| (shown_command(&exception.command), exception.method.name(), exception.timeout));
    let started_by = if subject.parent.is_empty() { String::new() } else { shown(subject.parent, PARENT_LIMIT, Keep::End) };
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
        Method::Desktop => authorize(settings, &subject, &DesktopPrompt::new(owners), &verifier, owners, log),
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
    // A refusal after the prompt was shown: the line is written at once and the right to a prompt is
    // kept for a while longer (it is dropped with `_claim` when this returns).
    let refuse_shown = |attempt: u32, reason: &str| {
        let error = refuse(settings, log, subject, attempt, reason);
        pause(owners, cool_down_ms());
        error
    };
    // Held until the attempts are over, so that no second prompt of the guard opens beside this one.
    let _claim = match prompt.begin(&text) {
        Ok(claim) => claim,
        Err(reason) => return Err(refuse(settings, log, subject, 0, &reason)),
    };
    let mut last_error = 0;
    for attempt in 1..=MAX_ATTEMPTS {
        // The credentials are dropped, and so wiped, as soon as they have been checked.
        let mut rejection: Option<String> = None;
        let verdict = match prompt.ask(attempt, last_error, &text) {
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
            Asked::NotShown(reason) => return Err(refuse(settings, log, subject, attempt - 1, &reason)),
            Asked::Unavailable(reason) => return Err(refuse_shown(attempt, &reason)),
            // The prompt is still open: nothing may keep the process alive, or the person could type into a prompt
            // whose answer is never read.
            Asked::Abandoned(reason) => return Err(refuse(settings, log, subject, attempt, &reason)),
        };
        let reason = match verdict {
            Verified::Approved => {
                if owners.gone() {
                    return Err(refuse(settings, log, subject, attempt, OWNER_GONE));
                }
                if log.blocked() {
                    return Err(refuse_shown(attempt, "the audit file (or standard error, when there is no audit file) cannot take lines, so the approval could not be recorded"));
                }
                let reason = format!("a cap of {} was approved: the password of the account the guard runs as was given at the {} prompt", hours_phrase(settings.max_seconds), exception.method.name());
                if !log.record_decision(&note(settings, subject, true, attempt, &reason), RECORD_MS) {
                    return Err(refuse_shown(attempt, "the approval could not be recorded"));
                }
                return Ok(());
            }
            Verified::OwnerGone => return Err(refuse(settings, log, subject, attempt, OWNER_GONE)),
            Verified::Wrong | Verified::OtherUser => rejection.unwrap_or_else(|| NOT_ACCEPTED.to_string()),
            Verified::Failed(code) if exception.method == Method::Console && AFTER_PASSWORD_CHECKED.contains(&code) => NOT_ACCEPTED.to_string(),
            Verified::Failed(UNIDENTIFIED) => return Err(refuse_shown(attempt, "the account of the credentials could not be identified")),
            Verified::Failed(code) => return Err(refuse_shown(attempt, &format!("the credentials could not be checked: {}", error_for(code).message()))),
        };
        if attempt == MAX_ATTEMPTS {
            return Err(refuse_shown(attempt, &format!("{}; no attempts are left", reason)));
        }
        log.push(&note(settings, subject, false, attempt, &reason));
        if !pause(owners, retry_delay_ms()) {
            return Err(refuse(settings, log, subject, attempt, OWNER_GONE));
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
    let mut session = 0u32;
    let session = (unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) } != 0).then_some(session);
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

/// The secure desktop prompt: `CredUIPromptForWindowsCredentialsW` showing only the accounts of
/// the current user, then `CredUnPackAuthenticationBufferW`. It is refused without showing
/// anything when the process has no interactive window station or runs in session 0. There is
/// no consent path of Windows Hello: a PIN does not unpack to a password, so an account that
/// signs in with a PIN alone cannot approve.
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
        if desktop_api().is_none() || window_station_api().is_none() {
            return Err(NOT_AVAILABLE.into());
        }
        // The field limits keep the message under the most the dialog takes; a message that is not
        // refuses the run rather than reach a dialog that would clip the way to refuse it.
        if text.encode_utf16().count() >= CREDUI_MAX_MESSAGE_LENGTH {
            return Err("the message of the prompt is longer than the dialog takes".into());
        }
        let (session, flags) = detect();
        present(session, flags)?;
        Ok(Claim { _lock: Some(PromptLock::take()?) })
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
    let mut credentials = Box::new(Credentials::new());
    let (mut user_chars, mut domain_chars, mut password_chars) = (CREDUI_USER_CHARS as u32, CREDUI_DOMAIN_CHARS as u32, CREDUI_PASSWORD_CHARS as u32);
    let unpacked = unsafe {
        (api.unpack)(0, out.pointer, out.size,
            credentials.user.0.as_mut_ptr(), &mut user_chars,
            credentials.domain.0.as_mut_ptr(), &mut domain_chars,
            credentials.password.0.as_mut_ptr(), &mut password_chars)
    };
    if unpacked == 0 {
        // The prompt was answered with something that is not a name and a password (a PIN or a smart
        // card may be so), or with a name or password that is too long: an attempt used, with no logon
        // tried, and the user is asked again. The buffers are wiped when `credentials` goes.
        let code = unsafe { GetLastError() };
        return Asked::Rejected(if code == ERROR_INSUFFICIENT_BUFFER {
            "the name or password is longer than the prompt allows".into()
        } else {
            format!("the answer of the prompt could not be read as a user name and password: {}", error_for(code).message())
        });
    }
    // A password that the system hands back in a protected (encrypted) form is not the text that was typed:
    // sent to `LogonUserW` it would fail as a wrong password and count toward the lockout of the account.
    // It is not sent; it uses an attempt of its own, with a reason of its own.
    if password_is_protected(api, &mut credentials.password.0) {
        return Asked::Rejected("the answer of the prompt holds a protected form of the password, which the guard does not unprotect".into());
    }
    Asked::Entered(credentials)
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
