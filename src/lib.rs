// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! Windows process tree deadline. No implicit timeout and no third party crates.
//!
//! Runs one command inside a job object that kills every process in the tree
//! when the job closes. Exit codes: the child's own code; 124 on timeout; 125
//! for any guard error or when the process that launched the guard exits. The
//! guard never exits with 2 outside hook mode, because 2 blocks a host hook event.
//!
//! # Programs
//!
//! The crate builds four programs, each a thin `main` over this library:
//!
//! | Program | Role | Entry point |
//! |---|---|---|
//! | `process-tree-guard` | the full command: every mode | [`main_full`] |
//! | `process-tree-guard-deadline` | the deadline role: `--timeout` and automatic mode | [`main_deadline`] |
//! | `process-tree-guard-gate` | the hook role: `process-tree-guard-gate VENDOR` takes the vendors and formats of `process-tree-guard hook VENDOR` | [`main_gate`] |
//! | `process-tree-guard-contain` | the contain role: `--timeout` inside an extendable run, as a request to it | [`main_contain`] |
//!
//! The 1.x names `process-guard` and `process-guard-auto` are aliases of
//! `process-tree-guard` through all of 2.x. Dispatch is by the program's file
//! name: a name ending in `-auto` selects automatic mode in the full command and
//! in the deadline role, and the 1.x names behave exactly as the 2.0 names. The hook role is the
//! exception: it is the hook role under any file name, because the program
//! decides its rules (see [`main_gate`]). So is the contain role, which has no
//! automatic mode (see [`main_contain`]).
//!
//! # Where files are found
//!
//! Anything the guard looks for beside itself (the automatic copy a hook rewrites
//! to, `POLICY.md` one folder up) is found relative to [`std::env::current_exe`]
//! alone, never through `PATH` or the current folder, so a planted file elsewhere
//! is never used (Common Weakness Enumeration, CWE-427). Two layouts work. In the
//! install layout the full command is in `bin` and the roles are in `libexec`:
//!
//! ```text
//! <root>/bin/process-tree-guard.exe
//! <root>/bin/process-tree-guard-auto.exe
//! <root>/libexec/process-tree-guard-deadline.exe
//! <root>/libexec/process-tree-guard-deadline-auto.exe
//! <root>/libexec/process-tree-guard-gate.exe
//! <root>/libexec/process-tree-guard-contain.exe
//! <root>/POLICY.md
//! ```
//!
//! In the flat layout every program is in one folder, `bin`. In both, the `-auto`
//! files are copies of the programs they are named after, a program looks for its
//! automatic copy in its own folder (the gate's is the deadline role's), and for
//! `POLICY.md` one folder above its own.
//!
//! The program the guard is asked to run is found as the `PATH` search finds it,
//! the current folder first unless `NoDefaultCurrentDirectoryInExePath` is set,
//! as in 1.x. So is the shell the guard chooses for [`run_shell`]: `pwsh.exe` if
//! that search finds one, otherwise `powershell.exe`, and for `cmd` the value of
//! `COMSPEC`, otherwise `cmd.exe`. A caller that needs one exact shell names it
//! with a full path in `COMSPEC`, or runs it through [`run`].
//!
//! # Library use
//!
//! [`run`] runs a program and its arguments under a deadline, [`run_shell`] runs
//! an encoded command line in a shell, [`run_auto`] is automatic mode and
//! [`run_hook`] is a hook mode. Errors are a [`GuardError`].
//!
//! The command inherits the caller's standard input, output and error handles, and
//! runs in the caller's console when it has one, so its output appears where the
//! caller's own output does. The notices `PROCESS_TIMEOUT` and `PROCESS_OWNER_EXITED`
//! are written to the caller's standard error, as the programs write them, once the tree has ended (a
//! standard error that nobody reads cannot keep the tree alive, and the write is
//! abandoned after half a second).
//!
//! The command inherits more than those three. The command is created with handle
//! inheritance on and without a list of handles, so every handle of the caller that
//! is marked inheritable passes into the command and its descendants, and an
//! unrelated pipe or file held that way stays open until the whole tree has exited.
//! An embedder should mark its own handles non-inheritable before the call (files
//! opened through Rust's standard library already are), or start the
//! `process-tree-guard` program as a child, so that it chooses what that child
//! inherits.
//!
//! # Extendable runs
//!
//! `process-tree-guard --extendable --timeout SECONDS COMMAND...` runs the command
//! in a job whose deadline can be held up by the processes in it. The guard serves
//! a private named pipe and passes its name to the command in
//! `PROCESS_TREE_GUARD_CHANNEL`. A process in the job calls [`extend`] (or runs
//! `process-tree-guard extend SECONDS`) to ask that its deadline be held for that
//! many seconds from now, at most `--max-extension` (21,600, six hours, unless the
//! guard's launch arguments say otherwise, and never more than 86,400). The guard
//! verifies the process before it answers, keeps the hold on the process's handle,
//! ends the hold when the process exits, and logs every request, grant and
//! refusal; a request after the deadline is refused. The run ends, with exit code 124, at the latest of its own `--timeout`
//! deadline and the holds of live processes; a run whose processes renew in time goes on
//! for as long as they do, and each renewal is capped and logged. While the audit file named by `--extension-log` cannot
//! take lines, the run grants nothing. With no audit file, standard error is the only
//! record: a grant stands only once its line has been written there, and a run whose
//! standard error is closed or is the null device does not start. A guard started inside an extendable
//! run, whatever its role, asks for its own `--timeout` as it starts, and exits
//! with 125 when the run refuses. A library call ([`run`], [`run_shell`] or [`run_auto`])
//! made by a process in the run is such a guard in a process that goes on, so the hold
//! its start makes on the calling process is ended when the call returns, by a release
//! request that the run logs as `decision=released` and does not count against the
//! process's share of the rate limit. Each call is one request against that share, 12 per
//! process in any 10 seconds: a host that makes more calls than that inside a run has the
//! rest refused with a [`GuardError`] ("too many requests from this process; try again
//! later"), and their commands do not run. Each call has a hold of its own, and so has
//! [`extend`]: calls that overlap, from threads of one process, do not replace or release
//! one another's holds, and the run waits for the latest of them. A run without `--extendable` has no channel of its
//! own, sets no environment variable for its command and keeps the clock of
//! 2.0.0-alpha.2. The following differ from that version in every run, whether or not it is extendable (the changelog lists each): the notices
//! are written after the tree has ended (see above), and the trace lines with them; each line on standard error is written with one
//! call, and a standard error or standard output whose reader has gone does not end the guard with a crash in
//! any mode, the hook modes included, so the exit code is kept (a denial by a hook stays 2); a guard whose environment has
//! `PROCESS_TREE_GUARD_CHANNEL` naming a live channel asks that run for its deadline (a
//! value that is not the name of a channel, or names one that is gone, is read as no
//! run around the guard, and the guard keeps its own fixed deadline); the extension
//! options without `--extendable` are refused with a message of their own; and the usage text names
//! `extend` and the extension options. See the README.
//!
//! A `--max-extension` over 21,600 is a per-run exception: before the job is made and before
//! the command starts, the top-level guard asks for the approval of the signed-in user: with
//! the default method, for the consent of Windows Hello (only when the guard runs as the user who is
//! signed in to its session, and a consent that is asked for and not given is not answered by a
//! password) and, only where Windows Hello is not available, by the credential dialog of Windows on
//! the secure desktop; with `--authenticate console`, on a console that is really there. A password
//! is checked with `LogonUserW` against the guard's own user, and at most 3 attempts are allowed;
//! Windows Hello is asked once.
//! A run that nobody can be asked about, or that is cancelled or not answered within 300
//! seconds, exits with 125 and never starts its command. A guard inside an extendable run (a
//! nested guard) is refused before anyone is asked, and the contain role and automatic mode do
//! not ask: they refuse the options. Nor does the hook program: it denies a line that carries
//! the options, or wraps it whole as the command text of the automatic wrapper, which does not
//! ask either. A guard that another guard started (as the command of automatic mode, or under a
//! guard that is not extendable) is refused before anything is shown, because a command that an
//! agent runs is such a run and an agent must not be able to summon a prompt. Two tests make the
//! refusal. The first is by file name: the programs of this crate, the 1.x name, and any file name
//! that ends in `-auto`, which selects automatic mode. The search follows the parent chain while
//! each parent is alive, started before its child and is not one of `explorer.exe`,
//! `services.exe`, `wininit.exe`, `winlogon.exe`, `svchost.exe` or `smss.exe` at its system path
//! (`explorer.exe` in the Windows folder, the other five in `System32`; a program of one of those
//! names in any other folder, one under the Windows folder included, is a copy that a process of
//! the user may be able to make, and is walked past like any other process), for at most 32 levels; a parent
//! that has already exited ends it, so a command started through a launcher that exits before the
//! guard runs is not seen to be under a guard by this test, and a launcher can name a parent of its
//! choice. The second is by job: every job a guard makes kills its processes when it closes, so a
//! process whose innermost job does so is refused, however its chain of parents looks, unless the
//! process has put itself in a job of its own, which any process of the user can do with three
//! calls (nested jobs are allowed, and the test programs of this repository do it); the test
//! refuses commands that were not written to avoid it. It also refuses a guard started from
//! inside a host that puts its terminal in a job of that kind (continuous integration runners,
//! some editor terminals), which must start the guard from an ordinary terminal. An agent that
//! runs as the same user outside a guard job, that puts its own process in a job of its own (a
//! nested job replaces the innermost job that the job test reads) and starts the guard from a
//! process whose parent has exited, or that can set its own parent, can still summon a prompt; the
//! approval is still required.
//! Each attempt and the outcome is a line of the log. None of the calls `run`, `run_shell`,
//! `run_auto`, `run_hook` and `extend` asks; the entry points `main_full` and `main_deadline`
//! do, from the command line of the process, as the programs do.
//!
//! # The owner rule
//!
//! The guard ends the tree when the process that launched it exits, and in a
//! library call that process is the caller's parent, not the caller. [`run`] and
//! [`run_shell`] watch the parent of the calling process, and [`run_auto`] watches
//! every live ancestor of it. So a caller whose parent is gone cannot run a
//! command to its end. If Windows no longer has a record of the parent, the call
//! returns a [`GuardError`] carrying the Windows error 87 text, as in 1.x; if another
//! process still holds that record, the command is started and ended at once and
//! the call returns `Ok(125)`. A caller whose parent exits during the call has its
//! command tree ended and gets `Ok(125)` as well. The parent is identified by its
//! process ID when the call starts, and Windows may reuse an ID once its process
//! has exited, so a call made after the parent exited can end up watching an
//! unrelated process that has taken the ID. A long-lived embedder should call the
//! guard from a process whose parent outlives the call, or start the
//! `process-tree-guard` program as a child, which then watches the embedder itself.

mod auth;
mod base64;
mod cli;
mod engine;
mod extend;
mod hook;
mod sys;

pub use extend::{Grant, CHANNEL_VARIABLE, DEFAULT_MAX_EXTENSION};

use std::ffi::OsString;
use std::fmt;

/// The longest deadline the guard accepts, in seconds (24 hours).
pub const MAX_SECONDS: f64 = 86400.0;

/// A guard error: invalid arguments, a program that is not found, or a failed
/// system call. The command line programs report it on standard error as
/// `PROCESS_GUARD_ERROR: MESSAGE` and exit with 125.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardError(String);

impl GuardError {
    /// The error text, without the `PROCESS_GUARD_ERROR` prefix.
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for GuardError {}

/// A shell the guard can run an encoded command line in. PowerShell and `cmd` are
/// found as the `PATH` search for a command finds them, as in 1.x.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Shell {
    /// `pwsh.exe` when the `PATH` search finds one, otherwise `powershell.exe`.
    PowerShell,
    /// Git Bash at `C:/Program Files/Git/bin/bash.exe`.
    Bash,
    /// The program named by `COMSPEC`, otherwise `cmd.exe`.
    Cmd,
}

impl Shell {
    /// The name used on the command line: `powershell`, `bash` or `cmd`.
    pub fn name(self) -> &'static str {
        match self {
            Shell::PowerShell => "powershell",
            Shell::Bash => "bash",
            Shell::Cmd => "cmd",
        }
    }

    /// The shell with this command line name, if any.
    pub fn from_name(name: &str) -> Option<Shell> {
        [Shell::PowerShell, Shell::Bash, Shell::Cmd].into_iter().find(|shell| shell.name() == name)
    }
}

/// Run `command` (a program and its arguments) in a job object and end the
/// whole process tree after `seconds`. `seconds` must be finite, greater than
/// zero and at most [`MAX_SECONDS`]. Returns the command's exit code, 124 when
/// the deadline passed, or 125 when the owner exited: the owner is the calling
/// process's parent (see the owner rule in the crate documentation). When that
/// parent has already exited the call is an error, or returns 125 at once. Inside an
/// extendable run the call asks the run for `seconds` first (an error if the run refuses),
/// and the hold it makes is ended when the call returns; see the crate documentation.
pub fn run(command: &[String], seconds: f64) -> Result<u32, GuardError> {
    cli::check_seconds(seconds)?;
    if command.is_empty() {
        return Err(GuardError("a command is required".into()));
    }
    engine::run_library_job(command, seconds, None, false)
}

/// Run the Base64 encoded UTF-8 command text `command_b64` in `shell`, under the
/// same deadline and owner rules as [`run`]: the owner is the calling process's
/// parent, and when that parent has already exited the call is an error, or returns
/// 125 at once. The text must decode to a nonempty command with no NUL character.
pub fn run_shell(shell: Shell, command_b64: &str, seconds: f64) -> Result<u32, GuardError> {
    cli::check_seconds(seconds)?;
    let command = base64::decode_command(command_b64)?;
    let (argv, tail) = cli::shell_command(shell, command);
    engine::run_library_job(&argv, seconds, tail.as_deref(), false)
}

/// Automatic mode. `args` are the arguments after the program name (or after the
/// `auto` subcommand): `[--timeout SECONDS] [--shell powershell|bash|cmd] [--]
/// COMMAND...`. The deadline defaults to `PROCESS_TREE_GUARD_AUTO_TIMEOUT`, else
/// `PROCESS_GUARD_AUTO_TIMEOUT`, else `HARNESS_AUTO_TIMEOUT`, else two hours. The
/// owners are every live ancestor of the calling process, not only its parent: the
/// tree ends, with 125, when any of them exits. When the parent has already exited
/// the call is an error, or returns 125 at once.
pub fn run_auto(args: &[String]) -> Result<u32, GuardError> {
    cli::auto_with(args.to_vec(), true)
}

/// Ask the enclosing extendable run to hold the deadline of the calling process
/// for `seconds` from now. The run is the one named by `PROCESS_TREE_GUARD_CHANNEL`,
/// which an extendable `process-tree-guard` sets for its command. `seconds` is sent
/// as it is: the run refuses, and logs, a number that is not finite, not greater
/// than zero, over [`MAX_SECONDS`] or over its own cap. Returns the grant, or a
/// [`GuardError`] with the reason when the run refuses (the calling process is not
/// in its job, the request is invalid or over its cap, a rate limit, the run is
/// over), when it does not answer within a few seconds, or when there is no run to
/// ask. The hold ends when the calling process exits, or when the seconds run out.
pub fn extend(seconds: f64) -> Result<Grant, GuardError> {
    extend::request(extend::Target::Caller, seconds)
}

/// A hook mode of the full command: `pretooluse`, `cursor`, `cursor-context`,
/// `antigravity`, `antigravity-context` or `powershell-auto`; any other name is
/// `pretooluse`. Reads the host's payload on standard input and writes the host's
/// answer on standard output. Returns the exit code: 0 allows, 2 blocks (the
/// `antigravity` vendors always return 0). The files it looks for (the automatic
/// copy, `POLICY.md`) and the envelope it accepts follow the file name of the
/// running program, as for `process-tree-guard hook VENDOR`.
pub fn run_hook(vendor: &str) -> i32 {
    hook::main(vendor, Role::Full)
}

/// Which program is running; each role has its own set of modes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Full,
    Deadline,
    Gate,
    Contain,
}

/// The arguments after the first `skip` as text, or an error when one is not Unicode.
fn text_args(skip: usize) -> Result<Vec<String>, GuardError> {
    std::env::args_os().skip(skip)
        .map(|arg| arg.into_string().map_err(|_: OsString| GuardError("arguments must be valid Unicode".into())))
        .collect()
}

/// Report an outcome as the exit code of the process.
fn finish(result: Result<u32, GuardError>) -> i32 {
    match result {
        Ok(code) => code as i32,
        Err(error) => {
            // Not `eprintln!`: a standard error whose reader has gone must not turn 125 into a crash.
            // And one write for the line, as the log writes its lines, so that neither lands inside the other.
            extend::write_standard_error(&format!("PROCESS_GUARD_ERROR: {}", error));
            125
        }
    }
}

fn entry(role: Role) -> i32 {
    let code = entry_of(role);
    // What the trace kept and no run wrote: an argument error, or a hook.
    engine::flush_trace(None);
    code
}

fn entry_of(role: Role) -> i32 {
    engine::trace("start");
    let mut args = std::env::args_os().skip(1);
    if role == Role::Gate {
        let first = args.next().and_then(|v| v.into_string().ok());
        // The gate would otherwise read the help flag as a vendor and wait for a payload.
        if matches!(first.as_deref(), Some("-h" | "--help")) {
            cli::say(cli::GATE_USAGE);
            return 0;
        }
        let vendor = first.unwrap_or_else(|| "pretooluse".into());
        return hook::main(&vendor, Role::Gate);
    }
    // The contain role runs one command in an extendable run: no automatic mode, no
    // hook, whatever its file name.
    if role == Role::Contain {
        return finish(text_args(1).and_then(|args| cli::run_args(args, role)));
    }
    // Installed under a name ending in "-auto", the program is the automatic
    // wrapper itself, so a host can name it as a single program path. Only the
    // ending is read, so process-tree-guard-auto and the 1.x alias
    // process-guard-auto select it alike.
    let auto_by_name = std::env::current_exe().ok()
        .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().to_ascii_lowercase()))
        .map_or(false, |s| s.ends_with("-auto"));
    if auto_by_name {
        return finish(text_args(1).and_then(cli::auto));
    }
    match args.next().as_deref().and_then(|a| a.to_str()) {
        Some("hook") if role == Role::Full => {
            let vendor = args.next().and_then(|v| v.into_string().ok()).unwrap_or_else(|| "pretooluse".into());
            return hook::main(&vendor, Role::Full);
        }
        Some("auto") => return finish(text_args(2).and_then(cli::auto)),
        Some("extend") => return finish(text_args(2).and_then(cli::extend_command)),
        _ => {}
    }
    finish(text_args(1).and_then(|args| cli::run_args(args, role)))
}

/// The entry point of `process-tree-guard`, the full command: `--timeout` (with
/// `--extendable`), the `extend`, `auto` and `hook` subcommands and automatic mode
/// by a file name ending in `-auto`. Returns the exit code for `std::process::exit`.
pub fn main_full() -> i32 {
    entry(Role::Full)
}

/// The entry point of `process-tree-guard-deadline`, the deadline role: the full
/// command with `--timeout` (and `--extendable`), `extend` or automatic mode, and
/// no hook mode. Returns the exit code for `std::process::exit`.
pub fn main_deadline() -> i32 {
    entry(Role::Deadline)
}

/// The entry point of `process-tree-guard-gate`, the hook role:
/// `process-tree-guard-gate VENDOR` takes the vendors and formats of
/// `process-tree-guard hook VENDOR`, with `pretooluse` when no vendor is given.
/// It differs in the envelope set it accepts, the automatic copy it rewrites to,
/// and `-h` and `--help`: as its first argument, either prints the usage and
/// returns 0 without reading standard input, and the gate has no other options.
/// The program is the hook role whatever its file name: it keeps the gate's
/// envelope and wrapper rules and never accepts an envelope that names its own
/// path, in whatever letter case it was started. Returns the exit code for
/// `std::process::exit`.
pub fn main_gate() -> i32 {
    entry(Role::Gate)
}

/// The entry point of `process-tree-guard-contain`, the contain role:
/// `process-tree-guard-contain --timeout SECONDS COMMAND...` runs the command in a
/// job of its own as a child of an extendable run. Its `--timeout` is a request to
/// the run that encloses it, which is refused (exit code 125) when it is over the
/// run's cap; with no such run it refuses to start, with 125, because it never
/// runs a command without a deadline that something finite holds. It takes no
/// extension options and has no automatic or hook mode, whatever its file name.
/// Returns the exit code for `std::process::exit`.
pub fn main_contain() -> i32 {
    entry(Role::Contain)
}
