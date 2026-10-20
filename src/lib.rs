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
//! The crate builds three programs, each a thin `main` over this library:
//!
//! | Program | Role | Entry point |
//! |---|---|---|
//! | `process-tree-guard` | the full command: every mode | [`main_full`] |
//! | `process-tree-guard-deadline` | the deadline role: `--timeout` and automatic mode | [`main_deadline`] |
//! | `process-tree-guard-gate` | the hook role: `process-tree-guard-gate VENDOR` takes the vendors and formats of `process-tree-guard hook VENDOR` | [`main_gate`] |
//!
//! The 1.x names `process-guard` and `process-guard-auto` are aliases of
//! `process-tree-guard` through all of 2.x. Dispatch is by the program's file
//! name: a name ending in `-auto` selects automatic mode in the full command and
//! in the deadline role, and the 1.x names behave exactly as the 2.0 names. The hook role is the
//! exception: it is the hook role under any file name, because the program
//! decides its rules (see [`main_gate`]).
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
//! are written to the caller's standard error, as the programs write them.
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

mod base64;
mod cli;
mod engine;
mod hook;
mod sys;

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
/// parent has already exited the call is an error, or returns 125 at once.
pub fn run(command: &[String], seconds: f64) -> Result<u32, GuardError> {
    cli::check_seconds(seconds)?;
    if command.is_empty() {
        return Err(GuardError("a command is required".into()));
    }
    engine::run_job(command, seconds, None, false)
}

/// Run the Base64 encoded UTF-8 command text `command_b64` in `shell`, under the
/// same deadline and owner rules as [`run`]: the owner is the calling process's
/// parent, and when that parent has already exited the call is an error, or returns
/// 125 at once. The text must decode to a nonempty command with no NUL character.
pub fn run_shell(shell: Shell, command_b64: &str, seconds: f64) -> Result<u32, GuardError> {
    cli::check_seconds(seconds)?;
    let command = base64::decode_command(command_b64)?;
    let (argv, tail) = cli::shell_command(shell, command);
    engine::run_job(&argv, seconds, tail.as_deref(), false)
}

/// Automatic mode. `args` are the arguments after the program name (or after the
/// `auto` subcommand): `[--timeout SECONDS] [--shell powershell|bash|cmd] [--]
/// COMMAND...`. The deadline defaults to `PROCESS_TREE_GUARD_AUTO_TIMEOUT`, else
/// `PROCESS_GUARD_AUTO_TIMEOUT`, else `HARNESS_AUTO_TIMEOUT`, else two hours. The
/// owners are every live ancestor of the calling process, not only its parent: the
/// tree ends, with 125, when any of them exits. When the parent has already exited
/// the call is an error, or returns 125 at once.
pub fn run_auto(args: &[String]) -> Result<u32, GuardError> {
    cli::auto(args.to_vec())
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
            eprintln!("PROCESS_GUARD_ERROR: {}", error);
            125
        }
    }
}

fn entry(role: Role) -> i32 {
    engine::trace("start");
    let mut args = std::env::args_os().skip(1);
    if role == Role::Gate {
        let first = args.next().and_then(|v| v.into_string().ok());
        // The gate would otherwise read the help flag as a vendor and wait for a payload.
        if matches!(first.as_deref(), Some("-h" | "--help")) {
            println!("{}", cli::GATE_USAGE);
            return 0;
        }
        let vendor = first.unwrap_or_else(|| "pretooluse".into());
        return hook::main(&vendor, Role::Gate);
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
        _ => {}
    }
    finish(text_args(1).and_then(cli::run_args))
}

/// The entry point of `process-tree-guard`, the full command: `--timeout`, the
/// `auto` subcommand, the `hook` subcommand and automatic mode by a file name
/// ending in `-auto`. Returns the exit code for `std::process::exit`.
pub fn main_full() -> i32 {
    entry(Role::Full)
}

/// The entry point of `process-tree-guard-deadline`, the deadline role: the full
/// command with `--timeout` or automatic mode, and no hook mode. Returns the
/// exit code for `std::process::exit`.
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
