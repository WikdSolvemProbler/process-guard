// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! The command line forms: `--timeout SECONDS ...` and automatic mode.

use crate::base64::{base64_encode, decode_command};
use crate::engine::{parent_image, run_job, which};
use crate::{GuardError, Shell, MAX_SECONDS};

pub const USAGE: &str = "usage: process-tree-guard --timeout SECONDS (--shell {powershell,bash,cmd} --command-b64 BASE64 | [--] COMMAND [ARGS...])";

/// What `process-tree-guard-gate -h` prints: the gate takes no deadline, only a vendor.
pub const GATE_USAGE: &str = "usage: process-tree-guard-gate [VENDOR]  (VENDOR: pretooluse, cursor, cursor-context, antigravity, antigravity-context or powershell-auto; reads the hook payload on standard input; the default is pretooluse)";

/// Seconds that are finite, greater than zero and at most MAX_SECONDS.
pub fn check_seconds(seconds: f64) -> Result<f64, GuardError> {
    if !seconds.is_finite() || seconds <= 0.0 || seconds > MAX_SECONDS {
        return Err(GuardError("timeout must be greater than zero and at most 86400 seconds".into()));
    }
    Ok(seconds)
}

/// Seconds from text: a finite number greater than zero and at most 86400.
fn duration(value: &str) -> Result<f64, GuardError> {
    let seconds: f64 = value.trim().parse().map_err(|_| GuardError("timeout must be a number".into()))?;
    check_seconds(seconds)
}

/// The argument list and verbatim `cmd` tail that run `command` in `shell`. The
/// PowerShell and `cmd` programs are named as in 1.x and found when the job starts.
pub fn shell_command(shell: Shell, command: String) -> (Vec<String>, Option<String>) {
    match shell {
        Shell::PowerShell => {
            let utf16: Vec<u8> = command.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            let host = which("pwsh.exe").unwrap_or_else(|| "powershell.exe".into());
            (vec![host, "-NoLogo".into(), "-NoProfile".into(), "-NonInteractive".into(), "-EncodedCommand".into(), base64_encode(&utf16)], None)
        }
        Shell::Bash => (vec!["C:/Program Files/Git/bin/bash.exe".into(), "--noprofile".into(), "--norc".into(), "-c".into(), command], None),
        Shell::Cmd => (vec![std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".into()), "/d".into(), "/s".into(), "/c".into()], Some(command)),
    }
}

struct Options {
    help: bool,
    timeout: Option<String>,
    shell: Option<String>,
    command_b64: Option<String>,
    command: Vec<String>,
}

/// Parse the argument list. Errors become exit 125, never 2. `-h` and `--help`
/// stop the parse and ask for the usage text.
fn parse(args: Vec<String>) -> Result<Options, GuardError> {
    let mut options = Options { help: false, timeout: None, shell: None, command_b64: None, command: Vec::new() };
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if !arg.starts_with('-') || arg == "--" {
            options.command = args[i..].to_vec();
            break;
        }
        if arg == "-h" || arg == "--help" {
            options.help = true;
            break;
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
                if Shell::from_name(&value).is_none() {
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

/// `--timeout SECONDS (--shell SHELL --command-b64 BASE64 | [--] COMMAND [ARGS...])`,
/// with `args` the arguments after the program name.
pub fn run_args(args: Vec<String>) -> Result<u32, GuardError> {
    let options = parse(args)?;
    if options.help {
        println!("{}", USAGE);
        return Ok(0);
    }
    let timeout = options.timeout.ok_or_else(|| GuardError("the following arguments are required: --timeout".into()))?;
    let seconds = duration(&timeout)?;
    let mut raw_tail: Option<String> = None;
    let child: Vec<String> = if let Some(shell) = options.shell {
        let encoded = match (&options.command_b64, options.command.is_empty()) {
            (Some(b64), true) => b64,
            _ => return Err(GuardError("--shell requires --command-b64 and no additional arguments".into())),
        };
        let command = decode_command(encoded)?;
        let shell = Shell::from_name(&shell).expect("the shell was checked when the arguments were parsed");
        let (child, tail) = shell_command(shell, command);
        raw_tail = tail;
        child
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
    run_job(&child, seconds, raw_tail.as_deref(), false)
}

/// Default hard deadline for `auto` mode: two hours, the longest any host shell call may run.
const AUTO_DEFAULT_SECONDS: f64 = 7200.0;

/// The environment variables that set the automatic deadline, in the order they
/// are read: the 2.0 name, the 1.x name (an alias through 2.x), then the legacy
/// host name. The first one that is set is used.
const AUTO_TIMEOUT_VARIABLES: [&str; 3] = ["PROCESS_TREE_GUARD_AUTO_TIMEOUT", "PROCESS_GUARD_AUTO_TIMEOUT", "HARNESS_AUTO_TIMEOUT"];

/// The value of the first of AUTO_TIMEOUT_VARIABLES that `lookup` finds.
fn auto_timeout_setting(lookup: impl Fn(&str) -> Option<String>) -> Option<String> {
    AUTO_TIMEOUT_VARIABLES.iter().find_map(|name| lookup(name))
}

/// `auto [--timeout SECONDS] [--shell powershell|bash|cmd] [--] COMMAND...`, with
/// `args` the arguments after the program name (or after the `auto` subcommand).
///
/// The automatic wrapper a host puts in front of every shell command. One
/// remaining argument is a command line for a shell: the shell named by
/// --shell, otherwise the same kind of shell that launched the guard (Git
/// Bash when unknown). Several remaining arguments are a program and its
/// arguments. The deadline is --timeout, else the first of
/// AUTO_TIMEOUT_VARIABLES that is set, else two hours. The host's own
/// per-call timeout still applies: when the host kills the process that
/// launched the guard, the guard kills the whole tree.
pub fn auto(args: Vec<String>) -> Result<u32, GuardError> {
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
        return run_job(&rest, seconds, None, true);
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
    let shell = Shell::from_name(&shell).ok_or_else(|| GuardError(format!("argument --shell: invalid choice: '{}'", shell)))?;
    let (mut child, tail) = shell_command(shell, command);
    // PowerShell runs in the same edition that called the wrapper (Windows
    // PowerShell or PowerShell 7), so behaviour matches an unwrapped call.
    if shell == Shell::PowerShell && parent_is_powershell && !parent.is_empty() {
        child[0] = parent.clone();
    }
    run_job(&child, seconds, tail.as_deref(), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_bounds() {
        assert!(duration(".3").is_ok());
        assert!(duration("86400").is_ok());
        for bad in ["0", "-1", "nan", "inf", "86401", "x", ""] {
            assert!(duration(bad).is_err(), "{}", bad);
        }
        assert!(check_seconds(0.5).is_ok());
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY, 86401.0] {
            assert!(check_seconds(bad).is_err(), "{}", bad);
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
    fn argument_errors_never_exit_two() {
        assert!(parse(vec!["--bogus".into(), "1".into()]).is_err());
        assert!(matches!(parse(vec!["--bogus".into()]), Err(GuardError(m)) if m.starts_with("unrecognized")));
        assert!(parse(vec!["--shell".into(), "zsh".into()]).is_err());
        assert!(parse(vec!["--timeout".into()]).is_err());
        let ok = parse(vec!["--timeout=5".into(), "--".into(), "x".into()]).ok().unwrap();
        assert_eq!(ok.timeout.as_deref(), Some("5"));
        assert_eq!(ok.command, vec!["--".to_string(), "x".to_string()]);
        assert!(parse(vec!["--help".into()]).ok().unwrap().help);
        assert!(parse(vec!["-h".into(), "--bogus".into()]).ok().unwrap().help);
    }

    #[test]
    fn shell_commands_name_the_shell_host() {
        let (cmd, tail) = shell_command(Shell::Cmd, "echo x".into());
        assert_eq!(cmd[1..], ["/d", "/s", "/c"]);
        assert_eq!(cmd[0], std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".into()));
        assert_eq!(tail.as_deref(), Some("echo x"));
        let (bash, tail) = shell_command(Shell::Bash, "echo x".into());
        assert_eq!(bash.last().map(String::as_str), Some("echo x"));
        assert!(tail.is_none());
        let (ps, _) = shell_command(Shell::PowerShell, "echo x".into());
        assert_eq!(ps[0], which("pwsh.exe").unwrap_or_else(|| "powershell.exe".into()));
        assert_eq!(ps[ps.len() - 2], "-EncodedCommand");
        assert_eq!(ps[ps.len() - 1], base64_encode(&"echo x".encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<u8>>()));
    }
}
