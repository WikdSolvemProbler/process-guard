// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! `process-tree-guard hook VENDOR`: the command envelope check for agent shell tools.
//!
//! Reads the host's pre-execution hook payload as JavaScript Object Notation
//! (JSON) on standard input and allows the command only when it is exactly the
//! guard envelope:
//!
//! ```text
//! <this executable> --timeout SECONDS --shell powershell|bash|cmd --command-b64 BASE64
//! ```
//!
//! with forward slashes in the executable path, an optional leading `& `, a
//! timeout above zero and at most 86400, and a payload that decodes to nonempty
//! UTF-8 with no NUL. Anything else is denied with exit code 2, which is how a
//! host hook blocks a tool call; this is the one place the guard uses exit 2 on purpose.
//!
//! The executable has two names, `process-tree-guard` and the 1.x alias
//! `process-guard`, kept through all of 2.x. When it is installed under either
//! name, the envelope may name either name in the same folder, and the automatic
//! wrapper is the one of the executable's own name.
//!
//! The hook role, `process-tree-guard-gate`, runs the same modes. It never runs a
//! command itself, so an envelope never names it: the envelope names a program
//! that enforces the deadline (`process-tree-guard`, `process-guard` or
//! `process-tree-guard-deadline`) in the gate's own folder or, when the gate is
//! in a folder named `libexec` (in any letter case), in the `bin` folder beside it. Its automatic
//! wrapper is `process-tree-guard-deadline-auto` in its own folder. Every path is
//! built from the gate's own location and never from `PATH`. The rules follow the
//! program, not its file name: the hook role keeps them under any file name, and
//! never accepts its own path whatever it is called, while the full command keeps
//! the rules of its name even when it is called `process-tree-guard-gate`.
//!
//! Formats: `pretooluse` reads `tool_input.command` (or `tool_input.cmd`) and
//! answers in the PreToolUse format; `cursor` reads `command` and answers in the
//! beforeShellExecution format; `cursor-context` prints the policy as session context.
//!
//! `antigravity` is different: it rewrites instead of only checking. It reads a
//! Google Antigravity PreToolUse payload, and for the `run_command` tool replaces
//! `CommandLine` with a call to the automatic wrapper beside this executable (the
//! wrapper of its own name), so the command runs under the guard. Every outcome, denials included, is a JSON decision
//! on standard output and the exit code is always 0. `antigravity-context` prints the
//! policy as a SessionStart system message.
//!
//! `powershell-auto` also rewrites: it reads a PreToolUse payload for a PowerShell
//! tool and replaces `tool_input.command` with a call to the automatic wrapper, so
//! the command runs under the guard.

use crate::Role;
use std::io::{Read, Write};

#[derive(Debug)]
pub enum Json {
    Null,
    Bool(bool),
    Number(f64),
    Str(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(pairs) => pairs.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.pos < self.bytes.len() && matches!(self.bytes[self.pos], b' ' | b'\t' | b'\n' | b'\r') {
            self.pos += 1;
        }
    }
    fn eat(&mut self, b: u8) -> Option<()> {
        self.ws();
        if self.bytes.get(self.pos) == Some(&b) { self.pos += 1; Some(()) } else { None }
    }
    fn literal(&mut self, word: &str, value: Json) -> Option<Json> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) { self.pos += word.len(); Some(value) } else { None }
    }
    fn value(&mut self) -> Option<Json> {
        self.ws();
        self.depth += 1;
        if self.depth > 256 {
            return None;
        }
        let result = match *self.bytes.get(self.pos)? {
            b'{' => {
                self.pos += 1;
                let mut pairs = Vec::new();
                if self.eat(b'}').is_none() {
                    loop {
                        self.ws();
                        let key = self.string()?;
                        self.eat(b':')?;
                        pairs.push((key, self.value()?));
                        if self.eat(b',').is_some() { continue; }
                        self.eat(b'}')?;
                        break;
                    }
                }
                Json::Object(pairs)
            }
            b'[' => {
                self.pos += 1;
                let mut items = Vec::new();
                if self.eat(b']').is_none() {
                    loop {
                        items.push(self.value()?);
                        if self.eat(b',').is_some() { continue; }
                        self.eat(b']')?;
                        break;
                    }
                }
                Json::Array(items)
            }
            b'"' => Json::Str(self.string()?),
            b't' => self.literal("true", Json::Bool(true))?,
            b'f' => self.literal("false", Json::Bool(false))?,
            b'n' => self.literal("null", Json::Null)?,
            _ => {
                let start = self.pos;
                while self.pos < self.bytes.len() && matches!(self.bytes[self.pos], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9') {
                    self.pos += 1;
                }
                let text = std::str::from_utf8(&self.bytes[start..self.pos]).ok()?;
                Json::Number(text.parse().ok()?)
            }
        };
        self.depth -= 1;
        Some(result)
    }
    fn hex4(&mut self) -> Option<u32> {
        let text = std::str::from_utf8(self.bytes.get(self.pos..self.pos + 4)?).ok()?;
        self.pos += 4;
        u32::from_str_radix(text, 16).ok()
    }
    fn string(&mut self) -> Option<String> {
        if self.bytes.get(self.pos) != Some(&b'"') {
            return None;
        }
        self.pos += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let b = *self.bytes.get(self.pos)?;
            self.pos += 1;
            match b {
                b'"' => return String::from_utf8(out).ok(),
                b'\\' => {
                    let e = *self.bytes.get(self.pos)?;
                    self.pos += 1;
                    let c = match e {
                        b'"' => '"', b'\\' => '\\', b'/' => '/', b'b' => '\u{8}', b'f' => '\u{c}',
                        b'n' => '\n', b'r' => '\r', b't' => '\t',
                        b'u' => {
                            let mut unit = self.hex4()?;
                            if (0xD800..0xDC00).contains(&unit) {
                                if self.bytes.get(self.pos..self.pos + 2)? != b"\\u" { return None; }
                                self.pos += 2;
                                let low = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&low) { return None; }
                                unit = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00);
                            }
                            char::from_u32(unit)?
                        }
                        _ => return None,
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
                0..=0x1f => return None,
                _ => out.push(b),
            }
        }
    }
}

pub fn parse_json(text: &str) -> Option<Json> {
    let mut parser = Parser { bytes: text.as_bytes(), pos: 0, depth: 0 };
    let value = parser.value()?;
    parser.ws();
    if parser.pos == parser.bytes.len() { Some(value) } else { None }
}

/// Compact JSON text for a parsed value.
pub fn to_json(value: &Json) -> String {
    match value {
        Json::Null => "null".into(),
        Json::Bool(b) => b.to_string(),
        Json::Number(n) if n.is_finite() => format!("{}", n),
        Json::Number(_) => "null".into(),
        Json::Str(s) => quote(s),
        Json::Array(items) => format!("[{}]", items.iter().map(to_json).collect::<Vec<_>>().join(",")),
        Json::Object(pairs) => format!("{{{}}}", pairs.iter().map(|(k, v)| format!("{}:{}", quote(k), to_json(v))).collect::<Vec<_>>().join(",")),
    }
}

/// The two names of the one executable, the 2.0 name first. `process-guard` is the
/// 1.x name, an alias through all of 2.x; each name also has an automatic copy, the
/// same name with `-auto` added.
const NAMES: [&str; 2] = ["process-tree-guard", "process-guard"];

/// The folder of `exe` and the index in NAMES of its program name, when it has one.
fn family(exe: &str) -> Option<(&str, usize)> {
    let (dir, file) = exe.rsplit_once('/')?;
    let lower = file.to_ascii_lowercase();
    let stem = lower.strip_suffix(".exe")?;
    NAMES.iter().position(|name| *name == stem).map(|index| (dir, index))
}

/// The deadline role, which the hook role vouches for.
const DEADLINE: &str = "process-tree-guard-deadline";

/// The paths a guard envelope may name when the hook runs as the hook role in
/// `dir`: the programs that enforce a deadline, in `dir` and, in the install
/// layout (the last folder of `dir` is named `libexec`, in any letter case, as
/// Windows folder names are not case sensitive), in the `bin` folder beside it, with
/// the rest of the path as it is spelled. The hook role itself is never among them,
/// whatever its file name (`exe`), because it would not run the command.
fn gate_envelope_paths(exe: &str, dir: &str) -> Vec<String> {
    let mut folders = vec![dir.to_string()];
    if let Some((root, last)) = dir.rsplit_once('/') {
        if last.eq_ignore_ascii_case("libexec") {
            folders.push(format!("{}/bin", root));
        }
    }
    let mut paths = Vec::new();
    for folder in &folders {
        for name in [NAMES[0], NAMES[1], DEADLINE] {
            paths.push(format!("{}/{}.exe", folder, name));
        }
    }
    // Windows paths are not case sensitive, and `exe` keeps the case it was started with.
    paths.retain(|path| !path.eq_ignore_ascii_case(exe));
    paths
}

/// The paths a guard envelope may name when this executable is `exe`: `exe` itself
/// and, when it is installed under one of the two names, the other name in the
/// same folder; for the hook role, see `gate_envelope_paths`. The other file need
/// not exist; a command that names a missing program only fails to run.
fn envelope_paths(exe: &str, role: Role) -> Vec<String> {
    if role == Role::Gate {
        return exe.rsplit_once('/').map_or_else(Vec::new, |(dir, _)| gate_envelope_paths(exe, dir));
    }
    let mut paths = vec![exe.to_string()];
    if let Some((dir, own)) = family(exe) {
        paths.push(format!("{}/{}.exe", dir, NAMES[1 - own]));
    }
    paths
}

/// The automatic wrapper paths beside `exe`: the wrapper of its own name first,
/// then the other name's. An executable under any other name keeps the 1.x
/// behaviour: only `process-guard-auto.exe`. The hook role's own wrapper is
/// `process-tree-guard-deadline-auto.exe` in its folder, then the two names'
/// wrappers there. None when `exe` has no folder.
pub fn wrapper_paths(exe: &str, role: Role) -> Option<Vec<String>> {
    let (dir, _) = exe.rsplit_once('/')?;
    let auto = |name: &str| format!("{}/{}-auto.exe", dir, name);
    if role == Role::Gate {
        return Some(vec![auto(DEADLINE), auto(NAMES[0]), auto(NAMES[1])]);
    }
    Some(match family(exe) {
        Some((_, own)) => vec![auto(NAMES[own]), auto(NAMES[1 - own])],
        None => vec![auto(NAMES[1])],
    })
}

/// The PowerShell command line that runs `command` under the automatic guard.
pub fn powershell_wrapped(auto_exe: &str, command: &str) -> String {
    let utf8 = crate::base64::base64_encode(command.as_bytes());
    format!("& '{}' --shell powershell --command-b64 {}; exit $LASTEXITCODE", auto_exe.replace('\'', "''"), utf8)
}

/// `hook powershell-auto`: rewrite a PowerShell tool call so the automatic
/// guard runs it. A command that already starts with a guard path is left as is.
pub fn powershell_auto(exe: &str, role: Role) -> i32 {
    let wrappers = match wrapper_paths(exe, role) {
        Some(paths) => paths,
        None => return 0,
    };
    let auto_exe = wrappers[0].clone();
    let mut input = String::new();
    if std::io::stdin().take(16 * 1024 * 1024).read_to_string(&mut input).is_err() {
        return 0;
    }
    let payload = match parse_json(&input) { Some(p) => p, None => return 0 };
    let tool_input = match payload.get("tool_input") { Some(Json::Object(pairs)) => pairs.clone_pairs(), _ => return 0 };
    let command = match tool_input.iter().find(|(k, _)| k == "command").and_then(|(_, v)| v.as_str()) {
        Some(c) => c.to_string(),
        None => return 0,
    };
    // Pass through unchanged only what is already exactly guarded: this hook's
    // own wrapping (with either name's wrapper), or a valid envelope. Anything
    // else, including a command that merely starts with a guard path, is wrapped
    // again (a double guard is harmless).
    let wrapped_already = |wrapper: &String| command.trim()
        .strip_prefix(&format!("& '{}' --shell powershell --command-b64 ", wrapper.replace('\'', "''")))
        .and_then(|r| r.strip_suffix("; exit $LASTEXITCODE"))
        .map_or(false, |b64| crate::base64::decode_command(b64).is_ok());
    let already = valid_envelope(&command, exe, role) || wrappers.iter().any(wrapped_already);
    if already {
        println!("{{}}");
        return 0;
    }
    let mut updated = tool_input;
    for (k, v) in updated.iter_mut() {
        if k == "command" {
            *v = Json::Str(powershell_wrapped(&auto_exe, &command));
        }
    }
    let bypass = payload.get("permission_mode").and_then(Json::as_str) == Some("bypassPermissions");
    println!("{{\"hookSpecificOutput\":{{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":{},\"permissionDecisionReason\":{},\"updatedInput\":{}}}}}",
        quote(if bypass { "allow" } else { "ask" }),
        quote("Command runs under the process guard (automatic deadline and process tree cleanup)."),
        to_json(&Json::Object(updated)));
    0
}

trait ClonePairs {
    fn clone_pairs(&self) -> Vec<(String, Json)>;
}

impl ClonePairs for Vec<(String, Json)> {
    fn clone_pairs(&self) -> Vec<(String, Json)> {
        self.iter().map(|(k, v)| (k.clone(), v.deep_clone())).collect()
    }
}

impl Json {
    fn deep_clone(&self) -> Json {
        match self {
            Json::Null => Json::Null,
            Json::Bool(b) => Json::Bool(*b),
            Json::Number(n) => Json::Number(*n),
            Json::Str(s) => Json::Str(s.clone()),
            Json::Array(items) => Json::Array(items.iter().map(Json::deep_clone).collect()),
            Json::Object(pairs) => Json::Object(pairs.clone_pairs()),
        }
    }
}

pub fn quote(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The executable path exactly as the envelope must spell it: forward slashes.
pub fn self_path() -> Option<String> {
    let path = std::env::current_exe().ok()?;
    let text = path.to_str()?.replace('\\', "/");
    Some(text.strip_prefix("//?/").unwrap_or(&text).to_string())
}

/// True when `command` is exactly the guard envelope for executable `exe`, or for
/// the same executable under its other name (see `envelope_paths`).
pub fn valid_envelope(command: &str, exe: &str, role: Role) -> bool {
    envelope_paths(exe, role).iter().any(|path| envelope_for(command, path))
}

/// True when `command` is exactly the guard envelope naming the executable `exe`.
fn envelope_for(command: &str, exe: &str) -> bool {
    let mut rest = command.trim();
    if let Some(r) = rest.strip_prefix("& ") {
        rest = r;
    }
    let rest = match rest.strip_prefix(exe).and_then(|r| r.strip_prefix(" --timeout ")) {
        Some(r) => r,
        None => return false,
    };
    let (timeout, rest) = match rest.split_once(' ') {
        Some(pair) => pair,
        None => return false,
    };
    let mut parts = timeout.splitn(2, '.');
    let whole = parts.next().unwrap_or("");
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(whole) || !parts.next().map_or(true, digits) {
        return false;
    }
    match timeout.parse::<f64>() {
        Ok(t) if t > 0.0 && t <= 86400.0 => {}
        _ => return false,
    }
    let rest = match rest.strip_prefix("--shell ") {
        Some(r) => r,
        None => return false,
    };
    let rest = ["powershell", "bash", "cmd"].iter().find_map(|s| rest.strip_prefix(s)).and_then(|r| r.strip_prefix(" --command-b64 "));
    let payload = match rest {
        Some(p) => p,
        None => return false,
    };
    let body = payload.trim_end_matches('=');
    if payload.len() - body.len() > 2 || body.is_empty() || !body.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/') {
        return false;
    }
    crate::base64::decode_command(payload).is_ok()
}

/// The policy file of the executable at `exe`: `POLICY.md` in the folder above the
/// executable's own folder, whatever those folders are called.
fn policy_path(exe: &str) -> Option<String> {
    let (dir, _) = exe.rsplit_once('/')?;
    let (root, _) = dir.rsplit_once('/')?;
    Some(format!("{}/POLICY.md", root))
}

/// The text of the policy file found relative to this executable alone.
fn policy_text() -> String {
    self_path().as_deref().and_then(policy_path)
        .and_then(|path| std::fs::read_to_string(path).ok())
        .unwrap_or_else(|| "POLICY.md not found beside the installed process guard.".into())
}

/// True when every character of `path` is in `[A-Za-z0-9:/._-]`, so the path can
/// be written without quoting and parse the same in PowerShell, cmd and Git Bash.
fn plain_path(path: &str) -> bool {
    path.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'/' | b'.' | b'_' | b'-'))
}

/// The longest rewritten `CommandLine` the hook produces, in characters. Wrapping
/// grows a command by about 4/3 plus the wrapper path, and `cmd.exe` cannot run a
/// line of more than 8191 characters; the margin leaves room for the host's own
/// `cmd.exe /d /s /c "` prefix. The hook cannot know which shell the host uses, so
/// a longer command is denied with an explanation instead of failing with a shell error.
const MAX_REWRITTEN_LINE: usize = 8000;

/// The command line that runs `command` under the automatic wrapper at `wrapper`.
pub fn antigravity_wrapped(wrapper: &str, command: &str) -> String {
    format!("{} --command-b64 {}", wrapper, crate::base64::base64_encode(command.as_bytes()))
}

/// True when `command` is exactly the wrapper form `<wrapper> --command-b64 BASE64`
/// with a payload that decodes to a valid command, or a valid guard envelope. The
/// wrapper is either name's automatic copy beside `exe`, and the envelope names
/// either name of the executable. Nothing else counts: trailing text, other
/// separators, another path or a path in another case are wrapped again.
pub fn antigravity_guarded(command: &str, exe: &str, role: Role) -> bool {
    // Shells split on ASCII space, tab and newline only; trimming anything wider
    // (a no-break space, a vertical tab) would pass a line the wrapper then rejects.
    let trimmed = command.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'));
    wrapper_paths(exe, role).unwrap_or_default().iter().any(|wrapper| {
        trimmed.strip_prefix(wrapper.as_str())
            .and_then(|r| r.strip_prefix(" --command-b64 "))
            .map_or(false, |b64| crate::base64::decode_command(b64).is_ok())
    })
        // valid_envelope trims Unicode whitespace itself; refuse what it would silently strip.
        || (trimmed.trim().len() == trimmed.len() && valid_envelope(trimmed, exe, role))
}

fn antigravity_deny(why: &str) -> String {
    format!("{{\"decision\":\"deny\",\"reason\":{}}}", quote(&format!(
        "TIMEOUT_REQUIRED: {} Native tool timeout alone does not guarantee child cleanup.", why)))
}

/// Whether `obj` is an object with more than one key equal to `key` in any ASCII letter
/// case, a repeated key included.
fn ambiguous(obj: &Json, key: &str) -> bool {
    match obj {
        Json::Object(pairs) => pairs.iter().filter(|(k, _)| k.eq_ignore_ascii_case(key)).count() > 1,
        _ => false,
    }
}

/// The one-line JSON decision for a Google Antigravity PreToolUse payload.
/// `exe` is this executable's path with forward slashes; `wrapper_exists` says
/// whether the automatic wrapper of its own name is present beside it.
fn antigravity_decision(exe: &str, role: Role, input: Option<&str>, wrapper_exists: bool) -> String {
    let payload = match input.and_then(parse_json) {
        Some(p) => p,
        None => return antigravity_deny("the hook payload is missing or is not valid JSON."),
    };
    // The hook reads exact keys. A host that matches keys without regard to case, or lets
    // another spelling or a repeated key win, could act on a different tool or command than
    // the one checked, so any second candidate for a key the hook reads is denied.
    if ambiguous(&payload, "toolCall") {
        return antigravity_deny("the hook payload holds ambiguous toolCall keys (more than one key that is toolCall in any letter case).");
    }
    if let Some(c) = payload.get("toolCall") {
        if let Some(key) = ["name", "args"].into_iter().find(|k| ambiguous(c, k)) {
            return antigravity_deny(&format!("the toolCall object holds ambiguous {} keys (more than one key that is {} in any letter case).", key, key));
        }
    }
    // A payload without a toolCall object that names its tool is not the documented
    // shape (the schema changed or the hook is miswired); it is denied, not waved through.
    let call = payload.get("toolCall").filter(|c| matches!(c, Json::Object(_)));
    match call.and_then(|c| c.get("name")).and_then(Json::as_str) {
        None => return antigravity_deny("the hook payload has no toolCall object with a string name, so it is not a recognised Antigravity PreToolUse payload."),
        Some("run_command") => {}
        Some(_) => return "{\"decision\":\"allow\"}".into(),
    }
    // The hook rewrites only the exact key `CommandLine`, under the same rule.
    if call.and_then(|c| c.get("args")).map_or(false, |a| ambiguous(a, "CommandLine")) {
        return antigravity_deny("run_command arguments hold ambiguous CommandLine keys (more than one key that is CommandLine in any letter case).");
    }
    let command = match call.and_then(|c| c.get("args")).and_then(|a| a.get("CommandLine")).and_then(Json::as_str) {
        Some(c) if !c.trim().is_empty() && !c.contains('\0') => c,
        _ => return antigravity_deny("run_command has no CommandLine, or it is empty or contains NUL."),
    };
    let wrapper = match wrapper_paths(exe, role).and_then(|paths| paths.into_iter().next()) {
        Some(path) => path,
        None => return antigravity_deny("the location of the process guard is unknown."),
    };
    if !wrapper_exists {
        return antigravity_deny(&format!("the automatic wrapper {} is missing beside the process guard.", wrapper));
    }
    if !plain_path(&wrapper) {
        return antigravity_deny("the process guard must be installed in a path with only the characters A-Z, a-z, 0-9, colon, slash, period, underscore and hyphen, so the rewritten command parses the same in every shell.");
    }
    if antigravity_guarded(command, exe, role) {
        return "{\"decision\":\"allow\"}".into();
    }
    let rewritten = antigravity_wrapped(&wrapper, command);
    if rewritten.len() > MAX_REWRITTEN_LINE {
        let fixed = antigravity_wrapped(&wrapper, "").len();
        return antigravity_deny(&format!("the command is too long to run under the guard: wrapping it makes a line of {} characters and the limit is {}, which allows a command of about {} bytes here. Write the long content to a file and run the file.",
            rewritten.len(), MAX_REWRITTEN_LINE, MAX_REWRITTEN_LINE.saturating_sub(fixed) / 4 * 3));
    }
    format!("{{\"decision\":\"allow\",\"reason\":{},\"overwrite\":{{\"CommandLine\":{}}}}}",
        quote("Command runs under the process guard (automatic deadline and process tree cleanup)."),
        quote(&rewritten))
}

/// `hook antigravity`: rewrite a Google Antigravity `run_command` call so the
/// automatic guard runs it. Every outcome is a JSON decision and the exit code is 0.
pub fn antigravity(exe: &str, role: Role) -> i32 {
    let mut input = String::new();
    let read = std::io::stdin().take(16 * 1024 * 1024).read_to_string(&mut input).is_ok();
    let wrapper_exists = wrapper_paths(exe, role).and_then(|paths| paths.into_iter().next()).map_or(false, |path| std::path::Path::new(&path).is_file());
    let line = antigravity_decision(exe, role, if read { Some(&input) } else { None }, wrapper_exists);
    let _ = writeln!(std::io::stdout(), "{}", line);
    0
}

/// `hook antigravity-context`: the policy as a SessionStart system message.
pub fn antigravity_context() -> i32 {
    let _ = writeln!(std::io::stdout(), "{{\"injectSteps\":[{{\"systemMessage\":{{\"systemMessage\":{}}}}}]}}", quote(&policy_text()));
    0
}

/// Run the hook as `role`: the hook role (`Role::Gate`) or any other program, whose
/// rules then follow its file name. Returns the process exit code: 0 allows, 2
/// blocks (the `antigravity` vendors always return 0).
pub fn main(vendor: &str, role: Role) -> i32 {
    let exe = self_path().unwrap_or_default();
    let policy = policy_path(&exe).unwrap_or_else(|| "POLICY.md".into());
    let reason = format!("TIMEOUT_REQUIRED: execute exactly the process-guard envelope with an explicit finite timeout. \
        No unwrapped commands, prefixes, suffixes, or polling-timeout substitutes. See {}. \
        Native tool timeout alone does not guarantee child cleanup.", policy);
    if vendor == "powershell-auto" {
        return powershell_auto(&exe, role);
    }
    if vendor == "antigravity" {
        return antigravity(&exe, role);
    }
    if vendor == "antigravity-context" {
        return antigravity_context();
    }
    if vendor == "cursor-context" {
        println!("{{\"additional_context\":{}}}", quote(&policy_text()));
        return 0;
    }
    let mut input = String::new();
    let allowed = std::io::stdin().take(16 * 1024 * 1024).read_to_string(&mut input).is_ok()
        && parse_json(&input).map_or(false, |payload| {
            let command = if vendor == "cursor" {
                payload.get("command")
            } else {
                payload.get("tool_input").and_then(|t| t.get("command").or_else(|| t.get("cmd")))
            };
            command.and_then(Json::as_str).map_or(false, |c| !exe.is_empty() && valid_envelope(c, &exe, role))
        });
    if allowed {
        println!("{}", if vendor == "cursor" { "{\"permission\":\"allow\"}" } else { "{}" });
        return 0;
    }
    if vendor == "cursor" {
        println!("{{\"permission\":\"deny\",\"user_message\":{0},\"agent_message\":{0}}}", quote(&reason));
    } else {
        println!("{{\"hookSpecificOutput\":{{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":{}}}}}", quote(&reason));
    }
    eprintln!("{}", reason);
    2
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The role a program has when it is called by `exe`: the hook role only under its own file name.
    fn role_of(exe: &str) -> Role {
        if exe.ends_with("/process-tree-guard-gate.exe") { Role::Gate } else { Role::Full }
    }

    // The rules below are written for programs under their own file names, so these
    // shadow the functions that take the role explicitly; the checks of a renamed
    // program call them as `super::...` with the role.
    fn valid_envelope(command: &str, exe: &str) -> bool {
        super::valid_envelope(command, exe, role_of(exe))
    }

    fn envelope_paths(exe: &str) -> Vec<String> {
        super::envelope_paths(exe, role_of(exe))
    }

    fn wrapper_paths(exe: &str) -> Option<Vec<String>> {
        super::wrapper_paths(exe, role_of(exe))
    }

    fn antigravity_guarded(command: &str, exe: &str) -> bool {
        super::antigravity_guarded(command, exe, role_of(exe))
    }

    fn antigravity_decision(exe: &str, input: Option<&str>, wrapper_exists: bool) -> String {
        super::antigravity_decision(exe, role_of(exe), input, wrapper_exists)
    }

    const EXE: &str = "C:/Tools/process-tree-guard/bin/process-guard.exe";

    #[test]
    fn envelope_accepts_only_the_exact_form() {
        let b64 = "ZWNobyBPSw=="; // "echo OK"
        let good = format!("{} --timeout 60 --shell powershell --command-b64 {}", EXE, b64);
        assert!(valid_envelope(&good, EXE));
        assert!(valid_envelope(&format!("& {}", good), EXE));
        assert!(valid_envelope(&format!("  {}  ", good), EXE));
        assert!(valid_envelope(&good.replace("60", "0.5"), EXE));
        for bad in [
            "echo bad".to_string(),
            format!("{}; echo bypass", good),
            format!("{}\necho bypass", good),
            format!("echo {}", good),
            good.replace("--timeout 60", "--timeout 0"),
            good.replace("--timeout 60", "--timeout 86401"),
            good.replace("--timeout 60", "--timeout .5"),
            good.replace("--timeout 60", "--timeout 1e3"),
            good.replace("--timeout 60", "--timeout -1"),
            good.replace("--timeout 60 ", ""),
            good.replace(b64, "////"),
            good.replace(b64, "AA=="),
            good.replace(b64, "IA=="),
            good.replace(b64, "ZWNobyBPSw"),
            good.replace(b64, "ZWNobyBPSw==="),
            good.replace("powershell", "zsh"),
            good.replace(EXE, "C:/Tools/process-tree-guard/bin/process-guard.exe.evil"),
            good.replace(EXE, "c:/tools/process-tree-guard/bin/process-guard.exe"),
            good.replace("--shell powershell", "--shell  powershell"),
            format!("{} | more", good),
            format!("{} --extra", good),
        ] {
            assert!(!valid_envelope(&bad, EXE), "{}", bad);
        }
    }

    const WRAPPER: &str = "C:/Tools/process-tree-guard/bin/process-guard-auto.exe";

    #[test]
    fn base64_encoder_round_trips_through_the_decoder() {
        assert_eq!(crate::base64::base64_encode(b"f"), "Zg==");
        assert_eq!(crate::base64::base64_encode(b"fo"), "Zm8=");
        assert_eq!(crate::base64::base64_encode(b"foo"), "Zm9v");
        assert_eq!(crate::base64::base64_encode(b"foob"), "Zm9vYg==");
        for text in ["a", "ab", "abc", "abcd", "echo \"q\" 'r' \\ s\nt","echo \u{fc}\u{4e2d}\u{1f600}"] {
            assert_eq!(crate::base64::decode_command(&crate::base64::base64_encode(text.as_bytes())).ok().as_deref(), Some(text), "{:?}", text);
        }
    }

    #[test]
    fn antigravity_guarded_matches_only_exact_forms() {
        let good = antigravity_wrapped(WRAPPER, "echo OK");
        assert_eq!(good, format!("{} --command-b64 ZWNobyBPSw==", WRAPPER));
        assert!(antigravity_guarded(&good, EXE));
        assert!(antigravity_guarded(&format!("  {}\n", good), EXE));
        let envelope = format!("{} --timeout 60 --shell powershell --command-b64 ZWNobyBPSw==", EXE);
        assert!(antigravity_guarded(&envelope, EXE));
        for bad in [
            "echo bad".to_string(),
            format!("{}; evil", good),
            format!("{} && evil", good),
            format!("{} | more", good),
            format!("{}\nevil", good),
            format!("echo {}", good),
            format!("{}  --command-b64 ZWNobyBPSw==", WRAPPER),
            good.replace(WRAPPER, "c:/tools/process-tree-guard/bin/process-guard-auto.exe"),
            good.replace(WRAPPER, "C:/Tools/process-tree-guard/bin/other-auto.exe"),
            good.replace(WRAPPER, &format!("{}.evil", WRAPPER)),
            good.replace("ZWNobyBPSw==", "ZWNobyBPSw"),
            good.replace("ZWNobyBPSw==", "////"),
            good.replace("ZWNobyBPSw==", "IA=="),
            good.replace("ZWNobyBPSw==", ""),
            format!("{} --command-b64 ", WRAPPER),
            format!("{} --shell bash --command-b64 ZWNobyBPSw==", WRAPPER),
            format!("{}; evil", envelope),
            // Only ASCII space, tab, CR and LF are separators to a shell.
            format!("{}\u{a0}", good),
            format!("\u{a0}{}", good),
            format!("{}\u{b}", good),
            format!("{}\u{2028}", good),
            format!("{}\u{a0}", envelope),
            format!("\u{b}{}", envelope),
        ] {
            assert!(!antigravity_guarded(&bad, EXE), "{:?}", bad);
        }
    }

    const TREE_EXE: &str = "C:/Tools/process-tree-guard/bin/process-tree-guard.exe";
    const TREE_WRAPPER: &str = "C:/Tools/process-tree-guard/bin/process-tree-guard-auto.exe";

    #[test]
    fn both_names_are_one_family() {
        assert_eq!(wrapper_paths(EXE), Some(vec![WRAPPER.to_string(), TREE_WRAPPER.to_string()]));
        assert_eq!(wrapper_paths(TREE_EXE), Some(vec![TREE_WRAPPER.to_string(), WRAPPER.to_string()]));
        // Another name keeps the 1.x wrapper alone; a path without a folder has no wrapper.
        assert_eq!(wrapper_paths("C:/Tools/pg/bin/other.exe"), Some(vec!["C:/Tools/pg/bin/process-guard-auto.exe".to_string()]));
        assert_eq!(wrapper_paths("process-guard.exe"), None);
        assert_eq!(envelope_paths(EXE), vec![EXE.to_string(), TREE_EXE.to_string()]);
        assert_eq!(envelope_paths(TREE_EXE), vec![TREE_EXE.to_string(), EXE.to_string()]);
        assert_eq!(envelope_paths("C:/Tools/pg/bin/other.exe"), vec!["C:/Tools/pg/bin/other.exe".to_string()]);
        // The automatic copies are not envelope names.
        assert_eq!(envelope_paths(WRAPPER).len(), 1);
    }

    #[test]
    fn envelope_accepts_either_name_in_the_same_folder_only() {
        let b64 = "ZWNobyBPSw==";
        for (exe, other) in [(EXE, TREE_EXE), (TREE_EXE, EXE)] {
            assert!(valid_envelope(&format!("{} --timeout 60 --shell bash --command-b64 {}", exe, b64), exe));
            assert!(valid_envelope(&format!("& {} --timeout 60 --shell bash --command-b64 {}", other, b64), exe));
            for bad in [
                other.replace("/bin/", "/other/"),
                other.to_uppercase(),
                other.replace(".exe", "-auto.exe"),
                format!("{}.evil", other),
                other.replace("process-", "xprocess-"),
            ] {
                let line = format!("{} --timeout 60 --shell bash --command-b64 {}", bad, b64);
                assert!(!valid_envelope(&line, exe), "{}", line);
            }
        }
        // An executable under any other name allows only its own path.
        let own = "C:/Tools/pg/bin/other.exe";
        assert!(valid_envelope(&format!("{} --timeout 5 --shell cmd --command-b64 {}", own, b64), own));
        assert!(!valid_envelope(&format!("C:/Tools/pg/bin/process-guard.exe --timeout 5 --shell cmd --command-b64 {}", b64), own));
    }

    const GATE_EXE: &str = "C:/Tools/ptg/libexec/process-tree-guard-gate.exe";
    const FLAT_GATE_EXE: &str = "C:/Tools/ptg/bin/process-tree-guard-gate.exe";

    #[test]
    fn the_gate_vouches_for_the_programs_that_enforce_a_deadline() {
        // Install layout: its own folder, then the bin folder beside libexec. Never itself.
        let paths = envelope_paths(GATE_EXE);
        assert_eq!(paths, [
            "C:/Tools/ptg/libexec/process-tree-guard.exe",
            "C:/Tools/ptg/libexec/process-guard.exe",
            "C:/Tools/ptg/libexec/process-tree-guard-deadline.exe",
            "C:/Tools/ptg/bin/process-tree-guard.exe",
            "C:/Tools/ptg/bin/process-guard.exe",
            "C:/Tools/ptg/bin/process-tree-guard-deadline.exe",
        ]);
        // Flat layout: its own folder only.
        assert_eq!(envelope_paths(FLAT_GATE_EXE).len(), 3);
        assert!(envelope_paths(FLAT_GATE_EXE).iter().all(|p| p.starts_with("C:/Tools/ptg/bin/")));
        for exe in [GATE_EXE, FLAT_GATE_EXE] {
            assert!(!envelope_paths(exe).contains(&exe.to_string()));
            assert!(!valid_envelope(&format!("{} --timeout 60 --shell bash --command-b64 ZWNobyBPSw==", exe), exe));
        }
        let b64 = "ZWNobyBPSw==";
        let line = |path: &str| format!("{} --timeout 60 --shell bash --command-b64 {}", path, b64);
        assert!(valid_envelope(&line("C:/Tools/ptg/bin/process-tree-guard.exe"), GATE_EXE));
        assert!(valid_envelope(&line("C:/Tools/ptg/libexec/process-tree-guard-deadline.exe"), GATE_EXE));
        for bad in [
            "C:/Tools/ptg/bin/process-tree-guard-auto.exe",
            "C:/Tools/ptg/other/process-tree-guard.exe",
            "C:/Tools/ptg/bin/PROCESS-TREE-GUARD.EXE",
            "C:/Tools/ptg/libexec/process-tree-guard-deadline-auto.exe",
            "C:/Tools/ptg/bin/process-tree-guard.exe.evil",
            "C:/Tools/other/bin/process-tree-guard.exe",
        ] {
            assert!(!valid_envelope(&line(bad), GATE_EXE), "{}", bad);
        }
        // The flat gate does not reach into a sibling bin folder.
        assert!(!valid_envelope(&line("C:/Tools/ptg/libexec/process-tree-guard.exe"), FLAT_GATE_EXE));
        // Windows folder names are not case sensitive: libexec is recognised in any letter case, and
        // the rest of the path is kept as the gate was started.
        for folder in ["LIBEXEC", "LibExec", "Libexec"] {
            let gate = format!("C:/Tools/ptg/{}/process-tree-guard-gate.exe", folder);
            assert_eq!(envelope_paths(&gate).len(), 6, "{}", gate);
            assert!(valid_envelope(&line("C:/Tools/ptg/bin/process-tree-guard.exe"), &gate), "{}", gate);
            assert!(valid_envelope(&line(&format!("C:/Tools/ptg/{}/process-tree-guard-deadline.exe", folder)), &gate), "{}", gate);
        }
        // A folder that only contains or starts or ends with the word is not libexec.
        for folder in ["libexec2", "xlibexec", "my-libexec", "libexe", "libexec "] {
            let gate = format!("C:/Tools/ptg/{}/process-tree-guard-gate.exe", folder);
            assert_eq!(envelope_paths(&gate).len(), 3, "{}", gate);
            assert!(!valid_envelope(&line("C:/Tools/ptg/bin/process-tree-guard.exe"), &gate), "{}", gate);
        }
        // Another file name keeps its own path only, as before.
        assert_eq!(envelope_paths("C:/Tools/ptg/libexec/other.exe"), vec!["C:/Tools/ptg/libexec/other.exe".to_string()]);
    }

    #[test]
    fn the_rules_follow_the_role_not_the_file_name() {
        let b64 = "ZWNobyBPSw==";
        let line = |path: &str| format!("{} --timeout 60 --shell bash --command-b64 {}", path, b64);
        // The hook role under other names, one of them a name of the full command: still the gate's
        // rules, and never itself.
        for renamed in [
            "C:/Tools/ptg/libexec/hookgate.exe",
            "C:/Tools/ptg/libexec/process-guard.exe",
            "C:/Tools/ptg/libexec/process-tree-guard-deadline.exe",
            "C:/Tools/ptg/libexec/process-tree-guard-gate-auto.exe",
        ] {
            let paths = super::envelope_paths(renamed, Role::Gate);
            assert!(!paths.contains(&renamed.to_string()), "{}", renamed);
            assert!(!super::valid_envelope(&line(renamed), renamed, Role::Gate), "{}", renamed);
            assert!(super::valid_envelope(&line("C:/Tools/ptg/bin/process-tree-guard.exe"), renamed, Role::Gate), "{}", renamed);
            assert_eq!(super::wrapper_paths(renamed, Role::Gate).and_then(|w| w.into_iter().next()).as_deref(),
                Some("C:/Tools/ptg/libexec/process-tree-guard-deadline-auto.exe"), "{}", renamed);
        }
        // Started under another letter case, the hook role still never vouches for its own path.
        let cased = "C:/Tools/ptg/libexec/Process-Tree-Guard-Deadline.exe";
        assert!(!super::valid_envelope(&line("C:/Tools/ptg/libexec/process-tree-guard-deadline.exe"), cased, Role::Gate));
        assert!(!super::valid_envelope(&line(cased), cased, Role::Gate));
        assert!(super::valid_envelope(&line("C:/Tools/ptg/bin/process-tree-guard.exe"), cased, Role::Gate));
        // The deadline role's path is among the others, and only the hook role's own path leaves the list.
        assert_eq!(super::envelope_paths("C:/Tools/ptg/libexec/process-tree-guard-deadline.exe", Role::Gate).len(), 5);
        assert_eq!(super::envelope_paths("C:/Tools/ptg/libexec/hookgate.exe", Role::Gate).len(), 6);
        // A program that is not the hook role keeps the rules of its name, even under the hook role's file name.
        assert_eq!(super::envelope_paths(GATE_EXE, Role::Full), vec![GATE_EXE.to_string()]);
        assert!(super::valid_envelope(&line(GATE_EXE), GATE_EXE, Role::Full));
        assert_eq!(super::wrapper_paths(GATE_EXE, Role::Full), Some(vec!["C:/Tools/ptg/libexec/process-guard-auto.exe".to_string()]));
        // No folder: the hook role vouches for nothing.
        assert!(super::envelope_paths("gate.exe", Role::Gate).is_empty());
    }

    #[test]
    fn the_policy_file_is_one_folder_above_the_executables_folder() {
        for (exe, policy) in [
            ("C:/Tools/ptg/bin/process-tree-guard.exe", Some("C:/Tools/ptg/POLICY.md")),
            ("C:/Tools/ptg/libexec/process-tree-guard-gate.exe", Some("C:/Tools/ptg/POLICY.md")),
            // A folder called bin or libexec earlier in the path does not move the policy file.
            ("C:/Tools/bin/ptg/libexec/process-tree-guard-gate.exe", Some("C:/Tools/bin/ptg/POLICY.md")),
            ("C:/Tools/libexec/ptg/bin/process-tree-guard.exe", Some("C:/Tools/libexec/ptg/POLICY.md")),
            // A folder with neither name.
            ("C:/Tools/ptg/flat/process-tree-guard-gate.exe", Some("C:/Tools/ptg/POLICY.md")),
            ("C:/gate.exe", None),
            ("gate.exe", None),
        ] {
            assert_eq!(policy_path(exe).as_deref(), policy, "{}", exe);
        }
    }

    #[test]
    fn the_gate_rewrites_to_the_automatic_deadline_role_in_its_own_folder() {
        assert_eq!(wrapper_paths(GATE_EXE), Some(vec![
            "C:/Tools/ptg/libexec/process-tree-guard-deadline-auto.exe".to_string(),
            "C:/Tools/ptg/libexec/process-tree-guard-auto.exe".to_string(),
            "C:/Tools/ptg/libexec/process-guard-auto.exe".to_string(),
        ]));
        let own = "C:/Tools/ptg/libexec/process-tree-guard-deadline-auto.exe";
        let input = call(&quote("echo hi"));
        let d = parse_json(&antigravity_decision(GATE_EXE, Some(&input), true)).expect("one JSON object");
        let line = d.get("overwrite").and_then(|o| o.get("CommandLine")).and_then(Json::as_str).unwrap();
        assert_eq!(line, antigravity_wrapped(own, "echo hi"));
        // The wrapper forms of all three families pass through unchanged.
        for wrapper in wrapper_paths(GATE_EXE).unwrap() {
            let input = call(&quote(&antigravity_wrapped(&wrapper, "echo hi")));
            let d = parse_json(&antigravity_decision(GATE_EXE, Some(&input), true)).unwrap();
            assert_eq!(d.get("decision").and_then(Json::as_str), Some("allow"), "{}", wrapper);
            assert!(d.get("overwrite").is_none(), "{}", wrapper);
        }
        // A missing wrapper is reported by the gate's own wrapper name.
        let missing = parse_json(&antigravity_decision(GATE_EXE, Some(&call("\"echo hi\"")), false)).unwrap();
        assert_eq!(missing.get("decision").and_then(Json::as_str), Some("deny"));
        assert!(missing.get("reason").and_then(Json::as_str).map_or(false, |r| r.contains("process-tree-guard-deadline-auto.exe")));
    }

    #[test]
    fn antigravity_guarded_accepts_both_names_wrappers_and_envelopes() {
        let b64 = "ZWNobyBPSw==";
        for exe in [EXE, TREE_EXE] {
            for wrapper in [WRAPPER, TREE_WRAPPER] {
                assert!(antigravity_guarded(&format!("{} --command-b64 {}", wrapper, b64), exe), "{} {}", exe, wrapper);
            }
            for path in [EXE, TREE_EXE] {
                assert!(antigravity_guarded(&format!("{} --timeout 60 --shell powershell --command-b64 {}", path, b64), exe), "{} {}", exe, path);
            }
            for bad in [
                format!("{} --command-b64 {}", WRAPPER.to_uppercase(), b64),
                format!("{} --command-b64 {}", TREE_WRAPPER.replace("/bin/", "/other/"), b64),
                format!("{}.evil --command-b64 {}", TREE_WRAPPER, b64),
                format!("{} --command-b64 {}; evil", TREE_WRAPPER, b64),
            ] {
                assert!(!antigravity_guarded(&bad, exe), "{}", bad);
            }
        }
    }

    #[test]
    fn antigravity_decision_uses_the_wrapper_of_its_own_name() {
        let decide_for = |exe: &str, original: &str| {
            let input = call(&quote(original));
            parse_json(&antigravity_decision(exe, Some(&input), true)).expect("one JSON object")
        };
        for (exe, wrapper) in [(EXE, WRAPPER), (TREE_EXE, TREE_WRAPPER)] {
            let d = decide_for(exe, "echo hi");
            let line = d.get("overwrite").and_then(|o| o.get("CommandLine")).and_then(Json::as_str).unwrap();
            assert_eq!(line, antigravity_wrapped(wrapper, "echo hi"));
            // The other name's wrapper passes through unchanged.
            let other = if wrapper == WRAPPER { TREE_WRAPPER } else { WRAPPER };
            let d = decide_for(exe, &antigravity_wrapped(other, "echo hi"));
            assert_eq!(d.get("decision").and_then(Json::as_str), Some("allow"));
            assert!(d.get("overwrite").is_none());
        }
        // A missing wrapper is reported by its own name.
        let missing = parse_json(&antigravity_decision(TREE_EXE, Some(&call("\"echo hi\"")), false)).unwrap();
        assert_eq!(missing.get("decision").and_then(Json::as_str), Some("deny"));
        assert!(missing.get("reason").and_then(Json::as_str).map_or(false, |r| r.contains("process-tree-guard-auto.exe")));
    }

    fn call(command_json: &str) -> String {
        format!("{{\"toolCall\":{{\"name\":\"run_command\",\"args\":{{\"CommandLine\":{}}}}},\"stepIdx\":1}}", command_json)
    }

    fn decide(input: &str) -> Json {
        parse_json(&antigravity_decision(EXE, Some(input), true)).expect("one JSON object")
    }

    #[test]
    fn antigravity_decision_rewrites_allows_and_denies() {
        // A plain command is rewritten; the original is recoverable from the payload exactly.
        let original = "echo \"q\" 'r' \\ s\n\u{fc}";
        let d = decide(&call(&quote(original)));
        assert_eq!(d.get("decision").and_then(Json::as_str), Some("allow"));
        let rewritten = d.get("overwrite").and_then(|o| o.get("CommandLine")).and_then(Json::as_str).unwrap();
        let b64 = rewritten.strip_prefix(&format!("{} --command-b64 ", WRAPPER)).expect("wrapper form");
        assert_eq!(crate::base64::decode_command(b64).ok().as_deref(), Some(original));
        assert!(matches!(d.get("overwrite"), Some(Json::Object(pairs)) if pairs.len() == 1));
        // Fed back, the wrapper form passes unchanged.
        let again = decide(&call(&quote(rewritten)));
        assert_eq!(again.get("decision").and_then(Json::as_str), Some("allow"));
        assert!(again.get("overwrite").is_none());
        // A tool with another string name is not this hook's business.
        for input in [r#"{"toolCall":{"name":"view_file","args":{}}}"#, r#"{"toolCall":{"name":"run_command ","args":{}}}"#, r#"{"toolCall":{"name":""}}"#] {
            let d = decide(input);
            assert_eq!(d.get("decision").and_then(Json::as_str), Some("allow"), "{}", input);
            assert!(d.get("overwrite").is_none(), "{}", input);
        }
        // Everything that cannot be wrapped safely, or is not a recognised payload, is denied.
        for input in [
            "", "not json", "{",
            "{}", "[]", "null", r#"{"toolCall":null}"#, r#"{"toolCall":[]}"#, r#"{"toolCall":"run_command"}"#,
            r#"{"toolCall":{"name":7}}"#, r#"{"toolCall":{"name":null}}"#,
            r#"{"toolCall":{"args":{"CommandLine":"echo a"}}}"#,
            r#"{"toolCall":{"name":"run_command","args":{}}}"#,
            r#"{"toolCall":{"name":"run_command"}}"#,
            r#"{"toolCall":{"name":"run_command","args":{"CommandLine":""}}}"#,
            r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"  \n"}}}"#,
            r#"{"toolCall":{"name":"run_command","args":{"CommandLine":7}}}"#,
            r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"a\u0000b"}}}"#,
            // A second key that is CommandLine in any case, or a repeated key, is ambiguous.
            r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"echo hi","commandline":"evil"}}}"#,
            r#"{"toolCall":{"name":"run_command","args":{"COMMANDLINE":"evil","CommandLine":"echo hi"}}}"#,
            r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"echo hi","CommandLine":"evil"}}}"#,
            // The same holds for the toolCall, name and args keys, whatever the tool.
            r#"{"toolCall":{"name":"view_file","args":{}},"toolcall":{"name":"run_command","args":{"CommandLine":"evil"}}}"#,
            r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"evil"}},"toolCall":{"name":"view_file","args":{}}}"#,
            r#"{"toolCall":{"name":"view_file","Name":"run_command","args":{"CommandLine":"evil"}}}"#,
            r#"{"toolCall":{"name":"run_command","name":"view_file","args":{"CommandLine":"evil"}}}"#,
            r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"echo hi"},"ARGS":{"CommandLine":"evil"}}}"#,
        ] {
            let d = decide(input);
            assert_eq!(d.get("decision").and_then(Json::as_str), Some("deny"), "{}", input);
            assert!(d.get("reason").and_then(Json::as_str).map_or(false, |r| r.starts_with("TIMEOUT_REQUIRED")), "{}", input);
        }
        let denied = |exe: &str, exists: bool| {
            parse_json(&antigravity_decision(exe, Some(&call("\"echo hi\"")), exists)).and_then(|d| d.get("decision").and_then(Json::as_str).map(str::to_string))
        };
        // The longest command that fits is wrapped; one more group of three bytes is denied with a reason.
        let room = (MAX_REWRITTEN_LINE - antigravity_wrapped(WRAPPER, "").len()) / 4 * 3;
        let fits = decide(&call(&quote(&"a".repeat(room))));
        assert_eq!(fits.get("decision").and_then(Json::as_str), Some("allow"));
        assert!(fits.get("overwrite").is_some());
        let over = decide(&call(&quote(&"a".repeat(room + 1))));
        assert_eq!(over.get("decision").and_then(Json::as_str), Some("deny"));
        assert!(over.get("overwrite").is_none());
        assert!(over.get("reason").and_then(Json::as_str).map_or(false, |r| r.contains("too long") && r.contains("file")));
        assert_eq!(denied(EXE, false).as_deref(), Some("deny"));
        assert_eq!(denied("C:/Program Files/pg/bin/process-guard.exe", true).as_deref(), Some("deny"));
        assert_eq!(denied("", true).as_deref(), Some("deny"));
        assert_eq!(parse_json(&antigravity_decision(EXE, None, true)).and_then(|d| d.get("decision").and_then(Json::as_str).map(str::to_string)).as_deref(), Some("deny"));
    }

    #[test]
    fn json_parsing() {
        let v = parse_json(r#"{"tool_input":{"command":"a\"b\\c\u00fc\ud83d\ude00","n":[1,2.5,true,null]}}"#).unwrap();
        assert_eq!(v.get("tool_input").and_then(|t| t.get("command")).and_then(Json::as_str), Some("a\"b\\cü😀"));
        for bad in ["", "{", "{\"a\":}", "{\"a\":1} x", "\"\\ud800\"", "\"a\nb\"", "[1,]"] {
            assert!(parse_json(bad).is_none(), "{:?}", bad);
        }
        let deep = "[".repeat(10000);
        assert!(parse_json(&deep).is_none());
        assert_eq!(quote("a\"\\\n\u{1}"), "\"a\\\"\\\\\\n\\u0001\"");
    }
}
