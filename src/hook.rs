// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! `process-guard hook VENDOR`: the command envelope check for agent shell tools.
//!
//! Reads the host's pre-execution hook payload as JavaScript Object Notation
//! (JSON) on standard input and allows the command only when it is exactly the
//! guard envelope:
//!
//!     <this executable> --timeout SECONDS --shell powershell|bash|cmd --command-b64 BASE64
//!
//! with forward slashes in the executable path, an optional leading `& `, a
//! timeout above zero and at most 86400, and a payload that decodes to nonempty
//! UTF-8 with no NUL. Anything else is denied with exit code 2, which is how a
//! host hook blocks a tool call; this is the one place the guard uses exit 2 on purpose.
//!
//! Formats: `pretooluse` reads `tool_input.command` (or `tool_input.cmd`) and
//! answers in the PreToolUse format; `cursor` reads `command` and answers in the
//! beforeShellExecution format; `cursor-context` prints the policy as session context.
//!
//! `antigravity` is different: it rewrites instead of only checking. It reads a
//! Google Antigravity PreToolUse payload, and for the `run_command` tool replaces
//! `CommandLine` with a call to the automatic wrapper beside this executable, so the
//! command runs under the guard. Every outcome, denials included, is a JSON decision
//! on standard output and the exit code is always 0. `antigravity-context` prints the
//! policy as a SessionStart system message.

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

/// The PowerShell command line that runs `command` under the automatic guard.
pub fn powershell_wrapped(auto_exe: &str, command: &str) -> String {
    let utf8 = crate::base64_encode(command.as_bytes());
    format!("& '{}' --shell powershell --command-b64 {}; exit $LASTEXITCODE", auto_exe.replace('\'', "''"), utf8)
}

/// `hook powershell-auto`: rewrite a PowerShell tool call so the automatic
/// guard runs it. A command that already starts with a guard path is left as is.
pub fn powershell_auto(exe: &str) -> i32 {
    let auto_exe = match exe.rsplit_once('/') {
        Some((dir, _)) => format!("{}/process-guard-auto.exe", dir),
        None => return 0,
    };
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
    // own wrapping, or a valid envelope. Anything else, including a command that
    // merely starts with a guard path, is wrapped again (a double guard is harmless).
    let already = valid_envelope(&command, exe) || command.trim()
        .strip_prefix(&format!("& '{}' --shell powershell --command-b64 ", auto_exe.replace('\'', "''")))
        .and_then(|r| r.strip_suffix("; exit $LASTEXITCODE"))
        .map_or(false, |b64| crate::decode_command(b64).is_ok());
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

/// True when `command` is exactly the guard envelope for executable `exe`.
pub fn valid_envelope(command: &str, exe: &str) -> bool {
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
    crate::decode_command(payload).is_ok()
}

fn policy_text() -> String {
    std::env::current_exe().ok()
        .and_then(|p| p.parent().and_then(|bin| bin.parent()).map(|home| home.join("POLICY.md")))
        .and_then(|p| std::fs::read_to_string(p).ok())
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
    format!("{} --command-b64 {}", wrapper, crate::base64_encode(command.as_bytes()))
}

/// True when `command` is exactly the wrapper form `<wrapper> --command-b64 BASE64`
/// with a payload that decodes to a valid command, or a valid guard envelope.
/// Nothing else counts: trailing text, other separators, another path or a path
/// in another case are wrapped again.
pub fn antigravity_guarded(command: &str, wrapper: &str, exe: &str) -> bool {
    // Shells split on ASCII space, tab and newline only; trimming anything wider
    // (a no-break space, a vertical tab) would pass a line the wrapper then rejects.
    let trimmed = command.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'));
    trimmed.strip_prefix(wrapper)
        .and_then(|r| r.strip_prefix(" --command-b64 "))
        .map_or(false, |b64| crate::decode_command(b64).is_ok())
        // valid_envelope trims Unicode whitespace itself; refuse what it would silently strip.
        || (trimmed.trim().len() == trimmed.len() && valid_envelope(trimmed, exe))
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
/// whether `process-guard-auto.exe` is present beside it.
fn antigravity_decision(exe: &str, input: Option<&str>, wrapper_exists: bool) -> String {
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
    let wrapper = match exe.rsplit_once('/') {
        Some((dir, _)) => format!("{}/process-guard-auto.exe", dir),
        None => return antigravity_deny("the location of the process guard is unknown."),
    };
    if !wrapper_exists {
        return antigravity_deny(&format!("the automatic wrapper {} is missing beside the process guard.", wrapper));
    }
    if !plain_path(&wrapper) {
        return antigravity_deny("the process guard must be installed in a path with only the characters A-Z, a-z, 0-9, colon, slash, period, underscore and hyphen, so the rewritten command parses the same in every shell.");
    }
    if antigravity_guarded(command, &wrapper, exe) {
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
pub fn antigravity(exe: &str) -> i32 {
    let mut input = String::new();
    let read = std::io::stdin().take(16 * 1024 * 1024).read_to_string(&mut input).is_ok();
    let wrapper_exists = exe.rsplit_once('/').map_or(false, |(dir, _)| std::path::Path::new(&format!("{}/process-guard-auto.exe", dir)).is_file());
    let line = antigravity_decision(exe, if read { Some(&input) } else { None }, wrapper_exists);
    let _ = writeln!(std::io::stdout(), "{}", line);
    0
}

/// `hook antigravity-context`: the policy as a SessionStart system message.
pub fn antigravity_context() -> i32 {
    let _ = writeln!(std::io::stdout(), "{{\"injectSteps\":[{{\"systemMessage\":{{\"systemMessage\":{}}}}}]}}", quote(&policy_text()));
    0
}

/// Run the hook. Returns the process exit code: 0 allows, 2 blocks (the
/// `antigravity` vendors always return 0).
pub fn main(vendor: &str) -> i32 {
    let exe = self_path().unwrap_or_default();
    let policy = exe.rsplit_once("/bin/").map(|(home, _)| format!("{}/POLICY.md", home)).unwrap_or_else(|| "POLICY.md".into());
    let reason = format!("TIMEOUT_REQUIRED: execute exactly the process-guard envelope with an explicit finite timeout. \
        No unwrapped commands, prefixes, suffixes, or polling-timeout substitutes. See {}. \
        Native tool timeout alone does not guarantee child cleanup.", policy);
    if vendor == "powershell-auto" {
        return powershell_auto(&exe);
    }
    if vendor == "antigravity" {
        return antigravity(&exe);
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
            command.and_then(Json::as_str).map_or(false, |c| !exe.is_empty() && valid_envelope(c, &exe))
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

    const EXE: &str = "C:/Tools/process-guard/bin/process-guard.exe";

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
            good.replace(EXE, "C:/Tools/process-guard/bin/process-guard.exe.evil"),
            good.replace(EXE, "c:/tools/process-guard/bin/process-guard.exe"),
            good.replace("--shell powershell", "--shell  powershell"),
            format!("{} | more", good),
            format!("{} --extra", good),
        ] {
            assert!(!valid_envelope(&bad, EXE), "{}", bad);
        }
    }

    const WRAPPER: &str = "C:/Tools/process-guard/bin/process-guard-auto.exe";

    #[test]
    fn base64_encoder_round_trips_through_the_decoder() {
        assert_eq!(crate::base64_encode(b"f"), "Zg==");
        assert_eq!(crate::base64_encode(b"fo"), "Zm8=");
        assert_eq!(crate::base64_encode(b"foo"), "Zm9v");
        assert_eq!(crate::base64_encode(b"foob"), "Zm9vYg==");
        for text in ["a", "ab", "abc", "abcd", "echo \"q\" 'r' \\ s\nt","echo \u{fc}\u{4e2d}\u{1f600}"] {
            assert_eq!(crate::decode_command(&crate::base64_encode(text.as_bytes())).ok().as_deref(), Some(text), "{:?}", text);
        }
    }

    #[test]
    fn antigravity_guarded_matches_only_exact_forms() {
        let good = antigravity_wrapped(WRAPPER, "echo OK");
        assert_eq!(good, format!("{} --command-b64 ZWNobyBPSw==", WRAPPER));
        assert!(antigravity_guarded(&good, WRAPPER, EXE));
        assert!(antigravity_guarded(&format!("  {}\n", good), WRAPPER, EXE));
        let envelope = format!("{} --timeout 60 --shell powershell --command-b64 ZWNobyBPSw==", EXE);
        assert!(antigravity_guarded(&envelope, WRAPPER, EXE));
        for bad in [
            "echo bad".to_string(),
            format!("{}; evil", good),
            format!("{} && evil", good),
            format!("{} | more", good),
            format!("{}\nevil", good),
            format!("echo {}", good),
            format!("{}  --command-b64 ZWNobyBPSw==", WRAPPER),
            good.replace(WRAPPER, "c:/tools/process-guard/bin/process-guard-auto.exe"),
            good.replace(WRAPPER, "C:/Tools/process-guard/bin/other-auto.exe"),
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
            assert!(!antigravity_guarded(&bad, WRAPPER, EXE), "{:?}", bad);
        }
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
        assert_eq!(crate::decode_command(b64).ok().as_deref(), Some(original));
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
