// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! Shared helpers for the process guard integration tests.
//!
//! Each test crate includes this module. It locates the built guard and the
//! helper executable, runs commands with a hard limit and full output capture,
//! reads and writes small JavaScript Object Notation (JSON) values, and
//! collects named checks so one run reports every failure in a group.
#![allow(dead_code)]

use std::ffi::c_void;
use std::fmt::Display;
use std::io::{Read, Write};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(access: u32, inherit: i32, id: u32) -> *mut c_void;
    fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
    fn CloseHandle(handle: *mut c_void) -> i32;
}

const SYNCHRONIZE: u32 = 0x0010_0000;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 0x102;

// ---------------------------------------------------------------- locations

/// Windows path text with long names and no verbatim prefix.
pub fn long_path(path: &Path) -> String {
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let text = canonical.to_string_lossy().into_owned();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.len() >= 2 && rest.as_bytes()[1] == b':' => rest.to_string(),
        _ => text,
    }
}

/// Forward slashes and no verbatim prefix, as the guard spells its own path.
pub fn posix(text: &str) -> String {
    let text = text.replace('\\', "/");
    match text.strip_prefix("//?/") {
        Some(rest) => rest.to_string(),
        None => text.clone(),
    }
}

pub fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// A binary path recorded at compile time. When the tests were compiled on
/// another machine and copied here, that path does not exist, so the binary
/// of the same name in the folder above this test executable is used.
fn built(recorded: &str) -> PathBuf {
    let path = PathBuf::from(recorded);
    if path.is_file() {
        return path;
    }
    let name = path.file_name().expect("binary path has a file name").to_owned();
    let exe = std::env::current_exe().expect("test executable path");
    exe.parent().and_then(Path::parent).expect("test executable folder").join(name)
}

/// The guard under test: the built binary, or the one named by PROCESS_GUARD_EXE.
pub fn guard() -> &'static str {
    static GUARD: OnceLock<String> = OnceLock::new();
    GUARD.get_or_init(|| {
        let raw = std::env::var_os("PROCESS_GUARD_EXE").map(PathBuf::from).unwrap_or_else(|| built(env!("CARGO_BIN_EXE_process-guard")));
        long_path(&raw)
    })
}

/// The helper executable that stands in for every child process.
pub fn testkit() -> &'static str {
    static TESTKIT: OnceLock<String> = OnceLock::new();
    TESTKIT.get_or_init(|| long_path(&built(env!("CARGO_BIN_EXE_testkit"))))
}

pub const BASH: &str = "C:/Program Files/Git/bin/bash.exe";

// ------------------------------------------------------------------- running

pub struct Out {
    pub code: u32,
    pub stdout: Vec<u8>,
    pub stdout_len: u64,
    pub stderr: Vec<u8>,
    pub elapsed: Duration,
}

impl Out {
    pub fn out(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
    pub fn err(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

pub struct Opts {
    pub input: Option<Vec<u8>>,
    pub limit_secs: u64,
    pub keep_stdout: bool,
}

impl Default for Opts {
    fn default() -> Opts {
        Opts { input: None, limit_secs: 60, keep_stdout: true }
    }
}

struct Drain {
    buffer: Arc<Mutex<Vec<u8>>>,
    length: Arc<AtomicU64>,
    done: mpsc::Receiver<()>,
}

fn drain<R: Read + Send + 'static>(mut source: R, keep: bool) -> Drain {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let length = Arc::new(AtomicU64::new(0));
    let (sender, done) = mpsc::channel();
    let (shared_buffer, shared_length) = (buffer.clone(), length.clone());
    thread::spawn(move || {
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            match source.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    shared_length.fetch_add(n as u64, Ordering::Relaxed);
                    if keep {
                        shared_buffer.lock().unwrap().extend_from_slice(&chunk[..n]);
                    }
                }
            }
        }
        let _ = sender.send(());
    });
    Drain { buffer, length, done }
}

impl Drain {
    /// Wait a bounded time for the stream to close, then return what arrived.
    fn finish(self, wait: Duration) -> (Vec<u8>, u64) {
        let _ = self.done.recv_timeout(wait);
        let data = std::mem::take(&mut *self.buffer.lock().unwrap());
        (data, self.length.load(Ordering::Relaxed))
    }
}

/// Wait for a child to exit, at most `secs` seconds. None means still running.
pub fn wait_limited(child: &mut Child, secs: u64) -> Option<ExitStatus> {
    let milliseconds = secs.saturating_mul(1000).min(u32::MAX as u64 - 1) as u32;
    let waited = unsafe { WaitForSingleObject(child.as_raw_handle() as *mut c_void, milliseconds) };
    if waited == WAIT_OBJECT_0 {
        child.wait().ok()
    } else {
        None
    }
}

pub fn kill(child: &mut Child) {
    let _ = child.kill();
    let _ = wait_limited(child, 10);
}

pub fn exec(command: Command) -> Out {
    exec_with(command, Opts::default())
}

/// Run a command to completion with captured output and a hard time limit.
pub fn exec_with(mut command: Command, opts: Opts) -> Out {
    let Opts { input, limit_secs, keep_stdout } = opts;
    command
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let began = Instant::now();
    let mut child = command.spawn().unwrap_or_else(|e| panic!("cannot start {:?}: {}", command.get_program(), e));
    // The child may exit before reading everything; a failed write is not an error.
    let _writer = input.map(|data| {
        let mut stdin = child.stdin.take().expect("stdin pipe");
        thread::spawn(move || {
            let _ = stdin.write_all(&data);
        })
    });
    let out = drain(child.stdout.take().expect("stdout pipe"), keep_stdout);
    let err = drain(child.stderr.take().expect("stderr pipe"), true);
    let status = match wait_limited(&mut child, limit_secs) {
        Some(status) => status,
        None => {
            kill(&mut child);
            panic!("{:?} did not finish within {} seconds", command.get_program(), limit_secs);
        }
    };
    let (stdout, stdout_len) = out.finish(Duration::from_secs(10));
    let (stderr, _) = err.finish(Duration::from_secs(10));
    Out { code: status.code().unwrap_or(-1) as u32, stdout, stdout_len, stderr, elapsed: began.elapsed() }
}

/// Run a command whose standard streams the caller has already set.
pub fn run_status(mut command: Command, limit_secs: u64) -> u32 {
    let mut child = command.spawn().unwrap_or_else(|e| panic!("cannot start {:?}: {}", command.get_program(), e));
    match wait_limited(&mut child, limit_secs) {
        Some(status) => status.code().unwrap_or(-1) as u32,
        None => {
            kill(&mut child);
            panic!("{:?} did not finish within {} seconds", command.get_program(), limit_secs);
        }
    }
}

pub fn guard_cmd(args: &[&str]) -> Command {
    let mut command = Command::new(guard());
    command.args(args);
    command
}

pub fn run_guard(args: &[&str]) -> Out {
    exec(guard_cmd(args))
}

pub fn run_guard_input(args: &[&str], input: &[u8]) -> Out {
    exec_with(guard_cmd(args), Opts { input: Some(input.to_vec()), ..Opts::default() })
}

/// The guard with `--timeout SECONDS --` in front of the child command.
pub fn guarded(timeout: &str, child: &[&str]) -> Out {
    let mut args = vec!["--timeout", timeout, "--"];
    args.extend_from_slice(child);
    run_guard(&args)
}

/// The guard with a shell payload.
pub fn shell(timeout: &str, shell_name: &str, payload: &str) -> Out {
    run_guard(&["--timeout", timeout, "--shell", shell_name, "--command-b64", &base64(payload.as_bytes())])
}

/// Start the guard (or anything else) with all standard streams null.
pub fn spawn_quiet(program: &str, args: &[&str]) -> Child {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot start {}: {}", program, e))
}

// ------------------------------------------------------------ processes, files

/// True while the process with this identifier is running.
pub fn alive(id: u32) -> bool {
    unsafe {
        let handle = OpenProcess(SYNCHRONIZE, 0, id);
        if handle.is_null() {
            return false;
        }
        let waited = WaitForSingleObject(handle, 0);
        CloseHandle(handle);
        waited == WAIT_TIMEOUT
    }
}

pub fn count_alive(ids: &[u32]) -> usize {
    ids.iter().filter(|id| alive(**id)).count()
}

pub fn nap(secs: f64) {
    thread::sleep(Duration::from_secs_f64(secs));
}

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A unique folder under the system temporary folder, removed when dropped.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// The prefix may contain spaces and letters outside the basic Latin set.
    pub fn new(prefix: &str) -> TempDir {
        let base = PathBuf::from(long_path(&std::env::temp_dir()));
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let name = format!("{}pg{}-{}-{}", prefix, std::process::id(), SEQUENCE.fetch_add(1, Ordering::Relaxed), nanos);
        let path = base.join(name);
        std::fs::create_dir_all(&path).expect("create temporary folder");
        TempDir { path }
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
    pub fn text(&self) -> String {
        text(&self.path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        for _ in 0..20 {
            if std::fs::remove_dir_all(&self.path).is_ok() || !self.path.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

/// The process identifier a marker file holds.
pub fn read_id(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Identifiers held by every marker file (extension pid) in a folder.
pub fn ids_in(dir: &Path) -> Vec<u32> {
    let mut found = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |x| x == "pid") {
                if let Some(id) = read_id(&path) {
                    found.push(id);
                }
            }
        }
    }
    found.sort_unstable();
    found
}

/// Identifiers listed one per line in a file; empty when the file is absent.
pub fn ids_from_lines(path: &Path) -> Vec<u32> {
    std::fs::read_to_string(path)
        .map(|body| body.lines().filter_map(|line| line.trim().parse().ok()).collect())
        .unwrap_or_default()
}

pub fn wait_for_file(path: &Path, secs: f64) -> bool {
    let end = Instant::now() + Duration::from_secs_f64(secs);
    while !path.exists() {
        if Instant::now() >= end {
            return false;
        }
        thread::sleep(Duration::from_millis(20));
    }
    true
}

/// Wait until a folder holds at least `count` marker files.
pub fn wait_for_ids(dir: &Path, count: usize, secs: f64) -> bool {
    let end = Instant::now() + Duration::from_secs_f64(secs);
    while ids_in(dir).len() < count {
        if Instant::now() >= end {
            return false;
        }
        thread::sleep(Duration::from_millis(50));
    }
    true
}

// ---------------------------------------------------------------- Base64, JSON

/// Standard Base64 with padding.
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let n = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A JSON string literal: quote, backslash and control characters escaped.
pub fn json_quote(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// Strict parse: the whole text must be one value.
    pub fn parse(text: &str) -> Option<Json> {
        let mut reader = Reader { bytes: text.as_bytes(), pos: 0 };
        let value = reader.value(0)?;
        reader.skip();
        if reader.pos == reader.bytes.len() { Some(value) } else { None }
    }
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(pairs) => pairs.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Num(n) => Some(*n),
            _ => None,
        }
    }
    pub fn is_empty_object(&self) -> bool {
        matches!(self, Json::Obj(pairs) if pairs.is_empty())
    }
    /// The strings of an array made only of strings.
    pub fn strings(&self) -> Option<Vec<String>> {
        match self {
            Json::Arr(items) => items.iter().map(|i| i.as_str().map(str::to_string)).collect(),
            _ => None,
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn skip(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.bytes.get(self.pos) {
            self.pos += 1;
        }
    }
    fn eat(&mut self, byte: u8) -> bool {
        self.skip();
        if self.bytes.get(self.pos) == Some(&byte) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn word(&mut self, word: &str, value: Json) -> Option<Json> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Some(value)
        } else {
            None
        }
    }
    fn value(&mut self, depth: usize) -> Option<Json> {
        if depth > 64 {
            return None;
        }
        self.skip();
        match *self.bytes.get(self.pos)? {
            b'{' => {
                self.pos += 1;
                let mut pairs = Vec::new();
                if !self.eat(b'}') {
                    loop {
                        self.skip();
                        let key = self.string()?;
                        if !self.eat(b':') {
                            return None;
                        }
                        pairs.push((key, self.value(depth + 1)?));
                        if self.eat(b',') {
                            continue;
                        }
                        if self.eat(b'}') {
                            break;
                        }
                        return None;
                    }
                }
                Some(Json::Obj(pairs))
            }
            b'[' => {
                self.pos += 1;
                let mut items = Vec::new();
                if !self.eat(b']') {
                    loop {
                        items.push(self.value(depth + 1)?);
                        if self.eat(b',') {
                            continue;
                        }
                        if self.eat(b']') {
                            break;
                        }
                        return None;
                    }
                }
                Some(Json::Arr(items))
            }
            b'"' => Some(Json::Str(self.string()?)),
            b't' => self.word("true", Json::Bool(true)),
            b'f' => self.word("false", Json::Bool(false)),
            b'n' => self.word("null", Json::Null),
            _ => {
                let start = self.pos;
                while let Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9') = self.bytes.get(self.pos) {
                    self.pos += 1;
                }
                if start == self.pos {
                    return None;
                }
                std::str::from_utf8(&self.bytes[start..self.pos]).ok()?.parse().ok().map(Json::Num)
            }
        }
    }
    fn hex4(&mut self) -> Option<u32> {
        let digits = std::str::from_utf8(self.bytes.get(self.pos..self.pos + 4)?).ok()?;
        self.pos += 4;
        u32::from_str_radix(digits, 16).ok()
    }
    fn string(&mut self) -> Option<String> {
        if self.bytes.get(self.pos) != Some(&b'"') {
            return None;
        }
        self.pos += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let byte = *self.bytes.get(self.pos)?;
            self.pos += 1;
            match byte {
                b'"' => return String::from_utf8(out).ok(),
                b'\\' => {
                    let escape = *self.bytes.get(self.pos)?;
                    self.pos += 1;
                    let c = match escape {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let mut unit = self.hex4()?;
                            if (0xD800..0xDC00).contains(&unit) {
                                if self.bytes.get(self.pos..self.pos + 2)? != b"\\u" {
                                    return None;
                                }
                                self.pos += 2;
                                let low = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&low) {
                                    return None;
                                }
                                unit = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00);
                            }
                            char::from_u32(unit)?
                        }
                        _ => return None,
                    };
                    let mut buffer = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
                }
                0..=0x1f => return None,
                _ => out.push(byte),
            }
        }
    }
}

// -------------------------------------------------------------------- checks

/// Timing bounds are asserted unless PROCESS_GUARD_TIMING is set to "info",
/// which a loaded machine can use to report them without failing the run.
pub fn timing_strict() -> bool {
    std::env::var("PROCESS_GUARD_TIMING").map_or(true, |value| !value.eq_ignore_ascii_case("info"))
}

pub fn median(values: &mut [f64]) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = values.len();
    if n == 0 {
        0.0
    } else if n % 2 == 1 {
        values[n / 2]
    } else {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    }
}

/// Named checks in one group; `finish` fails the test if any check failed.
pub struct Checks {
    section: String,
    failed: Vec<String>,
}

impl Checks {
    pub fn new(section: &str) -> Checks {
        Checks { section: section.to_string(), failed: Vec::new() }
    }
    pub fn check(&mut self, id: &str, name: &str, ok: bool, detail: impl Display) {
        println!("{} {} {} {}", if ok { "PASS" } else { "FAIL" }, id, name, detail);
        if !ok {
            self.failed.push(format!("{} {}", id, name));
        }
    }
    /// A bound on time or load: asserted when timing is strict, otherwise reported only.
    pub fn timing(&mut self, id: &str, name: &str, ok: bool, detail: impl Display) {
        if timing_strict() {
            self.check(id, name, ok, detail);
        } else {
            println!("INFO {} {} {} (not asserted: {})", id, name, if ok { "within the bound" } else { "outside the bound" }, detail);
        }
    }
    pub fn info(&self, line: impl Display) {
        println!("INFO {}", line);
    }
    pub fn finish(self) {
        if !self.failed.is_empty() {
            panic!("{}: {} failed: {}", self.section, self.failed.len(), self.failed.join("; "));
        }
    }
}
