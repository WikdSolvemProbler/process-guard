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
    fn GetExitCodeProcess(handle: *mut c_void, code: *mut u32) -> i32;
}

const SYNCHRONIZE: u32 = 0x0010_0000;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
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

/// A binary path recorded at compile time by cargo for the binary it built in
/// this run. When the tests were compiled on another machine and copied here,
/// that path does not exist, so the binary of the same name in the folder above
/// this test executable is used. No file is ever found by a name written in the
/// tests, so a stale file left in the build folder by an earlier version (for
/// example a process-guard.exe) is never picked up.
fn built(recorded: &str) -> PathBuf {
    let path = PathBuf::from(recorded);
    if path.is_file() {
        return path;
    }
    let name = path.file_name().expect("binary path has a file name").to_owned();
    let exe = std::env::current_exe().expect("test executable path");
    exe.parent().and_then(Path::parent).expect("test executable folder").join(name)
}

/// The two program names of the guard: the 2.0 name, and the 1.x name kept as an
/// alias through 2.x. Each also has an automatic copy, the same name with `-auto`.
pub const NAMES: [&str; 2] = ["process-tree-guard", "process-guard"];

/// The guard under test: the built binary, or the one named by
/// PROCESS_TREE_GUARD_EXE, else by the 1.x name PROCESS_GUARD_EXE. The tests never
/// depend on the name of this file; they copy it to the names they need.
pub fn guard() -> &'static str {
    static GUARD: OnceLock<String> = OnceLock::new();
    GUARD.get_or_init(|| {
        let named = std::env::var_os("PROCESS_TREE_GUARD_EXE").or_else(|| std::env::var_os("PROCESS_GUARD_EXE")).map(PathBuf::from);
        let raw = named.unwrap_or_else(|| built(env!("CARGO_BIN_EXE_process-tree-guard")));
        long_path(&raw)
    })
}

/// A copy of the guard in `dir` named `<name>.exe`; returns its Windows path text.
pub fn copy_guard(dir: &Path, name: &str) -> String {
    let target = dir.join(format!("{}.exe", name));
    std::fs::copy(guard(), &target).unwrap_or_else(|e| panic!("cannot copy the guard to {}: {}", target.display(), e));
    text(&target)
}

/// The helper executable that stands in for every child process.
pub fn testkit() -> &'static str {
    static TESTKIT: OnceLock<String> = OnceLock::new();
    TESTKIT.get_or_init(|| long_path(&built(env!("CARGO_BIN_EXE_testkit"))))
}

// ------------------------------------------------------- role programs, layouts

/// The four programs the crate builds: the full command, the deadline role, the
/// hook role and the contain role.
pub const ROLES: [&str; 4] = ["process-tree-guard", "process-tree-guard-deadline", "process-tree-guard-gate", "process-tree-guard-contain"];

/// The built program of this name (one of ROLES), exactly as cargo built it in
/// this run. Unlike `guard()`, it is not replaced by PROCESS_TREE_GUARD_EXE.
pub fn role(name: &str) -> &'static str {
    static PATHS: OnceLock<[String; 4]> = OnceLock::new();
    let paths = PATHS.get_or_init(|| [
        long_path(&built(env!("CARGO_BIN_EXE_process-tree-guard"))),
        long_path(&built(env!("CARGO_BIN_EXE_process-tree-guard-deadline"))),
        long_path(&built(env!("CARGO_BIN_EXE_process-tree-guard-gate"))),
        long_path(&built(env!("CARGO_BIN_EXE_process-tree-guard-contain"))),
    ]);
    let index = ROLES.iter().position(|known| *known == name).unwrap_or_else(|| panic!("{} is not a program of this crate", name));
    &paths[index]
}

/// A copy of the built program `role_name` in `dir` named `<file_name>.exe`; returns its Windows path text.
pub fn copy_role(dir: &Path, role_name: &str, file_name: &str) -> String {
    let target = dir.join(format!("{}.exe", file_name));
    std::fs::copy(role(role_name), &target).unwrap_or_else(|e| panic!("cannot copy {} to {}: {}", role_name, target.display(), e));
    text(&target)
}

/// Where the programs are installed. `Install` puts the full command in `bin` and
/// the two roles in `libexec`; `Flat` puts every program in one folder, `bin`.
/// `POLICY.md`, when there is one, is in the root either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    Install,
    Flat,
}

pub const LAYOUTS: [Layout; 2] = [Layout::Install, Layout::Flat];

impl Layout {
    pub fn name(self) -> &'static str {
        match self {
            Layout::Install => "install layout",
            Layout::Flat => "flat layout",
        }
    }
}

/// A private tree holding every program in one of the layouts: the full command
/// and its automatic copy, the deadline role and its automatic copy, the gate and
/// the contain role.
pub struct Tree {
    _root: TempDir,
    pub layout: Layout,
    pub root: PathBuf,
    /// The folder of the full command and its automatic copy.
    pub bin: PathBuf,
    /// The folder of the deadline role, its automatic copy and the gate.
    pub libexec: PathBuf,
}

impl Tree {
    pub fn new(layout: Layout, prefix: &str) -> Tree {
        Tree::new_in(&std::env::temp_dir(), layout, prefix)
    }

    /// Like `new`, with the tree made under `base`.
    pub fn new_in(base: &Path, layout: Layout, prefix: &str) -> Tree {
        let root = TempDir::new_in(base, prefix);
        let bin = root.join("bin");
        let libexec = if layout == Layout::Install { root.join("libexec") } else { bin.clone() };
        for dir in [&bin, &libexec] {
            std::fs::create_dir_all(dir).expect("create a program folder");
        }
        let root_path = root.path().to_path_buf();
        let tree = Tree { _root: root, layout, root: root_path, bin, libexec };
        copy_role(&tree.bin, ROLES[0], ROLES[0]);
        copy_role(&tree.bin, ROLES[0], "process-tree-guard-auto");
        copy_role(&tree.libexec, ROLES[1], ROLES[1]);
        copy_role(&tree.libexec, ROLES[1], "process-tree-guard-deadline-auto");
        copy_role(&tree.libexec, ROLES[2], ROLES[2]);
        copy_role(&tree.libexec, ROLES[3], ROLES[3]);
        tree
    }

    /// The Windows path of `<name>.exe` in the folder that holds it in this layout.
    pub fn exe(&self, name: &str) -> String {
        let folder = if name == ROLES[0] || name == "process-tree-guard-auto" { &self.bin } else { &self.libexec };
        text(&folder.join(format!("{}.exe", name)))
    }

    /// Remove `<name>.exe` from its folder.
    pub fn remove(&self, name: &str) {
        std::fs::remove_file(self.exe(name)).unwrap_or_else(|e| panic!("cannot remove {}: {}", name, e));
    }
}

pub const BASH: &str = "C:/Program Files/Git/bin/bash.exe";

// ------------------------------------------------------------------- running

pub struct Out {
    pub code: u32,
    pub stdout: Vec<u8>,
    pub stdout_len: u64,
    pub stderr: Vec<u8>,
    pub elapsed: Duration,
    /// When the command was started, in milliseconds since 1970 (the clock the guard's log lines are written in).
    pub began_unix_ms: i64,
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
    let began_unix_ms = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64);
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
    Out { code: status.code().unwrap_or(-1) as u32, stdout, stdout_len, stderr, elapsed: began.elapsed(), began_unix_ms }
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

/// The environment variables that set the automatic deadline, in the order the
/// guard reads them.
pub const AUTO_TIMEOUT_VARIABLES: [&str; 3] = ["PROCESS_TREE_GUARD_AUTO_TIMEOUT", "PROCESS_GUARD_AUTO_TIMEOUT", "HARNESS_AUTO_TIMEOUT"];

/// Remove the automatic deadline variables from a command's environment, so the
/// settings of the machine running the tests cannot change what a check sees.
pub fn without_deadline_variables(command: &mut Command) -> &mut Command {
    for name in AUTO_TIMEOUT_VARIABLES {
        command.env_remove(name);
    }
    command
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

// ------------------------------------------------------------ extendable runs

/// The unit of time in the scaled tests of extendable runs: one second. A test
/// that plans an end at `n` units expects it between `n` units and `n` units plus
/// the grace; the grace covers starting the processes and tearing the tree down.
pub const UNIT: f64 = 1.0;
/// The grace G of the scaled tests, in seconds.
pub const GRACE: f64 = 1.5;
/// The unit of the three cases of a deadline held up by children (G51 to G53), three seconds: in
/// the first two the boss has 2 units, in which the two guards it starts must start and register,
/// and a unit of one second leaves a busy machine too little time for that.
pub const CASE_UNIT: f64 = 3.0;

/// The environment variable that names the channel of an extendable run.
pub const CHANNEL_VARIABLE: &str = "PROCESS_TREE_GUARD_CHANNEL";

/// The arguments of an extendable run: `--extendable`, the options, `--timeout`, then the child.
pub fn extendable_args<'a>(options: &[&'a str], timeout: &'a str, child: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec!["--extendable"];
    args.extend_from_slice(options);
    args.extend(["--timeout", timeout, "--"]);
    args.extend_from_slice(child);
    args
}

/// An extendable run of the guard under test.
pub fn extendable(options: &[&str], timeout: &str, child: &[&str]) -> Out {
    run_guard(&extendable_args(options, timeout, child))
}

/// The log lines the guard wrote for requests, from a standard error text.
pub fn extension_lines(stderr: &str) -> Vec<String> {
    stderr.lines().filter(|line| line.starts_with("PROCESS_TREE_GUARD_EXTENSION: ")).map(str::to_string).collect()
}

/// The value of `name=` in a log line: the quoted text, or the word up to the next space.
pub fn log_field(line: &str, name: &str) -> Option<String> {
    let at = line.find(&format!(" {}=", name))? + name.len() + 2;
    let rest = &line[at..];
    if let Some(quoted) = rest.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = quoted.chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => return Some(out),
                '\\' => out.push(chars.next()?),
                c => out.push(c),
            }
        }
        None
    } else {
        Some(rest.split(' ').next()?.to_string())
    }
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

/// A handle to a process that is not a child of the test, opened while the
/// process is running, so that its exit code can be read after it has ended.
pub struct Watched {
    handle: *mut c_void,
}

impl Watched {
    /// None when the process cannot be opened.
    pub fn open(id: u32) -> Option<Watched> {
        let handle = unsafe { OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 0, id) };
        if handle.is_null() { None } else { Some(Watched { handle }) }
    }

    /// The exit code, once the process has ended; None if it is still running after `secs` seconds.
    pub fn exit_code(&self, secs: u64) -> Option<u32> {
        let milliseconds = secs.saturating_mul(1000).min(u32::MAX as u64 - 1) as u32;
        unsafe {
            if WaitForSingleObject(self.handle, milliseconds) != WAIT_OBJECT_0 {
                return None;
            }
            let mut code = 0u32;
            if GetExitCodeProcess(self.handle, &mut code) == 0 { None } else { Some(code) }
        }
    }
}

impl Drop for Watched {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
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
        TempDir::new_in(&std::env::temp_dir(), prefix)
    }
    /// Like `new`, with the folder created under `base` instead of the system temporary folder.
    pub fn new_in(base: &Path, prefix: &str) -> TempDir {
        std::fs::create_dir_all(base).expect("create the base folder");
        let base = PathBuf::from(long_path(base));
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

/// The text of a file that a child publishes by renaming it into place, once it
/// exists; None when it has not appeared within `secs` seconds.
pub fn published(path: &Path, secs: f64) -> Option<String> {
    wait_for_file(path, secs).then(|| std::fs::read_to_string(path).unwrap_or_default())
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

// ---------------------------------------------------------- version resources

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn BeginUpdateResourceW(filename: *const u16, delete_existing: i32) -> *mut c_void;
    fn UpdateResourceW(update: *mut c_void, kind: *const u16, name: *const u16, language: u16, data: *const c_void, size: u32) -> i32;
    fn EndUpdateResourceW(update: *mut c_void, discard: i32) -> i32;
}

type SizeFn = unsafe extern "system" fn(*const u16, *mut u32) -> u32;
type InfoFn = unsafe extern "system" fn(*const u16, u32, u32, *mut c_void) -> i32;
type QueryFn = unsafe extern "system" fn(*const c_void, *const u16, *mut *mut c_void, *mut u32) -> i32;

/// GetFileVersionInfoSizeW, GetFileVersionInfoW and VerQueryValueW from version.dll in
/// the system folder. They are loaded when first used, so the tests link on every
/// toolchain, including those that ship no import library for version.dll.
struct VersionApi {
    size: SizeFn,
    info: InfoFn,
    query: QueryFn,
}

fn version_api() -> &'static VersionApi {
    static API: OnceLock<VersionApi> = OnceLock::new();
    API.get_or_init(|| unsafe {
        let system = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let module = LoadLibraryW(wide(&format!(r"{}\System32\version.dll", system)).as_ptr());
        assert!(!module.is_null(), "version.dll cannot be loaded");
        let find = |name: &[u8]| {
            let address = GetProcAddress(module, name.as_ptr());
            assert!(!address.is_null(), "{} is not in version.dll", String::from_utf8_lossy(&name[..name.len() - 1]));
            address
        };
        VersionApi {
            size: std::mem::transmute::<*mut c_void, SizeFn>(find(b"GetFileVersionInfoSizeW\0")),
            info: std::mem::transmute::<*mut c_void, InfoFn>(find(b"GetFileVersionInfoW\0")),
            query: std::mem::transmute::<*mut c_void, QueryFn>(find(b"VerQueryValueW\0")),
        }
    })
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The version resource of an executable, read with the system calls Explorer
/// and Task Manager use: GetFileVersionInfoW and VerQueryValueW.
pub struct VersionInfo {
    block: Vec<u8>,
}

impl VersionInfo {
    /// None when the file has no version resource.
    pub fn read(path: &str) -> Option<VersionInfo> {
        let name = wide(path);
        unsafe {
            let mut handle = 0u32;
            let size = (version_api().size)(name.as_ptr(), &mut handle);
            if size == 0 {
                return None;
            }
            let mut block = vec![0u8; size as usize];
            if (version_api().info)(name.as_ptr(), 0, size, block.as_mut_ptr() as *mut c_void) == 0 {
                return None;
            }
            Some(VersionInfo { block })
        }
    }

    /// The bytes VerQueryValueW finds for `sub_block`, in the block, with the item count it reports.
    fn query(&self, sub_block: &str) -> Option<(Vec<u8>, u32)> {
        let name = wide(sub_block);
        unsafe {
            let mut found: *mut c_void = std::ptr::null_mut();
            let mut length = 0u32;
            if (version_api().query)(self.block.as_ptr() as *const c_void, name.as_ptr(), &mut found, &mut length) == 0 || found.is_null() {
                return None;
            }
            let start = (found as usize).checked_sub(self.block.as_ptr() as usize)?;
            if start > self.block.len() {
                return None;
            }
            Some((self.block[start..].to_vec(), length))
        }
    }

    /// The first language and code page pair of `\VarFileInfo\Translation`.
    pub fn translation(&self) -> Option<(u16, u16)> {
        let (bytes, length) = self.query("\\VarFileInfo\\Translation")?;
        if length < 4 || bytes.len() < 4 {
            return None;
        }
        Some((u16::from_le_bytes([bytes[0], bytes[1]]), u16::from_le_bytes([bytes[2], bytes[3]])))
    }

    /// A string of the first string table, such as `FileDescription`; None when it is not there.
    pub fn string(&self, name: &str) -> Option<String> {
        let (language, code_page) = self.translation()?;
        let (bytes, length) = self.query(&format!("\\StringFileInfo\\{:04x}{:04x}\\{}", language, code_page, name))?;
        let units: Vec<u16> = bytes.chunks_exact(2).take(length as usize).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        let end = units.iter().position(|unit| *unit == 0).unwrap_or(units.len());
        Some(String::from_utf16_lossy(&units[..end]))
    }

    /// The thirteen words of VS_FIXEDFILEINFO.
    pub fn fixed(&self) -> Option<[u32; 13]> {
        let (bytes, length) = self.query("\\")?;
        if length < 52 || bytes.len() < 52 {
            return None;
        }
        let mut words = [0u32; 13];
        for (index, word) in words.iter_mut().enumerate() {
            *word = u32::from_le_bytes([bytes[4 * index], bytes[4 * index + 1], bytes[4 * index + 2], bytes[4 * index + 3]]);
        }
        Some(words)
    }
}

/// Replace the version resource (RT_VERSION, name 1, US English) of the executable at `path` with `data`.
pub fn set_version_resource(path: &Path, data: &[u8]) -> bool {
    let name = wide(&text(path));
    unsafe {
        let update = BeginUpdateResourceW(name.as_ptr(), 0);
        if update.is_null() {
            return false;
        }
        let added = UpdateResourceW(update, 16usize as *const u16, 1usize as *const u16, 0x0409, data.as_ptr() as *const c_void, data.len() as u32);
        let ended = EndUpdateResourceW(update, if added == 0 { 1 } else { 0 });
        added != 0 && ended != 0
    }
}

/// The resources of a `.res` file as (type, name, data), for the numbered (ordinal)
/// types and names only; None when the file is not well formed. The first entry,
/// the empty resource that starts every `.res` file, is checked and left out.
pub fn parse_res(bytes: &[u8]) -> Option<Vec<(u16, u16, Vec<u8>)>> {
    const EMPTY: [u8; 32] = [0, 0, 0, 0, 32, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    if bytes.get(..32)? != EMPTY {
        return None;
    }
    let word = |at: usize| bytes.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize);
    let half = |at: usize| bytes.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let mut found = Vec::new();
    let mut at = 32;
    while at < bytes.len() {
        let (size, header) = (word(at)?, word(at + 4)?);
        if header != 32 || half(at + 8)? != 0xFFFF || half(at + 12)? != 0xFFFF {
            return None;
        }
        let data = bytes.get(at + header..at + header + size)?.to_vec();
        found.push((half(at + 10)?, half(at + 14)?, data));
        at += header + (size + 3) / 4 * 4;
    }
    if at == bytes.len() { Some(found) } else { None }
}

// -------------------------------------------------------------------- checks

/// Whether timing bounds are asserted, given the values of PROCESS_TREE_GUARD_TIMING
/// and of the 1.x name PROCESS_GUARD_TIMING. The first one that is set decides;
/// "info" reports the bounds without failing, as a loaded machine needs.
pub fn timing_strict_for(new_name: Option<&str>, old_name: Option<&str>) -> bool {
    new_name.or(old_name).map_or(true, |value| !value.eq_ignore_ascii_case("info"))
}

/// Timing bounds are asserted unless PROCESS_TREE_GUARD_TIMING, else
/// PROCESS_GUARD_TIMING, is set to "info".
pub fn timing_strict() -> bool {
    let (new_name, old_name) = (std::env::var("PROCESS_TREE_GUARD_TIMING").ok(), std::env::var("PROCESS_GUARD_TIMING").ok());
    timing_strict_for(new_name.as_deref(), old_name.as_deref())
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
    /// A structural bound on time: asserted whatever the timing setting. It is set well
    /// away from the right answer and near the wrong one (the time a broken run would take
    /// is a multiple of the right one), so a broken implementation cannot pass it, and a
    /// correct run meets it on a machine that is busy but not oversubscribed. On a machine
    /// that is oversubscribed a helper can start so late that a correct run ends after the
    /// bound, or is refused its request, and the check then fails: the bounds are not
    /// proof against any load. The tight bounds, the planned end plus the grace, are `timing`
    /// checks.
    pub fn bound(&mut self, id: &str, name: &str, ok: bool, detail: impl Display) {
        self.check(id, &format!("{} (structural bound, always asserted)", name), ok, detail);
    }
    pub fn info(&self, line: impl Display) {
        println!("INFO {}", line);
    }
    /// A line that must show on a plain `cargo test`: it is written straight to
    /// standard error, which the test harness does not capture, where `info` is hidden
    /// unless the run is made with `--nocapture`.
    pub fn notice(&self, line: impl Display) {
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), "NOTICE {}", line);
    }
    pub fn finish(self) {
        if !self.failed.is_empty() {
            panic!("{}: {} failed: {}", self.section, self.failed.len(), self.failed.join("; "));
        }
    }
}
