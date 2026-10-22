// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! Extendable runs: the channel, the holds, the deadline and the log.
//!
//! A guard started with `--extendable` serves a private named pipe. A process in
//! the guard's job can ask on it for its deadline to be held up, for a number of
//! seconds no greater than the cap of the run. The guard checks, before it
//! replies, that the process is alive, is in its job and started before the
//! guard learned of the connection, and keeps a hold on that process by
//! handle, never by process identifier. The deadline of the run at every
//! moment is the latest of its own deadline and the holds of live processes;
//! it is recalculated under one lock on every grant and every
//! exit. The clock is `GetTickCount64`, which counts
//! time asleep and does not follow changes of the wall clock. A request that
//! arrives after the deadline is refused, whether or not the supervisor has yet
//! noticed that the deadline passed.
//!
//! The pipe has four instances, each served by a thread of its own, and what one
//! connection can cost is bounded: who the client is, and its share of the rate, are
//! settled before a byte of its message is waited for, and the waits are short. The
//! pipe has no outgoing buffer, so a reply is written only as far as the client reads
//! it; a grant whose reply is not taken in time is withdrawn, so that the client and
//! the run agree about whether a hold exists.
//!
//! The log is written by threads of its own, from bounded queues, so that a
//! destination that stops taking lines (a standard error that nobody reads) can
//! never hold up the answers or the deadline. The audit file is the one
//! destination that can stop the grants: while it cannot take the lines of the
//! grants, nothing is granted (see `AuditFile`). With no audit file, standard error is the
//! only record, and a grant stands only once its line has been written there (see
//! `Log::record`).
//!
//! The same module is the client: `request` asks the enclosing run, and
//! `register_start` is the request a nested guard makes when it starts. A library
//! call made inside a run is a nested guard in a process that goes on, so when it
//! returns it makes a `release`, which ends the hold its start made.

use crate::auth::Exception;
use crate::engine::{format_seconds, job_process_ids};
use crate::sys::*;
use crate::GuardError;
use std::ffi::c_void;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::collections::VecDeque;
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The environment variable that names the channel of the enclosing extendable run.
pub const CHANNEL_VARIABLE: &str = "PROCESS_TREE_GUARD_CHANNEL";

/// The largest extension a run grants unless `--max-extension` says otherwise: six hours.
pub const DEFAULT_MAX_EXTENSION: f64 = 21600.0;

const PIPE_PREFIX: &str = "\\\\.\\pipe\\process-tree-guard-";
const REQUEST_MAGIC: u64 = u64::from_le_bytes(*b"PTGERQ01");
const REPLY_MAGIC: u64 = u64::from_le_bytes(*b"PTGERP01");
const REQUEST_SIZE: usize = 24;
const REPLY_SIZE: usize = 40;
/// Requests allowed per process in one window, and the window. Every client outside
/// the job shares one such allowance.
const RATE_LIMIT: usize = 12;
const RATE_WINDOW_MS: u64 = 10_000;
/// Live processes the rate limit tells apart at once; when they are all live, a new one is refused.
/// A process that has exited is forgotten as soon as the table is full.
const MAX_RATE_KEYS: usize = 1024;
/// After a pass over the table that forgot nobody (every process in it is live), the next one waits this long.
const FORGET_MS: u64 = 250;
/// Live holds at once.
const MAX_HOLDS: usize = 256;
/// Live holds one process can have at once, all its tokens together, so that one process
/// cannot take the table from the rest.
const MAX_HOLDS_PER_PROCESS: usize = 8;
/// Refusal lines written in one window, over all processes; the rest are counted in one line.
const REFUSAL_LINES: usize = 24;
/// Instances of the pipe, all made by the guard before the command starts, each served by a
/// thread of its own, so that a client that stalls one cannot keep the others waiting.
const INSTANCES: u32 = 4;
/// How long a client that the run will answer has to send its request, and then to take the
/// reply. A client that sends nothing is dropped when the first runs out. The pipe has no
/// outgoing buffer, so the write of a reply completes only when the client reads it: a reply
/// that is not taken in time is cancelled, and the hold it granted is withdrawn.
const READ_MS: u32 = 250;
const TAKE_MS: u32 = 500;
/// How long a grant waits for its line to be written to standard error when that is the only record.
pub(crate) const RECORD_MS: u64 = 500;
/// The same for a client that is refused whatever it sends (the rate limit, a run that has
/// ended): the request is read only to put its numbers in the log.
const REFUSED_READ_MS: u32 = 25;
const REFUSED_TAKE_MS: u32 = 250;
/// The longest the supervisor goes without recalculating the deadline.
pub(crate) const BACKSTOP_MS: u64 = 100;
/// The log file is rotated once it would pass this size.
const LOG_LIMIT: u64 = 1 << 20;
/// The most a file that cannot be turned over keeps free below twice its limit before the run
/// stops granting: room for the lines that are queued when it happens.
const MAX_RESERVE: u64 = 64 * 1024;
/// How long after a turn over of the audit file failed it is tried again.
const TURN_OVER_RETRY_MS: u64 = 1000;
/// How long the audit file waits for a line before it tries again to write the ones it holds.
const RETRY_MS: u64 = 500;
/// Lines the audit file holds back, to try again, while it cannot be written; past that,
/// lines are left out, and counted.
const HELD_LINES: usize = LOG_QUEUE;
/// Lines each copy of the log can have waiting; the next ones are dropped, and counted.
const LOG_QUEUE: usize = 256;
/// How long the end of a run waits for a copy of the log to take its last lines.
pub(crate) const LOG_FLUSH_MS: u64 = 500;
/// How long a client waits for the channel.
const CONNECT_MS: u64 = 5000;
/// How long a client waits for the reply once its request is sent.
const REPLY_MS: u32 = 5000;
/// The mode of the channel: messages, not bytes, and no client from another machine.
const CHANNEL_PIPE_MODE: u32 = PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS;
/// The size of the outgoing buffer of the channel: none, so that a write completes when the
/// client reads it, and the guard knows whether a reply was taken.
const OUT_BUFFER: u32 = 0;
/// Rights on the pipe for its one user: read and write data, read attributes,
/// read the access list and synchronize; not the right to make another instance.
const PIPE_RIGHTS: &str = "0x12019b";
/// The same with the right to make another instance, which the guard needs for the length of
/// the time it makes the instances.
const PIPE_RIGHTS_WHILE_MAKING: &str = "0x12019f";
/// What a client asks for: exactly those rights, since the generic write right
/// includes the one the list leaves out.
const CLIENT_ACCESS: u32 = 0x0010_0183;

/// A grant: how long the deadline was held, and until when (wall clock time).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Grant {
    /// The seconds granted, from the moment of the grant.
    pub seconds: f64,
    /// The time the hold ends, as the guard's clock read it at the grant.
    pub until: SystemTime,
}

// ------------------------------------------------------------------ clocks, text

pub(crate) fn tick() -> u64 {
    unsafe { GetTickCount64() }
}

/// The wall clock to the precision the system has, in the units of a process's
/// creation time. The coarse clock can read earlier than a process that began a
/// moment ago, so it is never used to compare with one.
fn filetime_now() -> u64 {
    let mut time = 0u64;
    unsafe { GetSystemTimePreciseAsFileTime(&mut time) };
    time
}

fn unix_ms_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

fn millis(seconds: f64) -> u64 {
    (seconds * 1000.0).ceil() as u64
}

/// Universal time as `2026-10-20T15:04:05.123Z`, from milliseconds since 1970.
pub(crate) fn iso8601(unix_ms: u64) -> String {
    let days = (unix_ms / 86_400_000) as i64;
    let in_day = unix_ms % 86_400_000;
    // Civil date from a day count (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted + 2) / 5 + 1;
    let month = if shifted < 10 { shifted + 3 } else { shifted - 9 };
    let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z", year, month, day,
        in_day / 3_600_000, in_day / 60_000 % 60, in_day / 1000 % 60, in_day % 1000)
}

/// The characters of the Unicode category Cf (format): the ones that change how the text
/// around them is shown without being shown themselves, such as the bidirectional
/// controls, the zero width characters and the byte order mark.
pub(crate) fn is_format(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x0890..=0x0891 | 0x08E2 | 0x180E
        | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB
        | 0x110BD | 0x110CD | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F)
}

/// Text for a log value in double quotes: the quote, the backslash and every
/// control, line separating or format character are escaped, so no value can end a
/// line or start a field of its own, and none can change how the rest of the line is
/// shown, as a right-to-left override does (Common Weakness Enumeration, CWE-117 and CWE-451).
pub(crate) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() || c == '\u{2028}' || c == '\u{2029}' || is_format(c) => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

// ----------------------------------------------------------------------- the wire

/// Whose deadline a request holds up: the process that asks, or its parent (the
/// `extend` program, which ends at once, asks for the process that ran it). A release
/// is the end of a hold the process asked for: a library call makes one when it returns.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Target {
    Caller = 1,
    Parent = 2,
    Release = 3,
}

/// Why a request was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Refusal {
    OverCap = 1,
    NotInJob,
    RateLimited,
    Malformed,
    TooManyHolds,
    Ended,
    InvalidSeconds,
    Unverified,
    Crowded,
    NoHold,
    TooManyHoldsHere,
    AuditBlocked,
    HolderNotInJob,
}

impl Refusal {
    fn from_code(code: u64) -> Option<Refusal> {
        [Refusal::OverCap, Refusal::NotInJob, Refusal::RateLimited, Refusal::Malformed, Refusal::TooManyHolds,
            Refusal::Ended, Refusal::InvalidSeconds, Refusal::Unverified, Refusal::Crowded, Refusal::NoHold,
            Refusal::TooManyHoldsHere, Refusal::AuditBlocked, Refusal::HolderNotInJob].into_iter().find(|r| *r as u64 == code)
    }

    /// The reason as the log and the refused process read it. `cap` is the run's cap in seconds.
    pub(crate) fn describe(self, cap: f64) -> String {
        match self {
            Refusal::OverCap => format!("the request is over the cap of {} seconds", format_seconds(cap)),
            Refusal::NotInJob => "the process is not in the job of this run".into(),
            Refusal::RateLimited => "too many requests from this process; try again later".into(),
            Refusal::Malformed => "the request is malformed".into(),
            Refusal::TooManyHolds => "too many processes hold the deadline".into(),
            Refusal::Ended => "the run has ended".into(),
            Refusal::InvalidSeconds => "the seconds must be greater than zero and at most 86400".into(),
            Refusal::Unverified => "the process could not be verified".into(),
            Refusal::Crowded => "too many processes are asking at once; try again later".into(),
            Refusal::NoHold => "the process holds no deadline to end".into(),
            Refusal::TooManyHoldsHere => "this process holds too many deadlines".into(),
            Refusal::AuditBlocked => "the audit file (or standard error, when there is no audit file) cannot take lines, so nothing is granted until it can".into(),
            Refusal::HolderNotInJob => "the process to hold is not in the job of this run".into(),
        }
    }
}

pub(crate) enum Reply {
    /// `held` is the process the hold is on when it is not the one that asked (0 otherwise).
    Granted { seconds: f64, until_unix_ms: u64, held: u32 },
    Refused { refusal: Refusal, cap: f64 },
}

fn word(bytes: &[u8], index: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
    u64::from_le_bytes(raw)
}

/// Which hold of a process a request is for. A process has one hold for each token: the
/// calls of the library that overlap in one process (threads of a host) each have a token
/// of their own, so that one call's grant and release never touch another call's hold.
/// Token 0 is the hold of the process itself (the `extend` call, the `extend` program and
/// a guard program). A token is 56 bits: it shares a word of the request with the target.
pub(crate) type Token = u64;

const TOKEN_BITS: u32 = 56;

/// A token no other call of this process has used: the next number, from 1.
pub(crate) fn next_token() -> Token {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::SeqCst) & ((1 << TOKEN_BITS) - 1)
}

fn encode_request(target: Target, token: Token, seconds: f64) -> [u8; REQUEST_SIZE] {
    let mut out = [0u8; REQUEST_SIZE];
    let kind = target as u64 | ((token & ((1 << TOKEN_BITS) - 1)) << 8);
    for (index, value) in [REQUEST_MAGIC, kind, seconds.to_bits()].into_iter().enumerate() {
        out[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    out
}

fn decode_request(bytes: &[u8]) -> Option<(Target, Token, f64)> {
    if bytes.len() != REQUEST_SIZE || word(bytes, 0) != REQUEST_MAGIC {
        return None;
    }
    let kind = word(bytes, 1);
    let target = match kind & 0xff {
        1 => Target::Caller,
        2 => Target::Parent,
        3 => Target::Release,
        _ => return None,
    };
    Some((target, kind >> 8, f64::from_bits(word(bytes, 2))))
}

fn encode_reply(reply: &Reply) -> [u8; REPLY_SIZE] {
    let words = match reply {
        Reply::Granted { seconds, until_unix_ms, held } => [REPLY_MAGIC, 0, *held as u64, seconds.to_bits(), *until_unix_ms],
        Reply::Refused { refusal, cap } => [REPLY_MAGIC, 1, *refusal as u64, cap.to_bits(), 0],
    };
    let mut out = [0u8; REPLY_SIZE];
    for (index, value) in words.into_iter().enumerate() {
        out[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    out
}

/// The latest time a reply can name, the end of the year 9999, in milliseconds since 1970.
const LATEST_UNTIL_MS: u64 = 253_402_300_799_999;

/// A reply as the client reads it. The client does not know who serves the channel, so it
/// accepts nothing out of range: the seconds (and the cap, in a refusal) are finite numbers
/// from 0 to `MAX_SECONDS`, and the time is one a clock can show.
fn decode_reply(bytes: &[u8]) -> Option<Reply> {
    if bytes.len() != REPLY_SIZE || word(bytes, 0) != REPLY_MAGIC {
        return None;
    }
    let seconds = f64::from_bits(word(bytes, 3));
    if !(seconds.is_finite() && (0.0..=crate::MAX_SECONDS).contains(&seconds)) {
        return None;
    }
    match word(bytes, 1) {
        0 if word(bytes, 4) <= LATEST_UNTIL_MS => Some(Reply::Granted { seconds, until_unix_ms: word(bytes, 4), held: u32::try_from(word(bytes, 2)).ok()? }),
        1 => Some(Reply::Refused { refusal: Refusal::from_code(word(bytes, 2))?, cap: seconds }),
        _ => None,
    }
}

fn not_understood() -> GuardError {
    GuardError("the extendable run sent a reply that is not understood".into())
}

// ---------------------------------------------------------------------- the log

/// One request as the log records it.
struct Entry<'a> {
    pid: u32,
    image: &'a str,
    requested: Option<f64>,
    granted: Option<f64>,
    reason: &'a str,
}

/// A number of seconds as the log records it: exactly, and in a bounded number of
/// characters. A value too large or too small to read as a plain decimal is written in
/// scientific form (`1e300`, `5e-324`), never rounded or cut.
fn log_seconds(value: f64) -> String {
    if !value.is_finite() {
        "invalid".into()
    } else if value != 0.0 && (value.abs() >= 1e15 || value.abs() < 1e-6) {
        format!("{:e}", value)
    } else {
        format!("{}", value)
    }
}

fn log_line(unix_ms: u64, entry: &Entry) -> String {
    let number = |value: Option<f64>| value.map_or_else(|| "unknown".to_string(), log_seconds);
    format!("PROCESS_TREE_GUARD_EXTENSION: time={} pid={} image=\"{}\" requested={} granted={} decision={} reason=\"{}\"",
        iso8601(unix_ms), entry.pid, escape(entry.image), number(entry.requested), number(entry.granted.or(Some(0.0))),
        if entry.granted.is_some() { "granted" } else { "refused" }, escape(entry.reason))
}

/// The line for the end of a hold at the request of the process that held it. It moves
/// the deadline only earlier, and is a line of its own like a grant.
fn released_line(unix_ms: u64, pid: u32, image: &str, reason: &str) -> String {
    format!("PROCESS_TREE_GUARD_EXTENSION: time={} pid={} image=\"{}\" requested=0 granted=0 decision=released reason=\"{}\"",
        iso8601(unix_ms), pid, escape(image), escape(reason))
}

/// The line for a grant taken back because the process did not take the reply: the run and
/// the process must not disagree about whether a hold exists. It moves the deadline only earlier.
fn withdrawn_line(unix_ms: u64, back: &Withdraw, take_ms: u32) -> String {
    format!("PROCESS_TREE_GUARD_EXTENSION: time={} pid={} image=\"{}\" requested={} granted=0 decision=withdrawn reason=\"the reply was not taken within {} milliseconds; the hold was withdrawn\"",
        iso8601(unix_ms), back.pid, escape(&back.image), log_seconds(back.seconds), take_ms)
}

/// The line for a grant taken back because its own line was not written to standard error, which
/// is the only record when there is no audit file: a deadline is not moved by a request that is
/// recorded nowhere. It moves the deadline only earlier.
fn unrecorded_line(unix_ms: u64, back: &Withdraw, wait_ms: u64) -> String {
    format!("PROCESS_TREE_GUARD_EXTENSION: time={} pid={} image=\"{}\" requested={} granted=0 decision=withdrawn reason=\"the line of the grant was not written to standard error within {} milliseconds, and there is no audit file; the hold was withdrawn\"",
        iso8601(unix_ms), back.pid, escape(&back.image), log_seconds(back.seconds), wait_ms)
}

/// A notice about the log itself.
fn notice_line(unix_ms: u64, text: &str) -> String {
    format!("PROCESS_TREE_GUARD_EXTENSION: time={} notice=\"{}\"", iso8601(unix_ms), escape(text))
}

/// The hours of a number of seconds as a figure, rounded up to two decimals, with the zeros at
/// the end left off (`24`, `6.5`, `6.95`), so that a cap such as 25000 seconds is not shown as
/// `6.944444444444445`. Rounded up from the whole seconds, so that the figure is never smaller
/// than the cap: a cap just over six hours is never shown as the default cap that needs no password.
pub(crate) fn hours_figure(seconds: f64) -> String {
    let hundredths = (seconds / 36.0).ceil() as u64;
    let fraction = format!("{:02}", hundredths % 100);
    match fraction.trim_end_matches('0') {
        "" => format!("{}", hundredths / 100),
        digits => format!("{}.{}", hundredths / 100, digits),
    }
}

/// What the line for a decision on an exception above the cap is about. `account` is the account
/// the guard runs as and `command` the command line the decision is about (as the prompt shows it),
/// so that the record says what was approved and for whom; `method` is how the user was asked
/// (`desktop` or `console`), `timeout` the deadline the run starts with, in seconds, and
/// `started_by` the nearest process that started the guard, as the prompt shows it (empty when it
/// is not known). `requested` is the cap asked for, in seconds. `attempt` is the number of the
/// attempt (the attempts made before it when the run was refused before one was shown: 0 for a
/// prompt that was never shown).
pub(crate) struct ExceptionRecord<'a> {
    pub unix_ms: u64,
    pub pid: u32,
    pub image: &'a str,
    pub account: &'a str,
    pub command: &'a str,
    pub method: &'a str,
    pub timeout: f64,
    pub started_by: &'a str,
    pub requested: f64,
    pub approved: bool,
    pub attempt: u32,
    pub reason: &'a str,
}

/// The line for the decision on an exception above the cap, taken at the start of the run:
/// `exception-approved` once the user has given the password, `exception-refused` for an
/// attempt that failed or a run that cannot be asked. `hours` is the cap in hours (rounded up).
/// Nothing the user typed is in it: not the password, and not a name.
pub(crate) fn exception_line(record: &ExceptionRecord) -> String {
    format!("PROCESS_TREE_GUARD_EXTENSION: time={} pid={} image=\"{}\" account=\"{}\" command=\"{}\" method=\"{}\" timeout={} started_by=\"{}\" requested={} hours={} granted=0 decision={} attempt={} reason=\"{}\"",
        iso8601(record.unix_ms), record.pid, escape(record.image), escape(record.account), escape(record.command), escape(record.method), log_seconds(record.timeout),
        escape(record.started_by), log_seconds(record.requested), hours_figure(record.requested),
        if record.approved { "exception-approved" } else { "exception-refused" }, record.attempt, escape(record.reason))
}

/// The text of the notice for a run whose exception was approved and which then could not start.
pub(crate) fn not_started_text(error: &GuardError) -> String {
    format!("the approved run did not start: {}", error.message())
}

/// The time now, as the lines of the log write it.
pub(crate) fn now_ms() -> u64 {
    unix_ms_now()
}

/// The notice that lines were left out of a copy of the log because it could not keep up.
fn dropped_line(unix_ms: u64, count: usize) -> String {
    format!("PROCESS_TREE_GUARD_EXTENSION: time={} notice=\"{} log lines were not written because this copy of the log could not keep up\"",
        iso8601(unix_ms), count)
}

/// The notice that refusal lines were left out, so that the lines before them stay in the log.
fn withheld_line(unix_ms: u64, count: u32) -> String {
    format!("PROCESS_TREE_GUARD_EXTENSION: time={} notice=\"{} refusal lines were not written, to keep the earlier lines in the log\"",
        iso8601(unix_ms), count)
}

fn relock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// One copy of the log: a bounded queue of lines and the thread that writes them. A
/// destination that stops taking lines holds up its own thread and nothing else; the
/// lines wait in the queue, and when it is full they are dropped and counted.
struct Sink {
    queue: Mutex<Option<SyncSender<String>>>,
    /// The lines queued so far, and (with a signal for whoever waits) the lines the thread has finished writing.
    queued: AtomicUsize,
    progress: Arc<(Mutex<usize>, Condvar)>,
    dropped: Arc<AtomicUsize>,
    finished: Mutex<Receiver<()>>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

/// Write the notice for the lines dropped since the last one, if any.
fn report_dropped(dropped: &AtomicUsize, write: &mut dyn FnMut(&str)) {
    let count = dropped.swap(0, Ordering::SeqCst);
    if count > 0 {
        write(&dropped_line(unix_ms_now(), count));
    }
}

/// What a destination does besides taking a line: called with `false` when no line has come
/// for `RETRY_MS` (so a destination that failed is tried again without waiting for the next
/// line), and once with `true` when the sink has taken its last line.
type Idle = Box<dyn FnMut(bool) + Send>;

impl Sink {
    fn start(name: &str, write: Box<dyn FnMut(&str) + Send>, capacity: usize) -> Result<Sink, GuardError> {
        Sink::start_with(name, write, None, capacity)
    }

    fn start_with(name: &str, mut write: Box<dyn FnMut(&str) + Send>, mut idle: Option<Idle>, capacity: usize) -> Result<Sink, GuardError> {
        let (sender, lines) = sync_channel::<String>(capacity);
        let (done, finished) = std::sync::mpsc::channel();
        let dropped = Arc::new(AtomicUsize::new(0));
        let counted = dropped.clone();
        let progress = Arc::new((Mutex::new(0usize), Condvar::new()));
        let written = progress.clone();
        let thread = std::thread::Builder::new().name(name.into()).spawn(move || {
            loop {
                let line = match idle.as_mut() {
                    None => match lines.recv() {
                        Ok(line) => line,
                        Err(_) => break,
                    },
                    Some(idle) => match lines.recv_timeout(Duration::from_millis(RETRY_MS)) {
                        Ok(line) => line,
                        Err(RecvTimeoutError::Timeout) => {
                            idle(false);
                            continue;
                        }
                        Err(RecvTimeoutError::Disconnected) => break,
                    },
                };
                write(&line);
                *relock(&written.0) += 1;
                written.1.notify_all();
                report_dropped(&counted, &mut *write);
            }
            report_dropped(&counted, &mut *write);
            if let Some(idle) = idle.as_mut() {
                idle(true);
            }
            let _ = done.send(());
        }).map_err(|error| GuardError(format!("cannot start the log thread: {}", error)))?;
        Ok(Sink { queue: Mutex::new(Some(sender)), queued: AtomicUsize::new(0), progress, dropped, finished: Mutex::new(finished), thread: Mutex::new(Some(thread)) })
    }

    /// Queue a line without waiting: a full queue drops it and counts it. The answer is the
    /// number of the line among those queued (the queue lock is held, so numbers are in queue
    /// order), or none when the line was dropped.
    fn enqueue(&self, line: &str) -> Option<usize> {
        let queue = relock(&self.queue);
        let sender = queue.as_ref()?;
        if sender.try_send(line.to_string()).is_err() {
            self.dropped.fetch_add(1, Ordering::SeqCst);
            return None;
        }
        Some(self.queued.fetch_add(1, Ordering::SeqCst) + 1)
    }

    fn push(&self, line: &str) {
        let _ = self.enqueue(line);
    }

    /// Wait, at most `wait_ms`, until the thread has finished writing the line with this number.
    fn wait_written(&self, number: usize, wait_ms: u64) -> bool {
        let end = Instant::now() + Duration::from_millis(wait_ms);
        let mut done = relock(&self.progress.0);
        while *done < number {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            done = self.progress.1.wait_timeout(done, left).unwrap_or_else(|poisoned| poisoned.into_inner()).0;
        }
        true
    }

    /// Stop taking lines and wait, at most `wait_ms`, for the ones queued to be written.
    /// A thread still stuck in a write is left to end with the process.
    fn finish(&self, wait_ms: u64) {
        if relock(&self.queue).take().is_none() {
            return;
        }
        if relock(&self.finished).recv_timeout(Duration::from_millis(wait_ms)).is_ok() {
            if let Some(thread) = relock(&self.thread).take() {
                let _ = thread.join();
            }
        }
    }
}

/// Write a line to standard error with a call on its handle, not through Rust's lock on
/// it: a write that cannot finish then holds up the log thread only, and the guard's own
/// notices, which share the stream, can still be written. The line is one call, so a line
/// of the log cannot land inside it, nor it inside one (Common Weakness Enumeration,
/// CWE-362); the notices and the errors of the guard are written the same way, and a
/// write that fails is ignored.
pub(crate) fn write_standard_error(line: &str) {
    let _ = try_write_standard_error(line);
}

/// As `write_standard_error`, and true when the whole line was written.
fn try_write_standard_error(line: &str) -> bool {
    unsafe {
        let handle = GetStdHandle(-12i32 as u32);
        if handle.is_null() || handle == INVALID_HANDLE {
            return false;
        }
        let text = format!("{}\n", line);
        let mut mode = 0u32;
        if GetConsoleMode(handle, &mut mode) != 0 {
            let units: Vec<u16> = text.encode_utf16().collect();
            let mut written = 0u32;
            return WriteConsoleW(handle, units.as_ptr() as *const c_void, units.len() as u32, &mut written, std::ptr::null_mut()) != 0;
        }
        let bytes = text.as_bytes();
        let mut done = 0usize;
        while done < bytes.len() {
            let mut written = 0u32;
            if WriteFile(handle, bytes[done..].as_ptr() as *const c_void, (bytes.len() - done) as u32, &mut written, std::ptr::null_mut()) == 0 || written == 0 {
                return false;
            }
            done += written as usize;
        }
        true
    }
}

/// True when standard error can hold a record: it is open and is a console, a file or a
/// pipe. A character device that is not a console (the null device) takes every write and
/// keeps none of it, so a log written there is a log nowhere.
fn standard_error_records() -> bool {
    unsafe {
        let handle = GetStdHandle(-12i32 as u32);
        if handle.is_null() || handle == INVALID_HANDLE {
            return false;
        }
        let mut mode = 0u32;
        GetConsoleMode(handle, &mut mode) != 0 || matches!(GetFileType(handle), FILE_TYPE_DISK | FILE_TYPE_PIPE)
    }
}

/// Open the file once for appending, so a bad path is an error before the command starts.
/// The path must name a file on a disk: a device (the null device, a console) or a pipe
/// takes every write and keeps none of it, which is a log nowhere (Common Weakness
/// Enumeration, CWE-778).
fn check_log_path(path: Option<&Path>) -> Result<(), GuardError> {
    if let Some(path) = path {
        let file = std::fs::OpenOptions::new().create(true).append(true).open(path)
            .map_err(|error| GuardError(format!("cannot open the extension log {}: {}", path.display(), error)))?;
        require_disk_file(&file, path)?;
    }
    Ok(())
}

fn require_disk_file(file: &std::fs::File, path: &Path) -> Result<(), GuardError> {
    use std::os::windows::io::AsRawHandle;
    if unsafe { GetFileType(file.as_raw_handle() as Handle) } != FILE_TYPE_DISK {
        return Err(GuardError(format!("the extension log must be a regular file: {} is a device or a pipe; the run did not start", path.display())));
    }
    Ok(())
}

/// The audit file: lines are appended, and the file is turned over to `PATH.1` when a line
/// would take it past `limit`. A turn over can fail, because a program that follows the
/// file may hold it open without sharing the right to delete it, which stops a rename.
/// The earlier lines are never discarded for that: the file is copied to `PATH.1` and
/// emptied instead, and when that fails too it grows past `limit` as far as twice `limit`,
/// with a notice in it, and then takes no more lines until a turn over works (standard
/// error still has them). `PATH.1` is not held open by the guard: a program that reads it
/// without sharing the right to delete it (and any program in the job can) stops both ways
/// of turning the file over. So the file cannot be relied on to take lines for ever, and a
/// run whose file is about to stop taking them stops granting (see `blocked`).
///
/// A write can fail too: a program that reads the file without sharing the right to write
/// it (the default of many file readers) refuses the guard's append. The file is held open
/// for the run, which keeps such a reader from opening it at all; when a write fails
/// nonetheless (the reader was there first, the folder went away), the line is held, up to
/// `HELD_LINES`, and written in order as soon as a write works again. Standard error is told
/// of the failure at once, and the file gets a notice with the counts once it takes lines.
///
/// A grant that the file would not record is a deadline moved by a request that is not in
/// the audit record, so while lines cannot be placed (writes failing, or a file that cannot
/// be turned over and has less than `reserve` bytes left before twice its limit) the file is
/// `blocked` and the run grants nothing, with a reason, until it can place lines again.
struct AuditFile {
    path: PathBuf,
    limit: u64,
    /// Bytes below twice `limit` that a file which cannot be turned over keeps for the lines
    /// that are already on their way when it becomes blocked.
    reserve: u64,
    /// Set while the file cannot be relied on to take the lines of the grants: the run reads it.
    blocked: Arc<AtomicBool>,
    /// The notice that a turn over failed is in the file.
    stuck: bool,
    /// The notice that the file takes no more lines is in the file.
    full: bool,
    /// When a failed turn over was last tried, so a file that cannot be turned over is not
    /// copied for every line.
    tried: Option<std::time::Instant>,
    /// The file, open for appending for the whole run, so that a program that reads it
    /// without sharing the right to write cannot open it. Never written through.
    _keep: Option<std::fs::File>,
    /// Lines that could not be written, oldest first.
    held: VecDeque<String>,
    /// Lines left out because `HELD_LINES` were already held.
    lost: usize,
    /// Lines written late (held, and written when the file took lines again) in this failure.
    late: usize,
    /// The file cannot be written, and standard error has been told.
    failing: bool,
    /// Where a notice goes at once: standard error.
    alert: Box<dyn Fn(&str) + Send>,
}

impl AuditFile {
    fn new(path: PathBuf, limit: u64) -> AuditFile {
        let _keep = AuditFile::open(&path).ok();
        AuditFile {
            path, limit, reserve: (limit / 16).min(MAX_RESERVE), blocked: Arc::new(AtomicBool::new(false)), stuck: false, full: false, tried: None,
            _keep, held: VecDeque::new(), lost: 0, late: 0, failing: false, alert: Box::new(|_| {}),
        }
    }

    /// Before the command starts: turn the file over if it is already past its limit, and say
    /// whether it can take lines. A file that cannot is a record the run could not keep.
    fn settle(&mut self) -> bool {
        self.turn_over_if_due(0);
        self.refresh();
        !self.blocked.load(Ordering::SeqCst)
    }

    /// Work out whether the file can be relied on to take the lines of the grants, and tell the run.
    fn refresh(&self) {
        // `tried` is set from a failed turn over until one works.
        let near_full = self.tried.is_some() && self.size() + self.reserve > 2 * self.limit;
        self.blocked.store(self.failing || self.full || near_full, Ordering::SeqCst);
    }

    fn size(&self) -> u64 {
        std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0)
    }

    /// Turn the file over when `extra` more bytes would take it past its limit, unless a turn
    /// over failed less than `TURN_OVER_RETRY_MS` ago (a file that cannot be turned over is
    /// not copied for every line).
    fn turn_over_if_due(&mut self, extra: u64) {
        let waiting = self.tried.map_or(false, |at| at.elapsed() < Duration::from_millis(TURN_OVER_RETRY_MS));
        let size = self.size();
        if size > 0 && size + extra > self.limit && !waiting {
            if self.turn_over() {
                self.stuck = false;
                self.full = false;
                self.tried = None;
                // A rename moved the file the held handle was on; hold the new one.
                self._keep = AuditFile::open(&self.path).ok();
            } else {
                self.tried = Some(std::time::Instant::now());
            }
        }
    }

    /// The same, with the place a notice goes at once.
    fn alerting(mut self, alert: Box<dyn Fn(&str) + Send>) -> AuditFile {
        self.alert = alert;
        self
    }

    fn open(path: &Path) -> std::io::Result<std::fs::File> {
        std::fs::OpenOptions::new().create(true).append(true).open(path)
    }

    fn write(&self, line: &str) -> std::io::Result<()> {
        AuditFile::open(&self.path)?.write_all(format!("{}\n", line).as_bytes())
    }

    /// Move the lines to `PATH.1`, replacing what is there, and leave the file empty.
    fn turn_over(&self) -> bool {
        let mut rotated = self.path.as_os_str().to_owned();
        rotated.push(".1");
        let rotated = PathBuf::from(rotated);
        std::fs::rename(&self.path, &rotated).is_ok()
            || (std::fs::copy(&self.path, &rotated).is_ok()
                && std::fs::OpenOptions::new().write(true).truncate(true).open(&self.path).is_ok())
    }

    /// Write one line, turning the file over first when it is due. An error is a write that
    /// failed; a line left out on purpose, because the file is at twice its limit, is not one.
    fn place(&mut self, line: &str) -> std::io::Result<()> {
        self.turn_over_if_due(line.len() as u64 + 1);
        let size = self.size();
        if size > 0 && size + line.len() as u64 + 1 > self.limit {
            // The turn over failed or was not tried: the lines stay, and the file says so.
            if !self.stuck {
                self.write(&notice_line(unix_ms_now(), "the log file could not be turned over; it grows past its limit, to twice the limit, and then takes no more lines (standard error has them)"))?;
                self.stuck = true;
            }
            if size + line.len() as u64 + 1 > 2 * self.limit {
                if !self.full {
                    self.write(&notice_line(unix_ms_now(), "the log file is at twice its limit and could not be turned over; it takes no more lines until it can be (standard error has them)"))?;
                    self.full = true;
                }
                return Ok(());
            }
        }
        self.write(line)
    }

    /// Take a line: it is written after the ones held before it, or held itself.
    fn append(&mut self, line: &str) {
        if self.held.len() < HELD_LINES {
            self.held.push_back(line.to_string());
        } else {
            self.lost += 1;
        }
        self.flush();
    }

    /// Write the lines held, oldest first, until one cannot be written. The first failure
    /// of a run of them is told to standard error at once; when the last line held has been
    /// written, the file and standard error are told how many were written late and how many
    /// were not written at all. A file that could not be turned over is tried again here too,
    /// with no line to wake it, so that a run which stopped granting for want of room starts
    /// again once a program lets go of `PATH.1`; and the run is told whether the file can be
    /// relied on to take lines.
    fn flush(&mut self) {
        self.turn_over_if_due(0);
        self.drain();
        self.refresh();
    }

    fn drain(&mut self) {
        while let Some(line) = self.held.pop_front() {
            if let Err(error) = self.place(&line) {
                self.held.push_front(line);
                if !self.failing {
                    self.failing = true;
                    (self.alert)(&notice_line(unix_ms_now(), &format!(
                        "the log file {} cannot be written ({}); its lines are kept, up to {}, and written when it can be (standard error has them)",
                        self.path.display(), error, HELD_LINES)));
                }
                return;
            }
            if self.failing {
                self.late += 1;
                if self.held.is_empty() {
                    let text = format!("the log file could not be written for a time: {} lines were written late and {} were not written because too many were waiting (standard error has them)",
                        self.late, self.lost);
                    (self.alert)(&notice_line(unix_ms_now(), &text));
                    self.held.push_back(notice_line(unix_ms_now(), &text));
                    self.failing = false;
                    self.late = 0;
                    self.lost = 0;
                }
            }
        }
    }

    /// The run is over: a last try, and a word to standard error about what the file never got.
    fn close(&mut self) {
        self.flush();
        if !self.held.is_empty() {
            (self.alert)(&notice_line(unix_ms_now(), &format!(
                "{} log lines were not written to the log file, which could not be written when the run ended (standard error has them)",
                self.held.len() + self.lost)));
        }
    }
}

/// The audit record: standard error, and with `--extension-log` a file bounded at
/// one mebibyte (MiB) with one rotation, `PATH.1` (see `AuditFile` for a file that
/// cannot be turned over or written). Each copy has its queue and its thread. It records;
/// it controls nothing, and nothing waits for it.
pub(crate) struct Log {
    sinks: Vec<Arc<Sink>>,
    /// The file cannot be relied on to take the lines of the grants (see `AuditFile`).
    blocked: Arc<AtomicBool>,
    /// Without an audit file, standard error is the only record, and a grant stands only once its
    /// line has been written there (see `record`).
    only: Option<StandardErrorOnly>,
}

struct StandardErrorOnly {
    sink: Arc<Sink>,
    /// Whether the last line written to standard error was written.
    last_written: Arc<AtomicBool>,
}

impl Log {
    pub(crate) fn start(path: Option<PathBuf>, limit: u64) -> Result<Log, GuardError> {
        let last_written = Arc::new(AtomicBool::new(true));
        let seen = last_written.clone();
        let stderr = Arc::new(Sink::start("extension-log-stderr", Box::new(move |line: &str| seen.store(try_write_standard_error(line), Ordering::SeqCst)), LOG_QUEUE)?);
        let mut sinks = vec![stderr.clone()];
        let mut blocked = Arc::new(AtomicBool::new(false));
        let mut only = Some(StandardErrorOnly { sink: stderr.clone(), last_written });
        if let Some(path) = path {
            only = None;
            // A file that a reader keeps open is not opened here, and its lines are held (see `AuditFile`); one that opens must be on a disk.
            if let Ok(file) = AuditFile::open(&path) {
                require_disk_file(&file, &path)?;
            }
            // The file's notices go to standard error through its queue, never by a write that could wait.
            let mut file = AuditFile::new(path, limit).alerting(Box::new(move |text: &str| stderr.push(text)));
            if !file.settle() {
                return Err(GuardError(format!("the extension log {} is past its limit and cannot be turned over (is {}.1 held open?); the run did not start",
                    file.path.display(), file.path.display())));
            }
            blocked = file.blocked.clone();
            let written = Arc::new(Mutex::new(file));
            let on_idle = written.clone();
            let idle: Idle = Box::new(move |last: bool| {
                let mut file = relock(&on_idle);
                if last { file.close() } else { file.flush() }
            });
            sinks.push(Arc::new(Sink::start_with("extension-log-file", Box::new(move |line: &str| relock(&written).append(line)), Some(idle), LOG_QUEUE)?));
        }
        Ok(Log { sinks, blocked, only })
    }

    /// A log that keeps its lines in `lines`, for the tests of other modules. With `fail`, it
    /// behaves as a log whose only record is a standard error: a line is a record only when `fail`
    /// is clear as it is written; without it, the log has a file's rule and nothing is waited for.
    #[cfg(test)]
    pub(crate) fn capture(lines: Arc<Mutex<Vec<String>>>, fail: Option<Arc<AtomicBool>>) -> Log {
        let last_written = Arc::new(AtomicBool::new(true));
        let seen = last_written.clone();
        let failing = fail.clone();
        let write = move |line: &str| {
            relock(&lines).push(line.to_string());
            seen.store(!failing.as_ref().map_or(false, |fail| fail.load(Ordering::SeqCst)), Ordering::SeqCst);
        };
        let sink = Arc::new(Sink::start("test-log", Box::new(write), 16).expect("start the sink"));
        let only = fail.map(|_| StandardErrorOnly { sink: sink.clone(), last_written });
        Log { sinks: vec![sink], blocked: Arc::new(AtomicBool::new(false)), only }
    }

    /// True while the audit record cannot be relied on to take lines: nothing is granted then.
    /// That is the audit file when there is one, and otherwise standard error, once a line
    /// written to it has failed (a write that works lifts it).
    pub(crate) fn blocked(&self) -> bool {
        self.blocked.load(Ordering::SeqCst) || self.only.as_ref().map_or(false, |only| !only.last_written.load(Ordering::SeqCst))
    }

    /// Queue the line of a grant and say whether the grant may stand. With an audit file the
    /// file is the record and `blocked` stops the grants when it fails, so nothing is waited
    /// for. Without one, the line is waited for, for at most `wait_ms`: a grant whose line was
    /// not written (standard error closed, full, or unreadable) is a deadline moved by a
    /// request that no record has (Common Weakness Enumeration, CWE-778).
    pub(crate) fn record(&self, line: &str, wait_ms: u64) -> bool {
        let Some(only) = &self.only else {
            self.push(line);
            return true;
        };
        match only.sink.enqueue(line) {
            Some(number) => only.sink.wait_written(number, wait_ms) && only.last_written.load(Ordering::SeqCst),
            None => false,
        }
    }

    /// Queue the line of the approval of an exception above the cap and say whether it stands.
    /// Unlike the line of a grant, which with an audit file is not waited for, the line of an
    /// approval is waited for, for at most `wait_ms`, in the record: the audit file when there is
    /// one (which must not be blocked once the line is placed: a file that cannot take it holds
    /// it, and `blocked` says so), and otherwise standard error. An approval whose line was not
    /// written is not an approval (Common Weakness Enumeration, CWE-778).
    pub(crate) fn record_decision(&self, line: &str, wait_ms: u64) -> bool {
        let Some(only) = &self.only else {
            // Standard error is a copy of the audit file: the line is queued for both, the file's copy is waited for, and the
            // file must not be unable to take it, which `blocked` says once its write has failed.
            let numbers: Vec<Option<usize>> = self.sinks.iter().map(|sink| sink.enqueue(line)).collect();
            return match (self.sinks.last(), numbers.last()) {
                (Some(file), Some(Some(number))) => file.wait_written(*number, wait_ms) && !self.blocked.load(Ordering::SeqCst),
                (None, _) => !self.blocked.load(Ordering::SeqCst),
                _ => false,
            };
        };
        match only.sink.enqueue(line) {
            Some(number) => only.sink.wait_written(number, wait_ms) && only.last_written.load(Ordering::SeqCst),
            None => false,
        }
    }

    pub(crate) fn push(&self, line: &str) {
        for sink in &self.sinks {
            sink.push(line);
        }
    }

    /// A line of the log that is a notice, with the time now.
    pub(crate) fn note(&self, text: &str) {
        self.push(&notice_line(unix_ms_now(), text));
    }

    /// Stop taking lines and give each copy a moment to write the ones it has. The file
    /// goes first, so that what it has to say as it ends still reaches standard error.
    pub(crate) fn finish(&self, wait_ms: u64) {
        for sink in self.sinks.iter().rev() {
            sink.finish(wait_ms);
        }
    }
}

// ------------------------------------------------------------- processes, state

/// A process opened by handle, with the time it was created.
struct Process {
    handle: Handle,
    id: u32,
    created: u64,
}

unsafe impl Send for Process {}

impl Process {
    fn open(id: u32) -> Option<Process> {
        if id == 0 {
            return None;
        }
        let handle = unsafe { OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 0, id) };
        if handle.is_null() {
            return None;
        }
        let (mut created, mut exited, mut kernel, mut user) = (0u64, 0u64, 0u64, 0u64);
        if unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
            unsafe { CloseHandle(handle) };
            return None;
        }
        Some(Process { handle, id, created })
    }

    fn alive(&self) -> bool {
        unsafe { WaitForSingleObject(self.handle, 0) == WAIT_TIMEOUT }
    }

    /// True when the process is alive and began no later than `connected_at`, a time in
    /// the units of its creation time, read from the system (wall) clock: one that began
    /// after the client connected is not that client, but a process that took over its
    /// identifier. `connected_at` is when the guard learned of the connection, so a
    /// process that took the identifier between the connection and that moment passes.
    fn started_before(&self, connected_at: u64) -> bool {
        self.created <= connected_at && self.alive()
    }

    fn in_job(&self, job: Handle) -> bool {
        let mut result: Bool = 0;
        unsafe { IsProcessInJob(self.handle, job, &mut result) != 0 && result != 0 }
    }

    /// The path of the program the process runs, as Windows spells it.
    fn image_path(&self) -> Option<String> {
        let mut buffer = [0u16; 1024];
        let mut size = buffer.len() as u32;
        if unsafe { QueryFullProcessImageNameW(self.handle, 0, buffer.as_mut_ptr(), &mut size) } == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&buffer[..size as usize]))
    }

    /// The file name of the program the process runs.
    fn image(&self) -> String {
        self.image_path().map_or_else(|| "unknown".into(), |path| file_name(&path))
    }

    fn parent_id(&self) -> Option<u32> {
        unsafe {
            let mut info: ProcessBasicInformation = std::mem::zeroed();
            let status = NtQueryInformationProcess(self.handle, 0, &mut info as *mut _ as *mut c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32, std::ptr::null_mut());
            if status == 0 { Some(info.parent_process_id as u32) } else { None }
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}

fn file_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().filter(|name| !name.is_empty()).unwrap_or("unknown").to_string()
}

/// The file name of the program a process runs, or "unknown" when it cannot be read.
pub(crate) fn image_of(id: u32) -> String {
    Process::open(id).map_or_else(|| "unknown".into(), |process| process.image())
}

/// Git Bash runs a program by forking: the program's parent is a copy of the shell
/// that ends as soon as the program does, so a hold on it would end with the program.
/// The hold goes to the shell that started the copy, which is the same program, older,
/// alive and in the job. Anything that is not such a copy is returned as it is.
fn enclosing_shell(mut process: Process, job: Handle) -> Process {
    for _ in 0..MAX_SHELL_COPIES {
        let Some(path) = process.image_path() else { break };
        if !["bash.exe", "sh.exe"].contains(&file_name(&path).to_ascii_lowercase().as_str()) {
            break;
        }
        match process.parent_id().and_then(Process::open) {
            Some(up) if up.created < process.created && up.alive() && up.in_job(job)
                && up.image_path().map_or(false, |other| other.eq_ignore_ascii_case(&path)) => process = up,
            _ => break,
        }
    }
    process
}

/// The copies of a shell that are looked through, at most.
const MAX_SHELL_COPIES: usize = 8;

struct Hold {
    process: Process,
    /// Which hold of the process this is (see `Token`).
    token: Token,
    until: u64,
}

/// What it takes to back out of a grant whose reply the client did not take: the hold, as it
/// stood when granted and as it was before, and the client as the log names it.
struct Withdraw {
    id: u32,
    created: u64,
    token: Token,
    until: u64,
    previous: Option<u64>,
    pid: u32,
    image: String,
    seconds: f64,
}

/// A process and the creation time that tells it from one that later takes its identifier.
type RateKey = (u32, u64);

/// The key every client outside the job shares: to the rate limit they are one party,
/// so they cannot take the place of the processes that are in the job.
const OUTSIDE: RateKey = (0, 0);

/// What the rate limit makes of a request.
#[derive(Debug, PartialEq, Eq)]
enum Admit {
    Allowed,
    /// Over the limit, and the first in its window: logged as a line of its own.
    First,
    /// Over the limit, after the first: counted, and logged with the rest of its window of refusals as one line.
    Counted,
    /// Not counted at all, because the table holds as many live processes as it can.
    Full,
}

/// Whether the process of a rate key is the one it was and is still running.
fn process_alive(key: RateKey) -> bool {
    Process::open(key.0).map_or(false, |process| process.created == key.1 && process.alive())
}

struct Rate {
    key: RateKey,
    times: Vec<u64>,
    /// Requests refused for the rate since `refusing_since`, the first of them included.
    refused: u32,
    /// When the first of them was refused: the window of the refusals runs from here for `RATE_WINDOW_MS`.
    refusing_since: u64,
    pid: u32,
    image: String,
}

/// The refusals of one process in one window of refusals that were not logged one by one.
struct Summary {
    pid: u32,
    image: String,
    count: u32,
}

impl Rate {
    /// Close the window of refusals once it has run its course (at once when `all`): the
    /// ones after the first, which were counted and not logged, become a summary, and the
    /// next refusal opens a window of its own and is logged as the first of it. A process
    /// that keeps asking is never idle, so this cannot wait for it to stop.
    fn close_refusals(&mut self, now: u64, all: bool, summaries: &mut Vec<Summary>) {
        if self.refused > 0 && (all || now.saturating_sub(self.refusing_since) >= RATE_WINDOW_MS) {
            if self.refused > 1 {
                summaries.push(Summary { pid: self.pid, image: self.image.clone(), count: self.refused - 1 });
            }
            self.refused = 0;
        }
    }
}

#[derive(Default)]
struct Limiter {
    rates: Vec<Rate>,
    summaries: Vec<Summary>,
    /// When a pass over a full table last forgot nobody.
    unproductive: Option<u64>,
}

impl Limiter {
    /// Count a request of `key` (the process `who`) at `now`. A process is held to
    /// `RATE_LIMIT` requests in any window. A process that has exited cannot ask again,
    /// so it is forgotten when the table is full (`alive` says whether a process of the
    /// table is still running); a live process is never forgotten to make room for
    /// another, so a process that starts many cannot reset the share of the rest.
    fn admit(&mut self, key: RateKey, who: (u32, &str), now: u64, alive: &dyn Fn(RateKey) -> bool) -> Admit {
        self.sweep(now, false);
        if self.rates.len() >= MAX_RATE_KEYS && !self.rates.iter().any(|rate| rate.key == key) {
            self.forget_the_dead(now, alive);
        }
        let Some(rate) = self.rates.iter_mut().find(|rate| rate.key == key) else {
            if self.rates.len() >= MAX_RATE_KEYS {
                return Admit::Full;
            }
            let (pid, image) = if key == OUTSIDE { (0, "outside the job") } else { who };
            self.rates.push(Rate { key, times: vec![now], refused: 0, refusing_since: 0, pid, image: image.to_string() });
            return Admit::Allowed;
        };
        rate.times.retain(|time| now.saturating_sub(*time) < RATE_WINDOW_MS);
        if rate.times.len() >= RATE_LIMIT {
            // The sweep above has closed a window of refusals that ran its course, so the first
            // refusal after it is the first of a new window.
            rate.refused += 1;
            if rate.refused == 1 {
                rate.refusing_since = now;
                return Admit::First;
            }
            return Admit::Counted;
        }
        rate.times.push(now);
        Admit::Allowed
    }

    /// Give back the latest request of `key`, which was counted when its connection arrived.
    fn refund(&mut self, key: RateKey) {
        if let Some(rate) = self.rates.iter_mut().find(|rate| rate.key == key) {
            rate.times.pop();
        }
    }

    /// Take back the latest refusal for the rate of `key`, which was counted when its connection arrived.
    fn unrefuse(&mut self, key: RateKey) {
        if let Some(rate) = self.rates.iter_mut().find(|rate| rate.key == key) {
            rate.refused = rate.refused.saturating_sub(1);
        }
    }

    /// Keep the entries `keep` accepts, with a summary of the refusals that were counted
    /// and not logged for each one that goes.
    fn retain(&mut self, keep: impl Fn(&Rate) -> bool) {
        let summaries = &mut self.summaries;
        self.rates.retain(|rate| {
            let kept = keep(rate);
            if !kept && rate.refused > 1 {
                summaries.push(Summary { pid: rate.pid, image: rate.image.clone(), count: rate.refused - 1 });
            }
            kept
        });
    }

    /// Close the windows of refusals that have run their course, whether or not the process
    /// is still asking, and forget the processes whose window has passed (all of them when `all`).
    fn sweep(&mut self, now: u64, all: bool) {
        for rate in self.rates.iter_mut() {
            rate.close_refusals(now, all, &mut self.summaries);
        }
        self.retain(|rate| !all && rate.times.last().map_or(false, |last| now.saturating_sub(*last) < RATE_WINDOW_MS));
    }

    /// Forget the processes that have exited, whose window has not passed. A pass that
    /// forgets nobody is not repeated for `FORGET_MS`, so a table full of live processes
    /// cannot make every request pay for a look at all of them.
    fn forget_the_dead(&mut self, now: u64, alive: &dyn Fn(RateKey) -> bool) {
        if self.unproductive.map_or(false, |at| now.saturating_sub(at) < FORGET_MS) {
            return;
        }
        let before = self.rates.len();
        self.retain(|rate| rate.key == OUTSIDE || alive(rate.key));
        self.unproductive = if self.rates.len() == before { Some(now) } else { None };
    }
}

/// How many refusal lines are written in a window, over all processes, so that a flood
/// of refusals cannot push the earlier lines, the grants among them, out of the log.
#[derive(Default)]
struct Budget {
    written: Vec<u64>,
    withheld: u32,
}

impl Budget {
    /// True when one more refusal line may be written now; otherwise it is counted.
    fn allow(&mut self, now: u64) -> bool {
        self.written.retain(|time| now.saturating_sub(*time) < RATE_WINDOW_MS);
        if self.written.len() < REFUSAL_LINES {
            self.written.push(now);
            return true;
        }
        self.withheld += 1;
        false
    }

    /// The number of lines withheld, once the window has passed (at once when `all`).
    fn overflow(&mut self, now: u64, all: bool) -> Option<u32> {
        self.written.retain(|time| now.saturating_sub(*time) < RATE_WINDOW_MS);
        if self.withheld > 0 && (all || self.written.is_empty()) {
            return Some(std::mem::take(&mut self.withheld));
        }
        None
    }
}

/// A request that was refused: why, and whether it was only counted for the log.
#[derive(Debug, PartialEq, Eq)]
struct Refused {
    refusal: Refusal,
    counted: bool,
}

impl From<Refusal> for Refused {
    fn from(refusal: Refusal) -> Refused {
        Refused { refusal, counted: false }
    }
}

struct State {
    /// The run's own deadline, from `--timeout`, in ticks.
    base: u64,
    cap_seconds: f64,
    holds: Vec<Hold>,
    limiter: Limiter,
    budget: Budget,
    /// Nothing more is granted: the command has finished, or the channel can no longer be
    /// served. The deadline is not touched by it: the holds already granted stand.
    closed: bool,
    /// The deadline has passed. It never goes back.
    passed: bool,
    /// Whether a process of the rate table is still running; a field so a test can say.
    alive: fn(RateKey) -> bool,
}

/// The latest of the run's own deadline and the given holds.
fn latest(base: u64, holds: impl Iterator<Item = u64>) -> u64 {
    holds.fold(base, u64::max)
}

impl State {
    fn new(base: u64, cap_seconds: f64) -> State {
        State { base, cap_seconds, holds: Vec::new(), limiter: Limiter::default(), budget: Budget::default(), closed: false, passed: false, alive: process_alive }
    }

    /// The latest of the run's own deadline and the holds of the live processes.
    fn deadline(&self) -> u64 {
        latest(self.base, self.holds.iter().map(|hold| hold.until))
    }

    /// Drop the holds that have run out, whose process has exited, or (when there is a
    /// `job` to ask) that are not in it or that its process list does not show: the
    /// backstop for a lost completion message. Every holder is polled, by its handle,
    /// whatever the port reported.
    fn release(&mut self, now: u64, job: Option<Handle>) {
        let listed = job.and_then(job_process_ids);
        self.holds.retain(|hold| {
            hold.until > now && hold.process.alive() && job.map_or(true, |job| hold.process.in_job(job))
                && listed.as_ref().map_or(true, |ids| ids.contains(&hold.process.id))
        });
    }

    /// Release what no longer holds the run up and note that the deadline has passed.
    /// True when it has. Every decision about a hold is made after this, under the same
    /// lock, so a request that arrives after the deadline is refused even if nobody has
    /// yet noticed that the deadline passed.
    fn expire(&mut self, now: u64, job: Option<Handle>) -> bool {
        if !self.passed {
            self.release(now, job);
            if now >= self.deadline() {
                self.passed = true;
            }
        }
        self.passed
    }

    /// True when a request now is refused because the run has ended: its deadline has
    /// passed, or nothing more is granted.
    fn ended(&mut self, now: u64, job: Option<Handle>) -> bool {
        self.expire(now, job) || self.closed
    }

    /// Hold the run up for `seconds` from `now` on `process`, as its hold `token`, or say
    /// why not. `parent` is the key and the description of the process held when it is not
    /// the one that asked, which has its share of the rate limit too.
    fn grant(&mut self, now: u64, job: Option<Handle>, seconds: f64, process: Process, token: Token, parent: Option<(RateKey, u32, &str)>) -> Result<(), Refused> {
        if self.ended(now, job) {
            return Err(Refusal::Ended.into());
        }
        if let Some((key, pid, image)) = parent {
            match self.limiter.admit(key, (pid, image), now, &self.alive) {
                Admit::Allowed => {}
                Admit::Counted => return Err(Refused { refusal: Refusal::RateLimited, counted: true }),
                Admit::First => return Err(Refusal::RateLimited.into()),
                Admit::Full => return Err(Refusal::Crowded.into()),
            }
        }
        if !seconds.is_finite() || seconds <= 0.0 {
            return Err(Refusal::InvalidSeconds.into());
        }
        if seconds > self.cap_seconds || seconds > crate::MAX_SECONDS {
            return Err(Refusal::OverCap.into());
        }
        let until = now + millis(seconds);
        match self.holds.iter_mut().find(|hold| hold.process.id == process.id && hold.process.created == process.created && hold.token == token) {
            Some(hold) => hold.until = until,
            None => {
                if self.holds.iter().filter(|hold| hold.process.id == process.id && hold.process.created == process.created).count() >= MAX_HOLDS_PER_PROCESS {
                    return Err(Refusal::TooManyHoldsHere.into());
                }
                if self.holds.len() >= MAX_HOLDS {
                    return Err(Refusal::TooManyHolds.into());
                }
                self.holds.push(Hold { process, token, until });
            }
        }
        Ok(())
    }

    /// When the hold `token` of the process `id`, created at `created`, ends, if it has one.
    fn hold_until(&self, id: u32, created: u64, token: Token) -> Option<u64> {
        self.holds.iter().find(|hold| hold.process.id == id && hold.process.created == created && hold.token == token).map(|hold| hold.until)
    }

    /// Take back a grant whose reply the client did not take: the hold goes back to what it
    /// was before (none, or the earlier one) unless something has changed it since. True when
    /// the grant was still standing.
    fn withdraw(&mut self, back: &Withdraw) -> bool {
        let Some(index) = self.holds.iter().position(|hold| hold.process.id == back.id && hold.process.created == back.created
            && hold.token == back.token && hold.until == back.until) else { return false };
        match back.previous {
            Some(until) => self.holds[index].until = until,
            None => {
                self.holds.remove(index);
            }
        }
        true
    }

    /// End the hold `token` of the process `id`, created at `created`, at its own request;
    /// its other holds stand. True when there was one; the request is then not counted against the process's share of the
    /// rate, since it can only follow a grant that was, and only brings the deadline in.
    /// `limited` says that the request came in over the share and was counted as a refusal
    /// when it arrived, which is then taken back; otherwise it was counted as a request, and is given back.
    fn drop_hold(&mut self, id: u32, created: u64, token: Token, limited: bool) -> bool {
        let before = self.holds.len();
        self.holds.retain(|hold| !(hold.process.id == id && hold.process.created == created && hold.token == token));
        let removed = self.holds.len() < before;
        if removed {
            if limited {
                self.limiter.unrefuse((id, created));
            } else {
                self.limiter.refund((id, created));
            }
        }
        removed
    }

    /// The lines for what was counted and not logged one by one: the refusals of each
    /// process in each window of refusals that has run its course (all of them when `all`),
    /// written only as the budget of refusal lines allows, and one line for the lines the
    /// budget withheld. A process that keeps asking has a line for each window while it asks.
    fn notices(&mut self, now: u64, unix_ms: u64, all: bool) -> Vec<String> {
        self.limiter.sweep(now, all);
        let mut lines = Vec::new();
        for summary in std::mem::take(&mut self.limiter.summaries) {
            if self.budget.allow(now) {
                let reason = format!("too many requests; {} more refused within {} seconds of the first, not logged one by one",
                    summary.count, RATE_WINDOW_MS / 1000);
                lines.push(log_line(unix_ms, &Entry { pid: summary.pid, image: &summary.image, requested: None, granted: None, reason: &reason }));
            }
        }
        if let Some(count) = self.budget.overflow(now, all) {
            lines.push(withheld_line(unix_ms, count));
        }
        lines
    }
}

struct Shared {
    state: Mutex<State>,
    log: Log,
    job: usize,
    wake: usize,
    stopping: AtomicBool,
    /// Threads still serving an instance of the pipe.
    serving: AtomicUsize,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// What the run asks of its channel: the cap and the audit file. `exception` is set when the
/// cap is over the default, and the run then needs the password of the account the guard runs as to start.
pub struct Settings {
    pub max_seconds: f64,
    pub log_path: Option<PathBuf>,
    pub exception: Option<Exception>,
}

/// A running channel: the instances of the pipe, the threads that serve them and watch the job, and the deadline.
pub struct Extension {
    shared: Arc<Shared>,
    pipes: Vec<Handle>,
    stop: Handle,
    port: Handle,
    wake: Handle,
    servers: Vec<JoinHandle<()>>,
    monitor: Option<JoinHandle<()>>,
    started: u64,
    /// The name of the channel, for `PROCESS_TREE_GUARD_CHANNEL`.
    pub channel: String,
}

fn random_hex() -> Result<String, GuardError> {
    let mut bytes = [0u8; 16];
    if unsafe { SystemFunction036(bytes.as_mut_ptr(), bytes.len() as u32) } == 0 {
        return Err(GuardError("the system random generator failed".into()));
    }
    Ok(bytes.iter().map(|b| format!("{:02x}", b)).collect())
}

/// The text form of the security identifier of the user this process runs as.
pub(crate) fn current_user_sid() -> Result<String, GuardError> {
    unsafe {
        let mut token: Handle = std::ptr::null_mut();
        checked(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token))?;
        let sid = token_user_sid(token);
        CloseHandle(token);
        sid
    }
}

/// The text form of the security identifier of the user of `token`, which stays open.
pub(crate) fn token_user_sid(token: Handle) -> Result<String, GuardError> {
    unsafe {
        let mut needed = 0u32;
        GetTokenInformation(token, TOKEN_USER_CLASS, std::ptr::null_mut(), 0, &mut needed);
        let mut buffer = vec![0u64; (needed as usize + 7) / 8 + 1];
        checked(GetTokenInformation(token, TOKEN_USER_CLASS, buffer.as_mut_ptr() as *mut c_void, (buffer.len() * 8) as u32, &mut needed))?;
        // TOKEN_USER starts with a pointer to the security identifier.
        sid_text(*(buffer.as_ptr() as *const *mut c_void))
    }
}

/// The text form of the security identifier `sid`.
pub(crate) fn sid_text(sid: *mut c_void) -> Result<String, GuardError> {
    unsafe {
        let mut text: *mut u16 = std::ptr::null_mut();
        checked(ConvertSidToStringSidW(sid, &mut text))?;
        let mut length = 0;
        while *text.add(length) != 0 {
            length += 1;
        }
        let sid_text = String::from_utf16_lossy(std::slice::from_raw_parts(text, length));
        LocalFree(text as *mut c_void);
        Ok(sid_text)
    }
}

/// An access list, in the text form, as a security descriptor (to be freed with `LocalFree`).
fn security_descriptor(sddl: &str) -> Result<*mut c_void, GuardError> {
    let text = wide(sddl);
    let mut descriptor: *mut c_void = std::ptr::null_mut();
    checked(unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), 1, &mut descriptor, std::ptr::null_mut()) })?;
    Ok(descriptor)
}

/// The open mode of instance `index` of the channel: duplex and overlapped, with the right to
/// change the access list, and, for the first only, the first-instance flag.
fn instance_open_mode(index: u32) -> u32 {
    let first = if index == 0 { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
    PIPE_ACCESS_DUPLEX | first | WRITE_DAC | FILE_FLAG_OVERLAPPED
}

/// Make the instances of the pipe `name`. The first is made with the first-instance flag,
/// so the name is not one that somebody else already holds. All `INSTANCES` the pipe allows
/// are made here, before the command starts, so nobody else can make another. The access
/// list is for the current user only and protected, so nothing is inherited into it. Making
/// the later instances takes the right to make an instance, so the list has it while they are
/// made and loses it at once after: the list the command's processes see does not give it.
fn create_pipes(name: &str) -> Result<Vec<Handle>, GuardError> {
    let sid = current_user_sid()?;
    let making = security_descriptor(&format!("D:P(A;;{};;;{})", PIPE_RIGHTS_WHILE_MAKING, sid))?;
    let settled = match security_descriptor(&format!("D:P(A;;{};;;{})", PIPE_RIGHTS, sid)) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            unsafe { LocalFree(making) };
            return Err(error);
        }
    };
    unsafe {
        let mut attributes = SecurityAttributes { length: std::mem::size_of::<SecurityAttributes>() as u32, descriptor: making, inherit: 0 };
        let wide_name = wide(name);
        let mut pipes = Vec::new();
        let mut failure = None;
        for index in 0..INSTANCES {
            let pipe = CreateNamedPipeW(wide_name.as_ptr(), instance_open_mode(index),
                CHANNEL_PIPE_MODE, INSTANCES, OUT_BUFFER, 512, 0, &mut attributes);
            if pipe == INVALID_HANDLE {
                failure = Some(os_error());
                break;
            }
            pipes.push(pipe);
        }
        if failure.is_none() {
            for pipe in &pipes {
                if SetKernelObjectSecurity(*pipe, DACL_SECURITY_INFORMATION, settled) == 0 {
                    failure = Some(os_error());
                    break;
                }
            }
        }
        LocalFree(making);
        LocalFree(settled);
        match failure {
            Some(error) => {
                for pipe in pipes {
                    CloseHandle(pipe);
                }
                Err(error)
            }
            None => Ok(pipes),
        }
    }
}

/// Open the log of an extendable run: the audit file, when there is one, must be a file on a
/// disk, and without one standard error must be able to hold a record. The run does not start
/// when it cannot be opened. It is opened before the command is known to be wanted, so that
/// the decision on an exception above the cap has a place to be recorded.
pub(crate) fn open_log(settings: &Settings) -> Result<Log, GuardError> {
    check_log_path(settings.log_path.as_deref())?;
    if settings.log_path.is_none() && !standard_error_records() {
        return Err(GuardError("an extendable run needs a record of its grants: standard error is closed or is the null device, \
            and --extension-log was not given; the run did not start".into()));
    }
    Log::start(settings.log_path.clone(), LOG_LIMIT)
}

impl Extension {
    /// Open the channel of a run whose own deadline is `timeout_seconds` from now.
    /// `job` is the run's job object, which stays open for as long as the extension. `log` is
    /// the log the run has already opened (it records the decision on an exception above the
    /// cap before the job exists); without one it is opened here. The log is finished on every
    /// path out of this function: by the extension when it ends, or here when it cannot start.
    pub fn start(job: Handle, settings: &Settings, timeout_seconds: f64, log: Option<Log>) -> Result<Extension, GuardError> {
        let log = match log {
            Some(log) => log,
            None => open_log(settings)?,
        };
        // A run that holds an approved exception says in the log when it then fails to start, so that the record does not
        // show a cap approved for a command that never ran.
        let announce = settings.exception.is_some();
        let channel = match random_hex() {
            Ok(hex) => format!("{}{}", PIPE_PREFIX, hex),
            Err(error) => {
                if announce {
                    log.note(&not_started_text(&error));
                }
                log.finish(LOG_FLUSH_MS);
                return Err(error);
            }
        };
        let started = tick();
        let (wake, stop) = unsafe { (CreateEventW(std::ptr::null_mut(), 0, 0, std::ptr::null()), CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null())) };
        if wake.is_null() || stop.is_null() {
            let error = os_error();
            unsafe {
                for event in [wake, stop] {
                    if !event.is_null() {
                        CloseHandle(event);
                    }
                }
            }
            if announce {
                log.note(&not_started_text(&error));
            }
            log.finish(LOG_FLUSH_MS);
            return Err(error);
        }
        let shared = Arc::new(Shared {
            state: Mutex::new(State::new(started + millis(timeout_seconds), settings.max_seconds)),
            log,
            job: job as usize,
            wake: wake as usize,
            stopping: AtomicBool::new(false),
            serving: AtomicUsize::new(INSTANCES as usize),
        });
        // From here on a failure drops the extension, which closes whatever exists.
        let mut extension = Extension {
            shared: shared.clone(), pipes: Vec::new(), stop, port: std::ptr::null_mut(), wake, servers: Vec::new(), monitor: None, started, channel,
        };
        let for_note = shared.clone();
        let made = (|| -> Result<(), GuardError> {
            extension.pipes = create_pipes(&extension.channel)?;
            unsafe {
                extension.port = CreateIoCompletionPort(INVALID_HANDLE, std::ptr::null_mut(), 0, 1);
                if extension.port.is_null() {
                    return Err(os_error());
                }
                let mut association = AssociateCompletionPort { key: 0, port: extension.port };
                checked(SetInformationJobObject(job, ASSOCIATE_COMPLETION_PORT_CLASS, &mut association as *mut _ as *mut c_void,
                    std::mem::size_of::<AssociateCompletionPort>() as u32))?;
            }
            let (port, stop_event) = (extension.port as usize, stop as usize);
            let spawn = |name: &str, body: Box<dyn FnOnce() + Send>| {
                std::thread::Builder::new().name(name.into()).spawn(body).map_err(|error| GuardError(format!("cannot start the extension thread: {}", error)))
            };
            for pipe in extension.pipes.clone() {
                let (serving, pipe) = (shared.clone(), pipe as usize);
                let server = spawn("extension-server", Box::new(move || serve(&serving, pipe as Handle, stop_event as Handle)))?;
                extension.servers.push(server);
            }
            extension.monitor = Some(spawn("extension-monitor", Box::new(move || watch_job(&shared, port as Handle)))?);
            Ok(())
        })();
        match made {
            Ok(()) => Ok(extension),
            Err(error) => {
                // The extension is dropped on return, which ends its threads and finishes the log: the line comes first.
                if announce {
                    for_note.log.note(&not_started_text(&error));
                }
                Err(error)
            }
        }
    }

    /// Put a line in the log saying what happened to the run, for the engine: a run with an approved exception whose command could
    /// not be started says so, before the log is finished.
    pub fn note(&self, text: &str) {
        self.shared.log.note(text);
    }

    /// The event the supervisor waits on besides the processes: set when a process
    /// in the job exits, so the deadline is recalculated without waiting for the backstop.
    pub fn wake(&self) -> Handle {
        self.wake
    }

    /// Milliseconds until the deadline of the run, recalculated now under the lock;
    /// None when it has passed, and the run then grants nothing more. A run that grants
    /// nothing more for another reason (its channel stopped serving) goes on to its deadline.
    pub fn remaining(&self) -> Option<u64> {
        let mut state = self.shared.lock();
        let now = tick();
        let passed = state.expire(now, Some(self.shared.job as Handle));
        for line in state.notices(now, unix_ms_now(), false) {
            self.shared.log.push(&line);
        }
        if passed { None } else { Some(state.deadline() - now) }
    }

    /// A hold of `seconds` on the process `id`, as a request from it would make, for tests of the supervisor.
    #[cfg(test)]
    pub(crate) fn hold_for_test(&self, id: u32, seconds: f64) {
        let process = Process::open(id).expect("open the holder");
        let mut state = self.shared.lock();
        assert_eq!(state.grant(tick(), Some(self.shared.job as Handle), seconds, process, 0, None), Ok(()));
    }

    /// Stop granting: the command has finished, or the deadline has passed.
    pub fn close(&self) {
        self.shared.lock().closed = true;
    }

    /// Seconds since the run began.
    pub fn elapsed_seconds(&self) -> f64 {
        tick().saturating_sub(self.started) as f64 / 1000.0
    }

    /// Stop the threads, cancel what they wait for and close the handles.
    pub fn shutdown(&mut self) {
        self.close();
        self.shared.stopping.store(true, Ordering::SeqCst);
        unsafe {
            if !self.stop.is_null() {
                SetEvent(self.stop);
            }
            for pipe in &self.pipes {
                CancelIoEx(*pipe, std::ptr::null_mut());
            }
            if !self.port.is_null() {
                PostQueuedCompletionStatus(self.port, 0, 0, std::ptr::null_mut());
            }
        }
        // These threads wait on the pipe and the port only, with the stop event to wake them,
        // and never on the log, so the join is bounded.
        for thread in self.servers.drain(..).chain(self.monitor.take()) {
            let _ = thread.join();
        }
        {
            let mut state = self.shared.lock();
            for line in state.notices(tick(), unix_ms_now(), true) {
                self.shared.log.push(&line);
            }
            state.holds.clear();
        }
        // The last lines get a moment to be written. A destination that does not take
        // them (a standard error nobody reads) is left behind: the process is about to end.
        self.shared.log.finish(LOG_FLUSH_MS);
        unsafe {
            for pipe in self.pipes.drain(..) {
                CloseHandle(pipe);
            }
            for handle in [&mut self.stop, &mut self.port, &mut self.wake] {
                if !handle.is_null() {
                    CloseHandle(*handle);
                    *handle = std::ptr::null_mut();
                }
            }
        }
    }
}

impl Drop for Extension {
    fn drop(&mut self) {
        self.shutdown();
    }
}

// ---------------------------------------------------------------------- the threads

/// Tell the supervisor when a process in the job exits.
fn watch_job(shared: &Shared, port: Handle) {
    while !shared.stopping.load(Ordering::SeqCst) {
        let (mut message, mut key, mut overlapped) = (0u32, 0usize, std::ptr::null_mut());
        let got = unsafe { GetQueuedCompletionStatus(port, &mut message, &mut key, &mut overlapped, 250) };
        if got != 0 && (message == JOB_OBJECT_MSG_EXIT_PROCESS || message == JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS) {
            unsafe { SetEvent(shared.wake as Handle) };
        }
    }
}

enum Message {
    Bytes(Vec<u8>),
    TooLong,
    Silent,
}

/// The pipe, the event its operations signal, and the event that ends the service.
struct Io {
    pipe: Handle,
    event: Handle,
    stop: Handle,
}

/// Finish an overlapped operation on `pipe`: wait for it at most `timeout_ms`, the
/// first handle of `wait` being the event it signals and any other a reason to stop
/// waiting, and cancel it and wait for the cancellation otherwise. The bytes moved, or
/// the Windows error (`WAIT_TIMEOUT` when it was cancelled). `started` is true when
/// the call completed at once, and the call is the last one made before this.
fn finish_io(pipe: Handle, overlapped: &mut Overlapped, started: bool, wait: &[Handle], timeout_ms: u32) -> Result<u32, u32> {
    let mut transferred = 0u32;
    if !started {
        let error = unsafe { GetLastError() };
        if error != ERROR_IO_PENDING {
            return Err(error);
        }
        if unsafe { WaitForMultipleObjects(wait.len() as u32, wait.as_ptr(), 0, timeout_ms) } != WAIT_OBJECT_0 {
            // The operation may have completed in the instant before it was cancelled, and then it is done.
            let completed = unsafe {
                CancelIoEx(pipe, overlapped);
                GetOverlappedResult(pipe, overlapped, &mut transferred, 1)
            };
            return if completed != 0 { Ok(transferred) } else { Err(WAIT_TIMEOUT) };
        }
    }
    if unsafe { GetOverlappedResult(pipe, overlapped, &mut transferred, 0) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    Ok(transferred)
}

impl Io {
    /// Finish an overlapped operation on the pipe: at most `timeout_ms`, or until
    /// the service is stopped.
    fn finish(&self, overlapped: &mut Overlapped, started: bool, timeout_ms: u32) -> Result<u32, u32> {
        finish_io(self.pipe, overlapped, started, &[self.event, self.stop], timeout_ms)
    }

    /// The client's message, waiting for it at most `timeout_ms`.
    fn read(&self, timeout_ms: u32) -> Message {
        let mut buffer = [0u8; 64];
        let mut overlapped = Overlapped::with_event(self.event);
        unsafe { ResetEvent(self.event) };
        let mut read = 0u32;
        let started = unsafe { ReadFile(self.pipe, buffer.as_mut_ptr() as *mut c_void, buffer.len() as u32, &mut read, &mut overlapped) } != 0;
        match self.finish(&mut overlapped, started, timeout_ms) {
            Ok(n) => Message::Bytes(buffer[..n as usize].to_vec()),
            Err(ERROR_MORE_DATA) => Message::TooLong,
            Err(_) => Message::Silent,
        }
    }

    /// Send the reply and wait, at most `timeout_ms`, for the client to take it. The pipe has no
    /// outgoing buffer, so the write completes only when the client has read the message; one
    /// that is not read in time is cancelled, and nothing of it is left for the client to read.
    /// True when the client took the reply.
    fn write(&self, reply: &Reply, timeout_ms: u32) -> bool {
        let bytes = encode_reply(reply);
        let mut overlapped = Overlapped::with_event(self.event);
        unsafe { ResetEvent(self.event) };
        let mut written = 0u32;
        let started = unsafe { WriteFile(self.pipe, bytes.as_ptr() as *const c_void, bytes.len() as u32, &mut written, &mut overlapped) } != 0;
        self.finish(&mut overlapped, started, timeout_ms) == Ok(bytes.len() as u32)
    }
}

/// One instance of the pipe can no longer be served. When it was the last, the channel is
/// gone: nothing more is granted, and the log says so. The holds already granted stand, and
/// the run ends at its deadline as it would have.
fn stopped_serving(shared: &Shared) {
    if shared.serving.fetch_sub(1, Ordering::SeqCst) != 1 {
        return;
    }
    shared.lock().closed = true;
    let line = log_line(unix_ms_now(), &Entry {
        pid: std::process::id(), image: &image_of(std::process::id()), requested: None, granted: None, reason: "the channel stopped serving; no further request is granted",
    });
    shared.log.push(&line);
}

/// Wait for a client to connect to `pipe` (or for `stop`). When one has, the moment this
/// thread learns of it, taken as soon as it does, in the units of a process's creation time:
/// the client connected at that moment or earlier, and how much earlier is the time this
/// thread took to run (the whole time since the connect when the client was there before the
/// call). None when the wait ended without a client.
fn accept(pipe: Handle, event: Handle, stop: Handle) -> Option<u64> {
    let mut overlapped = Overlapped::with_event(event);
    unsafe { ResetEvent(event) };
    if unsafe { ConnectNamedPipe(pipe, &mut overlapped) } != 0 {
        return Some(filetime_now());
    }
    match unsafe { GetLastError() } {
        ERROR_PIPE_CONNECTED => Some(filetime_now()),
        ERROR_IO_PENDING => {
            let handles = [event, stop];
            let mut transferred = 0u32;
            if unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) } == WAIT_OBJECT_0 {
                let connected_at = filetime_now();
                (unsafe { GetOverlappedResult(pipe, &mut overlapped, &mut transferred, 0) } != 0).then_some(connected_at)
            } else {
                unsafe {
                    CancelIoEx(pipe, &mut overlapped);
                    GetOverlappedResult(pipe, &mut overlapped, &mut transferred, 1);
                }
                None
            }
        }
        _ => None,
    }
}

fn serve(shared: &Shared, pipe: Handle, stop: Handle) {
    let event = unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) };
    if event.is_null() {
        stopped_serving(shared);
        return;
    }
    let mut failures = 0;
    let mut gave_up = false;
    while !shared.stopping.load(Ordering::SeqCst) {
        if let Some(connected_at) = accept(pipe, event, stop) {
            failures = 0;
            handle_client(shared, &Io { pipe, event, stop }, connected_at);
        } else {
            failures += 1;
            if failures > 100 {
                gave_up = true;
                break;
            }
            unsafe { Sleep(10) };
        }
        unsafe { DisconnectNamedPipe(pipe) };
    }
    unsafe { CloseHandle(event) };
    if gave_up {
        stopped_serving(shared);
    }
}

/// Serve one connection. Who the client is, and what the run makes of it, is settled before
/// a byte of its message is waited for, and the time spent on a connection is bounded: a
/// client that stalls costs this instance at most a few hundred milliseconds, is charged
/// to its share of the rate limit like any request, and cannot keep the other instances
/// from serving the rest.
fn handle_client(shared: &Shared, io: &Io, connected_at: u64) {
    let mut id = 0u32;
    if unsafe { GetNamedPipeClientProcessId(io.pipe, &mut id) } == 0 {
        id = 0;
    }
    let mut arrival = arrive(shared, id);
    let (read_ms, take_ms) = match (&arrival.shut, arrival.in_job) {
        (Some(_), false) => {
            // A client outside the job whose allowance is used up (or whose run has ended) is
            // disconnected at once: its message is not waited for and it is not answered.
            let (_, line, _) = decide(shared, arrival, connected_at, &Message::Silent);
            if let Some(line) = line {
                shared.log.push(&line);
            }
            return;
        }
        (Some(_), true) => (REFUSED_READ_MS, REFUSED_TAKE_MS),
        (None, _) => (READ_MS, TAKE_MS),
    };
    let message = io.read(read_ms);
    if shared.stopping.load(Ordering::SeqCst) {
        return;
    }
    if let (Message::Silent, None) = (&message, &arrival.shut) {
        // The client was let in and sent nothing: it has used a request of its share, and the
        // log says so (as a refusal, within the budget of refusal lines). There is nothing to answer.
        let reason = format!("no request arrived within {} milliseconds", READ_MS);
        let line = log_line(unix_ms_now(), &Entry { pid: arrival.id, image: &arrival.image, requested: None, granted: None, reason: &reason });
        if shared.lock().budget.allow(tick()) {
            shared.log.push(&line);
        }
        return;
    }
    // The client is still there, with its end open, or it is refused as not verified.
    arrival.gone = client_gone(io.pipe);
    let (mut reply, line, mut back) = decide(shared, arrival, connected_at, &message);
    // The line is queued, never written here: nothing the log is written to can hold up
    // the answers, and so nothing it is written to can hold up the deadline. The one
    // exception is a grant in a run with no audit file: standard error is then the only
    // record, and the grant stands only once its line is written (see `Log::record`).
    if let Some(line) = line {
        let stands = if back.is_some() { shared.log.record(&line, RECORD_MS) } else { shared.log.push(&line); true };
        if !stands {
            if let Some(back) = back.take() {
                if shared.lock().withdraw(&back) {
                    unsafe { SetEvent(shared.wake as Handle) };
                    shared.log.push(&unrecorded_line(unix_ms_now(), &back, RECORD_MS));
                }
                let cap = shared.lock().cap_seconds;
                reply = Reply::Refused { refusal: Refusal::AuditBlocked, cap };
            }
        }
    }
    if !io.write(&reply, take_ms) && !shared.stopping.load(Ordering::SeqCst) {
        // The client did not take the reply: it gets an error and not the grant, so the run
        // must not keep the hold, or the two would disagree about whether there is one.
        if let Some(back) = back {
            if shared.lock().withdraw(&back) {
                unsafe { SetEvent(shared.wake as Handle) };
                shared.log.push(&withdrawn_line(unix_ms_now(), &back, take_ms));
            }
        }
    }
}

/// Why a connection is refused whatever it sends.
enum Shut {
    /// A refusal for this reason, a line of its own as far as the budget allows.
    Refusal(Refusal),
    /// A refusal for the rate after the first of its window: counted, and logged with the rest as one line.
    Counted,
}

/// What is known of a connection before any of its message is read.
struct Arrival {
    id: u32,
    image: String,
    client: Option<Process>,
    in_job: bool,
    shut: Option<Shut>,
    /// The client has closed its end of the pipe: set once its message is read, before the decision.
    gone: bool,
}

/// True when the client has closed its end of the pipe, or the end can no longer be asked
/// about. A client waits for its reply with its end open, so an end that is closed is a
/// client that has gone, whatever process now has its identifier.
fn client_gone(pipe: Handle) -> bool {
    let (mut available, mut left) = (0u32, 0u32);
    unsafe { PeekNamedPipe(pipe, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut available, &mut left) == 0 }
}

/// Open the client, find out whether it is in the job, and count the connection against
/// its share of the rate: a client that is not in the job has no share of its own, all
/// of them draw on one, so they cannot crowd out the processes in it.
fn arrive(shared: &Shared, id: u32) -> Arrival {
    let client = Process::open(id);
    let image = client.as_ref().map_or_else(|| "unknown".to_string(), Process::image);
    let job = shared.job as Handle;
    let in_job = client.as_ref().map_or(false, |client| client.in_job(job));
    let key = match &client {
        Some(client) if in_job => (client.id, client.created),
        _ => OUTSIDE,
    };
    let shut = {
        let mut state = shared.lock();
        let now = tick();
        if state.ended(now, Some(job)) {
            Some(Shut::Refusal(Refusal::Ended))
        } else {
            let alive = state.alive;
            match state.limiter.admit(key, (id, &image), now, &alive) {
                Admit::Allowed => None,
                Admit::First => Some(Shut::Refusal(Refusal::RateLimited)),
                Admit::Counted => Some(Shut::Counted),
                Admit::Full => Some(Shut::Refusal(Refusal::Crowded)),
            }
        }
    };
    Arrival { id, image, client, in_job, shut, gone: false }
}

/// What the log is told of a request.
enum Line {
    /// A grant: always a line of its own, and what it takes to back out of it.
    Granted(String, Withdraw),
    /// The end of a hold at its process's request: always a line of its own.
    Released(String),
    /// A refusal: a line of its own, as far as the budget of refusal lines allows.
    Refused(String),
    /// A refusal for the rate after the first of its window: counted, and logged with the rest as one line.
    Counted,
}

/// A refusal: the reply, and the line to log.
fn refused(id: u32, image: &str, requested: Option<f64>, refusal: Refusal, cap: f64) -> (Reply, Line) {
    let reason = refusal.describe(cap);
    (Reply::Refused { refusal, cap }, Line::Refused(log_line(unix_ms_now(), &Entry { pid: id, image, requested, granted: None, reason: &reason })))
}

/// Verify the process and decide the request, and say what the log is to be told. The
/// checks that read the process take no lock; every decision about the deadline, the
/// rate and the hold is made under the one lock that also guards the deadline.
fn decide(shared: &Shared, arrival: Arrival, connected_at: u64, message: &Message) -> (Reply, Option<String>, Option<Withdraw>) {
    let (reply, line) = evaluate(shared, arrival, connected_at, message);
    match line {
        Line::Granted(line, back) => (reply, Some(line), Some(back)),
        Line::Released(line) => (reply, Some(line), None),
        Line::Counted => (reply, None, None),
        Line::Refused(line) => (reply, shared.lock().budget.allow(tick()).then_some(line), None),
    }
}

fn evaluate(shared: &Shared, arrival: Arrival, connected_at: u64, message: &Message) -> (Reply, Line) {
    let Arrival { id, image, client, in_job, shut, gone } = arrival;
    let job = shared.job as Handle;
    let cap = shared.lock().cap_seconds;
    let request = match message {
        Message::Bytes(bytes) => decode_request(bytes),
        _ => None,
    };
    let requested = request.map(|(_, _, seconds)| seconds);
    let refuse = |refusal: Refusal| refused(id, &image, requested, refusal, cap);
    let counted = || (Reply::Refused { refusal: Refusal::RateLimited, cap }, Line::Counted);
    // Before anything is believed of the client: the run may be over, and the client is
    // held to its share of the rate (settled when it connected). A release is let past the
    // rate: it only ends a hold that a counted grant made, and one that finds none is refused
    // below with the rest of its share used, so the share still bounds what a process can do.
    let release = matches!(request, Some((Target::Release, _, _)));
    let limited = matches!(shut, Some(Shut::Counted | Shut::Refusal(Refusal::RateLimited)));
    match shut {
        Some(Shut::Refusal(refusal)) if !(release && limited) => return refuse(refusal),
        Some(Shut::Counted) if !release => return counted(),
        _ => {}
    }
    let Some((target, token, seconds)) = request else { return refuse(Refusal::Malformed) };
    let Some(client) = client else { return refuse(Refusal::Unverified) };
    // The process must be the one that connected: alive now, and started before the guard
    // learned of the connection, which a process that took over a reused identifier later did
    // not; and the end of the pipe it connected with must still be open, since a client waits
    // for its reply. One that has closed it is gone, and whatever process now has its identifier
    // (one that began between the connection and the guard's look at it) is not the client.
    if gone || !client.started_before(connected_at) {
        return refuse(Refusal::Unverified);
    }
    if !in_job {
        return refuse(Refusal::NotInJob);
    }
    // The extend program ends at once, so it asks for the process that ran it. That
    // parent is read from the verified client's own record and must be older than it
    // (a reused identifier is newer), alive and in the job like any other. When it is
    // a copy of Git Bash made to run the program, the shell that made the copy is held.
    if target == Target::Release {
        let removed = shared.lock().drop_hold(client.id, client.created, token, limited);
        if !removed {
            // Over its share, the refusal is the one for the rate; within it, there was no hold.
            return match shut {
                Some(Shut::Counted) => counted(),
                Some(Shut::Refusal(refusal)) => refuse(refusal),
                None => refuse(Refusal::NoHold),
            };
        }
        unsafe { SetEvent(shared.wake as Handle) };
        let line = released_line(unix_ms_now(), id, &image, "the hold ended with the library call that asked for it");
        return (Reply::Granted { seconds: 0.0, until_unix_ms: 0, held: 0 }, Line::Released(line));
    }
    // A grant that the audit file could not record would be a deadline moved by a request that
    // is not in the record, so nothing is granted while the file cannot take lines.
    if shared.log.blocked() {
        return refuse(Refusal::AuditBlocked);
    }
    let holder = match target {
        Target::Caller | Target::Release => None,
        Target::Parent => match client.parent_id().and_then(Process::open) {
            Some(parent) if parent.created < client.created && parent.alive() => {
                let parent = enclosing_shell(parent, job);
                if !parent.in_job(job) {
                    return refuse(Refusal::HolderNotInJob);
                }
                Some(parent)
            }
            _ => return refuse(Refusal::Unverified),
        },
    };
    let held = holder.as_ref().map(|parent| (parent.id, parent.image()));
    let parent_rate = holder.as_ref().zip(held.as_ref()).map(|(parent, (pid, name))| ((parent.id, parent.created), *pid, name.as_str()));
    let process = holder.unwrap_or(client);
    let (id_held, created_held) = (process.id, process.created);
    let (outcome, now, previous) = {
        let mut state = shared.lock();
        let now = tick();
        let previous = state.hold_until(id_held, created_held, token);
        (state.grant(now, Some(job), seconds, process, token, parent_rate), now, previous)
    };
    if let Err(no) = outcome {
        return match no {
            Refused { refusal: Refusal::RateLimited, counted: true } => counted(),
            Refused { refusal, .. } => refuse(refusal),
        };
    }
    unsafe { SetEvent(shared.wake as Handle) };
    let until = now + millis(seconds);
    let reason = format!("within the cap{}",
        held.as_ref().map_or(String::new(), |(pid, name)| format!("; held for the parent, process {} ({})", pid, name)));
    let line = log_line(unix_ms_now(), &Entry { pid: id, image: &image, requested: Some(seconds), granted: Some(seconds), reason: &reason });
    let back = Withdraw { id: id_held, created: created_held, token, until, previous, pid: id, image, seconds };
    (Reply::Granted { seconds, until_unix_ms: unix_ms_now() + (until - now), held: held.map_or(0, |(pid, _)| pid) }, Line::Granted(line, back))
}

// ---------------------------------------------------------------------- the client

fn valid_channel(name: &str) -> bool {
    name.strip_prefix(PIPE_PREFIX).map_or(false, |rest| rest.len() == 32 && rest.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// The channel of the enclosing run, if the environment names one. The name is
/// checked before it is opened, so a changed variable never names a file or a pipe
/// that is not a channel.
fn channel_from_environment() -> Result<Option<String>, GuardError> {
    match std::env::var_os(CHANNEL_VARIABLE) {
        None => Ok(None),
        Some(value) if value.is_empty() => Ok(None),
        Some(value) => match value.into_string() {
            Ok(name) if valid_channel(&name) => Ok(Some(name)),
            _ => Err(GuardError(format!("{} does not name an extension channel", CHANNEL_VARIABLE))),
        },
    }
}

/// What a client says when the channel it names is not there.
const CHANNEL_GONE: &str = "the extendable run's channel is gone";

/// Open the channel, waiting a little while its single instance is busy. None when there is no
/// such channel: the run that made it has ended.
fn connect(name: &str) -> Result<Option<Handle>, GuardError> {
    let wide_name = wide(name);
    let began = tick();
    loop {
        // Anonymous impersonation level: the server never acts as this process.
        let pipe = unsafe { CreateFileW(wide_name.as_ptr(), CLIENT_ACCESS, 0, std::ptr::null_mut(), OPEN_EXISTING, SECURITY_SQOS_PRESENT | FILE_FLAG_OVERLAPPED, std::ptr::null_mut()) };
        if pipe != INVALID_HANDLE {
            return Ok(Some(pipe));
        }
        match unsafe { GetLastError() } {
            ERROR_PIPE_BUSY if tick().saturating_sub(began) < CONNECT_MS => {
                unsafe { WaitNamedPipeW(wide_name.as_ptr(), 500) };
            }
            ERROR_FILE_NOT_FOUND => return Ok(None),
            ERROR_PIPE_BUSY => return Err(GuardError("the extendable run's channel is busy".into())),
            _ => return Err(os_error()),
        }
    }
}

/// What a client makes of a failed call: the run did not answer in time, or a Windows error.
fn client_error(code: u32) -> GuardError {
    if code == WAIT_TIMEOUT {
        GuardError("the extendable run did not answer".into())
    } else {
        error_for(code)
    }
}

/// Send `request` on the open channel and read the reply, each step for at most
/// `REPLY_MS`: a run that no longer answers is refused here, not waited for.
fn exchange(pipe: Handle, request: &[u8]) -> Result<Reply, GuardError> {
    unsafe {
        let mut mode = PIPE_READMODE_MESSAGE;
        checked(SetNamedPipeHandleState(pipe, &mut mode, std::ptr::null_mut(), std::ptr::null_mut()))?;
        let event = CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null());
        if event.is_null() {
            return Err(os_error());
        }
        let outcome = (|| -> Result<Reply, GuardError> {
            let mut overlapped = Overlapped::with_event(event);
            let mut written = 0u32;
            let started = WriteFile(pipe, request.as_ptr() as *const c_void, request.len() as u32, &mut written, &mut overlapped) != 0;
            finish_io(pipe, &mut overlapped, started, &[event], REPLY_MS).map_err(client_error)?;
            ResetEvent(event);
            let mut overlapped = Overlapped::with_event(event);
            let mut reply = [0u8; REPLY_SIZE];
            let mut read = 0u32;
            let started = ReadFile(pipe, reply.as_mut_ptr() as *mut c_void, reply.len() as u32, &mut read, &mut overlapped) != 0;
            let length = finish_io(pipe, &mut overlapped, started, &[event], REPLY_MS).map_err(client_error)?;
            decode_reply(&reply[..length as usize]).ok_or_else(not_understood)
        })();
        CloseHandle(event);
        outcome
    }
}

/// Ask the enclosing extendable run to hold the deadline of `target` for `seconds`
/// from now. Refused with the reason when the run says no. The seconds are sent as
/// they are, whatever they are: the run refuses an invalid or excessive request and
/// logs it, so that every request that reaches a run is in its log.
pub(crate) fn request(target: Target, seconds: f64) -> Result<Grant, GuardError> {
    request_held(target, 0, seconds).map(|(grant, _)| grant)
}

/// `request` for the hold `token` of the process, and the process the hold is on when it is
/// not the one that asked (the parent of the `extend` program), or 0.
pub(crate) fn request_held(target: Target, token: Token, seconds: f64) -> Result<(Grant, u32), GuardError> {
    let name = channel_from_environment()?.ok_or_else(|| GuardError(format!("no extendable run encloses this process ({} is not set)", CHANNEL_VARIABLE)))?;
    ask(&name, target, token, seconds)?.ok_or_else(|| GuardError(CHANNEL_GONE.into()))
}

/// Send one request to the channel `name`. None when the channel is not there.
fn ask(name: &str, target: Target, token: Token, seconds: f64) -> Result<Option<(Grant, u32)>, GuardError> {
    let Some(pipe) = connect(name)? else { return Ok(None) };
    let outcome = exchange(pipe, &encode_request(target, token, seconds));
    unsafe { CloseHandle(pipe) };
    match outcome? {
        Reply::Granted { seconds, until_unix_ms, held } => {
            // `decode_reply` has kept the time in range; the sum is checked all the same, since a panic here is a crash.
            let until = UNIX_EPOCH.checked_add(Duration::from_millis(until_unix_ms)).ok_or_else(not_understood)?;
            Ok(Some((Grant { seconds, until }, held)))
        }
        Reply::Refused { refusal, cap } => Err(GuardError(format!("extension refused: {}", refusal.describe(cap)))),
    }
}

/// The request a guard makes when it starts inside an extendable run: its deadline
/// is a request for that many seconds. True when the request was made and granted, and
/// false when no run encloses the guard: the variable is not set, does not name a channel,
/// or names one that is gone. Such a value is no run, so the guard keeps its own fixed
/// deadline, as it did before extendable runs; a value that names a channel that is
/// there, and a run that refuses or does not answer properly, end the guard with an error.
/// `required` is the contain role, which has no use for a run that is not there and never
/// runs a command without one: for it each of those cases is an error. The hold is the
/// process's hold `token`: a call of the library has one of its own.
pub(crate) fn register_start(seconds: f64, required: bool, token: Token) -> Result<bool, GuardError> {
    let none = || if required {
        Err(GuardError(format!("this program runs inside an extendable run of process-tree-guard, and none encloses it ({} is not set)", CHANNEL_VARIABLE)))
    } else {
        Ok(false)
    };
    let name = match channel_from_environment() {
        Ok(Some(name)) => name,
        Ok(None) => return none(),
        Err(error) => return if required { Err(error) } else { Ok(false) },
    };
    match ask(&name, Target::Caller, token, seconds)? {
        Some(_) => Ok(true),
        None if required => Err(GuardError(CHANNEL_GONE.into())),
        None => none(),
    }
}

/// Whether an extendable run encloses this process: the environment names a channel and the
/// channel is there. Nothing is sent to it, so it places no hold on the run, and a name that is
/// not a channel, or one that is gone, is no run (as for `register_start`). A channel that is
/// busy is there.
pub(crate) fn enclosed() -> bool {
    let Ok(Some(name)) = channel_from_environment() else { return false };
    let wide_name = wide(&name);
    unsafe { WaitNamedPipeW(wide_name.as_ptr(), 1) != 0 || GetLastError() != ERROR_FILE_NOT_FOUND }
}

/// End the hold `token` of the calling process on the enclosing run: what a library call
/// does when it returns, since the process that made it goes on and the hold was for the
/// call. Its other holds, the ones of calls that overlap it among them, stand. It moves
/// the deadline earlier or not at all.
pub(crate) fn release(token: Token) -> Result<(), GuardError> {
    request_held(Target::Release, token, 0.0).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every process of the table is running.
    fn live(_: RateKey) -> bool {
        true
    }

    #[test]
    fn time_is_written_in_universal_time() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601(1_700_000_000_000), "2023-11-14T22:13:20.000Z");
        assert_eq!(iso8601(951_782_400_123), "2000-02-29T00:00:00.123Z");
        assert_eq!(iso8601(4_102_444_799_999), "2099-12-31T23:59:59.999Z");
    }

    #[test]
    fn log_values_cannot_end_a_line_or_start_a_field() {
        assert_eq!(escape("plain.exe"), "plain.exe");
        assert_eq!(escape("a\"b\\c"), "a\\\"b\\\\c");
        let hostile = "x\r\nPROCESS_TREE_GUARD_EXTENSION: pid=1\t\u{85}\u{2028}\u{7f}\0end";
        let escaped = escape(hostile);
        assert!(escaped.chars().all(|c| !c.is_control() && c != '\u{2028}' && c != '\u{2029}'), "{}", escaped);
        assert!(escaped.contains("\\u{d}\\u{a}PROCESS_TREE_GUARD_EXTENSION"));
        let line = log_line(0, &Entry { pid: 7, image: hostile, requested: Some(60.0), granted: None, reason: "a\nb" });
        assert_eq!(line.lines().count(), 1, "{}", line);
        assert!(line.starts_with("PROCESS_TREE_GUARD_EXTENSION: time=1970-01-01T00:00:00.000Z pid=7 image=\""));
        assert!(line.ends_with("requested=60 granted=0 decision=refused reason=\"a\\u{a}b\""), "{}", line);
    }

    #[test]
    fn log_values_cannot_change_how_the_rest_of_the_line_is_shown() {
        // A right-to-left override without its end would show the rest of the line reversed.
        let spoof = "ok\u{202e}detnarg\u{202c}.exe";
        let escaped = escape(spoof);
        assert_eq!(escaped, "ok\\u{202e}detnarg\\u{202c}.exe");
        for c in ['\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202d}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
            '\u{200b}', '\u{200c}', '\u{200d}', '\u{2060}', '\u{feff}', '\u{061c}', '\u{00ad}', '\u{e0001}', '\u{e0041}'] {
            assert_eq!(escape(&c.to_string()), format!("\\u{{{:x}}}", c as u32), "U+{:04X}", c as u32);
        }
        for c in ['a', 'Z', '.', ' ', '\u{e9}', '\u{4e2d}', '\u{1f600}', '\u{200a}', '\u{2010}', '\u{2065}', '\u{fe0f}'] {
            assert_eq!(escape(&c.to_string()), c.to_string(), "U+{:04X} is shown as it is", c as u32);
        }
        let line = log_line(0, &Entry { pid: 7, image: spoof, requested: Some(5.0), granted: None, reason: "r" });
        assert!(!line.chars().any(|c| is_format(c) || c.is_control()), "{}", line);
    }

    #[test]
    fn the_log_records_the_seconds_asked_exactly_and_in_bounded_text() {
        for (value, text) in [
            (60.0, "60"), (1.5, "1.5"), (0.25, "0.25"), (0.0, "0"), (-5.0, "-5"), (86401.0, "86401"), (1e9, "1000000000"),
            (1e15, "1e15"), (1e19, "1e19"), (1e300, "1e300"), (1.8446744073709552e19, "1.8446744073709552e19"), (f64::MAX, "1.7976931348623157e308"),
            (5e-324, "5e-324"), (1e-7, "1e-7"), (1e-6, "0.000001"), (-1e300, "-1e300"),
        ] {
            assert_eq!(log_seconds(value), text);
            assert!(log_seconds(value).len() <= 24, "{}", value);
            let line = log_line(0, &Entry { pid: 1, image: "x", requested: Some(value), granted: None, reason: "r" });
            assert!(line.contains(&format!(" requested={} granted=0 ", text)), "{}", line);
        }
        // A number the log writes can be read back as the number that was asked for.
        for value in [1e300, 18446744073709551616.0, 5e-324, 1e19, 0.1 + 0.2] {
            assert_eq!(log_seconds(value).parse::<f64>().ok(), Some(value));
        }
        assert_eq!(log_seconds(f64::INFINITY), "invalid");
        assert_eq!(log_seconds(f64::NAN), "invalid");
    }

    #[test]
    fn log_lines_name_every_field() {
        let granted = log_line(1_700_000_000_000, &Entry { pid: 42, image: "kit.exe", requested: Some(1.5), granted: Some(1.5), reason: "within the cap" });
        assert_eq!(granted, "PROCESS_TREE_GUARD_EXTENSION: time=2023-11-14T22:13:20.000Z pid=42 image=\"kit.exe\" requested=1.5 granted=1.5 decision=granted reason=\"within the cap\"");
        let odd = log_line(0, &Entry { pid: 1, image: "x", requested: None, granted: None, reason: "r" });
        assert!(odd.contains("requested=unknown granted=0 decision=refused"));
        let bad = log_line(0, &Entry { pid: 1, image: "x", requested: Some(f64::NAN), granted: None, reason: "r" });
        assert!(bad.contains("requested=invalid"));
    }

    #[test]
    fn the_line_for_an_exception_has_decisions_of_its_own_and_the_attempt_and_escapes_what_it_is_given() {
        let record = |account, command, started_by, requested, approved, attempt, reason| ExceptionRecord {
            unix_ms: 1_700_000_000_000, pid: 42, image: "guard.exe", account, command, method: "console", timeout: 20.0, started_by, requested, approved, attempt, reason,
        };
        let approved = exception_line(&record("PC\\me", "C:\\tools\\run.exe --all", "C:\\Apps\\host.exe", 86_400.0, true, 2, "a cap of 24 hours was approved"));
        assert_eq!(approved, "PROCESS_TREE_GUARD_EXTENSION: time=2023-11-14T22:13:20.000Z pid=42 image=\"guard.exe\" account=\"PC\\\\me\" \
            command=\"C:\\\\tools\\\\run.exe --all\" method=\"console\" timeout=20 started_by=\"C:\\\\Apps\\\\host.exe\" requested=86400 hours=24 granted=0 \
            decision=exception-approved attempt=2 reason=\"a cap of 24 hours was approved\"");
        let refused = exception_line(&record("", "", "", 21_600.5, false, 0, "no \"one\"\r\nis here"));
        assert!(refused.contains("requested=21600.5 hours=6.01 granted=0 decision=exception-refused attempt=0 reason=\"no \\\"one\\\"\\u{d}\\u{a}is here\""), "{}", refused);
        assert!(refused.contains("started_by=\"\" requested="), "a starter that is not known is an empty field: {}", refused);
        assert!(exception_line(&record("a", "c", "s", 25_000.0, false, 1, "r")).contains("requested=25000 hours=6.95 granted=0"), "hours are rounded up to two decimals");
        let desktop = exception_line(&ExceptionRecord { method: "desktop", timeout: 0.5, ..record("a", "c", "s", 86_400.0, false, 1, "r") });
        assert!(desktop.contains("method=\"desktop\" timeout=0.5 started_by=\"s\" requested=86400"), "{}", desktop);
        for (seconds, text) in [(86_400.0, "24"), (3_600.0, "1"), (23_400.0, "6.5"), (25_000.0, "6.95"), (21_601.0, "6.01"), (21_600.0, "6"), (21_600.5, "6.01"),
            (21_600.000_000_1, "6.01"), (1_800.0, "0.5"), (86_396.4, "24"), (44_100.0, "12.25")] {
            assert_eq!(hours_figure(seconds), text, "{}", seconds);
        }
        // Never smaller than the cap, so a figure can only overstate what a person approves.
        for seconds in (21_601..86_400).step_by(37) {
            let shown: f64 = hours_figure(seconds as f64).parse().unwrap_or(0.0);
            assert!(shown * 3600.0 + 1e-6 >= seconds as f64 && shown > 6.0, "{} {}", seconds, shown);
        }
        assert!(!refused.chars().any(|c| c.is_control()), "a line is one line of printable text: {:?}", refused);
        let odd_image = exception_line(&ExceptionRecord { image: "k\u{2028}it \"x\"=1.exe", ..record("a\u{202e}\"b", "c\r\n\"d\"", "s\u{85}\"t\"", 86_400.0, false, 1, "r") });
        assert!(odd_image.contains("image=\"k\\u{2028}it \\\"x\\\"=1.exe\""), "{}", odd_image);
        assert!(odd_image.contains("account=\"a\\u{202e}\\\"b\" command=\"c\\u{d}\\u{a}\\\"d\\\"\" method="), "the account and the command are escaped like the rest: {}", odd_image);
        assert!(odd_image.contains("started_by=\"s\\u{85}\\\"t\\\"\" requested="), "and so is the starter: {}", odd_image);
        assert!(!odd_image.chars().any(|c| c.is_control() || is_format(c)), "{:?}", odd_image);
    }

    #[test]
    fn the_user_of_a_token_is_read_for_the_check_of_an_exception_and_the_log_is_opened_before_the_job() {
        use std::os::windows::io::AsRawHandle;
        let mut token: Handle = std::ptr::null_mut();
        assert_ne!(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }, 0);
        let from_token = token_user_sid(token);
        unsafe { CloseHandle(token) };
        let ours = current_user_sid().expect("the user of this process");
        assert_eq!(from_token.as_ref().ok(), Some(&ours));
        assert!(ours.starts_with("S-1-"), "{}", ours);
        // A handle that is not a token has no user: the check of an exception cannot be passed with one.
        let file = std::fs::File::open(std::env::current_exe().expect("this program")).expect("open this program");
        assert!(token_user_sid(file.as_raw_handle() as Handle).is_err());
        // The log of a run is opened before the job, and refuses a file that is not on a disk.
        let device = Settings { max_seconds: 86_400.0, log_path: Some(PathBuf::from("NUL")), exception: None };
        assert!(matches!(open_log(&device), Err(GuardError(m)) if m.contains("must be a regular file")));
    }

    #[test]
    fn requests_and_replies_round_trip_in_fixed_sizes() {
        for (target, token, seconds) in [(Target::Caller, 0, 60.0), (Target::Parent, 0, 0.25), (Target::Release, 0, 0.0), (Target::Caller, 7, 5.0), (Target::Release, (1 << TOKEN_BITS) - 1, 0.0)] {
            let bytes = encode_request(target, token, seconds);
            assert_eq!(bytes.len(), REQUEST_SIZE);
            assert_eq!(decode_request(&bytes), Some((target, token, seconds)));
        }
        assert_eq!(decode_request(&encode_request(Target::Caller, u64::MAX, 1.0)).map(|(_, token, _)| token), Some((1 << TOKEN_BITS) - 1), "a token is 56 bits and never changes the target");
        let mut bytes = encode_request(Target::Caller, 0, 1.0);
        assert_eq!(decode_request(&bytes[..23]), None);
        bytes[0] ^= 1;
        assert_eq!(decode_request(&bytes), None);
        let mut bytes = encode_request(Target::Caller, 0, 1.0);
        bytes[8] = 4;
        assert_eq!(decode_request(&bytes), None);
        assert_eq!(decode_request(&[]), None);

        let granted = encode_reply(&Reply::Granted { seconds: 5.0, until_unix_ms: 123, held: 77 });
        assert_eq!(granted.len(), REPLY_SIZE);
        assert!(matches!(decode_reply(&granted), Some(Reply::Granted { seconds, until_unix_ms: 123, held: 77 }) if seconds == 5.0));
        for code in 1..=13u64 {
            let refusal = Refusal::from_code(code).expect("a code in range");
            let bytes = encode_reply(&Reply::Refused { refusal, cap: 9.0 });
            assert!(matches!(decode_reply(&bytes), Some(Reply::Refused { refusal: r, cap }) if r == refusal && cap == 9.0));
        }
        assert!(Refusal::from_code(0).is_none() && Refusal::from_code(14).is_none());
        assert!(decode_reply(&granted[..39]).is_none());
    }

    #[test]
    fn the_deadline_is_the_latest_of_its_own_and_the_live_holds() {
        // Time is in units of one second: the boss has 2, a helper holds until 6 and another until 4.
        assert_eq!(latest(2, [6, 4].into_iter()), 6);
        assert_eq!(latest(2, [4].into_iter()), 4, "the helper that held until 6 exited, so the deadline falls to 4");
        assert_eq!(latest(2, std::iter::empty()), 2, "no live hold: the run's own deadline");
        assert_eq!(latest(9, [4].into_iter()), 9, "a hold earlier than the run's own deadline does not shorten it");
    }

    #[test]
    fn requests_are_limited_per_process_in_a_window() {
        let mut limiter = Limiter::default();
        let (key, who) = ((10, 100), (10, "worker.exe"));
        for n in 0..RATE_LIMIT {
            assert_eq!(limiter.admit(key, who, n as u64, &live), Admit::Allowed, "request {}", n);
        }
        assert_eq!(limiter.admit(key, who, 500, &live), Admit::First, "the next request in the window is refused, and is the one that is logged");
        assert_eq!(limiter.admit(key, who, 600, &live), Admit::Counted);
        assert_eq!(limiter.admit(key, who, 700, &live), Admit::Counted);
        assert_eq!(limiter.admit((11, 100), (11, "other.exe"), 500, &live), Admit::Allowed, "another process has its own share");
        assert!(limiter.summaries.is_empty(), "nothing is summarised while the window is open");
        assert_eq!(limiter.admit(key, who, RATE_WINDOW_MS + RATE_LIMIT as u64 + 1, &live), Admit::Allowed, "the window has passed");
        assert_eq!(limiter.summaries.len(), 1);
        let summary = &limiter.summaries[0];
        assert_eq!((summary.pid, summary.image.as_str(), summary.count), (10, "worker.exe", 2), "the two refusals after the logged one");
    }

    #[test]
    fn a_live_process_is_never_forgotten_to_make_room_and_clients_outside_the_job_share_one_allowance() {
        let mut limiter = Limiter::default();
        for n in 0..MAX_RATE_KEYS as u32 {
            assert_eq!(limiter.admit((1000 + n, 1), (1000 + n, "p.exe"), 1, &live), Admit::Allowed);
        }
        assert_eq!(limiter.admit((1000, 1), (1000, "p.exe"), 1, &live), Admit::Allowed, "a process in the table keeps its share");
        assert_eq!(limiter.admit((9000, 1), (9000, "late.exe"), 2, &live), Admit::Full, "a new process is refused, and nobody is evicted");
        assert!(limiter.rates.len() == MAX_RATE_KEYS && limiter.rates.iter().any(|rate| rate.key == (1000, 1)));
        assert_eq!(limiter.admit((9001, 1), (9001, "later.exe"), 3, &live), Admit::Full, "and a look at the table that finds everyone live is not repeated at once");
        assert_eq!(limiter.unproductive, Some(2));
        let mut outside = Limiter::default();
        for n in 0..RATE_LIMIT as u32 {
            assert_eq!(outside.admit(OUTSIDE, (5000 + n, "x.exe"), n as u64, &live), Admit::Allowed, "request {} from a different process", n);
        }
        assert_eq!(outside.admit(OUTSIDE, (7777, "y.exe"), 100, &live), Admit::First, "all the clients outside the job draw on one allowance");
        assert_eq!(outside.rates.len(), 1);
    }

    #[test]
    fn a_process_that_has_exited_is_forgotten_when_the_table_is_full() {
        // Short-lived processes, each asking once, far more of them than the table holds in one window.
        let exited = |key: RateKey| key.0 >= 100_000;
        let mut limiter = Limiter::default();
        let mut refused = 0;
        for n in 0..3 * MAX_RATE_KEYS as u32 {
            // Every process is gone by the time the next one asks, except the first thousand, which stay.
            let pid = if n < 1000 { 1000 + n } else { 100_000 + n };
            if limiter.admit((pid, 1), (pid, "p.exe"), n as u64, &|key| !exited(key)) != Admit::Allowed {
                refused += 1;
            }
        }
        assert_eq!(refused, 0, "a process that is gone takes no room from the ones that come after it");
        assert!(limiter.rates.len() <= MAX_RATE_KEYS);
        assert!(limiter.rates.iter().filter(|rate| rate.key.0 < 100_000).count() == 1000, "the live ones were never forgotten");
        // Everyone alive: the table stays full, and the refusal is the table's own, not the rate's.
        let mut full = Limiter::default();
        for n in 0..MAX_RATE_KEYS as u32 {
            assert_eq!(full.admit((n + 1, 1), (n + 1, "p.exe"), 5, &live), Admit::Allowed);
        }
        assert_eq!(full.admit((70_000, 1), (70_000, "q.exe"), 5, &live), Admit::Full);
        // The first of them exits: its place goes to the next process that asks, with no wait.
        assert_eq!(full.admit((70_000, 1), (70_000, "q.exe"), 5 + FORGET_MS, &|key| key.0 != 1), Admit::Allowed);
        assert_eq!(full.rates.len(), MAX_RATE_KEYS);
        // A client outside the job is never forgotten as a dead process.
        let mut outside = Limiter::default();
        outside.admit(OUTSIDE, (9, "x.exe"), 1, &live);
        for n in 0..MAX_RATE_KEYS as u32 - 1 {
            outside.admit((n + 1, 1), (n + 1, "p.exe"), 1, &live);
        }
        assert_eq!(outside.admit((70_000, 1), (70_000, "q.exe"), 2, &|_| false), Admit::Allowed);
        assert!(outside.rates.iter().any(|rate| rate.key == OUTSIDE));
        assert_eq!(outside.rates.len(), 2, "the table was emptied of the exited processes, and the outside key stayed");
    }

    #[test]
    fn the_refusal_for_a_full_table_is_not_the_rate_limits() {
        assert_ne!(Refusal::Crowded.describe(1.0), Refusal::RateLimited.describe(1.0));
        assert!(Refusal::Crowded.describe(1.0).contains("too many processes"));
        let mut limiter = Limiter::default();
        for n in 0..MAX_RATE_KEYS as u32 {
            limiter.admit((n + 1, 1), (n + 1, "p.exe"), 1, &live);
        }
        let mut state = State::new(1_000_000, 60.0);
        state.limiter = limiter;
        state.alive = live;
        let late = this_process();
        let key = (late.id, late.created);
        assert_eq!(state.grant(2, None, 5.0, late, 0, Some((key, 4242, "late.exe"))), Err(Refusal::Crowded.into()));
    }

    #[test]
    fn refusal_lines_are_a_budget_and_the_rest_is_one_line() {
        let mut budget = Budget::default();
        for n in 0..REFUSAL_LINES {
            assert!(budget.allow(n as u64), "line {}", n);
        }
        assert!(!budget.allow(100) && !budget.allow(200), "over the budget the lines are counted");
        assert_eq!(budget.overflow(300, false), None, "the window is still open");
        assert_eq!(budget.overflow(RATE_WINDOW_MS + REFUSAL_LINES as u64, false), Some(2), "one line for the two that were withheld");
        assert_eq!(budget.overflow(RATE_WINDOW_MS + REFUSAL_LINES as u64, false), None);
        assert!(budget.allow(RATE_WINDOW_MS + 1000), "a new window starts afresh");
        let mut ending = Budget::default();
        for _ in 0..REFUSAL_LINES + 3 {
            ending.allow(5);
        }
        assert_eq!(ending.overflow(6, true), Some(3), "at the end of the run what was withheld is told at once");
    }

    #[test]
    fn counted_refusals_become_one_line_when_their_window_ends() {
        let mut state = State::new(0, 60.0);
        for n in 0..RATE_LIMIT {
            state.limiter.admit((7, 1), (7, "w.exe"), n as u64, &live);
        }
        for _ in 0..5 {
            state.limiter.admit((7, 1), (7, "w.exe"), 100, &live);
        }
        assert!(state.notices(200, 0, false).is_empty(), "the window has not passed");
        let lines = state.notices(RATE_WINDOW_MS + 100, 1_700_000_000_000, false);
        assert_eq!(lines.len(), 1, "{:?}", lines);
        assert!(lines[0].contains(" pid=7 image=\"w.exe\"") && lines[0].contains("decision=refused") && lines[0].contains("4 more refused"), "{}", lines[0]);
        let mut ending = State::new(0, 60.0);
        for n in 0..RATE_LIMIT + 3 {
            ending.limiter.admit((8, 1), (8, "v.exe"), n as u64, &live);
        }
        let lines = ending.notices(50, 0, true);
        assert!(lines.len() == 1 && lines[0].contains("2 more refused"), "the end of a run flushes what is pending: {:?}", lines);
    }

    fn this_process() -> Process {
        Process::open(std::process::id()).expect("open this process")
    }

    #[test]
    fn a_request_after_the_deadline_is_refused_and_moves_nothing() {
        // Ticks are milliseconds: the run's own deadline is at 10 000.
        let mut state = State::new(10_000, 60.0);
        assert_eq!(state.grant(2_000, None, 5.0, this_process(), 0, None), Ok(()));
        assert_eq!(state.deadline(), 10_000, "a hold earlier than the run's own deadline moves nothing");
        assert_eq!(state.grant(9_000, None, 5.0, this_process(), 0, None), Ok(()));
        assert_eq!(state.deadline(), 14_000);
        // The run is past its deadline at 14 000 and nobody has noticed: the request is refused all the same.
        assert_eq!(state.grant(14_000, None, 5.0, this_process(), 0, None), Err(Refusal::Ended.into()));
        assert!(state.passed && state.deadline() == 10_000, "the hold that ran out is gone and the deadline did not move");
        assert_eq!(state.grant(14_001, None, 5.0, this_process(), 0, None), Err(Refusal::Ended.into()), "and it stays ended");
        // A run with no hold at all, past its own deadline.
        let mut plain = State::new(10_000, 60.0);
        assert_eq!(plain.grant(10_500, None, 5.0, this_process(), 0, None), Err(Refusal::Ended.into()));
        assert!(plain.holds.is_empty() && plain.expire(10_501, None));
    }

    #[test]
    fn a_channel_that_stopped_serving_grants_nothing_and_the_run_still_ends_at_its_deadline() {
        // Ticks are milliseconds: the run's own deadline is at 10 000, and a hold granted before the channel
        // stopped serving runs to 14 000. Closing to grants is not the deadline passing.
        let mut state = State::new(10_000, 60.0);
        assert_eq!(state.grant(9_000, None, 5.0, this_process(), 0, None), Ok(()));
        state.closed = true;
        assert!(!state.expire(9_500, None), "the deadline has not passed: the run goes on");
        assert_eq!(state.deadline(), 14_000, "the hold that was granted stands");
        assert!(state.ended(9_500, None), "but a request is refused as the run being over");
        assert_eq!(state.grant(9_600, None, 5.0, this_process(), 0, None), Err(Refusal::Ended.into()));
        assert_eq!(state.deadline(), 14_000, "and moves nothing");
        assert!(!state.expire(13_999, None) && state.deadline() == 14_000, "the time left is the hold's, not nothing");
        assert!(state.expire(14_000, None), "the run ends at the deadline it had");
        // A hold that ran out stops holding the run up although nothing can be granted.
        let mut ran_out = State::new(10_000, 60.0);
        assert_eq!(ran_out.grant(9_000, None, 2.0, this_process(), 0, None), Ok(()));
        ran_out.closed = true;
        assert!(!ran_out.expire(10_500, None) && ran_out.deadline() == 11_000);
        assert!(!ran_out.expire(10_999, None));
        assert!(ran_out.expire(11_000, None));
    }

    #[test]
    fn a_hold_is_refused_beyond_the_limit_and_renewed_below_it() {
        let mut state = State::new(1_000_000, 3600.0);
        let fake = |n: u32| {
            let mut process = this_process();
            process.id = 4_000_000 + n;
            process.created = n as u64;
            process
        };
        for n in 0..MAX_HOLDS as u32 {
            assert_eq!(state.grant(1, None, 60.0, fake(n), 0, None), Ok(()), "hold {}", n);
        }
        assert_eq!(state.grant(1, None, 60.0, fake(MAX_HOLDS as u32), 0, None), Err(Refusal::TooManyHolds.into()));
        assert_eq!(state.holds.len(), MAX_HOLDS);
        assert_eq!(state.grant(2, None, 90.0, fake(0), 0, None), Ok(()), "a process that holds already can renew");
        assert_eq!(state.holds.len(), MAX_HOLDS);
        assert_eq!(state.grant(2, None, 7200.0, fake(0), 0, None), Err(Refusal::OverCap.into()));
        assert_eq!(state.grant(2, None, f64::NAN, fake(0), 0, None), Err(Refusal::InvalidSeconds.into()));
        assert_eq!(state.grant(2, None, 0.0, fake(0), 0, None), Err(Refusal::InvalidSeconds.into()));
    }

    #[test]
    fn one_process_cannot_take_the_table_of_holds_from_the_rest() {
        let mut state = State::new(1_000_000, 3600.0);
        let fake = |n: u32| {
            let mut process = this_process();
            process.id = 4_000_000 + n;
            process.created = n as u64;
            process
        };
        for token in 0..MAX_HOLDS_PER_PROCESS as u64 {
            assert_eq!(state.grant(1, None, 60.0, fake(0), token, None), Ok(()), "token {}", token);
        }
        assert_eq!(state.grant(1, None, 60.0, fake(0), MAX_HOLDS_PER_PROCESS as u64, None), Err(Refusal::TooManyHoldsHere.into()));
        assert_eq!(state.holds.len(), MAX_HOLDS_PER_PROCESS);
        assert_eq!(state.grant(2, None, 90.0, fake(0), 3, None), Ok(()), "a hold the process has renews");
        assert_eq!(state.grant(2, None, 60.0, fake(1), 0, None), Ok(()), "another process is not held back");
        // Not the same process: the same identifier with another creation time is another process.
        let mut later = fake(0);
        later.created = 77;
        assert_eq!(state.grant(2, None, 60.0, later, 0, None), Ok(()));
        assert!(state.drop_hold(4_000_000, 0, 0, false));
        assert_eq!(state.grant(3, None, 60.0, fake(0), 99, None), Ok(()), "a hold that ended makes room");
        assert_eq!(Refusal::TooManyHoldsHere.describe(60.0), "this process holds too many deadlines");
        assert_eq!(Refusal::from_code(Refusal::TooManyHoldsHere as u64), Some(Refusal::TooManyHoldsHere));
    }

    /// A log whose only record is a standard error simulated by a sink: `fail` makes its writes fail, and `delay_ms` makes them slow.
    fn standard_error_only(fail: &Arc<AtomicBool>, delay_ms: u64) -> Log {
        let last_written = Arc::new(AtomicBool::new(true));
        let (seen, failing) = (last_written.clone(), fail.clone());
        let write = move |_: &str| {
            std::thread::sleep(Duration::from_millis(delay_ms));
            seen.store(!failing.load(Ordering::SeqCst), Ordering::SeqCst);
        };
        let sink = Arc::new(Sink::start("test-stderr", Box::new(write), 8).expect("start the sink"));
        Log { sinks: vec![sink.clone()], blocked: Arc::new(AtomicBool::new(false)), only: Some(StandardErrorOnly { sink, last_written }) }
    }

    #[test]
    fn a_grant_stands_only_when_its_line_reached_standard_error_if_that_is_the_only_record() {
        let fail = Arc::new(AtomicBool::new(false));
        let log = standard_error_only(&fail, 0);
        assert!(log.record("granted", 2_000) && !log.blocked(), "a line that is written is a record");
        fail.store(true, Ordering::SeqCst);
        assert!(!log.record("granted", 2_000), "a line that could not be written is not");
        assert!(log.blocked(), "and nothing is granted while writes fail");
        fail.store(false, Ordering::SeqCst);
        log.push("a refusal");
        let end = Instant::now() + Duration::from_secs(5);
        while log.blocked() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!log.blocked(), "a write that works lifts it");
        assert!(log.record("granted", 2_000));
        log.finish(1_000);
    }

    #[test]
    fn a_line_that_does_not_finish_is_not_a_record_and_a_file_is_not_waited_for() {
        let fail = Arc::new(AtomicBool::new(false));
        let slow = standard_error_only(&fail, 400);
        assert!(!slow.record("granted", 20), "standard error that is slow to take the line: no record within the wait");
        slow.finish(1_000);
        let with_file = Log { sinks: Vec::new(), blocked: Arc::new(AtomicBool::new(false)), only: None };
        assert!(with_file.record("granted", 0) && !with_file.blocked(), "with an audit file the file's own rule decides, and nothing is waited for");
        with_file.blocked.store(true, Ordering::SeqCst);
        assert!(with_file.blocked());
    }

    #[test]
    fn with_an_audit_file_the_line_of_an_approval_is_a_record_only_when_the_file_took_it() {
        let folder = std::env::temp_dir().join(format!("ptg-record-{}", std::process::id()));
        std::fs::create_dir_all(&folder).expect("make a folder for the file");
        // A file that takes lines: the line is waited for and it is in the file.
        let path = folder.join("audit.log");
        let good = Log::start(Some(path.clone()), 1 << 20).expect("start a log with a file");
        assert!(good.record_decision("approved one", 5_000) && !good.blocked(), "a line the file wrote is a record");
        good.finish(1_000);
        assert!(std::fs::read_to_string(&path).unwrap_or_default().contains("approved one"));
        // A file in a folder that is not there cannot take a line: the approval of an exception is not recorded.
        let bad = Log::start(Some(folder.join("missing").join("audit.log")), 1 << 20).expect("start a log whose file cannot be written");
        assert!(!bad.record_decision("approved two", 5_000), "a line that the file could not take is not a record");
        assert!(bad.blocked(), "and nothing is granted while it cannot");
        // The line of a grant is not waited for with an audit file, as before.
        assert!(bad.record("granted", 0), "the line of a grant is queued and stands at once");
        bad.finish(1_000);
        let _ = std::fs::remove_dir_all(&folder);
    }

    #[test]
    fn a_grant_whose_reply_was_not_taken_is_taken_back() {
        let mut state = State::new(1_000, 3600.0);
        let me = this_process();
        let back = |until: u64, previous: Option<u64>| Withdraw { id: me.id, created: me.created, token: 5, until, previous, pid: me.id, image: "client.exe".into(), seconds: 60.0 };
        // A first grant is removed.
        let previous = state.hold_until(me.id, me.created, 5);
        assert_eq!(previous, None);
        assert_eq!(state.grant(10, None, 60.0, this_process(), 5, None), Ok(()));
        assert_eq!(state.deadline(), 60_010);
        assert!(state.withdraw(&back(60_010, previous)));
        assert!(state.holds.is_empty() && state.deadline() == 1_000, "the hold is gone");
        // A renewal goes back to the hold it replaced, which the client was told of.
        assert_eq!(state.grant(10, None, 20.0, this_process(), 5, None), Ok(()));
        let previous = state.hold_until(me.id, me.created, 5);
        assert_eq!(state.grant(11, None, 90.0, this_process(), 5, None), Ok(()));
        assert!(state.withdraw(&back(90_011, previous)));
        assert_eq!(state.deadline(), 20_010, "the earlier hold stands");
        // A hold that something else has changed since is not touched, and the other holds of the process stand.
        assert_eq!(state.grant(12, None, 5.0, this_process(), 6, None), Ok(()));
        assert!(!state.withdraw(&back(90_011, None)), "it is no longer the grant that was made");
        assert!(state.withdraw(&Withdraw { token: 6, ..back(5_012, None) }), "the other hold is withdrawn by its own record");
        assert_eq!(state.holds.len(), 1);
    }

    #[test]
    fn the_channel_is_a_message_mode_pipe_that_refuses_remote_clients() {
        // The mode create_pipes passes to CreateNamedPipeW, and that it is the one passed.
        assert_ne!(CHANNEL_PIPE_MODE & PIPE_TYPE_MESSAGE, 0, "message type");
        assert_ne!(CHANNEL_PIPE_MODE & PIPE_READMODE_MESSAGE, 0, "message read mode");
        assert_ne!(CHANNEL_PIPE_MODE & PIPE_REJECT_REMOTE_CLIENTS, 0, "remote clients rejected");
        assert_eq!(OUT_BUFFER, 0, "no outgoing buffer, so a write completes when the reply is read");
        // The call is spelled in parts here, so that this test does not find itself.
        let call = format!("{}, {}, {}, 512, 0, &mut attributes", "CHANNEL_PIPE_MODE", "INSTANCES", "OUT_BUFFER");
        assert_eq!(include_str!("extend.rs").matches(call.as_str()).count(), 1, "create_pipes passes the mode and the buffer sizes");
    }

    #[test]
    fn a_client_must_have_started_before_it_connected() {
        let me = this_process();
        assert!(me.started_before(me.created) && me.started_before(me.created + 1), "started at or before the connection");
        assert!(!me.started_before(me.created - 1), "a process that started after the connection is not the one that connected");
    }

    #[test]
    fn the_poll_releases_a_holder_that_exited_with_no_message_from_the_job() {
        // No completion port is involved: this is the backstop that the supervisor runs at least every BACKSTOP_MS.
        unsafe {
            let job = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
            assert!(!job.is_null());
            let mut child = std::process::Command::new("ping.exe").args(["-n", "60", "127.0.0.1"])
                .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().expect("start ping.exe");
            use std::os::windows::io::AsRawHandle;
            assert_ne!(AssignProcessToJobObject(job, child.as_raw_handle() as Handle), 0, "put the holder in the job");
            let mut state = State::new(1_000_000, 3600.0);
            state.holds.push(Hold { process: Process::open(child.id()).expect("open the holder"), token: 0, until: 900_000 });
            state.release(1, Some(job));
            assert_eq!(state.holds.len(), 1, "a holder that is alive, in the job and listed keeps its hold");
            child.kill().expect("end the holder");
            child.wait().expect("reap the holder");
            state.release(1, Some(job));
            assert!(state.holds.is_empty(), "the poll finds the holder gone");
            let mut late = State::new(1_000_000, 3600.0);
            late.holds.push(Hold { process: this_process(), token: 0, until:500 });
            late.release(501, None);
            assert!(late.holds.is_empty(), "a hold whose seconds ran out is released");
            CloseHandle(job);
        }
    }

    #[test]
    fn a_log_destination_that_stalls_holds_up_only_its_own_thread() {
        let (open, gate) = std::sync::mpsc::channel::<()>();
        let written = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen = written.clone();
        // The destination takes no line until the gate is dropped, like a standard error that nobody reads.
        let sink = Sink::start("test-sink", Box::new(move |line: &str| {
            let _ = gate.recv();
            seen.lock().unwrap().push(line.to_string());
        }), 4).expect("start the sink");
        let began = std::time::Instant::now();
        for n in 0..100 {
            sink.push(&format!("line {}", n));
        }
        assert!(began.elapsed() < Duration::from_secs(1), "queueing a line never waits for its destination");
        assert!(sink.dropped.load(Ordering::SeqCst) >= 95, "what does not fit in the queue is dropped and counted: {}", sink.dropped.load(Ordering::SeqCst));
        let began = std::time::Instant::now();
        sink.finish(100);
        assert!(began.elapsed() < Duration::from_secs(2), "finishing does not wait for a destination that is stuck");
        drop(open);
        let limit = std::time::Instant::now() + Duration::from_secs(10);
        while !written.lock().unwrap().iter().any(|line| line.contains("log lines were not written")) {
            assert!(std::time::Instant::now() < limit, "the notice of the dropped lines is written once the destination takes lines: {:?}", written.lock().unwrap());
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(written.lock().unwrap()[0], "line 0", "the lines that were kept come first, in order");
    }

    #[test]
    fn a_log_destination_that_works_gets_every_line_before_the_end() {
        let written = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen = written.clone();
        let sink = Sink::start("test-sink", Box::new(move |line: &str| seen.lock().unwrap().push(line.to_string())), LOG_QUEUE).expect("start the sink");
        for n in 0..LOG_QUEUE {
            sink.push(&format!("line {}", n));
        }
        sink.finish(5000);
        assert_eq!(written.lock().unwrap().len(), LOG_QUEUE, "finishing waits for the queued lines");
        sink.push("too late");
        assert_eq!(written.lock().unwrap().len(), LOG_QUEUE, "a finished sink takes no more lines");
    }

    #[test]
    fn refusals_say_why() {
        assert_eq!(Refusal::OverCap.describe(21600.0), "the request is over the cap of 21600 seconds");
        assert_eq!(Refusal::OverCap.describe(0.5), "the request is over the cap of 0.5 seconds");
        assert!(Refusal::NotInJob.describe(1.0).contains("not in the job"));
    }

    #[test]
    fn only_a_channel_name_is_opened() {
        let good = format!("{}{}", PIPE_PREFIX, "0123456789abcdef0123456789abcdef");
        assert!(valid_channel(&good));
        for bad in [
            "", "C:\\Windows\\win.ini", "\\\\.\\pipe\\other", "\\\\.\\pipe\\process-tree-guard-", "\\\\.\\pipe\\process-tree-guard-0123",
            "\\\\.\\pipe\\process-tree-guard-0123456789ABCDEF0123456789ABCDEF", "\\\\.\\pipe\\process-tree-guard-0123456789abcdef0123456789abcde/",
            "\\\\.\\pipe\\process-tree-guard-0123456789abcdef0123456789abcdef0", "\\\\server\\pipe\\process-tree-guard-0123456789abcdef0123456789abcdef",
        ] {
            assert!(!valid_channel(bad), "{}", bad);
        }
    }

    fn scratch_folder(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ptg-{}-{}-{}", name, std::process::id(), tick()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn size_of(path: &Path) -> u64 {
        std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
    }

    fn numbered(n: usize) -> String {
        format!("PROCESS_TREE_GUARD_EXTENSION: line {:02} padded to a useful length", n)
    }

    #[test]
    fn the_log_is_bounded_with_one_rotation() {
        let dir = scratch_folder("log");
        let path = dir.join("extension.log");
        let mut file = AuditFile::new(path.clone(), 300);
        for n in 0..40 {
            file.append(&numbered(n));
        }
        let rotated = dir.join("extension.log.1");
        assert!(size_of(&path) > 0 && size_of(&path) <= 300, "{}", size_of(&path));
        assert!(size_of(&rotated) > 0 && size_of(&rotated) <= 300, "{}", size_of(&rotated));
        assert!(std::fs::read_to_string(&path).unwrap().contains("line 39"), "the newest line is in the file");
        assert!(!dir.join("extension.log.2").exists(), "one rotation only");
        assert!(!std::fs::read_to_string(&path).unwrap().contains("notice="), "a rotation that works says nothing");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Open `path` for reading the way a program that follows a file does, sharing reading and
    /// writing but not deleting, so a rename of the file is refused.
    fn follow(path: &Path) -> std::fs::File {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().read(true).share_mode(1 | 2).open(path).expect("follow the file")
    }

    #[test]
    fn a_file_that_cannot_be_renamed_keeps_its_earlier_lines() {
        let dir = scratch_folder("follow");
        let path = dir.join("extension.log");
        let mut file = AuditFile::new(path.clone(), 300);
        file.append(&numbered(0));
        let _follower = follow(&path);
        assert!(std::fs::rename(&path, dir.join("probe")).is_err(), "a follower that does not share delete stops a rename");
        for n in 1..6 {
            file.append(&numbered(n));
        }
        let rotated = dir.join("extension.log.1");
        let earlier = std::fs::read_to_string(&rotated).unwrap_or_default();
        let now = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(earlier.contains("line 00") && earlier.contains("line 03"), "the earlier lines were copied to PATH.1: {:?} / {:?}", earlier, now);
        assert!(now.contains("line 05") && !now.contains("line 00"), "the file holds the later lines: {:?}", now);
        assert!(size_of(&path) <= 300, "and is bounded: {}", size_of(&path));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_that_cannot_be_turned_over_at_all_grows_to_twice_its_limit_and_says_so() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = scratch_folder("stuck");
        let path = dir.join("extension.log");
        let rotated = dir.join("extension.log.1");
        std::fs::write(&rotated, "an earlier turn over\n").unwrap();
        let mut file = AuditFile::new(path.clone(), 300);
        file.append(&numbered(0));
        // The file is followed, and PATH.1 is held open with no sharing at all, so neither a
        // rename nor a copy can replace it.
        let follower = follow(&path);
        assert!(std::fs::rename(&path, dir.join("probe")).is_err(), "a follower that does not share delete stops a rename");
        let held = std::fs::OpenOptions::new().read(true).write(true).share_mode(0).open(&rotated).expect("hold PATH.1");
        for n in 1..30 {
            file.append(&numbered(n));
        }
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(text.contains("line 00"), "the first line is still there: {:?}", text);
        assert!(text.contains("could not be turned over"), "and the file says that it could not be turned over: {:?}", text);
        assert!(text.contains("takes no more lines"), "and that it takes no more lines: {:?}", text);
        assert!(!text.contains("line 29"), "the lines past twice the limit are not written: {:?}", text);
        assert!(size_of(&path) <= 2 * 300 + 400, "bounded at twice the limit and a notice: {}", size_of(&path));
        drop(held);
        drop(follower);
        std::thread::sleep(Duration::from_millis(TURN_OVER_RETRY_MS + 100));
        for n in 30..33 {
            file.append(&numbered(n));
        }
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(text.contains("line 32") && !text.contains("line 00"), "once it can be turned over it is: {:?}", text);
        assert!(std::fs::read_to_string(&rotated).unwrap_or_default().contains("line 00"), "with the earlier lines in PATH.1");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_release_ends_a_hold_and_costs_its_process_nothing_if_there_was_one() {
        let me = this_process();
        let key = (me.id, me.created);
        let mut late = State::new(1_000, 60.0);
        assert_eq!(late.grant(5, None, 20.0, this_process(), 0, None), Ok(()));
        assert_eq!(late.deadline(), 20_005);
        assert!(late.drop_hold(me.id, me.created, 0,false), "there was a hold to end");
        assert_eq!(late.deadline(), 1_000, "the deadline falls back to the run's own");
        assert!(!late.drop_hold(me.id, me.created, 0,false), "and a second release finds none");
        // The rate: the request of a release that ended a hold is given back, so the share
        // of a process that makes library calls is used by the calls and not the releases.
        let mut counted = State::new(1_000_000, 60.0);
        for n in 0..RATE_LIMIT as u64 - 1 {
            assert_eq!(counted.limiter.admit(key, (me.id, "w.exe"), n, &live), Admit::Allowed);
        }
        counted.holds.push(Hold { process: this_process(), token: 0, until:900_000 });
        assert_eq!(counted.limiter.admit(key, (me.id, "w.exe"), RATE_LIMIT as u64, &live), Admit::Allowed, "the release arrives and is counted");
        assert!(counted.drop_hold(me.id, me.created, 0,false));
        assert_eq!(counted.limiter.admit(key, (me.id, "w.exe"), RATE_LIMIT as u64 + 1, &live), Admit::Allowed, "it was given back, so one more request fits");
        assert_eq!(counted.limiter.admit(key, (me.id, "w.exe"), RATE_LIMIT as u64 + 2, &live), Admit::First, "and then the share is used up");
        // A release that arrives when the share is used up is let past it: the refusal it was counted as is taken back.
        let mut full = State::new(1_000_000, 60.0);
        for n in 0..RATE_LIMIT as u64 {
            assert_eq!(full.limiter.admit(key, (me.id, "w.exe"), n, &live), Admit::Allowed);
        }
        full.holds.push(Hold { process: this_process(), token: 0, until:900_000 });
        assert_eq!(full.limiter.admit(key, (me.id, "w.exe"), 100, &live), Admit::First, "the release arrives over its share");
        assert!(full.drop_hold(me.id, me.created, 0,true));
        assert_eq!(full.limiter.admit(key, (me.id, "w.exe"), 101, &live), Admit::First, "and the refusal it was counted as is taken back: the next one is the first again");
        // A release that found no hold stays counted.
        let mut empty = State::new(1_000_000, 60.0);
        for n in 0..RATE_LIMIT as u64 {
            assert_eq!(empty.limiter.admit(key, (me.id, "w.exe"), n, &live), Admit::Allowed);
        }
        assert!(!empty.drop_hold(me.id, me.created, 0,false));
        assert_eq!(empty.limiter.admit(key, (me.id, "w.exe"), RATE_LIMIT as u64, &live), Admit::First);
    }

    /// The number a summary line counts.
    fn counted_in(line: &str) -> Option<u32> {
        line.split("requests; ").nth(1)?.split(' ').next()?.parse().ok()
    }

    #[test]
    fn a_process_that_keeps_asking_is_summarised_for_each_window_while_it_asks() {
        // One process asks every 400 milliseconds for 45 seconds, so it is never idle for a window, and the
        // supervisor looks at the table every 100 milliseconds, as it does. Nothing here waits: the time is a number.
        let mut state = State::new(0, 60.0);
        let (key, who) = ((9, 1), (9, "steady.exe"));
        let (mut firsts, mut counted, mut summed) = (0u32, 0u32, 0u32);
        let mut windows = Vec::new();
        for now in (0..45_000u64).step_by(100) {
            if now % 400 == 0 {
                match state.limiter.admit(key, who, now, &live) {
                    Admit::First => firsts += 1,
                    Admit::Counted => counted += 1,
                    Admit::Allowed => {}
                    Admit::Full => panic!("the table is not full"),
                }
            }
            for line in state.notices(now, 0, false) {
                assert!(line.contains(" pid=9 image=\"steady.exe\"") && line.contains("within 10 seconds of the first"), "{}", line);
                windows.push((now, counted_in(&line).expect("a count in the line")));
                summed += windows.last().unwrap().1;
            }
        }
        assert!(windows.len() >= 3, "a line for each window that ran its course while the process was still asking: {:?}", windows);
        assert!(windows.iter().all(|(_, count)| (1..=25).contains(count)), "a window of 10 seconds holds at most 25 requests of 400 milliseconds: {:?}", windows);
        assert!(windows.windows(2).all(|pair| pair[1].0 - pair[0].0 >= RATE_WINDOW_MS), "one line for each window, a window apart: {:?}", windows);
        assert!(firsts as usize >= windows.len(), "and the first refusal of each window is a line of its own: {} firsts", firsts);
        for line in state.notices(45_000, 0, true) {
            summed += counted_in(&line).expect("a count in the line");
        }
        assert_eq!(summed, counted, "every refusal that was counted is in a line, none twice");
    }

    #[test]
    fn a_reply_out_of_range_is_not_understood() {
        let granted = |seconds: f64, until: u64| encode_reply(&Reply::Granted { seconds, until_unix_ms: until, held: 0 });
        let refused = |cap: f64| encode_reply(&Reply::Refused { refusal: Refusal::OverCap, cap });
        assert!(decode_reply(&granted(5.0, LATEST_UNTIL_MS)).is_some() && decode_reply(&granted(0.0, 0)).is_some() && decode_reply(&granted(86400.0, 1)).is_some());
        assert!(decode_reply(&refused(0.0)).is_some() && decode_reply(&refused(86400.0)).is_some());
        for until in [LATEST_UNTIL_MS + 1, u64::MAX] {
            assert!(decode_reply(&granted(5.0, until)).is_none(), "until {}", until);
        }
        for seconds in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, 86401.0, 1e300] {
            assert!(decode_reply(&granted(seconds, 1)).is_none() && decode_reply(&refused(seconds)).is_none(), "seconds {}", seconds);
        }
        // What the sum would have done with such a time.
        assert!(UNIX_EPOCH.checked_add(Duration::from_millis(u64::MAX)).is_none());
        assert!(UNIX_EPOCH.checked_add(Duration::from_millis(LATEST_UNTIL_MS)).is_some());
    }

    /// The shared state of a run with nothing serving: enough to decide a request.
    fn shared_run(job: Handle) -> Shared {
        Shared {
            state: Mutex::new(State::new(tick() + 600_000, 3600.0)), log: Log { sinks: Vec::new(), blocked: Arc::new(AtomicBool::new(false)), only: None }, job: job as usize, wake: 0,
            stopping: AtomicBool::new(false), serving: AtomicUsize::new(0),
        }
    }

    #[test]
    fn a_client_that_started_after_it_connected_or_has_exited_is_not_verified() {
        unsafe {
            let job = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
            assert!(!job.is_null());
            let shared = shared_run(job);
            let request = Message::Bytes(encode_request(Target::Caller, 0, 5.0).to_vec());
            let arrival = |client: Process| Arrival { id: client.id, image: "client.exe".into(), client: Some(client), in_job: true, shut: None, gone: false };
            let unverified = |reply: &Reply| matches!(reply, Reply::Refused { refusal: Refusal::Unverified, .. });
            let created = this_process().created;
            // Connected before the process began: what is there now took the identifier of the one that connected.
            let (reply, line) = evaluate(&shared, arrival(this_process()), created - 1, &request);
            assert!(unverified(&reply) && matches!(line, Line::Refused(_)), "a process created after the connection is refused");
            assert!(shared.lock().holds.is_empty(), "and holds nothing");
            // The client connected, wrote its request and has exited: its record is still open, and it is not alive.
            let mut child = std::process::Command::new("ping.exe").args(["-n", "60", "127.0.0.1"])
                .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().expect("start ping.exe");
            let gone = Process::open(child.id()).expect("open the client");
            child.kill().expect("end the client");
            child.wait().expect("reap the client");
            let (reply, line) = evaluate(&shared, arrival(gone), filetime_now(), &request);
            assert!(unverified(&reply) && matches!(line, Line::Refused(_)), "a client that has exited before the reply is refused");
            assert!(shared.lock().holds.is_empty(), "and holds nothing");
            // A process that is alive, in the job and older than the connection, but whose identifier is not the
            // one that connected: the end of the pipe the client connected with is closed. It is what a process
            // that took the identifier of a client that wrote and exited looks like.
            let (reply, line) = evaluate(&shared, Arrival { gone: true, ..arrival(this_process()) }, created + 1, &request);
            assert!(unverified(&reply) && matches!(line, Line::Refused(_)), "a client that has closed its end is refused, whoever now has its identifier");
            assert!(shared.lock().holds.is_empty(), "and holds nothing");
            // The control: the same request from a client that began before the connection and is alive is granted.
            let (reply, line) = evaluate(&shared, arrival(this_process()), created + 1, &request);
            assert!(matches!(reply, Reply::Granted { .. }) && matches!(line, Line::Granted(..)));
            assert_eq!(shared.lock().holds.len(), 1);
            CloseHandle(job);
        }
    }

    #[test]
    fn a_released_line_names_its_decision() {
        let line = released_line(1_700_000_000_000, 42, "host.exe", "the hold ended with the library call that asked for it");
        assert_eq!(line, "PROCESS_TREE_GUARD_EXTENSION: time=2023-11-14T22:13:20.000Z pid=42 image=\"host.exe\" requested=0 granted=0 decision=released reason=\"the hold ended with the library call that asked for it\"");
        assert_eq!(notice_line(0, "a\nb"), "PROCESS_TREE_GUARD_EXTENSION: time=1970-01-01T00:00:00.000Z notice=\"a\\u{a}b\"");
    }

    /// The notices an `AuditFile` sends to standard error, as a test sees them.
    fn alerts() -> (Arc<Mutex<Vec<String>>>, Box<dyn Fn(&str) + Send>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let copy = seen.clone();
        (seen, Box::new(move |text: &str| copy.lock().unwrap().push(text.to_string())))
    }

    /// Open `path` for reading the way a reader does that denies write sharing: .NET's
    /// `File.OpenRead` and `FileStream` for reading share reading only.
    fn deny_writers(path: &Path) -> std::io::Result<std::fs::File> {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().read(true).share_mode(1).open(path)
    }

    fn contents(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }

    #[test]
    fn a_reader_that_denies_write_sharing_cannot_open_the_file_during_a_run() {
        const SHARING_VIOLATION: i32 = 32;
        let dir = scratch_folder("deny");
        let path = dir.join("extension.log");
        let mut file = AuditFile::new(path.clone(), 300);
        assert_eq!(deny_writers(&path).err().and_then(|error| error.raw_os_error()), Some(SHARING_VIOLATION), "the file is held open for appending, so a reader that denies writers is refused");
        file.append(&numbered(0));
        assert!(follow(&path).metadata().is_ok(), "a reader that allows writers can read it");
        assert!(contents(&path).contains("line 00"), "and so can the plain read of a file");
        for n in 1..10 {
            file.append(&numbered(n));
        }
        assert!(dir.join("extension.log.1").exists(), "the file was turned over");
        assert_eq!(deny_writers(&path).err().and_then(|error| error.raw_os_error()), Some(SHARING_VIOLATION), "and the new file is held too");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lines_that_cannot_be_written_are_held_told_of_and_written_late_in_order() {
        let dir = scratch_folder("blind");
        let path = dir.join("extension.log");
        std::fs::write(&path, "").unwrap();
        // A reader that denies writers was there first: the guard cannot append.
        let reader = deny_writers(&path).expect("read the file first");
        let (seen, alert) = alerts();
        let mut file = AuditFile::new(path.clone(), 100_000).alerting(alert);
        for n in 0..3 {
            file.append(&numbered(n));
        }
        assert_eq!(contents(&path), "", "nothing could be written");
        let told = seen.lock().unwrap().clone();
        assert!(told.len() == 1 && told[0].starts_with("PROCESS_TREE_GUARD_EXTENSION: ") && told[0].contains("cannot be written"), "standard error is told at once: {:?}", told);
        file.append(&numbered(3));
        assert_eq!(seen.lock().unwrap().len(), 1, "once for the failure, not for every line");
        drop(reader);
        file.flush();
        let text = contents(&path);
        let at = |what: &str| text.find(what).unwrap_or(usize::MAX);
        assert!(at("line 00") < at("line 01") && at("line 01") < at("line 02") && at("line 02") < at("line 03"), "the lines are written in order: {:?}", text);
        assert!(at("line 03") < at("4 lines were written late and 0 were not written"), "and the file says how many were late, after them: {:?}", text);
        let told = seen.lock().unwrap().clone();
        assert!(told.len() == 2 && told[1].contains("4 lines were written late and 0 were not written"), "and so does standard error: {:?}", told);
        file.flush();
        assert_eq!(contents(&path), text, "once written, nothing is written twice");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lines_past_the_limit_of_those_held_are_counted_and_a_run_that_ends_blind_says_so() {
        let dir = scratch_folder("overflow");
        let path = dir.join("extension.log");
        std::fs::write(&path, "").unwrap();
        let reader = deny_writers(&path).expect("read the file first");
        let (seen, alert) = alerts();
        let mut file = AuditFile::new(path.clone(), 1 << 20).alerting(alert);
        for n in 0..HELD_LINES + 5 {
            file.append(&numbered(n % 90));
        }
        assert_eq!((file.held.len(), file.lost), (HELD_LINES, 5), "what does not fit is counted");
        file.close();
        let told = seen.lock().unwrap().clone();
        assert!(told.last().map_or(false, |last| last.contains(&format!("{} log lines were not written", HELD_LINES + 5))), "the end of the run says how many the file never got: {:?}", told);
        drop(reader);
        file.flush();
        let text = contents(&path);
        assert_eq!(text.lines().count(), HELD_LINES + 1, "the held lines and a notice: {}", text.lines().count());
        assert!(text.lines().last().unwrap_or("").contains(&format!("{} lines were written late and 5 were not written", HELD_LINES)), "{:?}", text.lines().last());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_file_copy_of_the_log_is_tried_again_without_a_new_line() {
        let dir = scratch_folder("retry");
        let path = dir.join("extension.log");
        std::fs::write(&path, "").unwrap();
        let reader = deny_writers(&path).expect("read the file first");
        let log = Log::start(Some(path.clone()), LOG_LIMIT).expect("start the log");
        log.push("PROCESS_TREE_GUARD_EXTENSION: one");
        log.push("PROCESS_TREE_GUARD_EXTENSION: two");
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(contents(&path), "", "the reader keeps the file from taking lines");
        drop(reader);
        let limit = std::time::Instant::now() + Duration::from_secs(10);
        while !contents(&path).contains(": two") {
            assert!(std::time::Instant::now() < limit, "the lines are written when the reader has gone, with no further line to wake the file: {:?}", contents(&path));
            std::thread::sleep(Duration::from_millis(50));
        }
        log.finish(2000);
        let text = contents(&path);
        assert!(text.find(": one").unwrap_or(usize::MAX) < text.find(": two").unwrap_or(0), "in order: {:?}", text);
        assert!(text.contains("2 lines were written late"), "with the notice: {:?}", text);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The clock, read here and not through `filetime_now`, so a test of that function's use cannot share its fault.
    fn clock() -> u64 {
        let mut time = 0u64;
        unsafe { GetSystemTimePreciseAsFileTime(&mut time) };
        time
    }

    #[test]
    fn the_time_a_client_connected_is_read_from_the_clock_when_the_server_learns_of_it() {
        let open_client = |name: &str| std::fs::OpenOptions::new().read(true).write(true).open(name).expect("connect to the pipe");
        unsafe {
            for client_first in [false, true] {
                let name = format!("{}test-{}-{}-{}", PIPE_PREFIX, std::process::id(), tick(), client_first);
                let pipe = CreateNamedPipeW(wide(&name).as_ptr(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS, 1, 512, 512, 0, std::ptr::null_mut());
                assert!(pipe != INVALID_HANDLE, "make the pipe");
                let event = CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null());
                let stop = CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null());
                let (client, stamp, before, after);
                if client_first {
                    // The client is there before the server calls: the server learns of it at once, which is later than the connect.
                    before = clock();
                    client = open_client(&name);
                    stamp = accept(pipe, event, stop);
                    after = clock();
                } else {
                    let (p, e, s) = (pipe as usize, event as usize, stop as usize);
                    let server = std::thread::spawn(move || accept(p as Handle, e as Handle, s as Handle));
                    std::thread::sleep(Duration::from_millis(150));
                    before = clock();
                    client = open_client(&name);
                    stamp = server.join().expect("the server thread");
                    after = clock();
                }
                let stamp = stamp.expect("a client connected");
                assert!(stamp >= before && stamp <= after, "client first {}: the stamp {} lies between the moment before the client connected ({}) and the moment the server returned ({})", client_first, stamp, before, after);
                // A process that began before the stamp passes the check made with it, and one that began after does not.
                let me = this_process();
                assert!(me.created <= stamp && me.started_before(stamp), "this process began before the client connected");
                assert!(!me.started_before(me.created - 1), "and one that began after the stamp does not pass");
                drop(client);
                CloseHandle(pipe);
                CloseHandle(event);
                CloseHandle(stop);
            }
            // With no client, the wait ends when it is told to stop, and there is no stamp.
            let name = format!("{}test-{}-{}-stop", PIPE_PREFIX, std::process::id(), tick());
            let pipe = CreateNamedPipeW(wide(&name).as_ptr(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS, 1, 512, 512, 0, std::ptr::null_mut());
            let event = CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null());
            let stop = CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null());
            let (p, e, s) = (pipe as usize, event as usize, stop as usize);
            let server = std::thread::spawn(move || accept(p as Handle, e as Handle, s as Handle));
            std::thread::sleep(Duration::from_millis(100));
            SetEvent(stop);
            assert_eq!(server.join().expect("the server thread"), None);
            CloseHandle(pipe);
            CloseHandle(event);
            CloseHandle(stop);
        }
    }

    #[test]
    fn overlapping_calls_of_one_process_each_have_a_hold_of_their_own() {
        let me = this_process();
        let mut state = State::new(1_000, 3600.0);
        // Two calls of the library from threads of one process: A asks for 60 seconds, B for 5.
        assert_eq!(state.grant(5, None, 60.0, this_process(), 1, None), Ok(()));
        assert_eq!(state.grant(6, None, 5.0, this_process(), 2, None), Ok(()));
        assert_eq!(state.holds.len(), 2, "B's grant did not replace A's hold");
        assert_eq!(state.deadline(), 60_005, "the deadline is the latest of the holds");
        assert!(state.drop_hold(me.id, me.created, 2, false), "B returns and ends its own hold");
        assert_eq!(state.deadline(), 60_005, "A's hold stands");
        assert!(!state.drop_hold(me.id, me.created, 2, false), "B has no second hold to end");
        assert_eq!(state.grant(7, None, 90.0, this_process(), 1, None), Ok(()));
        assert_eq!(state.holds.len(), 1, "a call that renews replaces its own hold");
        assert_eq!(state.deadline(), 90_007);
        // The hold of the process itself (token 0, what `extend` asks for) is another hold again.
        assert_eq!(state.grant(8, None, 20.0, this_process(), 0, None), Ok(()));
        assert!(state.drop_hold(me.id, me.created, 1, false), "A returns");
        assert_eq!(state.deadline(), 20_008, "and the process's own hold stands");
        assert!(state.drop_hold(me.id, me.created, 0, false));
        assert_eq!(state.deadline(), 1_000);
    }

    #[test]
    fn a_token_is_next_to_none_that_this_process_has_used() {
        let (first, second) = (next_token(), next_token());
        assert!(first != 0 && second != 0 && first != second, "{} {}", first, second);
    }

    #[test]
    fn a_process_that_renews_in_time_keeps_the_deadline_a_fixed_time_ahead_and_one_that_is_late_cannot() {
        // Ticks are milliseconds: the run's own deadline is at 2 000 and the cap is 3 seconds.
        let mut state = State::new(2_000, 3.0);
        // A process renews before each hold ends. Each renewal is within the cap, so at every moment the deadline is
        // 3 seconds ahead of the latest one, and the run goes on for as long as the renewals do.
        for now in (1_000..=60_000).step_by(2_000) {
            assert_eq!(state.grant(now, None, 3.0, this_process(), 0, None), Ok(()), "renewal at {}", now);
            assert_eq!(state.deadline(), now + 3_000, "renewal at {}", now);
            assert!(!state.expire(now + 1_000, None), "the run is not over at {}", now + 1_000);
        }
        // A request over the cap moves nothing, however well the process stands.
        assert_eq!(state.grant(61_000, None, 3.5, this_process(), 0, None), Err(Refusal::OverCap.into()));
        assert_eq!(state.deadline(), 62_000);
        // Once the hold has run out the run is over, and a request that comes then moves nothing.
        assert!(state.expire(62_000, None));
        assert_eq!(state.grant(62_000, None, 3.0, this_process(), 0, None), Err(Refusal::Ended.into()));
        assert!(state.passed, "the run has ended and cannot go on");
    }

    #[test]
    fn only_the_first_instance_of_the_channel_is_made_with_the_first_instance_flag() {
        // The flag makes the call fail when the name already has an instance, whoever made it. It is on the first
        // instance and on no other, since the others are made on the name the first has made.
        assert_ne!(instance_open_mode(0) & FILE_FLAG_FIRST_PIPE_INSTANCE, 0, "the first instance");
        for index in 1..INSTANCES {
            assert_eq!(instance_open_mode(index) & FILE_FLAG_FIRST_PIPE_INSTANCE, 0, "instance {}", index);
        }
        for index in 0..INSTANCES {
            assert_eq!(instance_open_mode(index) & PIPE_ACCESS_DUPLEX, PIPE_ACCESS_DUPLEX, "instance {}", index);
            assert_ne!(instance_open_mode(index) & FILE_FLAG_OVERLAPPED, 0, "instance {}", index);
        }
        // The call that makes the instances takes its mode from the function and from nothing else.
        let call = format!("{}({}),", "CreateNamedPipeW(wide_name.as_ptr(), instance_open_mode", "index");
        assert_eq!(include_str!("extend.rs").matches(call.as_str()).count(), 1, "create_pipes passes the mode of the function");
    }

    #[test]
    fn the_channel_cannot_be_made_over_a_pipe_of_the_same_name_that_somebody_made_first() {
        // Somebody makes the name first, with the settings the guard uses so that nothing else differs. The guard
        // makes all four instances the pipe allows, so a name that already has one cannot be served.
        let name = format!("{}test-{}-{}-squat", PIPE_PREFIX, std::process::id(), tick());
        let squatter = unsafe {
            CreateNamedPipeW(wide(&name).as_ptr(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, CHANNEL_PIPE_MODE, INSTANCES, OUT_BUFFER, 512, 0, std::ptr::null_mut())
        };
        assert!(squatter != INVALID_HANDLE, "the test makes its pipe");
        assert!(create_pipes(&name).is_err(), "a name that is not new is refused");
        unsafe { CloseHandle(squatter) };
        // A new name is served, with all the instances.
        let fresh = format!("{}test-{}-{}-fresh", PIPE_PREFIX, std::process::id(), tick());
        let pipes = create_pipes(&fresh).expect("a new name is served");
        assert_eq!(pipes.len(), INSTANCES as usize);
        for pipe in pipes {
            unsafe { CloseHandle(pipe) };
        }
    }

    #[test]
    fn a_file_that_cannot_be_turned_over_stops_the_run_granting_before_it_is_full() {
        let dir = scratch_folder("blocked");
        let path = dir.join("extension.log");
        let rotated = dir.join("extension.log.1");
        std::fs::write(&rotated, "an earlier turn over\n").unwrap();
        let mut file = AuditFile::new(path.clone(), 600);
        assert!(!file.blocked.load(Ordering::SeqCst));
        // A program in the job reads PATH.1 and shares reading only (read access is all it needs): neither the rename
        // nor the copy can replace the file, whatever the folder allows.
        let reader = deny_writers(&rotated).expect("read PATH.1");
        let mut told = 0;
        for n in 0..60 {
            file.append(&numbered(n));
            if file.blocked.load(Ordering::SeqCst) {
                told = n;
                break;
            }
        }
        assert!(told > 0, "the file was blocked before the lines ran out");
        let size = size_of(&path);
        assert!(size + file.reserve > 2 * 600 && size <= 2 * 600, "blocked within the reserve of twice the limit, and not past it: {}", size);
        assert!(contents(&path).contains("could not be turned over") && !contents(&path).contains("takes no more lines until it can"), "blocked with room left, so every line so far is in the file: {:?}", contents(&path));
        assert!(contents(&path).contains(&format!("line {:02}", told)), "the line that blocked it is in the file");
        // Nobody asks it to turn over, and nothing is written, until the reader lets go and a turn over works: the retry needs no line.
        file.flush();
        assert!(file.blocked.load(Ordering::SeqCst), "still blocked while the reader holds PATH.1");
        drop(reader);
        std::thread::sleep(Duration::from_millis(TURN_OVER_RETRY_MS + 100));
        file.flush();
        assert!(!file.blocked.load(Ordering::SeqCst), "once a turn over works the file is relied on again");
        assert!(contents(&rotated).contains(&format!("line {:02}", told)) && size_of(&path) == 0, "with the lines in PATH.1: {:?}", contents(&rotated));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_that_cannot_be_written_stops_the_run_granting_until_it_can() {
        let dir = scratch_folder("noroom");
        let path = dir.join("extension.log");
        std::fs::write(&path, "").unwrap();
        let reader = deny_writers(&path).expect("read the file first");
        let mut file = AuditFile::new(path.clone(), 100_000);
        file.append(&numbered(0));
        assert!(file.blocked.load(Ordering::SeqCst), "a line that cannot be written is a grant that is not in the record");
        drop(reader);
        file.flush();
        assert!(!file.blocked.load(Ordering::SeqCst), "and it is relied on again once it takes lines");
        assert!(contents(&path).contains("line 00"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_that_is_past_its_limit_at_the_start_and_cannot_be_turned_over_stops_the_run_before_it_starts() {
        let dir = scratch_folder("settle");
        let path = dir.join("extension.log");
        let rotated = dir.join("extension.log.1");
        std::fs::write(&rotated, "an earlier turn over\n").unwrap();
        std::fs::write(&path, "x".repeat(1190)).unwrap();
        let reader = deny_writers(&rotated).expect("read PATH.1");
        let mut file = AuditFile::new(path.clone(), 600);
        assert!(!file.settle(), "1190 bytes of a limit of 600 with PATH.1 held: no room is left");
        drop(reader);
        let mut file = AuditFile::new(path.clone(), 600);
        assert!(file.settle(), "the same file with PATH.1 free is turned over before the run starts");
        assert_eq!(size_of(&path), 0);
        assert_eq!(size_of(&rotated), 1190);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_blocked_file_refuses_every_request_that_would_move_the_deadline() {
        unsafe {
            let job = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
            assert!(!job.is_null());
            let shared = shared_run(job);
            let request = Message::Bytes(encode_request(Target::Caller, 0, 5.0).to_vec());
            let arrival = || Arrival { id: std::process::id(), image: "client.exe".into(), client: Some(this_process()), in_job: true, shut: None, gone: false };
            let created = this_process().created;
            shared.log.blocked.store(true, Ordering::SeqCst);
            let (reply, line) = evaluate(&shared, arrival(), created + 1, &request);
            assert!(matches!(reply, Reply::Refused { refusal: Refusal::AuditBlocked, .. }) && matches!(line, Line::Refused(_)));
            assert!(shared.lock().holds.is_empty(), "and holds nothing");
            shared.log.blocked.store(false, Ordering::SeqCst);
            let (reply, _) = evaluate(&shared, arrival(), created + 1, &request);
            assert!(matches!(reply, Reply::Granted { .. }), "granted again once the file can be relied on");
            // A release only brings the deadline in, so it is let through while the file is blocked.
            shared.log.blocked.store(true, Ordering::SeqCst);
            let release = Message::Bytes(encode_request(Target::Release, 0, 0.0).to_vec());
            let (reply, line) = evaluate(&shared, arrival(), created + 1, &release);
            assert!(matches!(reply, Reply::Granted { .. }) && matches!(line, Line::Released(_)));
            assert!(shared.lock().holds.is_empty());
            CloseHandle(job);
        }
        assert!(Refusal::AuditBlocked.describe(1.0).contains("audit file"));
    }

    #[test]
    fn a_client_that_has_closed_its_end_of_the_pipe_is_gone() {
        unsafe {
            let name = format!("{}test-{}-{}-gone", PIPE_PREFIX, std::process::id(), tick());
            let pipe = CreateNamedPipeW(wide(&name).as_ptr(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS, 1, 512, 512, 0, std::ptr::null_mut());
            assert!(pipe != INVALID_HANDLE, "make the pipe");
            let event = CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null());
            let stop = CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null());
            let client = std::fs::OpenOptions::new().read(true).write(true).open(&name).expect("connect to the pipe");
            assert!(accept(pipe, event, stop).is_some());
            assert!(!client_gone(pipe), "a client that waits for its reply, with its end open, is there");
            drop(client);
            assert!(client_gone(pipe), "one that has closed its end is gone");
            CloseHandle(pipe);
            CloseHandle(event);
            CloseHandle(stop);
        }
    }
}
