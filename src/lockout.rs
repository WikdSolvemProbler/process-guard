// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! The lockout of the password exception: the third wrong password for an account within six hours starts a lockout of six hours.
//!
//! A run over the cap asks for the password of the account the guard runs as (`auth.rs`). Each run has three attempts. This module
//! keeps the count across runs, in a record of wrong passwords that a program running as the account, without administrator rights,
//! can only add to. While the account is locked no prompt is shown, by either method, and the run is refused.
//!
//! The rule is a function of the times in the record and the time now (`lockout`). A password that the system refused (not empty,
//! for the guard's own account), one whose check the system did not answer in time, one whose check was cut short because the
//! starter exited, and at the console prompt one answered with a code the system gives only for a correct password, are recorded
//! (see `auth.rs`). A correct password, a cancel, an empty answer, a prompt left unanswered and an account that does not match are
//! not. Nothing that is added to the record can shorten or end a lockout: a correct password adds no failure (the lock only has
//! room allocated with newlines, which the reading ignores), and a record can only add to a count.
//! A record dated ahead of the system clock by more than five minutes is ignored; one dated ahead by less is read as now, so that no
//! record locks for longer than six hours from now. The times kept while the record is read are exactly the times the rule reads,
//! taken against one reading of the clock, so a time that the rule ignores never takes the place of a real failure.
//!
//! The record is a file of one account, named for its security identifier and ending in `.lockout`, in a folder under the folder of
//! the programs' data of the machine. Its integrity is the access control of the file system, not encryption: any key the guard
//! held would be in the reach of the account.
//! A one-time elevated step (`process-tree-guard create-lockout-record`) makes the folder and the record, owned by the
//! Administrators group, with a protected access list that gives the account the right to read the record and to append to it
//! (`FILE_APPEND_DATA` without `FILE_WRITE_DATA`) and nothing more, and the other accounts nothing. The owner rights entry takes
//! away what an owner has by being the owner, so an owner that is the account itself could not change the list either. The guard
//! checks the list on every run over the cap: it builds the token of a process of the account without administrator rights,
//! asks the system what that token is granted on the folder of the programs' data, the folder and the record, and refuses the
//! run unless the account can read and append the record and do nothing else with it, and unless the list gives nothing to any
//! account or group but the system, the Administrators group, the account and the owner rights entry. It refuses an account whose
//! token holds a privilege that lets a program of the account act as the system (`DANGEROUS_PRIVILEGES`), unless the guard is
//! elevated. It also requires that the record, its
//! folder, the folder of the programs' data and every folder above that are owned by the Administrators group, the system or the
//! installer of the system, and are no links: a process without administrator rights can make a tree with exactly the right
//! list, and keep a handle it opened before the list was tightened, but it cannot make one of those the owner. A record that is
//! missing, that cannot be opened, or that allows more than that, refuses every run over the cap, with a message that names the
//! setup step and the account to run it for. So does a record, or its folder, that the volume keeps compressed: the room for the
//! next record cannot be allocated in a compressed file (see `FileRecord::reserve`), and the step makes both uncompressed.
//!
//! The folder of the programs' data is not taken from the known folder interface or an environment variable: they are read from
//! the account's own environment and profile, which a process of the account can redirect. It is the registry value of the
//! machine, which must be on the system drive. Nor is anything opened through a drive letter, which is resolved through the device
//! map of the logon session, where a process of the account can add or change letters (`subst`, `DefineDosDevice`): the system
//! volume is found as `NtCreateFile` finds `\SystemRoot`, a name in the root of the object manager, and every object the check
//! relies on is opened by its name from that root (`\Device\HarddiskVolume3\ProgramData\...`), which the device map does not reach.
//! The decision is made on the object that is used: the record is opened once, and the owner, the access list, the links and the
//! file it is (volume and index) are judged on that handle, and its final name must be the name it was asked for (see `SECURITY.md`).
//!
//! The record is locked for the run from the last look at it to the end of the attempt (`Record::lock`), so that a program of the
//! account that holds a range of it locked cannot make a wrong password uncounted, and two runs cannot both pass the look at two
//! wrong passwords and both guess. Under the same lock the room the next record will take is allocated before the logon
//! (`FileRecord::reserve`), so that a program of the account cannot make the append fail by filling the volume while the logon
//! goes on. All reads of the record in one run share `READ_LIMIT`.
//!
//! Nothing here can be switched, by an argument, a variable of the environment or a file, to read another record or another clock.
//! The times and the location are behind the `Record` trait and the `Place`, which the unit tests build for their own scratch files.

use crate::extend::{current_user_sid, sid_text};
use crate::sys::*;
use std::ffi::c_void;
use std::time::{Duration, Instant};

/// 100 nanosecond units per second, minute and hour: the unit of a file time.
const SECOND: u64 = 10_000_000;
const MINUTE: u64 = 60 * SECOND;
const HOUR: u64 = 3600 * SECOND;

/// The window of the rule and the length of a lockout: six hours.
pub(crate) const WINDOW: u64 = 6 * HOUR;

/// Wrong passwords within the window that start a lockout.
pub(crate) const THRESHOLD: usize = 3;

/// A record dated further ahead than this is ignored; one within it is read as now.
pub(crate) const SKEW: u64 = 5 * MINUTE;

/// The bytes of one record.
const RECORD_BYTES: usize = 20;

/// The record is read whole, in blocks of this many bytes, and only the times that can matter are kept (see `Scan`): so a record
/// of any size is read in constant memory, and nothing appended to it can push a real failure out of what is read.
const BLOCK: usize = 1 << 16;

/// The most time all the readings of the record in one run take together (see `Budget`). A record that cannot be read in that
/// time (it has been made to hold many gigabytes) refuses the run, as a record that cannot be read does; it is not read from its end.
const READ_LIMIT: Duration = Duration::from_secs(10);

/// How long the lock of the record is tried for before the run is refused, and how often.
const LOCK_WAIT: Duration = Duration::from_secs(2);
const LOCK_STEP: Duration = Duration::from_millis(50);

/// The room the volume of the record must have for the caller for a wrong password to be recorded.
const ROOM: u128 = 65_536;

/// A record shorter than this is made this long before a wrong password is guessed (see `FileRecord::reserve`): the size of the
/// smallest unit a volume allocates to a file that is not kept in its own table.
const FLOOR: u64 = 4096;

/// The most failure times kept while reading. The newest of them hold the latest lockout whatever was dropped: a time after the
/// latest start of a lockout has fewer than three others within six hours before it, so at most a handful of the newest are not
/// in that window, and the rest lie in the window of the latest start.
const KEPT: usize = 4096;

/// The folder of the records, in the folder of the programs' data, and the ending of the file name of a record.
const FOLDER_NAME: &str = "ProcessTreeGuard";
const RECORD_ENDING: &str = ".lockout";

/// The account the step is named for in a refusal: the account of this run, in the form the step takes (`DOMAIN\user`, in quotation
/// marks when it has a space in it), or the word ACCOUNT when the name cannot be read. Without an account the step makes the record
/// of the account of the elevated token, and the accounts the lockout protects are not the accounts that elevate.
fn step_account() -> String {
    crate::auth::own_account_name().map_or_else(|| "ACCOUNT".to_string(), |name| quoted(&name))
}

/// `name` as an argument of the command line: in quotation marks when it has a space in it.
fn quoted(name: &str) -> String {
    if name.contains(char::is_whitespace) { format!("\"{}\"", name) } else { name.to_string() }
}

/// The step that makes the record, named in every refusal that it can mend, for the account that is refused.
fn setup_step() -> String {
    setup_step_for(&step_account())
}

/// The step for `account`, which is how the step itself names the account it was run for.
fn setup_step_for(account: &str) -> String {
    format!("an administrator must run: process-tree-guard create-lockout-record {}", account)
}

/// Said at the end of the setup step, so that the person who runs it is told what the record cannot do for an account in the
/// Administrators group, which is the usual home account.
const NOT_PROTECTED: &str = " An account in the Administrators group is not protected from its own elevated programs; see SECURITY.md.";

/// What is done about a folder or a record that someone else owns: it is not taken over.
fn remove_and_setup() -> String {
    remove_and_setup_for(&step_account())
}

fn remove_and_setup_for(account: &str) -> String {
    format!("an administrator must remove it as described in the README and then run: process-tree-guard create-lockout-record {}", account)
}

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_HANDLE_EOF: u32 = 38;
const ERROR_SHARING_VIOLATION: u32 = 32;
const ERROR_LOCK_VIOLATION: u32 = 33;
const ERROR_BAD_PATHNAME: u32 = 161;

/// What a read or an append of the record says when another program holds a range of it locked. Only a read, an append or a lock
/// can run into a lock; opening the file cannot.
const LOCKED_RANGE: &str = "the lockout record is locked by another program or another run; wait for the run to end, or end that program, and run again";

/// What the lock of the record says when it could not be taken in time: another program holds a range of it locked, or another run
/// of this account is between its look at the record and the end of its attempt.
const LOCK_BUSY: &str = "the lockout record is locked by another program or another run; try again";

/// What the lock says when the volume has no room for a record: a wrong password could not be counted, so none is let be tried.
const NO_ROOM: &str = "the volume of the lockout record has no room for a record, so a wrong password could not be counted";

/// What the run is refused with when the volume would not allocate the room for the next record to the record (or the file system
/// reports no allocated size to count on): a wrong password could not be counted, so none is let be tried. A record that the volume
/// keeps compressed is the usual cause, and is refused before this (see `judge_record`); a record that is not compressed and still
/// could not be given the room is made again.
fn not_reserved() -> String {
    format!("the lockout record could not be given the room for the next record (the volume may keep it compressed), so a wrong password \
        could not be counted; {}", remove_and_setup())
}

/// What a record, or its folder, that the volume keeps compressed is refused with: the volume allocates a compressed file in units
/// that leave no room for the next record, so a wrong password could not be counted. The step clears the compression of the folder
/// and the record it makes or sets right, so it also mends one that was compressed since (`compact /u` does the same by hand).
fn compressed() -> String {
    format!("the lockout record (or its folder) is compressed, so the room for the next record cannot be allocated; {}, which makes it \
        uncompressed (or run compact /u on it, then the step)", setup_step())
}

// ------------------------------------------------------------------------- the rule

/// One record: a newline, `F `, sixteen lower case hexadecimal digits of the universal time as a file time, a newline. The newline
/// in front ends a torn record that came before it; both are single bytes, so one write of `RECORD_BYTES` bytes is one record.
pub(crate) fn encode(filetime: u64) -> [u8; RECORD_BYTES] {
    let text = format!("\nF {:016x}\n", filetime);
    let mut out = [0u8; RECORD_BYTES];
    out.copy_from_slice(text.as_bytes());
    out
}

/// The failure times in `bytes`: every line that is exactly `F ` and sixteen lower case hexadecimal digits. Anything else is
/// ignored, a torn record and garbage included.
pub(crate) fn parse(bytes: &[u8]) -> Vec<u64> {
    bytes.split(|b| *b == b'\n').filter_map(|line| {
        let digits = line.strip_prefix(b"F ")?;
        if digits.len() != 16 || !digits.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return None;
        }
        u64::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()
    }).collect()
}

/// The failure times of a record, read in blocks as it is: a line is a whole record only if it is no longer than one record, so a
/// line that is longer is skipped to its end, and a block boundary can fall anywhere. Only the times that can matter at `now` are
/// kept, which are those after `now - 2 * WINDOW` (a failure that starts a lockout in force lies less than `WINDOW` back, and the
/// failures that make it three lie `WINDOW` before that) and not later than `now + SKEW`: the times that can matter to the rule at
/// that `now`, and none that it ignores. A time that the rule ignores is never kept in place of a real one, and the scan and the rule
/// are given one reading of the clock (`look`), so that no record can push a real failure out by being dated where the rule does not
/// look. When more than `KEPT` are held the oldest are dropped, which cannot change the latest lockout (see `KEPT`).
struct Scan {
    line: Vec<u8>,
    overlong: bool,
    kept: Vec<u64>,
    low: u64,
    high: u64,
}

impl Scan {
    fn new(now: u64) -> Scan {
        Scan { line: Vec::new(), overlong: false, kept: Vec::new(), low: now.saturating_sub(2 * WINDOW), high: now.saturating_add(SKEW) }
    }

    fn feed(&mut self, bytes: &[u8]) {
        for piece in bytes.split_inclusive(|b| *b == b'\n') {
            let (body, ended) = match piece.split_last() {
                Some((b'\n', body)) => (body, true),
                _ => (piece, false),
            };
            if !self.overlong {
                if self.line.len() + body.len() > RECORD_BYTES {
                    self.overlong = true;
                    self.line.clear();
                } else {
                    self.line.extend_from_slice(body);
                }
            }
            if ended {
                self.end_line();
            }
        }
    }

    fn end_line(&mut self) {
        if !self.overlong {
            for time in parse(&self.line) {
                if time > self.low && time <= self.high {
                    self.kept.push(time);
                }
            }
        }
        self.line.clear();
        self.overlong = false;
        if self.kept.len() >= 2 * KEPT {
            self.trim();
        }
    }

    fn trim(&mut self) {
        self.kept.sort_unstable();
        let extra = self.kept.len().saturating_sub(KEPT);
        self.kept.drain(..extra);
    }

    /// The end of the record: a last line without its newline is a line.
    fn finish(mut self) -> Vec<u64> {
        self.end_line();
        self.trim();
        self.kept
    }
}

/// The times in a record of `size` bytes that can matter at `now`, read with `read(offset, block)`, which gives the bytes it has
/// read (none at the end). The reading is refused after `limit`, and the record is not guessed at from its end.
fn read_failures(now: u64, size: u64, limit: Duration, mut read: impl FnMut(u64, &mut [u8]) -> Result<usize, String>) -> Result<Vec<u64>, String> {
    let started = Instant::now();
    let mut scan = Scan::new(now);
    let mut block = vec![0u8; BLOCK];
    let mut at = 0u64;
    while at < size {
        if started.elapsed() >= limit {
            return Err(format!("the lockout record could not be read in time; {}", remove_and_setup()));
        }
        let want = (size - at).min(BLOCK as u64) as usize;
        let got = read(at, &mut block[..want])?;
        if got == 0 {
            break;
        }
        scan.feed(&block[..got]);
        at += got as u64;
    }
    Ok(scan.finish())
}

/// A lockout that is in force.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct Lockout {
    /// The wrong passwords in the window that ends with the last one.
    pub count: usize,
    /// The last of them (read as now when it is dated a little ahead).
    pub last: u64,
    /// When the lockout ends.
    pub until: u64,
}

/// The lockout in force at `now`, if any. A failure at `t` starts a lockout until `t + WINDOW` when at least `THRESHOLD` failures
/// (itself included) lie in `(t - WINDOW, t]`; the lockout is the latest end of those. Adding a failure can only add to a count, so
/// a record never shortens a lockout. A time within `SKEW` after `now` is read as `now`; a later one is ignored; so no record locks
/// for longer than `WINDOW` from now.
pub(crate) fn lockout(failures: &[u64], now: u64) -> Option<Lockout> {
    let mut times: Vec<u64> = failures.iter().filter(|t| **t <= now.saturating_add(SKEW)).map(|t| (*t).min(now)).collect();
    times.sort_unstable();
    let mut found: Option<Lockout> = None;
    let mut first = 0;
    for (index, t) in times.iter().enumerate() {
        while times[first] + WINDOW <= *t {
            first += 1;
        }
        let count = index + 1 - first;
        if count >= THRESHOLD {
            found = Some(Lockout { count, last: *t, until: *t + WINDOW });
        }
    }
    found.filter(|lock| now < lock.until)
}

/// Hours and minutes left, rounded up to the minute: `5h 25m`, `40m`, `6h 0m`.
pub(crate) fn time_left(until: u64, now: u64) -> String {
    let minutes = (until.saturating_sub(now) + MINUTE - 1) / MINUTE;
    if minutes >= 60 { format!("{}h {}m", minutes / 60, minutes % 60) } else { format!("{}m", minutes) }
}

/// `8:12pm`: the hour and minute of a local time on a twelve hour clock, with no leading zero on the hour.
pub(crate) fn clock(hour: u16, minute: u16) -> String {
    format!("{}:{:02}{}", if hour % 12 == 0 { 12 } else { hour % 12 }, minute, if hour < 12 { "am" } else { "pm" })
}

/// The reason, as the refusal and the line of the log carry it. `last_clock` and `until_clock` are the local times, formatted.
pub(crate) fn reason(lock: &Lockout, now: u64, last_clock: &str, until_clock: &str) -> String {
    format!("locked out after {} wrong passwords, the last at {}; the password can be asked again in {}, at {}",
        lock.count, last_clock, time_left(lock.until, now), until_clock)
}

// ------------------------------------------------------------------------ the record

/// The record of one account, and the clock it is read against.
pub(crate) trait Record {
    /// The universal time now, as a file time.
    fn now(&self) -> u64;

    /// The times of the wrong passwords in the record that can matter at `now` (the reading of `now` that the rule is then given):
    /// those from the last twelve hours or so, to the latest the rule reads as now (see `Scan`). An error is the reason that it
    /// cannot be read.
    fn failures(&self, now: u64) -> Result<Vec<u64>, String>;

    /// Add a wrong password at `filetime`, as one whole record. An error means the record is not there to hold it.
    fn add(&self, filetime: u64) -> Result<(), String>;

    /// Lock the record against every other program and every other run, from now until the lock is dropped: no one else can read a
    /// locked range, append to the record or lock it meanwhile. The run takes it from its last look at the record until the end of
    /// the attempt that look is for, so that a wrong password cannot be guessed and left uncounted, and two runs cannot both pass the
    /// look at two wrong passwords and both guess. An error is the reason that it could not be taken, which refuses the run.
    fn lock(&self) -> Result<Held<'_>, String>;

    /// The hour and minute of `filetime` on the clock of this computer.
    fn local_clock(&self, filetime: u64) -> (u16, u16);
}

/// What a lock of the record holds while it is alive; the lock is let go when this is dropped.
pub(crate) struct Held<'a> {
    release: Option<Box<dyn FnOnce() + 'a>>,
}

impl<'a> Held<'a> {
    /// A lock that is let go by calling `release`.
    pub(crate) fn new(release: impl FnOnce() + 'a) -> Held<'a> {
        Held { release: Some(Box::new(release)) }
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            release();
        }
    }
}

/// One look at the record, from one reading of it and one reading of the clock: the reason when the account is locked out, the text
/// of the refusal (Some), and how many wrong passwords of the account the record holds in the last six hours: those in
/// `(now - WINDOW, now]`, a time within `SKEW` after now read as now, as the rule reads it. The prompt says that count, so that a
/// person knows how near the lockout is. The reason of an error is that the record cannot be read.
pub(crate) fn look(record: &dyn Record) -> Result<(Option<String>, usize), String> {
    let now = record.now();
    let failures = record.failures(now)?;
    let locked = lockout(&failures, now).map(|lock| {
        // The end is shown rounded up to the minute, as the time left is: a time of day that is already past while the run is
        // still refused would send the person back to be refused again. A record dated ahead of the clock by less than SKEW is
        // read as now, so the end named for it can move later by up to SKEW as the clock reaches it.
        let (last, until) = (record.local_clock(lock.last), record.local_clock((lock.until + MINUTE - 1) / MINUTE * MINUTE));
        reason(&lock, now, &clock(last.0, last.1), &clock(until.0, until.1))
    });
    let recent = failures.iter().filter(|t| **t <= now.saturating_add(SKEW)).map(|t| (*t).min(now)).filter(|t| *t + WINDOW > now).count();
    Ok((locked, recent))
}

/// The time all the reads of the record in one run may take together: each read gets what the earlier ones left of `limit`, so a
/// record that takes nine seconds to read cannot be read again and again. When nothing is left a read refuses at once, with the
/// reason that the record could not be read in time.
struct Budget {
    limit: Duration,
    spent: std::cell::Cell<Duration>,
}

impl Budget {
    fn new(limit: Duration) -> Budget {
        Budget { limit, spent: std::cell::Cell::new(Duration::ZERO) }
    }

    /// Run `work` with the time that is left, and take what it used from what is left.
    fn spend<T>(&self, work: impl FnOnce(Duration) -> T) -> T {
        let left = self.limit.saturating_sub(self.spent.get());
        let started = Instant::now();
        let out = work(left);
        self.spent.set(self.spent.get() + started.elapsed());
        out
    }
}

/// The universal time now as a file time.
fn file_time_now() -> u64 {
    let mut now = 0u64;
    unsafe { GetSystemTimePreciseAsFileTime(&mut now) };
    now
}

/// The hour and minute of `filetime` on the clock of this computer, with its time zone and the rule for summer time. A time that
/// cannot be converted to a local time is given as the universal time, and one that is not a time at all as midnight.
fn local_clock_of(filetime: u64) -> (u16, u16) {
    let (mut universal, mut local) = (SystemTime::default(), SystemTime::default());
    unsafe {
        if FileTimeToSystemTime(&filetime, &mut universal) == 0 {
            return (0, 0);
        }
        if SystemTimeToTzSpecificLocalTime(std::ptr::null(), &universal, &mut local) == 0 {
            return (universal.hour, universal.minute);
        }
    }
    (local.hour, local.minute)
}

/// A handle that is closed when it goes away.
struct Open(Handle);

impl Drop for Open {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// The record file of the account, open for reading and appending: one handle for the run, opened only after the check of its
/// access control passed. It is the guard's record of the account in every run over the cap.
pub(crate) struct FileRecord {
    file: Open,
    budget: Budget,
}

impl FileRecord {
    /// The record of the account the guard runs as: where the registry puts the folder of the programs' data (on the system volume,
    /// named from the root of the object manager), checked, then opened and checked again as the file that is used.
    pub(crate) fn open() -> Result<FileRecord, String> {
        let sid = current_user_sid().map_err(|error| format!("the account of the guard cannot be identified, so its lockout record cannot be found: {}", error))?;
        open_at(&Place::new(&program_data()?, &sid)?, PRODUCTION.trusted)
    }

    fn new(file: Open) -> FileRecord {
        FileRecord { file, budget: Budget::new(READ_LIMIT) }
    }

    /// The room that the volume of the record has for the caller, in bytes: what the volume reports as available to the account.
    fn room(&self) -> Result<u128, String> {
        let api = record_api().ok_or("the system calls that check the lockout record are not available")?;
        let (mut size, mut status) = (FsFullSize::default(), IoStatusBlock::default());
        let result = unsafe {
            (api.nt_volume)(self.file.0, &mut status, &mut size as *mut FsFullSize as *mut c_void, std::mem::size_of::<FsFullSize>() as u32, FILE_FS_FULL_SIZE_INFORMATION)
        };
        if result < 0 {
            return Err(format!("the room on the volume of the lockout record could not be read: {}", error_for(unsafe { (api.nt_error)(result) }).message()));
        }
        Ok(size.caller_available.max(0) as u128 * size.sectors_per_unit as u128 * size.bytes_per_sector as u128)
    }

    /// Lock the whole record for this handle, trying for `wait`, see that the volume has room for a record, and have the room for the
    /// next record allocated (`reserve`).
    fn lock_within(&self, wait: Duration) -> Result<Held<'_>, String> {
        let started = Instant::now();
        let file = self.file.0;
        // The whole range there can be (from offset zero to the end of the largest file), so that the end of the file, where an
        // append lands, is in it.
        loop {
            let mut at = Overlapped::with_event(std::ptr::null_mut());
            if unsafe { LockFileEx(file, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, u32::MAX, u32::MAX, &mut at) } != 0 {
                break;
            }
            let code = unsafe { GetLastError() };
            if code != ERROR_LOCK_VIOLATION {
                return Err(format!("the lockout record could not be locked: {}", error_for(code).message()));
            }
            if started.elapsed() >= wait {
                return Err(LOCK_BUSY.into());
            }
            std::thread::sleep(LOCK_STEP);
        }
        let held = Held::new(move || {
            let mut at = Overlapped::with_event(std::ptr::null_mut());
            unsafe { UnlockFileEx(file, 0, u32::MAX, u32::MAX, &mut at) };
        });
        room_enough(self.room()?)?;
        self.reserve()?;
        Ok(held)
    }

    /// The allocated size of the record and its length, in bytes.
    fn sizes(&self) -> Result<(u64, u64), String> {
        let mut found = FileStandard::default();
        if unsafe { GetFileInformationByHandleEx(self.file.0, FILE_STANDARD_INFO, &mut found as *mut FileStandard as *mut c_void, std::mem::size_of::<FileStandard>() as u32) } == 0 {
            return Err(io_error("measured", unsafe { GetLastError() }));
        }
        Ok((found.allocation_size.max(0) as u64, found.end_of_file.max(0) as u64))
    }

    /// Have the volume allocate, now and under the lock, the room the wrong password that is added after the logon will take, so that
    /// the append needs no new allocation. Without it a program of the account could make the room check pass, fill the volume (or
    /// its quota) in the time the logon takes, and so make the append fail after the guess: a right password approves, and the
    /// failure ("could not be recorded") tells the program that the guess was wrong, which is an oracle with no record. The room
    /// is made by appending newlines, which the reading ignores (an empty line is no record), until the allocated size is at least
    /// `RECORD_BYTES` past the end of the file: a file shorter than `FLOOR` bytes is first made that long, because a short file may
    /// be kept in the volume's own table, where it takes no room of its own, and then one byte past its allocation makes the volume
    /// allocate another unit. What cannot be made refuses the run before the logon.
    fn reserve(&self) -> Result<(), String> {
        let wanted = RECORD_BYTES as u64;
        for _ in 0..2 {
            let (allocated, end) = self.sizes()?;
            if allocated >= end + wanted {
                return Ok(());
            }
            let padding = if end < FLOOR { (FLOOR - end).max(wanted) } else { allocated.saturating_sub(end) + 1 };
            let bytes = vec![b'\n'; padding as usize];
            let mut written = 0u32;
            if unsafe { WriteFile(self.file.0, bytes.as_ptr() as *const c_void, bytes.len() as u32, &mut written, std::ptr::null_mut()) } == 0 {
                return Err(format!("{}: {}", NO_ROOM, io_error("appended to", unsafe { GetLastError() })));
            }
            if written as usize != bytes.len() {
                return Err(NO_ROOM.into());
            }
        }
        let (allocated, end) = self.sizes()?;
        if allocated >= end + wanted { Ok(()) } else { Err(not_reserved()) }
    }
}

/// Whether `bytes` of room is enough for a record to be recorded.
fn room_enough(bytes: u128) -> Result<(), String> {
    if bytes >= ROOM { Ok(()) } else { Err(NO_ROOM.into()) }
}

/// What a read or an append that failed with `code` says.
fn io_error(what: &str, code: u32) -> String {
    if code == ERROR_LOCK_VIOLATION { LOCKED_RANGE.to_string() } else { format!("the lockout record could not be {}: {}", what, error_for(code).message()) }
}

impl Record for FileRecord {
    fn now(&self) -> u64 {
        file_time_now()
    }

    fn failures(&self, now: u64) -> Result<Vec<u64>, String> {
        self.budget.spend(|left| {
            let mut size = 0i64;
            if unsafe { GetFileSizeEx(self.file.0, &mut size) } == 0 {
                return Err(io_error("read", unsafe { GetLastError() }));
            }
            // What is added after this point is read by the next run: the size now bounds the work of this one.
            read_failures(now, size.max(0) as u64, left, |offset, block| {
                // The handle is synchronous: the offset of the structure says where the read starts, whatever the position of the handle is.
                let mut at = Overlapped::with_event(std::ptr::null_mut());
                at.offset = offset as u32;
                at.offset_high = (offset >> 32) as u32;
                let mut read = 0u32;
                let ok = unsafe { ReadFile(self.file.0, block.as_mut_ptr() as *mut c_void, block.len() as u32, &mut read, &mut at) };
                if ok == 0 {
                    let code = unsafe { GetLastError() };
                    if code == ERROR_HANDLE_EOF {
                        return Ok(0);
                    }
                    return Err(io_error("read", code));
                }
                Ok(read as usize)
            })
        })
    }

    fn add(&self, filetime: u64) -> Result<(), String> {
        let record = encode(filetime);
        let mut written = 0u32;
        // The handle has the right to append and not to write, so the system puts the bytes at the end whatever the position is.
        let ok = unsafe { WriteFile(self.file.0, record.as_ptr() as *const c_void, record.len() as u32, &mut written, std::ptr::null_mut()) };
        if ok == 0 {
            return Err(io_error("appended to", unsafe { GetLastError() }));
        }
        if written as usize != record.len() {
            return Err("the lockout record could not be appended to: the record was not written whole".into());
        }
        Ok(())
    }

    fn lock(&self) -> Result<Held<'_>, String> {
        self.lock_within(LOCK_WAIT)
    }

    fn local_clock(&self, filetime: u64) -> (u16, u16) {
        local_clock_of(filetime)
    }
}

// ----------------------------------------------------------------------- the location

/// Where the record of an account is: the folder of the programs' data, the folder of the records in it, and the file. The names are
/// those of the object manager (`\Device\HarddiskVolume3\ProgramData`), which is how the guard names them; a name on a drive
/// (`C:\...`) is taken as the device map of the logon session gives it, which only the unit tests' scratch folders use.
pub(crate) struct Place {
    /// The folders above the folder of the programs' data, from the root of the volume down: the check looks at each of them.
    pub ancestors: Vec<String>,
    pub programdata: String,
    pub folder: String,
    pub record: String,
}

impl Place {
    /// The place of the record of the account with the security identifier `sid`, in the folder of the programs' data `programdata`
    /// (a folder named from the object manager, as `program_data` gives it).
    pub(crate) fn new(programdata: &str, sid: &str) -> Result<Place, String> {
        if !sid.starts_with("S-") || !sid.chars().all(|c| c.is_ascii_digit() || c == 'S' || c == '-') {
            return Err(format!("the security identifier of the account is not in a form that names a file: {}", sid));
        }
        let folder = format!("{}\\{}", programdata, FOLDER_NAME);
        let record = format!("{}\\{}{}", folder, sid, RECORD_ENDING);
        Ok(Place { ancestors: ancestors_of(programdata), programdata: programdata.to_string(), folder, record })
    }

    /// The security identifier the record is named for: its file name without the ending.
    fn account(&self) -> &str {
        let name = self.record.rsplit('\\').next().unwrap_or("");
        // The system spells a name as it likes, in the letter case.
        match name.len().checked_sub(RECORD_ENDING.len()) {
            Some(cut) if name.is_char_boundary(cut) && name[cut..].eq_ignore_ascii_case(RECORD_ENDING) => &name[..cut],
            _ => name,
        }
    }
}

/// The folders above `path`, from the root of its drive or volume down: `C:\` for `C:\ProgramData`, `E:\` and `E:\Data` for
/// `E:\Data\Program Data`, and `\Device\HarddiskVolume3\` for `\Device\HarddiskVolume3\ProgramData`.
fn ancestors_of(path: &str) -> Vec<String> {
    let parts: Vec<&str> = path.split('\\').collect();
    // The root is the drive, or the volume device (the first of the three parts of its name is empty).
    let root = if split_device(path).is_some() { 3 } else { 1 };
    let mut found = Vec::new();
    if parts.len() > root {
        found.push(format!("{}\\", parts[..root].join("\\")));
        for end in root + 1..parts.len() {
            found.push(parts[..end].join("\\"));
        }
    }
    found
}

/// `\Device\HarddiskVolume3\ProgramData` as (`\Device\HarddiskVolume3`, `\ProgramData`): the volume device and what is on it. None for a
/// name that does not start with a device.
fn split_device(path: &str) -> Option<(&str, &str)> {
    let mut ends = path.match_indices('\\').map(|(at, _)| at);
    let (first, second) = (ends.next()?, ends.next()?);
    let end = ends.next().unwrap_or(path.len());
    if first != 0 || !path[first + 1..second].eq_ignore_ascii_case("Device") || end == second + 1 {
        return None;
    }
    Some((&path[..end], &path[end..]))
}

/// The name of an object as `NtCreateFile` takes it: a name from the object manager is used as it is, and a name on a drive is
/// looked up through the device map of the logon session (`\??\C:\...`).
fn nt_name(path: &str) -> String {
    if path.starts_with('\\') { path.to_string() } else { format!("\\??\\{}", path) }
}

/// `path`, named from the object manager, as the setup step names it for the calls that take a drive: the volume device of the
/// system folder is replaced by `drive`. A name that is not on that device is returned as it is.
fn on_drive(path: &str, device: &str, drive: &str) -> String {
    match split_device(path) {
        Some((found, rest)) if found.eq_ignore_ascii_case(device) => format!("{}{}", drive, rest),
        _ => path.to_string(),
    }
}

/// The system folder, `C:\Windows`, as the system gives it: from the system's own record of where it was started from, and not from
/// the device map or the environment.
fn windows_folder() -> Result<String, String> {
    let mut windows = vec![0u16; 260];
    let length = unsafe { GetSystemWindowsDirectoryW(windows.as_mut_ptr(), windows.len() as u32) } as usize;
    if length == 0 || length >= windows.len() {
        return Err("the system folder cannot be read, so the folder of the programs' data cannot be found".into());
    }
    Ok(String::from_utf16_lossy(&windows[..length]))
}

/// A name from the object manager as a program that takes a drive names it, for what is said and for the setup step, which an
/// administrator runs: `C:\ProgramData` for the folder of the programs' data on the system volume. A name on another volume, or on a
/// drive already, is returned as it is.
fn drive_form(path: &str) -> String {
    let Some(api) = record_api() else { return path.to_string() };
    match (windows_folder(), system_device(api)) {
        (Ok(windows), Ok(device)) => on_drive(path, &device, &windows.chars().take(2).collect::<String>()),
        _ => path.to_string(),
    }
}

/// Open the object `name` by its name in the object manager, without following a link at the end of it, sharing everything: with
/// `access` (the right to synchronize is added) and `options` (`FILE_OPEN_REPARSE_POINT`, `FILE_WRITE_THROUGH`). The names that start
/// with a backslash are looked up from the root of the object manager, which a process of the account cannot add to or change; a
/// drive letter is not looked up. The Windows error code is the failure.
fn nt_open(api: &RecordApi, name: &str, access: u32, options: u32) -> Result<Open, u32> {
    let mut units: Vec<u16> = nt_name(name).encode_utf16().collect();
    let bytes = units.len() * std::mem::size_of::<u16>();
    if bytes >= u16::MAX as usize {
        return Err(ERROR_BAD_PATHNAME);
    }
    let mut text = UnicodeString { length: bytes as u16, maximum: bytes as u16, buffer: units.as_mut_ptr() };
    let mut attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32, root: std::ptr::null_mut(), name: &mut text, attributes: OBJ_CASE_INSENSITIVE,
        descriptor: std::ptr::null_mut(), quality: std::ptr::null_mut(),
    };
    let (mut handle, mut status): (Handle, IoStatusBlock) = (std::ptr::null_mut(), IoStatusBlock::default());
    let result = unsafe {
        (api.nt_create)(&mut handle, access | SYNCHRONIZE, &mut attributes, &mut status, std::ptr::null_mut(), 0, FILE_SHARE_ALL, FILE_OPEN,
            options | FILE_SYNCHRONOUS_IO_NONALERT, std::ptr::null_mut(), 0)
    };
    if result < 0 {
        return Err(unsafe { (api.nt_error)(result) });
    }
    Ok(Open(handle))
}

/// The name that the object manager gives the object `handle` is open on: `\Device\HarddiskVolume3\ProgramData`.
fn final_path(handle: Handle) -> Result<String, u32> {
    let mut buffer = vec![0u16; 1024];
    for _ in 0..2 {
        let length = unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, VOLUME_NAME_NT) } as usize;
        if length == 0 {
            return Err(unsafe { GetLastError() });
        }
        if length < buffer.len() {
            return Ok(String::from_utf16_lossy(&buffer[..length]));
        }
        // The length asked for counts the end of the string; a path is at most 32,767 characters.
        if length > 32_768 {
            break;
        }
        buffer = vec![0u16; length + 1];
    }
    Err(ERROR_INSUFFICIENT_BUFFER)
}

/// Whether two names from the object manager are the same name: the system spells a path as it likes, in the letter case.
fn same_path(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

/// The volume device of the system folder, `\Device\HarddiskVolume3`: found by opening `\SystemRoot`, a link in the root of the
/// object manager that the kernel made, and asking where it leads.
fn system_device(api: &RecordApi) -> Result<String, String> {
    let root = nt_open(api, "\\SystemRoot", FILE_READ_ATTRIBUTES, 0).map_err(|code| format!("the system volume cannot be found: {}", error_for(code).message()))?;
    let path = final_path(root.0).map_err(|code| format!("the system volume cannot be named: {}", error_for(code).message()))?;
    split_device(&path).map(|(device, _)| device.to_string()).ok_or_else(|| format!("the system folder is not on a volume that the object manager names: {}", path))
}

/// The folder of the programs' data of this machine, named from the object manager on the system volume: the registry value of the
/// machine, read without expanding the variables in it, with `%SystemDrive%` replaced by the drive of the system folder, and that
/// drive replaced by the system volume (a folder of the programs' data on another drive is refused). No environment variable and no
/// folder of the account's profile is read, because a process of the account can change what they say.
fn program_data() -> Result<String, String> {
    let api = record_api().ok_or("the system calls that check the lockout record are not available")?;
    let mut buffer = vec![0u16; 520];
    let mut size = (buffer.len() * std::mem::size_of::<u16>()) as u32;
    let key = wide(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
    let value = wide("ProgramData");
    let code = unsafe {
        (api.registry)(HKEY_LOCAL_MACHINE, key.as_ptr(), value.as_ptr(), RRF_RT_STRINGS_NO_EXPAND, std::ptr::null_mut(), buffer.as_mut_ptr() as *mut c_void, &mut size)
    };
    if code != 0 {
        return Err(format!("the folder of the programs' data cannot be read from the registry: {}", error_for(code as u32).message()));
    }
    // The size counts the end of the string.
    let units = (size as usize / std::mem::size_of::<u16>()).saturating_sub(1).min(buffer.len());
    let raw = String::from_utf16_lossy(&buffer[..units]);
    let windows = windows_folder()?;
    let path = program_data_path(&raw, &windows)?;
    anchored(&path, &windows, &system_device(api)?)
}

/// `path`, a folder on a drive as `program_data_path` gives it, named from the object manager: the drive must be that of the system
/// folder `windows`, and is replaced by the system volume `device`. A folder on another drive is refused, because the volume that
/// the drive letter leads to is not known without the device map; the lockout record is kept on the system volume only.
fn anchored(path: &str, windows: &str, device: &str) -> Result<String, String> {
    let drive: String = windows.chars().take(2).collect();
    match path.get(..2) {
        Some(start) if start.eq_ignore_ascii_case(&drive) => Ok(format!("{}{}", device, &path[2..])),
        _ => Err(format!("the folder of the programs' data is not on the system drive ({}), and the lockout record is kept on the system drive only: {}", drive, path)),
    }
}

/// `raw` as the registry holds it, with `%SystemDrive%` at its start replaced by the drive of `windows`, the system folder. A path
/// that still has a percent sign, or that is not a folder on a drive, is refused.
fn program_data_path(raw: &str, windows: &str) -> Result<String, String> {
    let drive: String = windows.chars().take(2).collect();
    let is_drive = |text: &str| matches!(text.as_bytes(), [letter, b':'] if letter.is_ascii_alphabetic());
    if !is_drive(&drive) {
        return Err(format!("the system folder is not on a drive: {}", windows));
    }
    const VARIABLE: &str = "%SystemDrive%";
    let expanded = match raw.get(..VARIABLE.len()) {
        Some(start) if start.eq_ignore_ascii_case(VARIABLE) => format!("{}{}", drive, &raw[VARIABLE.len()..]),
        _ => raw.to_string(),
    };
    let path = expanded.trim_end_matches('\\');
    let bytes = path.as_bytes();
    let on_a_drive = bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
    if !on_a_drive || path.contains('%') || path.contains('/') || path.contains('\0') || path.split('\\').any(|part| part == ".." || part == ".") {
        return Err(format!("the folder of the programs' data is not a plain folder on a drive: {}", raw));
    }
    Ok(path.to_string())
}

// ---------------------------------------------------------------------------- rights

/// The rights a process without administrator rights may have on the record: to read it and to append to it, besides the right to
/// read its extended attributes (which the ordinary ways of reading a file ask for), its attributes and its access list, and to
/// wait for it. It must have the first two.
const RECORD_MUST: u32 = FILE_READ_DATA | FILE_APPEND_DATA;
const RECORD_MAY: u32 = RECORD_MUST | 0x8 | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;

/// The rights it may have on the folder of the records: to list it, read its attributes and pass through it.
const FOLDER_MAY: u32 = 0x1 | 0x8 | 0x20 | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;

/// What it may not have on the root of the drive: to delete what is in it (the folders on the way to the record with it), and to
/// change who may do what or who owns it. It may make folders in it, as it may by default.
const DRIVE_ROOT_MUST_NOT: u32 = 0x40 | WRITE_DAC | WRITE_OWNER;

/// What it may not have on the folder of the programs' data and the folders between it and the root: the same, and to delete or
/// rename the folder itself (`DELETE`), which would let it swap the tree below. The folder of the programs' data allows making
/// folders in it, as it does by default.
const PROGRAM_DATA_MUST_NOT: u32 = DRIVE_ROOT_MUST_NOT | 0x10000;

/// Which of the objects a mask is the rights on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Object {
    DriveRoot,
    ProgramData,
    Folder,
    Record,
}

/// The names of the rights in `mask`, as they are called for a file or for a folder.
fn rights(mask: u32, folder: bool) -> Vec<&'static str> {
    let file = [(0x1, "READ_DATA"), (0x2, "WRITE_DATA"), (0x4, "APPEND_DATA"), (0x8, "READ_EA"), (0x10, "WRITE_EA"), (0x20, "EXECUTE"),
        (0x40, "DELETE_CHILD"), (0x80, "READ_ATTRIBUTES"), (0x100, "WRITE_ATTRIBUTES")];
    let directory = [(0x1, "LIST"), (0x2, "ADD_FILE"), (0x4, "ADD_SUBDIRECTORY"), (0x8, "READ_EA"), (0x10, "WRITE_EA"), (0x20, "TRAVERSE"),
        (0x40, "DELETE_CHILD"), (0x80, "READ_ATTRIBUTES"), (0x100, "WRITE_ATTRIBUTES")];
    let standard = [(0x10000, "DELETE"), (READ_CONTROL, "READ_CONTROL"), (WRITE_DAC, "WRITE_DAC"), (WRITE_OWNER, "WRITE_OWNER"), (SYNCHRONIZE, "SYNCHRONIZE")];
    let mut names: Vec<&'static str> = (if folder { directory } else { file }).iter().chain(standard.iter())
        .filter(|(bit, _)| mask & bit != 0).map(|(_, name)| *name).collect();
    // Any bit that has no name above is still said.
    if mask & !0x1f01ff != 0 {
        names.push("OTHER_RIGHTS");
    }
    names
}

/// The rights in `granted` that `object` may not have, as a mask.
fn excess(object: Object, granted: u32) -> u32 {
    match object {
        Object::Record => granted & !RECORD_MAY,
        Object::Folder => granted & !FOLDER_MAY,
        Object::DriveRoot => granted & DRIVE_ROOT_MUST_NOT,
        Object::ProgramData => granted & PROGRAM_DATA_MUST_NOT,
    }
}

// ----------------------------------------------------------------------- the check

/// Why the record cannot be used: the reason as the refusal carries it.
#[derive(Debug)]
pub(crate) struct Fault {
    pub reason: String,
}

impl Fault {
    fn new(reason: String) -> Fault {
        Fault { reason }
    }

    fn missing() -> Fault {
        Fault::new(format!("no lockout record exists for this account; {}", setup_step()))
    }

    fn cannot_open(what: &str, code: u32) -> Fault {
        if code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND {
            return Fault::missing();
        }
        // Another program has it open and does not share it: the setup step cannot mend that. (A lock violation is not said here:
        // opening a file does not run into a locked range, only a read, an append or a lock does; see `io_error`.)
        if code == ERROR_SHARING_VIOLATION {
            return Fault::new(format!("{} is held open by another program that does not share it; end that program and run again", what));
        }
        Fault::new(format!("{} cannot be opened: {}; {}", what, error_for(code).message(), setup_step()))
    }

    /// `what` is owned by `owner`, who is not one that a process without administrator rights cannot be: `remedy` says what is done
    /// about it.
    fn untrusted(what: &str, owner: &str, remedy: &str) -> Fault {
        let owner = if owner.is_empty() { "an unknown owner" } else { owner };
        Fault::new(format!("{} is owned by {}, which is not the Administrators group, the system or the installer of the system, so it cannot be trusted; {}", what, owner, remedy))
    }

    /// `granted` is more than `object` may have.
    fn too_wide(object: Object, granted: u32) -> Fault {
        let list = rights(excess(object, granted), object != Object::Record).join(", ");
        match object {
            // Not mended by the step: a handle opened while the record allowed that may still be held (see `make_record`).
            Object::Record => Fault::new(format!("the lockout record for this account allows more than read and append ({}); {}", list, remove_and_setup())),
            Object::Folder => Fault::new(format!("the folder of the lockout records allows more than reading ({}); {}", list, setup_step())),
            Object::DriveRoot | Object::ProgramData => Fault::too_wide_above("the folder of the programs' data of this machine", object, granted),
        }
    }

    /// `granted` is more than the account may have on `what`, a folder above the folder of the records, which is judged as `object`.
    fn too_wide_above(what: &str, object: Object, granted: u32) -> Fault {
        let list = rights(excess(object, granted), true).join(", ");
        Fault::new(format!("{} lets this account delete or rename it or what is in it, or change its permissions or owner ({}), so a lockout record in it cannot be protected", what, list))
    }
}

/// A buffer for a security descriptor, aligned for one.
type Descriptor = Vec<u64>;

/// The security descriptor of `handle` with the parts `information` names, read as the system gives it (self-relative).
fn security_of(api: &RecordApi, handle: Handle, information: u32) -> Result<Descriptor, u32> {
    let mut buffer: Descriptor = vec![0u64; 512];
    for _ in 0..2 {
        let mut needed = 0u32;
        if unsafe { (api.security)(handle, information, buffer.as_mut_ptr() as *mut c_void, (buffer.len() * 8) as u32, &mut needed) } != 0 {
            return Ok(buffer);
        }
        let code = unsafe { GetLastError() };
        // A list is at most 64 KiB, so the second try with the size the system asked for is the last.
        if code != ERROR_INSUFFICIENT_BUFFER || needed as usize > 1 << 17 {
            return Err(code);
        }
        buffer = vec![0u64; (needed as usize + 7) / 8 + 1];
    }
    Err(ERROR_INSUFFICIENT_BUFFER)
}

/// What is known of one object: the rights the token has on it, what kind of file it is, which file it is (the volume and the
/// index on it), and the bytes of its security descriptor.
struct Inspected {
    granted: u32,
    attributes: u32,
    links: u32,
    identity: Identity,
    descriptor: Descriptor,
}

/// Which file an open handle is on: the serial number of the volume and the index of the file on it. Two handles that have the
/// same identity are on the same file, whatever the names they were opened by.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Identity {
    volume: u32,
    index_high: u32,
    index_low: u32,
}

/// A token for the checks: a process of the account without administrator rights, which is this process with the Administrators
/// group turned to deny only and the privileges but one taken away (the same token on an elevated process, which is the point),
/// as an impersonation token, the kind an access check takes.
struct Limited(Open);

impl Limited {
    /// The token, with the one right an access check asks of it: to be queried.
    fn new(api: &RecordApi) -> Result<Limited, String> {
        Limited::with_access(api, TOKEN_QUERY)
    }

    fn with_access(api: &RecordApi, access: u32) -> Result<Limited, String> {
        // The Administrators group, S-1-5-32-544, as the bytes of a security identifier: revision 1, two sub authorities, authority 5.
        let mut administrators: [u32; 4] = [0x0000_0201, 0x0500_0000, 32, 544];
        let sid = administrators.as_mut_ptr() as *mut c_void;
        let fail = |what: &str| format!("the token for the check of the lockout record cannot be made ({}): {}", what, os_error().message());
        unsafe {
            let mut process: Handle = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &mut process) == 0 {
                return Err(fail("the token of the process"));
            }
            let process = Open(process);
            let mut disable = SidAndAttributes { sid, attributes: 0 };
            let mut restricted: Handle = std::ptr::null_mut();
            if (api.restricted)(process.0, DISABLE_MAX_PRIVILEGE | LUA_TOKEN, 1, &mut disable, 0, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut restricted) == 0 {
                return Err(fail("restricting it"));
            }
            let restricted = Open(restricted);
            let mut impersonation: Handle = std::ptr::null_mut();
            if (api.duplicate)(restricted.0, access, std::ptr::null_mut(), SECURITY_IMPERSONATION, TOKEN_IMPERSONATION, &mut impersonation) == 0 {
                return Err(fail("duplicating it"));
            }
            Ok(Limited(Open(impersonation)))
        }
    }
}

/// The privileges that let a program of an account act as the system or go round the access control of a file, and so rewrite,
/// shorten or remove the record whatever its list says: to debug a process of the system and take its token, to load a driver, to
/// act as part of the operating system, to make a token, to assign a token to a process, to impersonate a client (a token of the
/// system that the program can get is then its own), to restore or back up files, to take ownership of them, to manage volumes and
/// to set the clock. A token that holds one of them (enabled or not) is not one the record can protect (Common Weakness
/// Enumeration, CWE-250 and CWE-269). The check of the list takes them away from the token it asks the system about, so it cannot
/// see them there: they are read from the token of the process first.
const DANGEROUS_PRIVILEGES: [&str; 11] = [
    "SeDebugPrivilege", "SeTcbPrivilege", "SeCreateTokenPrivilege", "SeLoadDriverPrivilege", "SeAssignPrimaryTokenPrivilege",
    "SeImpersonatePrivilege", "SeRestorePrivilege", "SeBackupPrivilege", "SeTakeOwnershipPrivilege", "SeManageVolumePrivilege",
    "SeSystemtimePrivilege",
];

/// The names of the privileges that `token` holds, enabled or not.
fn privileges_of(api: &RecordApi, token: Handle) -> Result<Vec<String>, String> {
    let fail = |what: &str, code: u32| format!("the privileges of this account cannot be read ({}): {}", what, error_for(code).message());
    let mut buffer = vec![0u64; 128];
    let mut needed = 0u32;
    for _ in 0..2 {
        if unsafe { GetTokenInformation(token, TOKEN_PRIVILEGES_CLASS, buffer.as_mut_ptr() as *mut c_void, (buffer.len() * 8) as u32, &mut needed) } != 0 {
            break;
        }
        let code = unsafe { GetLastError() };
        // The second try is with the size the system asked for, and is the last.
        if code != ERROR_INSUFFICIENT_BUFFER || needed as usize > 1 << 16 {
            return Err(fail("the list", code));
        }
        buffer = vec![0u64; (needed as usize + 7) / 8 + 1];
    }
    // A count of privileges, then for each a locally unique identifier of eight bytes and four bytes of attributes.
    let bytes: Vec<u8> = buffer.iter().flat_map(|word| word.to_le_bytes()).collect();
    let count = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if 4 + 12 * count > bytes.len() {
        return Err("the privileges of this account cannot be read: the list is longer than the system said".into());
    }
    let mut names = Vec::new();
    for entry in 0..count {
        let at = 4 + 12 * entry;
        let mut luid = [0u8; 8];
        luid.copy_from_slice(&bytes[at..at + 8]);
        let luid = u64::from_le_bytes(luid);
        let mut name = vec![0u16; 128];
        let mut length = name.len() as u32;
        if unsafe { (api.privilege_name)(std::ptr::null(), &luid, name.as_mut_ptr(), &mut length) } == 0 {
            return Err(fail("a name", unsafe { GetLastError() }));
        }
        names.push(String::from_utf16_lossy(&name[..length as usize]));
    }
    Ok(names)
}

/// Which of the privileges in `held` are among the dangerous ones, in the order of `held`.
fn dangerous_among(held: &[String]) -> Vec<String> {
    held.iter().filter(|name| DANGEROUS_PRIVILEGES.contains(&name.as_str())).cloned().collect()
}

/// The dangerous privileges that the token of this process holds.
fn dangerous_privileges(api: &RecordApi) -> Result<Vec<String>, String> {
    let mut token: Handle = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(format!("the privileges of this account cannot be read (the token of the process): {}", os_error().message()));
    }
    let token = Open(token);
    Ok(dangerous_among(&privileges_of(api, token.0)?))
}

/// The refusal for a token that holds `dangerous` privileges, if it holds any.
fn judge_privileges(dangerous: &[String]) -> Result<(), Fault> {
    if dangerous.is_empty() {
        return Ok(());
    }
    Err(Fault::new(format!("this account holds privileges ({}) that let a program of the account rewrite the lockout record, so it cannot be protected; do not use the exception for this account", dangerous.join(", "))))
}

/// The dangerous privileges that a program of this account without administrator rights holds, for the setup step to warn of: those
/// of the token of this process, or, when it is a split token, of the other one, which is the token the account's own programs have.
fn account_dangerous_privileges() -> Result<Vec<String>, String> {
    let api = record_api().ok_or("the system calls that check the lockout record are not available")?;
    let mut token: Handle = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(format!("the privileges of this account cannot be read (the token of the process): {}", os_error().message()));
    }
    let token = Open(token);
    let (mut linked, mut returned): (Handle, u32) = (std::ptr::null_mut(), 0);
    let split = unsafe { GetTokenInformation(token.0, TOKEN_LINKED_TOKEN_CLASS, &mut linked as *mut Handle as *mut c_void, std::mem::size_of::<Handle>() as u32, &mut returned) } != 0 && !linked.is_null();
    if split {
        let linked = Open(linked);
        return Ok(dangerous_among(&privileges_of(api, linked.0)?));
    }
    Ok(dangerous_among(&privileges_of(api, token.0)?))
}

/// What the step says of an account whose programs hold dangerous privileges: the record cannot protect it.
fn privilege_warning(dangerous: &[String]) -> Option<String> {
    judge_privileges(dangerous).err().map(|fault| format!("warning: {}", fault.reason))
}

/// What `token` is granted on the object with `descriptor`: everything the list would grant it.
fn granted_to(api: &RecordApi, token: Handle, descriptor: &mut Descriptor) -> Result<u32, u32> {
    let mut mapping = GenericMapping { read: 0x120089, write: 0x120116, execute: 0x1200a0, all: 0x1f01ff };
    let mut privileges = [0u64; 8];
    let (mut length, mut granted, mut status): (u32, u32, Bool) = (64, 0, 0);
    let ok = unsafe {
        (api.access_check)(descriptor.as_mut_ptr() as *mut c_void, token, MAXIMUM_ALLOWED, &mut mapping,
            privileges.as_mut_ptr() as *mut c_void, &mut length, &mut granted, &mut status)
    };
    if ok == 0 {
        return Err(unsafe { GetLastError() });
    }
    // A list that grants nothing is a status of false, with nothing granted.
    Ok(if status == 0 { 0 } else { granted })
}

/// Open `path` (a name from the object manager, or on a drive for the scratch folders of the unit tests) for reading its attributes
/// and its access list, without following a link, and say what the token is granted on it.
fn inspect(api: &RecordApi, token: Handle, path: &str) -> Result<Inspected, u32> {
    let file = nt_open(api, path, READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_OPEN_REPARSE_POINT)?;
    inspect_handle(api, token, file.0)
}

/// What is known of the object `handle` is open on (it must have been opened for the right to read its access list and its
/// attributes): the same for the objects that are looked at by their names and for the record that is used, so that what is judged
/// is the object that is held and not a name.
fn inspect_handle(api: &RecordApi, token: Handle, handle: Handle) -> Result<Inspected, u32> {
    let mut information = FileInformation::default();
    if unsafe { GetFileInformationByHandle(handle, &mut information) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    let mut descriptor = security_of(api, handle, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)?;
    let granted = granted_to(api, token, &mut descriptor)?;
    let identity = Identity { volume: information.volume, index_high: information.index_high, index_low: information.index_low };
    Ok(Inspected { granted, attributes: information.attributes, links: information.links, identity, descriptor })
}

/// Whether the owner of `found` is one of `trusted`.
fn trusted_owner(found: &Inspected, trusted: &[&str]) -> bool {
    trusted.contains(&owner_text(&found.descriptor).as_str())
}

/// How the access list of the record is judged.
pub(crate) enum RecordCheck<'a> {
    /// By asking the system what a process of this account without administrator rights is granted: the check of every run.
    Limited,
    /// By comparing the owner and the access list with `expected` byte for byte: for the record of another account, which a token
    /// of this one cannot stand for.
    Exactly(&'a [u64]),
}

/// The owner and the access list of a self-relative security descriptor, as bytes, and whether the list is protected.
fn parts(descriptor: &[u64]) -> Option<(Vec<u8>, Vec<u8>, bool)> {
    let bytes: Vec<u8> = descriptor.iter().flat_map(|word| word.to_le_bytes()).collect();
    if bytes.len() < 20 || bytes[0] != 1 {
        return None;
    }
    let control = u16::from_le_bytes([bytes[2], bytes[3]]);
    let offset = |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]) as usize;
    let (owner, list) = (offset(4), offset(16));
    if owner == 0 || list == 0 || owner + 8 > bytes.len() || list + 8 > bytes.len() {
        return None;
    }
    let owner_end = owner + 8 + 4 * bytes[owner + 1] as usize;
    let list_end = list + u16::from_le_bytes([bytes[list + 2], bytes[list + 3]]) as usize;
    if owner_end > bytes.len() || list_end > bytes.len() {
        return None;
    }
    Some((bytes[owner..owner_end].to_vec(), bytes[list..list_end].to_vec(), control & 0x1000 != 0))
}

/// The first entry of the access list `list` (the bytes of the list, as `parts` gives them) that allows something to an account or
/// group other than the system, the Administrators group, `account` (the security identifier the record is named for) and the
/// owner rights entry: its security identifier as text, or a description when the entry is of a kind that the step does not make
/// (an entry that allows, with a condition or for an object, or for two accounts at once). Entries that deny are not looked at,
/// because they take rights away. The reason that the list cannot be read is the error.
fn foreign_entry(list: &[u8], account: &str) -> Result<Option<String>, String> {
    const ALLOWED: [&str; 3] = ["S-1-5-18", "S-1-5-32-544", "S-1-3-4"];
    let unreadable = || "the access list of the lockout record cannot be read".to_string();
    if list.len() < 8 {
        return Err(unreadable());
    }
    let count = u16::from_le_bytes([list[4], list[5]]) as usize;
    let mut at = 8;
    for _ in 0..count {
        if at + 8 > list.len() {
            return Err(unreadable());
        }
        let (kind, size) = (list[at], u16::from_le_bytes([list[at + 2], list[at + 3]]) as usize);
        if size < 8 || at + size > list.len() {
            return Err(unreadable());
        }
        match kind {
            // Access allowed: the mask, then the security identifier.
            0 => {
                let sub_authorities = list[at + 9] as usize;
                let end = at + 8 + 8 + 4 * sub_authorities;
                if list[at + 8] != 1 || end > at + size {
                    return Err(unreadable());
                }
                let mut sid = vec![0u64; (end - at - 8 + 7) / 8];
                for (index, byte) in list[at + 8..end].iter().enumerate() {
                    sid[index / 8] |= (*byte as u64) << (8 * (index % 8));
                }
                let text = sid_text(sid.as_mut_ptr() as *mut c_void).map_err(|_| unreadable())?;
                if !ALLOWED.contains(&text.as_str()) && !text.eq_ignore_ascii_case(account) {
                    return Ok(Some(text));
                }
            }
            // Access denied, in its plain, object, callback and callback object forms: they take rights away.
            1 | 6 | 10 | 12 => {}
            other => return Ok(Some(format!("an entry of type {}", other))),
        }
        at += size;
    }
    Ok(None)
}

/// Check the access control of the objects against what a process of the account without administrator rights may do: nothing on
/// the folder of the programs' data, or on the folders above it, that deletes or takes over a folder, read the folder of the
/// records and nothing else, read and append the record and nothing else; that none is a link, and the record has one name only;
/// and that each is owned by one of `trusted`. The owner matters because a process without administrator rights can make a tree
/// of its own with exactly the right lists (and keep a handle it opened before the list was tightened), and cannot make the
/// Administrators group, the system or the installer of the system the owner of it. The objects are opened by their names from the
/// root of the object manager, which a process of the account cannot add to (a drive letter, which it can add to or change, is not
/// used); `verify` is the look at the names, and returns which file the record is, for `open_at` to hold the file that is used to.
pub(crate) fn verify(place: &Place, check: &RecordCheck, trusted: &[&str]) -> Result<Identity, Fault> {
    let api = record_api().ok_or_else(|| Fault::new("the system calls that check the lockout record are not available".into()))?;
    // Before the token of the check is made, which has no privileges: the programs of an account that holds one of the dangerous
    // privileges can act as the system, and the record cannot protect it. An elevated token is an administrator's, which the
    // documents already say the record does not protect.
    if !elevated() {
        judge_privileges(&dangerous_privileges(api).map_err(Fault::new)?)?;
    }
    let limited = Limited::new(api).map_err(Fault::new)?;
    let token = (limited.0).0;
    let above = |path: &str, what: &dyn Fn() -> String, object: Object| -> Result<(), Fault> {
        let found = inspect(api, token, path).map_err(|code| Fault::new(format!("{} cannot be checked: {}", what(), error_for(code).message())))?;
        if found.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || found.attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(Fault::new(format!("{} is a link or not a folder, so a lockout record in it cannot be protected", what())));
        }
        if !trusted_owner(&found, trusted) {
            return Err(Fault::untrusted(&what(), &owner_text(&found.descriptor), "a lockout record in it cannot be protected"));
        }
        if excess(object, found.granted) != 0 {
            return Err(Fault::too_wide_above(&what(), object, found.granted));
        }
        Ok(())
    };
    // From the root of the volume down, so that each folder on the way is looked at.
    for (index, path) in place.ancestors.iter().enumerate() {
        above(path, &|| format!("the folder {}", drive_form(path)), if index == 0 { Object::DriveRoot } else { Object::ProgramData })?;
    }
    above(&place.programdata, &|| "the folder of the programs' data of this machine".to_string(), Object::ProgramData)?;
    let folder = inspect(api, token, &place.folder).map_err(|code| Fault::cannot_open("the folder of the lockout records", code))?;
    if folder.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || folder.attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(Fault::new(format!("the folder of the lockout records is a link or not a folder; {}", remove_and_setup())));
    }
    if folder.attributes & FILE_ATTRIBUTE_COMPRESSED != 0 {
        return Err(Fault::new(compressed()));
    }
    if !trusted_owner(&folder, trusted) {
        return Err(Fault::untrusted("the folder of the lockout records", &owner_text(&folder.descriptor), &remove_and_setup()));
    }
    if excess(Object::Folder, folder.granted) != 0 {
        return Err(Fault::too_wide(Object::Folder, folder.granted));
    }
    let record = inspect(api, token, &place.record).map_err(|code| Fault::cannot_open("the lockout record for this account", code))?;
    judge_record(&record, check, trusted, place.account())?;
    Ok(record.identity)
}

/// What is judged of the record itself, on what is known of the file (by its name before it is opened, by the handle after): it is
/// no link and no folder and has one name, one of `trusted` owns it, and its access list is as `check` says.
fn judge_record(record: &Inspected, check: &RecordCheck, trusted: &[&str], account: &str) -> Result<(), Fault> {
    if record.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || record.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 || record.links != 1 {
        return Err(Fault::new(format!("the lockout record for this account is a link, a folder or has more than one name; {}", remove_and_setup())));
    }
    if record.attributes & FILE_ATTRIBUTE_COMPRESSED != 0 {
        return Err(Fault::new(compressed()));
    }
    if !trusted_owner(record, trusted) {
        return Err(Fault::untrusted("the lockout record for this account", &owner_text(&record.descriptor), &remove_and_setup()));
    }
    match check {
        RecordCheck::Limited => {
            if excess(Object::Record, record.granted) != 0 {
                return Err(Fault::too_wide(Object::Record, record.granted));
            }
            if record.granted & RECORD_MUST != RECORD_MUST {
                return Err(Fault::new(format!("the lockout record for this account does not let this account read it and append to it; {}", setup_step())));
            }
            // What this account is granted is not all that matters: an entry for another account or group that allows more than
            // reading could be used by a program of that one to rewrite the record, or to hold a handle opened while it did.
            if let Some(other) = parts(&record.descriptor).ok_or_else(|| "the access list of the lockout record cannot be read".to_string()).and_then(|(_, list, _)| foreign_entry(&list, account)).map_err(Fault::new)? {
                return Err(Fault::new(format!("the access list of the lockout record has an entry for another account or group ({}), which could be given more than reading and appending; {}", other, remove_and_setup())));
            }
        }
        RecordCheck::Exactly(expected) => {
            if parts(&record.descriptor).is_none() || parts(&record.descriptor) != parts(expected) {
                return Err(Fault::new(format!("the lockout record does not have the owner and access list that were set; {}", setup_step())));
            }
        }
    }
    Ok(())
}

/// The record of the account at `place`: its names are checked (`verify`), then the file is opened once, for reading and appending,
/// without following a link, with writes that go through to the disk, and that open file is checked again.
pub(crate) fn open_at(place: &Place, trusted: &[&str]) -> Result<FileRecord, String> {
    let seen = verify(place, &RecordCheck::Limited, trusted).map_err(|fault| fault.reason)?;
    open_checked(place, trusted, &seen)
}

/// Open the record at `place` and judge the file that is open: the file used is the one judged, and it is the file `seen` that
/// the look at the names found. The decision is on the handle, not on a name that could lead somewhere else the second time it is
/// used (Common Weakness Enumeration, CWE-367, time of check to time of use): the owner, the access list, the links and the kind
/// of file are those of the open file, which is the file the check saw (the volume and the index on it), and, for a name from the
/// object manager, its final name is that name, so that no link, mount point or other name on the way led it elsewhere than the
/// folders that were looked at.
fn open_checked(place: &Place, trusted: &[&str], seen: &Identity) -> Result<FileRecord, String> {
    let api = record_api().ok_or("the system calls that check the lockout record are not available")?;
    let limited = Limited::new(api)?;
    let what = "the lockout record for this account";
    let file = nt_open(api, &place.record, FILE_READ_DATA | FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_OPEN_REPARSE_POINT | FILE_WRITE_THROUGH)
        .map_err(|code| Fault::cannot_open(what, code).reason)?;
    let found = inspect_handle(api, (limited.0).0, file.0).map_err(|code| format!("{} cannot be checked once it is open: {}; {}", what, error_for(code).message(), setup_step()))?;
    judge_record(&found, &RecordCheck::Limited, trusted, place.account()).map_err(|fault| fault.reason)?;
    if found.identity != *seen {
        return Err(format!("{} is not the file that was checked a moment before (it was replaced, or its name led elsewhere the second time); run again", what));
    }
    if place.record.starts_with('\\') {
        let opened = final_path(file.0).map_err(|code| format!("{} cannot be named once it is open: {}; {}", what, error_for(code).message(), setup_step()))?;
        if !same_path(&opened, &place.record) {
            return Err(format!("{} was opened as {}, which is not the name it was asked for, {}; {}", what, opened, place.record, setup_step()));
        }
    }
    Ok(FileRecord::new(file))
}

// ------------------------------------------------------------------------- the setup

/// Whose authority the record is made under: the owner of what is made, as the text form of the access list names it (the
/// Administrators group), the owners that are trusted (an existing folder with one of them may be taken over, and the check of
/// every run requires one of them to own what it relies on), and the entries added to the access list of the folder and of each
/// record. The setup step and the guard use `PRODUCTION`, which adds nothing; the unit tests use their own, because they run
/// without administrator rights.
pub(crate) struct Authority<'a> {
    pub owner: &'a str,
    pub trusted: &'a [&'a str],
    pub folder: &'a str,
    pub record: &'a str,
    /// The rights beyond read and append that a record that is there may have for the account and still be set right in place:
    /// none for the setup step and the guard. A record that allowed more is not repaired (see `make_record`). The unit tests run
    /// without administrator rights, so they can open an object to set its list only if the list lets them change it, and name
    /// those two rights here.
    pub tolerated: u32,
}

/// The Administrators group owns the folder and the records. The owners that are trusted are that group, the system, and the
/// installer of the system, which owns the root of the system drive on a usual machine: none of them can be made the owner of
/// anything by a process without administrator rights. A folder of the records of another owner is not taken over.
pub(crate) const PRODUCTION: Authority<'static> = Authority {
    owner: "BA",
    trusted: &["S-1-5-32-544", "S-1-5-18", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"],
    folder: "",
    record: "",
    tolerated: 0,
};

/// The access list of the folder of the records: the system and the Administrators everything, every signed-in account the right to
/// pass through it and read its attributes and its permissions, and nothing else. Protected, with nothing inherited.
fn folder_sddl(authority: &Authority) -> String {
    format!("O:{}D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a0;;;AU){}", authority.owner, authority.folder)
}

/// The access list of a record: the system and the Administrators everything, the account the right to read it and to append to
/// it and nothing more, and the owner rights entry, which takes away what an owner has by being the owner (the right to change the
/// access list and to delete) and leaves it the right to read the list. Protected, with nothing inherited.
fn record_sddl(authority: &Authority, sid: &str) -> String {
    format!("O:{}D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12008d;;;{})(A;;0x20000;;;OW){}", authority.owner, sid, authority.record)
}

/// A security descriptor made from its text form, freed when it goes away.
struct Made {
    pointer: *mut c_void,
    size: u32,
}

impl Made {
    fn from(sddl: &str) -> Result<Made, String> {
        let text = wide(sddl);
        let (mut pointer, mut size): (*mut c_void, u32) = (std::ptr::null_mut(), 0);
        if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), 1, &mut pointer, &mut size) } == 0 {
            return Err(format!("the access list {} is not accepted by the system: {}", sddl, os_error().message()));
        }
        Ok(Made { pointer, size })
    }

    /// The descriptor as words, to compare with what the system holds for an object.
    fn words(&self) -> Descriptor {
        let mut words = vec![0u64; (self.size as usize + 7) / 8 + 1];
        // SAFETY: the system allocated `size` bytes at `pointer`, and the words are at least that long.
        unsafe { std::ptr::copy_nonoverlapping(self.pointer as *const u8, words.as_mut_ptr() as *mut u8, self.size as usize) };
        words
    }
}

impl Drop for Made {
    fn drop(&mut self) {
        unsafe { LocalFree(self.pointer) };
    }
}

/// Whether this process has an elevated token: it holds the rights of an administrator.
pub(crate) fn elevated() -> bool {
    unsafe {
        let mut token: Handle = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let token = Open(token);
        let (mut elevation, mut returned) = (0u32, 0u32);
        GetTokenInformation(token.0, TOKEN_ELEVATION_CLASS, &mut elevation as *mut u32 as *mut c_void, 4, &mut returned) != 0 && elevation != 0
    }
}

/// The security identifier of the user account `name`, as text: the account must be a user.
pub(crate) fn account_sid(name: &str) -> Result<String, String> {
    let api = logon_api().ok_or("the system call that finds an account is not available")?;
    let text = wide(name);
    let (mut sid_size, mut domain_chars, mut kind) = (0u32, 0u32, 0u32);
    unsafe {
        (api.lookup)(std::ptr::null(), text.as_ptr(), std::ptr::null_mut(), &mut sid_size, std::ptr::null_mut(), &mut domain_chars, &mut kind);
        let code = GetLastError();
        if code != ERROR_INSUFFICIENT_BUFFER {
            return Err(format!("the account {} cannot be found: {}", name, error_for(code).message()));
        }
        let mut sid = vec![0u64; (sid_size as usize + 7) / 8 + 1];
        let mut domain = vec![0u16; domain_chars as usize + 1];
        if (api.lookup)(std::ptr::null(), text.as_ptr(), sid.as_mut_ptr() as *mut c_void, &mut sid_size, domain.as_mut_ptr(), &mut domain_chars, &mut kind) == 0 {
            return Err(format!("the account {} cannot be found: {}", name, os_error().message()));
        }
        // SidTypeUser.
        if kind != 1 {
            return Err(format!("{} is not a user account", name));
        }
        sid_text(sid.as_mut_ptr() as *mut c_void).map_err(|error| error.to_string())
    }
}

/// The text form of the owner of a self-relative security descriptor; empty when it has none.
fn owner_text(descriptor: &Descriptor) -> String {
    let bytes = descriptor.as_ptr() as *const u8;
    // The owner is at the offset in the fifth to eighth bytes of a self-relative descriptor.
    let at = unsafe { std::ptr::read_unaligned(bytes.add(4) as *const u32) } as usize;
    if at == 0 || at + 8 > descriptor.len() * 8 {
        return String::new();
    }
    unsafe { sid_text(bytes.add(at) as *mut c_void) }.unwrap_or_default()
}

/// Open an existing object to take its owner and access list in hand, without following a link; the folder only if `folder`. The
/// step is run by an administrator and names what it makes as a program that takes a drive does (`drive_form`); the check that ends
/// it looks at the same objects by their names in the object manager, and fails if they are not the ones made.
fn open_to_repair(place_path: &str, folder: bool) -> Result<Open, String> {
    let path = drive_form(place_path);
    let path = path.as_str();
    let flags = FILE_FLAG_OPEN_REPARSE_POINT | if folder { FILE_FLAG_BACKUP_SEMANTICS } else { 0 };
    let name = wide(path);
    let handle = unsafe {
        CreateFileW(name.as_ptr(), WRITE_DAC | WRITE_OWNER | READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_ALL, std::ptr::null_mut(), OPEN_EXISTING, flags, std::ptr::null_mut())
    };
    if handle == INVALID_HANDLE {
        return Err(format!("{} cannot be opened to set its permissions: {}", path, os_error().message()));
    }
    let file = Open(handle);
    let mut information = FileInformation::default();
    if unsafe { GetFileInformationByHandle(file.0, &mut information) } == 0 {
        return Err(format!("{} cannot be read: {}", path, os_error().message()));
    }
    if information.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!("{} is a link, which is not followed; remove it as described in the README and run this again", path));
    }
    if (information.attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != folder {
        return Err(format!("{} is not a {}; remove it as described in the README and run this again", path, if folder { "folder" } else { "file" }));
    }
    if !folder && information.links != 1 {
        return Err(format!("{} has more than one name; remove it as described in the README and run this again", path));
    }
    Ok(file)
}

/// Open an existing folder or record to set its permissions, and see that its owner is one that `authority` trusts: a folder or a
/// record that a user made first (a user may make files in a folder of the records that was made without the lists of the step, and
/// keep a handle it opened for writing before the step runs) is not taken over, because the step would set its list and its owner
/// and the handle would still write. The owner is read from the handle that is then used to set the permissions.
fn open_trusted(path: &str, folder: bool, authority: &Authority) -> Result<Open, String> {
    let api = record_api().ok_or("the system calls that check the lockout record are not available")?;
    let file = open_to_repair(path, folder)?;
    let shown = drive_form(path);
    let owner = security_of(api, file.0, OWNER_SECURITY_INFORMATION).map_err(|code| format!("the owner of {} cannot be read: {}", shown, error_for(code).message()))?;
    let text = owner_text(&owner);
    if !authority.trusted.contains(&text.as_str()) {
        return Err(format!("the {} {} is owned by {}, which is not the Administrators group, the system or the installer of the system, so it is not taken over; \
            remove it as described in the README and run this again", if folder { "folder" } else { "record" }, shown, if text.is_empty() { "an unknown owner" } else { &text }));
    }
    Ok(file)
}

/// Set the owner and the access list of the object `file` is open on, to `made`, protected.
fn apply_permissions(file: &Open, path: &str, made: &Made) -> Result<(), String> {
    let information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    if unsafe { SetKernelObjectSecurity(file.0, information, made.pointer) } == 0 {
        return Err(format!("the permissions of {} cannot be set: {}", drive_form(path), os_error().message()));
    }
    Ok(())
}

/// Set the owner and the access list of an object that exists, to `made`, protected. A folder or a record is taken over only if its
/// owner is one that `authority` trusts.
fn set_permissions(path: &str, folder: bool, made: &Made, authority: &Authority) -> Result<(), String> {
    apply_permissions(&open_trusted(path, folder, authority)?, path, made)
}

/// Have the volume keep the folder, or the record, uncompressed. A file or folder made in a compressed folder is compressed (the
/// attribute is inherited, and a volume can be compressed as a whole), and the volume allocates a compressed file in units that leave
/// no room for the next record (see `FileRecord::reserve`), so a record that is compressed refuses every run (see `judge_record`).
/// Nothing is sent to one that is not compressed. The contents of a record are not changed by this, only how the volume keeps them.
fn clear_compression(path: &str, folder: bool) -> Result<(), String> {
    let shown = drive_form(path);
    let name = wide(&shown);
    let flags = FILE_FLAG_OPEN_REPARSE_POINT | if folder { FILE_FLAG_BACKUP_SEMANTICS } else { 0 };
    let open = |access: u32| -> Result<Open, String> {
        let handle = unsafe { CreateFileW(name.as_ptr(), access, FILE_SHARE_ALL, std::ptr::null_mut(), OPEN_EXISTING, flags, std::ptr::null_mut()) };
        if handle == INVALID_HANDLE {
            return Err(format!("{} cannot be opened to make it uncompressed: {}", shown, os_error().message()));
        }
        Ok(Open(handle))
    };
    let mut information = FileInformation::default();
    let look = open(FILE_READ_ATTRIBUTES)?;
    if unsafe { GetFileInformationByHandle(look.0, &mut information) } == 0 {
        return Err(format!("{} cannot be read: {}", shown, os_error().message()));
    }
    if information.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!("{} is a link, which is not followed; remove it as described in the README and run this again", shown));
    }
    if information.attributes & FILE_ATTRIBUTE_COMPRESSED == 0 {
        return Ok(());
    }
    drop(look);
    let file = open(FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES)?;
    let (mut format, mut returned) = (0u16, 0u32);
    if unsafe { DeviceIoControl(file.0, FSCTL_SET_COMPRESSION, &mut format as *mut u16 as *mut c_void, 2, std::ptr::null_mut(), 0, &mut returned, std::ptr::null_mut()) } == 0 {
        return Err(format!("{} cannot be made uncompressed: {}", shown, os_error().message()));
    }
    Ok(())
}

/// Make the folder of the records, or set the permissions of the one that is there.
fn make_folder(place: &Place, authority: &Authority, say: &mut dyn FnMut(String)) -> Result<(), String> {
    let made = Made::from(&folder_sddl(authority))?;
    let shown = drive_form(&place.folder);
    let name = wide(&shown);
    let mut attributes = SecurityAttributes { length: std::mem::size_of::<SecurityAttributes>() as u32, descriptor: made.pointer, inherit: 0 };
    // The list is in force from the first instant: it is the list the folder is made with.
    if unsafe { CreateDirectoryW(name.as_ptr(), &mut attributes as *mut SecurityAttributes as *mut c_void) } != 0 {
        // Before the record is made in it, so that the record is not made compressed.
        clear_compression(&place.folder, true)?;
        say(format!("created folder {}", shown));
        return Ok(());
    }
    let code = unsafe { GetLastError() };
    if code != ERROR_ALREADY_EXISTS {
        return Err(format!("the folder {} cannot be made: {}", shown, error_for(code).message()));
    }
    set_permissions(&place.folder, true, &made, authority)?;
    clear_compression(&place.folder, true)?;
    say(format!("folder {}: permissions set", shown));
    Ok(())
}

/// Make the record, or set the permissions of the one that is there. The contents of a record that is there are never touched, a
/// record whose owner is not trusted is not taken over (see `open_trusted`), and one whose list allowed more than reading and
/// appending is not set right in place but refused (see below).
fn make_record(place: &Place, sid: &str, label: &str, authority: &Authority, as_this_account: bool, say: &mut dyn FnMut(String)) -> Result<(), String> {
    let made = Made::from(&record_sddl(authority, sid))?;
    let shown = drive_form(&place.record);
    let name = wide(&shown);
    let mut attributes = SecurityAttributes { length: std::mem::size_of::<SecurityAttributes>() as u32, descriptor: made.pointer, inherit: 0 };
    let handle = unsafe {
        // A link at the name is not followed: it makes the creation fail with a name that exists, and `open_trusted` below refuses it,
        // so the step never creates the file a planted link leads to (CWE-59).
        CreateFileW(name.as_ptr(), READ_CONTROL, FILE_SHARE_ALL, &mut attributes as *mut SecurityAttributes as *mut c_void, CREATE_NEW,
            FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OPEN_REPARSE_POINT, std::ptr::null_mut())
    };
    if handle != INVALID_HANDLE {
        drop(Open(handle));
        clear_compression(&place.record, false)?;
        say(format!("created record {} for {} ({})", shown, label, sid));
        return Ok(());
    }
    let code = unsafe { GetLastError() };
    if code != ERROR_FILE_EXISTS && code != ERROR_ALREADY_EXISTS {
        return Err(format!("the record {} cannot be made: {}", shown, error_for(code).message()));
    }
    // The record is there: its owner is looked at first, with the handle that is then used to set the permissions, before anything
    // is asked of it or done to it.
    let file = open_trusted(&place.record, false, authority)?;
    // A record whose list gave the account more than reading and appending is not set right: a program of the account may have
    // opened it for writing while it did, and keep that handle, which a new list does not revoke and which writes, truncates or
    // rewrites the record for ever; and what the record holds cannot be restored. It is the reason a record owned by someone else is
    // not taken over, applied to the list. The answer is to remove the record and make a new one. A record whose list is as it
    // should be, or that lacks only the owner rights entry, is set right. What the account is granted is asked of the system for
    // this account's own record; for another account's, whose token cannot be made, the record must be exactly as the step makes it.
    let api = record_api().ok_or("the system calls that check the lockout record are not available")?;
    if as_this_account {
        let limited = Limited::new(api)?;
        let found = inspect_handle(api, (limited.0).0, file.0).map_err(|code| format!("the record {} cannot be checked before its permissions are set: {}", shown, error_for(code).message()))?;
        let wide = excess(Object::Record, found.granted) & !authority.tolerated;
        if wide != 0 {
            return Err(format!("the record {} allowed {} to this account, so a program of the account may hold a handle that was opened while it did and writes to the record, and what the record holds cannot be trusted; \
                it is not set right in place; {}", shown, rights(wide, false).join(", "), remove_and_setup_for(&quoted(label))));
        }
        // The same for another account or group that the list gives something to: it may hold a handle that was opened while the
        // list allowed it more. Only the system, the Administrators group, this account and the owner rights entry may be in it.
        let held = security_of(api, file.0, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
            .map_err(|code| format!("the record {} cannot be checked before its permissions are set: {}", shown, error_for(code).message()))?;
        let other = parts(&held).ok_or_else(|| format!("the access list of the record {} cannot be read", shown)).and_then(|(_, list, _)| foreign_entry(&list, sid))?;
        if let Some(other) = other {
            return Err(format!("the record {} has an entry in its access list for another account or group ({}), which may hold a handle that was opened while it allowed more than reading and appending, \
                and what the record holds cannot be trusted; it is not set right in place; {}", shown, other, remove_and_setup_for(&quoted(label))));
        }
    } else {
        let held = security_of(api, file.0, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
            .map_err(|code| format!("the record {} cannot be checked before its permissions are set: {}", shown, error_for(code).message()))?;
        if parts(&held).is_none() || parts(&held) != parts(&made.words()) {
            return Err(format!("the record {} is not as the step makes it, and what it allowed the account cannot be told, so a program of that account may hold a handle that was opened while it allowed more and writes to the record, \
                and what the record holds cannot be trusted; it is not set right in place; {}", shown, remove_and_setup_for(&quoted(label))));
        }
    }
    apply_permissions(&file, &place.record, &made)?;
    drop(file);
    clear_compression(&place.record, false)?;
    say(format!("record {}: permissions set", shown));
    Ok(())
}

/// The setup step at `place` for the account with the security identifier `sid`, named `label` in what it says: make or set right the
/// folder and the record, then run the check that the guard runs, and fail if it does not pass. `as_this_account` is true when
/// the account is the one this process runs as, for which the check asks the system what a process of the account is granted; for
/// another account the owner and the access list are compared with what was set.
pub(crate) fn create_in(place: &Place, sid: &str, label: &str, authority: &Authority, as_this_account: bool, say: &mut dyn FnMut(String)) -> Result<(), String> {
    make_folder(place, authority, say)?;
    make_record(place, sid, label, authority, as_this_account, say)?;
    let expected = Made::from(&record_sddl(authority, sid))?.words();
    let check = if as_this_account { RecordCheck::Limited } else { RecordCheck::Exactly(&expected) };
    if let Err(fault) = verify(place, &check, authority.trusted) {
        return Err(format!("the permissions were set, but the check of the lockout record does not pass: {}", fault.reason));
    }
    if as_this_account {
        say(format!("verified: a process of this account without administrator rights can read and append the record and do nothing else.{}", NOT_PROTECTED));
    } else {
        say(format!("verified: the record of {} has the permissions that let a process of that account without administrator rights read and append it and do nothing else.{}", label, NOT_PROTECTED));
    }
    Ok(())
}

/// Whether `sid` is the system account or one of the two service accounts (local service and network service): accounts of a
/// deployment tool, which have no password to be asked for. The access list of a record for such an account would grant the
/// account what the system is granted, so the record could not pass the check that it exists to pass.
fn service_account(sid: &str) -> bool {
    matches!(sid, "S-1-5-18" | "S-1-5-19" | "S-1-5-20")
}

/// The setup step for `account` (the account the elevated token belongs to when there is none), at the folder of the programs'
/// data of this machine. `own_name` is how the account of this process is named in what is said, when it is the one set up.
pub(crate) fn create(account: Option<&str>, own_name: Option<String>, say: &mut dyn FnMut(String)) -> Result<(), String> {
    let (sid, label, as_this_account) = match account {
        Some(name) => {
            let sid = account_sid(name)?;
            let own = current_user_sid().map_err(|error| error.to_string())?;
            let same = sid == own;
            (sid, name.to_string(), same)
        }
        None => {
            let sid = current_user_sid().map_err(|error| error.to_string())?;
            let label = own_name.unwrap_or_else(|| sid.clone());
            if service_account(&sid) {
                return Err(format!("the elevated token belongs to {}, which has no password to ask for and no record can protect; name the account the guard will run as: process-tree-guard create-lockout-record ACCOUNT", label));
            }
            (sid, label, true)
        }
    };
    let place = Place::new(&program_data()?, &sid)?;
    create_in(&place, &sid, &label, &PRODUCTION, as_this_account, say)?;
    // For the account of this process only: the token of another account cannot be read from here. An account whose programs hold
    // privileges that let them act as the system gets a record that cannot protect it, and the guard refuses its runs over the cap.
    if as_this_account {
        match account_dangerous_privileges() {
            Ok(held) => {
                if let Some(warning) = privilege_warning(&held) {
                    say(warning);
                }
            }
            Err(why) => say(format!("warning: {}", why)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    const T0: u64 = 134_000_000_000_000_000;

    /// A test that cannot assert something here says so on the standard error handle itself, which the test harness does not capture,
    /// so the notice is shown on an ordinary run in which the test passes.
    fn not_asserted(text: impl std::fmt::Display) {
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), "NOTICE NOT ASSERTED {}", text);
    }

    /// The check of the guard with the owners that these tests' scratch trees have: the account running the tests owns what they
    /// make (only an administrator can make the Administrators group the owner), and the Administrators group owns what a process
    /// with an elevated token makes, which is how a continuous integration runner makes the scratch folders. The tests of the
    /// owners call `super::verify` with the lists they mean.
    fn verify(place: &Place, check: &RecordCheck) -> Result<Identity, Fault> {
        let sid = current_user_sid().expect("the user of this test");
        super::verify(place, check, &[sid.as_str(), "S-1-5-32-544"])
    }

    fn open_at(place: &Place) -> Result<FileRecord, String> {
        let sid = current_user_sid().expect("the user of this test");
        super::open_at(place, &[sid.as_str(), "S-1-5-32-544"])
    }

    /// What the record says about the account now: Ok(Some(reason)) when it is locked out, Ok(None) when it is not, and the reason in
    /// Err when the record cannot be read.
    fn state(record: &dyn Record) -> Result<Option<String>, String> {
        look(record).map(|(locked, _)| locked)
    }

    /// How many wrong passwords of the last six hours the record holds.
    fn failures_in_window(record: &dyn Record) -> Result<usize, String> {
        look(record).map(|(_, recorded)| recorded)
    }

    #[test]
    fn two_failures_do_not_lock_and_three_do() {
        assert_eq!(lockout(&[T0, T0 + HOUR], T0 + 2 * HOUR), None);
        let lock = lockout(&[T0, T0 + HOUR, T0 + 2 * HOUR], T0 + 3 * HOUR).unwrap();
        assert_eq!((lock.count, lock.last, lock.until), (3, T0 + 2 * HOUR, T0 + 8 * HOUR));
    }

    #[test]
    fn four_failures_count_four_and_end_six_hours_after_the_last() {
        let lock = lockout(&[T0, T0 + HOUR, T0 + 2 * HOUR, T0 + 3 * HOUR], T0 + 4 * HOUR).unwrap();
        assert_eq!((lock.count, lock.until), (4, T0 + 9 * HOUR));
    }

    #[test]
    fn failures_older_than_the_window_do_not_count() {
        // The third failure exactly six hours after the first: the first is out of (t - 6h, t].
        assert_eq!(lockout(&[T0, T0 + HOUR, T0 + 6 * HOUR], T0 + 6 * HOUR), None);
        assert!(lockout(&[T0, T0 + HOUR, T0 + 6 * HOUR - 1], T0 + 6 * HOUR).is_some());
        assert_eq!(lockout(&[T0, T0 + 10 * HOUR, T0 + 20 * HOUR], T0 + 21 * HOUR), None);
    }

    #[test]
    fn the_lockout_ends_six_hours_after_the_third_wrong_password_and_not_before() {
        let record = [T0, T0 + MINUTE, T0 + 2 * MINUTE];
        assert!(lockout(&record, T0 + 2 * MINUTE + WINDOW - 1).is_some());
        assert_eq!(lockout(&record, T0 + 2 * MINUTE + WINDOW), None);
        // After it ended, one more wrong password is the first of a new count: the old three are out of its window.
        let mut later = record.to_vec();
        later.push(T0 + 2 * MINUTE + WINDOW);
        assert_eq!(lockout(&later, T0 + 2 * MINUTE + WINDOW), None);
        later.push(T0 + 2 * MINUTE + WINDOW + MINUTE);
        assert_eq!(lockout(&later, T0 + 2 * MINUTE + WINDOW + MINUTE), None);
        later.push(T0 + 2 * MINUTE + WINDOW + 2 * MINUTE);
        assert!(lockout(&later, T0 + 2 * MINUTE + WINDOW + 2 * MINUTE).is_some());
    }

    #[test]
    fn adding_a_record_never_shortens_a_lockout() {
        // The end of the lockout in force, or nothing (which is the least).
        let until = |times: &[u64], now: u64| lockout(times, now).map_or(0, |lock| lock.until);
        let grid = [0, 1, 2 * MINUTE, HOUR, 2 * HOUR, 6 * HOUR - MINUTE, 6 * HOUR, 6 * HOUR + MINUTE, 12 * HOUR].map(|offset| T0 + offset);
        // Every set of up to four times from the grid (with repeats and in every order), every time of reading around and after the
        // lockouts they make, and every kind of addition: those of the grid, the time of reading, the edge of the skew just inside
        // and just outside, zero and the largest time.
        let mut bases: Vec<Vec<u64>> = vec![Vec::new()];
        for length in 1..=4usize {
            let mut count = 1;
            for _ in 0..length {
                count *= grid.len();
            }
            for number in 0..count {
                let (mut left, mut base) = (number, Vec::new());
                for _ in 0..length {
                    base.push(grid[left % grid.len()]);
                    left /= grid.len();
                }
                bases.push(base);
            }
        }
        let mut locked = 0;
        for now in [T0 + 3 * MINUTE, T0 + 6 * HOUR, T0 + 7 * HOUR] {
            let extras: Vec<u64> = grid.iter().copied().chain([now, now + SKEW, now + SKEW + 1, 0, u64::MAX]).collect();
            for base in &bases {
                let before = until(base, now);
                locked += (before != 0) as u32;
                for extra in &extras {
                    let mut more = base.clone();
                    more.push(*extra);
                    assert!(until(&more, now) >= before, "adding {} to {:?} at {} shortened the lockout", extra, base, now);
                }
            }
        }
        assert!(locked > 1000, "the sets that lock are many: {}", locked);
    }

    #[test]
    fn a_future_dated_record_cannot_end_a_lockout_and_cannot_lock_for_longer_than_six_hours_from_now() {
        let now = T0 + 10 * HOUR;
        // Far in the future: ignored entirely, so three of them lock nothing.
        assert_eq!(lockout(&[now + SKEW + 1, now + HOUR, now + 1000 * HOUR], now), None);
        // Within the skew: read as now, so the lockout ends at most six hours from now.
        let lock = lockout(&[now + SKEW, now + SKEW, now + 1], now).unwrap();
        assert_eq!(lock.until, now + WINDOW);
        assert!(lockout(&[u64::MAX, u64::MAX, u64::MAX], now).is_none());
    }

    #[test]
    fn a_lockout_from_failures_in_the_past_is_not_changed_by_future_records() {
        let now = T0 + 3 * MINUTE;
        let base = [T0, T0 + MINUTE, T0 + 2 * MINUTE];
        let mut more = base.to_vec();
        more.extend([now + 1000 * HOUR, now + 2000 * HOUR]);
        assert_eq!(lockout(&more, now), lockout(&base, now));
    }

    #[test]
    fn garbage_and_a_partial_trailing_record_are_ignored_and_a_torn_record_does_not_swallow_the_next() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"junk\r\nF 123\nF 00000000000000zz\nf 0000000000000001\nF 0000000000000001 \n \n");
        bytes.extend_from_slice(&encode(5));
        bytes.extend_from_slice(b"\nF 000000000000");              // torn: no newline, too short
        bytes.extend_from_slice(&encode(7));                         // the next write starts with a newline
        bytes.extend_from_slice(b"F 0000000000000009");             // partial trailing record without its newline: still a whole line
        assert_eq!(parse(&bytes), vec![5, 7, 9]);
        assert_eq!(parse(b""), Vec::<u64>::new());
        assert_eq!(parse(&[0xff, 0xfe, b'\n', 0, 0]), Vec::<u64>::new());
        // Upper case digits and a wrong prefix are garbage.
        assert_eq!(parse(b"F 00000000000000AA\nG 0000000000000001\nF  000000000000001\n"), Vec::<u64>::new());
    }

    #[test]
    fn many_records_are_one_pass() {
        // Not a timing: a record the size of a mebibyte in valid records is counted whole, in one pass over the times.
        let failures: Vec<u64> = (0..(1usize << 20) / RECORD_BYTES).map(|i| T0 + i as u64).collect();
        let lock = lockout(&failures, T0 + failures.len() as u64).unwrap();
        assert_eq!(lock.count, failures.len());
    }

    /// The failure times that can matter at `now` in `bytes`, read as the guard reads a record, in blocks of `BLOCK` bytes.
    fn read_from(bytes: &[u8], now: u64) -> Result<Vec<u64>, String> {
        read_failures(now, bytes.len() as u64, Duration::from_secs(60), |offset, block| {
            let (start, end) = (offset as usize, (offset as usize + block.len()).min(bytes.len()));
            block[..end - start].copy_from_slice(&bytes[start..end]);
            Ok(end - start)
        })
    }

    /// `bytes` through a `Scan` in pieces of `piece` bytes.
    fn scanned(bytes: &[u8], now: u64, piece: usize) -> Vec<u64> {
        let mut scan = Scan::new(now);
        for part in bytes.chunks(piece) {
            scan.feed(part);
        }
        scan.finish()
    }

    #[test]
    fn a_record_of_any_size_is_read_whole_and_the_failures_in_it_count_wherever_they_are() {
        let now = T0 + 3 * MINUTE;
        let real = [T0, T0 + MINUTE, T0 + 2 * MINUTE].map(encode).concat();
        let three_mebibytes = vec![b'x'; 3 << 20];
        // First, last, in the middle, and spread over the blocks; garbage of one long line or of many lines.
        let mut cases: Vec<(&str, Vec<u8>)> = vec![
            ("first", [real.clone(), three_mebibytes.clone()].concat()),
            ("last", [three_mebibytes.clone(), real.clone()].concat()),
            ("middle", [three_mebibytes[..1 << 20].to_vec(), real.clone(), three_mebibytes[..2 << 20].to_vec()].concat()),
            ("short lines", [real.clone(), b"junk\n".repeat((3 << 20) / 5)].concat()),
            ("torn records", [b"\nF 0000000000".repeat(200_000), real.clone()].concat()),
        ];
        // Each of the three real records in a block of its own.
        let mut spread = Vec::new();
        for t in [T0, T0 + MINUTE, T0 + 2 * MINUTE] {
            spread.extend_from_slice(&encode(t));
            spread.extend(vec![b'x'; BLOCK + 7]);
        }
        cases.push(("spread over blocks", spread));
        for (name, bytes) in &cases {
            let failures = read_from(bytes, now).expect(name);
            assert_eq!(failures, [T0, T0 + MINUTE, T0 + 2 * MINUTE], "{}", name);
            assert!(lockout(&failures, now).is_some(), "{}", name);
        }
        // Two hundred thousand records of the right form dated in the window: more than are kept, and the lockout is there and is the
        // one the whole set makes. Nothing in them ends it, and a count of them is not what the message says it is.
        let many: Vec<u64> = (0..200_000u64).map(|i| now - 11 * HOUR + i * (11 * HOUR) / 200_000).collect();
        let bytes: Vec<u8> = many.iter().flat_map(|t| encode(*t)).collect();
        let kept = read_from(&bytes, now).expect("read");
        assert_eq!(kept.len(), KEPT);
        assert_eq!(kept.last(), many.last());
        assert_eq!(lockout(&kept, now).map(|lock| lock.until), lockout(&many, now).map(|lock| lock.until));
        assert!(lockout(&kept, now).is_some());
    }

    #[test]
    fn a_line_longer_than_a_record_is_skipped_to_its_end_and_a_record_may_straddle_two_blocks() {
        let now = T0 + 3 * MINUTE;
        // A very long line that has the form of a record at its end: it is one line, and it is no record.
        let mut bytes = vec![b'x'; 3 * BLOCK];
        bytes.extend_from_slice(format!("F {:016x}", T0).as_bytes());
        assert_eq!(scanned(&bytes, T0, 1000), Vec::<u64>::new());
        // The next line, after its newline, is a line again.
        bytes.extend_from_slice(&encode(T0 + MINUTE));
        assert_eq!(read_from(&bytes, now).expect("read"), [T0 + MINUTE]);
        // A record at every offset around the end of a block.
        for shift in 0..(2 * RECORD_BYTES) {
            let mut padded = vec![b'\n'; BLOCK - shift];
            padded.extend_from_slice(&encode(T0));
            padded.extend_from_slice(&encode(T0 + MINUTE));
            assert_eq!(read_from(&padded, now).expect("read"), [T0, T0 + MINUTE], "shift {}", shift);
        }
        // The last line without its newline is a line.
        assert_eq!(scanned(format!("F {:016x}", T0).as_bytes(), T0, 4), [T0]);
        assert_eq!(scanned(format!("F {:016x}", T0 - 13 * HOUR).as_bytes(), T0, 4), Vec::<u64>::new(), "and one before the window is dropped");
        assert_eq!(read_from(b"", now), Ok(vec![]));
    }

    #[test]
    fn the_pieces_a_record_is_read_in_make_no_difference() {
        // A mixture of records, torn records, garbage and long lines, from a generator with a fixed seed.
        let now = T0 + 10 * HOUR;
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut bytes = Vec::new();
        for _ in 0..3000 {
            match next() % 6 {
                0 | 1 => bytes.extend_from_slice(&encode(now - (next() % (13 * HOUR)))),
                2 => bytes.extend_from_slice(b"\nF 00000000000"),
                3 => bytes.extend(vec![b'x'; (next() % 40) as usize]),
                4 => bytes.extend_from_slice(b"\n\n"),
                _ => bytes.extend_from_slice(b"F "),
            }
        }
        let whole = scanned(&bytes, now, bytes.len());
        assert!(whole.len() > 100);
        for piece in [1, 2, 3, 7, 19, 20, 21, 64, 1000] {
            assert_eq!(scanned(&bytes, now, piece), whole, "pieces of {}", piece);
        }
        // What is kept is what parse finds, within the window and not later than the skew, and nothing else.
        let expected: Vec<u64> = { let mut found: Vec<u64> = parse(&bytes).into_iter().filter(|t| *t > now - 2 * WINDOW && *t <= now + SKEW).collect(); found.sort_unstable(); found };
        assert_eq!(whole, expected);
    }

    #[test]
    fn dropping_the_oldest_of_a_great_many_never_changes_the_lockout() {
        let now = T0 + 20 * HOUR;
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        // Shapes of a record: dense in the old part, dense in the new part, dense at the edge of the window, two recent ones after a
        // great many old ones, and a mixture; each with enough times that the oldest are dropped.
        let shapes: Vec<Vec<u64>> = vec![
            (0..9000).map(|i| now - 11 * HOUR + i * 1000).collect(),
            (0..9000).map(|i| now - 2 * HOUR + i * 1000).collect(),
            (0..9000).map(|i| now - 6 * HOUR - 5 * MINUTE + i * 1000).collect(),
            (0..9000).map(|i| now - 11 * HOUR + i * 1000).chain([now - HOUR, now - 30 * MINUTE]).collect(),
            (0..9000).map(|_| now - (next() % (12 * HOUR))).collect(),
            (0..9000).map(|_| now - 6 * HOUR - (next() % (6 * HOUR))).chain([now - 3 * MINUTE, now - MINUTE]).collect(),
            (0..9000).map(|i| now - 12 * HOUR + i * 5000).chain([now - 3 * MINUTE]).collect(),
        ];
        for (number, times) in shapes.iter().enumerate() {
            let bytes: Vec<u8> = times.iter().flat_map(|t| encode(*t)).collect();
            let kept = read_from(&bytes, now).expect("read");
            assert!(kept.len() <= KEPT, "shape {}", number);
            let in_range: Vec<u64> = times.iter().copied().filter(|t| *t > now - 2 * WINDOW - MINUTE).collect();
            // The count is of what is kept, which is at most `KEPT`; the lockout is the same: the same last time and the same end.
            let (kept_lock, true_lock) = (lockout(&kept, now), lockout(&in_range, now));
            assert_eq!(kept_lock.map(|lock| (lock.last, lock.until)), true_lock.map(|lock| (lock.last, lock.until)), "shape {}", number);
            assert_eq!(kept_lock.is_some(), true_lock.is_some());
        }
    }

    /// The end of the lockout that a record's bytes make at `now`, read as the guard reads it; none is zero.
    fn lockout_end(bytes: &[u8], now: u64) -> u64 {
        lockout(&read_from(bytes, now).expect("read"), now).map_or(0, |lock| lock.until)
    }

    #[test]
    fn a_flood_of_records_dated_just_beyond_the_skew_cannot_push_real_failures_out() {
        let now = T0 + 3 * MINUTE;
        let real = [T0, T0 + MINUTE, T0 + 2 * MINUTE].map(encode).concat();
        for beyond in [SKEW + 1, SKEW + 30 * SECOND, SKEW + MINUTE, SKEW + MINUTE + 1] {
            let flood = encode(now + beyond).repeat(5000);
            let (flood_first, real_first) = ([flood.clone(), real.clone()].concat(), [real.clone(), flood.clone()].concat());
            for (name, bytes) in [("flood first", flood_first), ("real first", real_first)] {
                let kept = read_from(&bytes, now).expect("read");
                assert_eq!(kept, [T0, T0 + MINUTE, T0 + 2 * MINUTE], "{} dated {} beyond now: only the real failures are kept", name, beyond);
                assert_eq!(lockout(&kept, now).map(|lock| lock.until), Some(T0 + 2 * MINUTE + WINDOW), "{} dated {} beyond now", name, beyond);
            }
        }
    }

    #[test]
    fn a_second_flood_dated_past_a_later_time_cannot_hide_a_lockout_the_first_one_was_waiting_to_make() {
        // The first flood is dated 5m30s ahead of the first reading. Six minutes later it is within the skew and counts, and the
        // wrong passwords of a run are recorded behind it; a second flood, dated 5m30s ahead of the later reading, follows.
        let first = T0 + 3 * MINUTE;
        let later = first + 6 * MINUTE;
        let real = [T0, T0 + MINUTE, T0 + 2 * MINUTE].map(encode).concat();
        let batch_one = encode(first + SKEW + 30 * SECOND).repeat(5000);
        let run = [later - 3 * SECOND, later - 2 * SECOND, later - SECOND].map(encode).concat();
        let batch_two = encode(later + SKEW + 30 * SECOND).repeat(5000);
        let before = [real.clone(), batch_one.clone(), run.clone()].concat();
        let after = [real, batch_one, run, batch_two].concat();
        assert!(lockout_end(&before, later) > 0, "the lockout is in force at the later reading");
        assert!(lockout_end(&after, later) >= lockout_end(&before, later), "and the second flood does not hide it");
        // At the first reading nothing of either flood counts, and the real failures lock.
        assert_eq!(lockout_end(&after, first), T0 + 2 * MINUTE + WINDOW);
    }

    #[test]
    fn nothing_added_to_the_bytes_of_a_record_shortens_the_lockout_it_makes() {
        // Through the read path: the bytes, the scan, the trim and the rule. Records at every place around the edges of what is kept
        // and what the rule reads, garbage, and many repeats, added in front of and behind bases of every kind, from a fixed seed.
        let mut seed = 0x1357_9bdf_2468_ace0u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let now = T0 + 10 * HOUR;
        let grid = [
            0, now - 2 * WINDOW - MINUTE - 1, now - 2 * WINDOW - MINUTE, now - 2 * WINDOW, now - 2 * WINDOW + 1, now - WINDOW - 1, now - WINDOW,
            now - WINDOW + 1, now - HOUR, now - MINUTE, now - 1, now, now + 1, now + SKEW - 1, now + SKEW, now + SKEW + 1, now + SKEW + MINUTE,
            now + SKEW + MINUTE + 1, now + SKEW + 30 * SECOND, now + 1000 * HOUR, u64::MAX,
        ];
        let piece = |next: &mut dyn FnMut() -> u64| -> Vec<u8> {
            let time = grid[(next() % grid.len() as u64) as usize];
            match next() % 8 {
                0 => b"garbage without a newline".to_vec(),
                1 => b"\nF 00000000000".to_vec(),
                2 => encode(time).repeat(5000),
                3 => encode(time).repeat(1 + (next() % 4) as usize),
                _ => encode(time).to_vec(),
            }
        };
        let mut locked = 0;
        for _ in 0..400 {
            let mut base = Vec::new();
            for _ in 0..(next() % 6) {
                base.extend(piece(&mut next));
            }
            let before = lockout_end(&base, now);
            locked += (before != 0) as u32;
            for _ in 0..4 {
                let extra = piece(&mut next);
                let (behind, in_front) = ([base.clone(), extra.clone()].concat(), [extra, base.clone()].concat());
                assert!(lockout_end(&behind, now) >= before, "adding behind {:?} shortened the lockout", base.len());
                assert!(lockout_end(&in_front, now) >= before, "adding in front of {:?} shortened the lockout", base.len());
            }
        }
        assert!(locked > 20, "the bases that lock are many: {}", locked);
    }

    #[test]
    fn a_record_that_cannot_be_read_in_time_refuses_and_is_not_guessed_at_from_its_end() {
        let bytes = encode(T0).repeat(10);
        let refused = read_failures(T0, bytes.len() as u64, Duration::ZERO, |_, _| Ok(0));
        assert!(refused.err().map_or(false, |reason| reason.starts_with("the lockout record could not be read in time; an administrator must remove it as described in the README")));
        // An empty record needs no time, and a reader that fails refuses with its reason.
        assert_eq!(read_failures(T0, 0, Duration::ZERO, |_, _| Ok(0)), Ok(vec![]));
        assert_eq!(read_failures(T0, 20, Duration::from_secs(1), |_, _| Err("the lockout record could not be read: gone".into())), Err("the lockout record could not be read: gone".into()));
        // A reader that gives nothing before the end ends the reading with what it has.
        assert_eq!(read_failures(T0, 400, Duration::from_secs(1), |_, _| Ok(0)), Ok(vec![]));
    }

    #[test]
    fn the_time_left_is_rounded_up_to_the_minute() {
        let now = T0;
        assert_eq!(time_left(now + WINDOW, now), "6h 0m");
        assert_eq!(time_left(now + 5 * HOUR + 25 * MINUTE, now), "5h 25m");
        assert_eq!(time_left(now + 5 * HOUR + 24 * MINUTE + 1, now), "5h 25m");
        assert_eq!(time_left(now + 5 * HOUR + 24 * MINUTE, now), "5h 24m");
        assert_eq!(time_left(now + 60 * MINUTE, now), "1h 0m");
        assert_eq!(time_left(now + 59 * MINUTE + 1, now), "1h 0m");
        assert_eq!(time_left(now + 1, now), "1m");
        assert_eq!(time_left(now + 40 * MINUTE, now), "40m");
        assert_eq!(time_left(now, now), "0m");
    }

    #[test]
    fn the_clock_is_twelve_hour_with_no_leading_zero_on_the_hour() {
        assert_eq!(clock(20, 12), "8:12pm");
        assert_eq!(clock(2, 12), "2:12am");
        assert_eq!(clock(0, 5), "12:05am");
        assert_eq!(clock(12, 0), "12:00pm");
        assert_eq!(clock(23, 59), "11:59pm");
    }

    #[test]
    fn the_system_and_the_service_accounts_are_not_accounts_a_record_is_made_for() {
        for sid in ["S-1-5-18", "S-1-5-19", "S-1-5-20"] {
            assert!(service_account(sid), "{}", sid);
        }
        // An ordinary account, an account of a domain, the Administrators group and a lookalike are not.
        for sid in ["S-1-5-21-1-2-3-1001", "S-1-5-32-544", "S-1-5-180", "S-1-5-18-1", "", "s-1-5-18"] {
            assert!(!service_account(sid), "{}", sid);
        }
    }

    /// A record that holds fixed times, read at a fixed time, on a clock that is seven hours behind universal time.
    struct Fixed {
        failures: Vec<u64>,
        now: u64,
        unreadable: bool,
    }

    impl Record for Fixed {
        fn now(&self) -> u64 {
            self.now
        }

        fn failures(&self, _now: u64) -> Result<Vec<u64>, String> {
            if self.unreadable { Err("the lockout record could not be read".into()) } else { Ok(self.failures.clone()) }
        }

        fn add(&self, _filetime: u64) -> Result<(), String> {
            Err("this record takes nothing".into())
        }

        fn lock(&self) -> Result<Held<'_>, String> {
            Ok(Held::new(|| {}))
        }

        fn local_clock(&self, filetime: u64) -> (u16, u16) {
            let minutes = (filetime / MINUTE + 1440 - 7 * 60) % 1440;
            ((minutes / 60) as u16, (minutes % 60) as u16)
        }
    }

    /// A time of day on the first day of the clock of these tests, in universal time.
    fn at(hour: u64, minute: u64) -> u64 {
        (T0 / (24 * HOUR)) * 24 * HOUR + hour * HOUR + minute * MINUTE
    }

    #[test]
    fn the_message_gives_the_count_the_last_time_the_time_left_rounded_up_and_the_end_in_local_time() {
        // Local time is seven hours behind: the wrong passwords at 3:10, 3:11 and 3:12 universal time are 8:10, 8:11 and 8:12 in the evening.
        let failures = vec![at(3, 10), at(3, 11), at(3, 12)];
        let said = |now: u64| state(&Fixed { failures: failures.clone(), now, unreadable: false });
        assert_eq!(said(at(3, 47)), Ok(Some("locked out after 3 wrong passwords, the last at 8:12pm; the password can be asked again in 5h 25m, at 2:12am".into())));
        // A second more of the time left rounds the minutes up, not down; a second less rounds the last minute down to the minute it is.
        assert!(said(at(3, 47) + SECOND).unwrap().unwrap().contains("in 5h 25m, at 2:12am"));
        assert!(said(at(3, 48)).unwrap().unwrap().contains("in 5h 24m, at 2:12am"));
        assert!(said(at(9, 11)).unwrap().unwrap().contains("in 1m, at 2:12am"));
        assert!(said(at(9, 12) - 1).unwrap().unwrap().contains("in 1m, at 2:12am"));
        assert_eq!(said(at(9, 12)), Ok(None), "the lockout is over at the minute it ends");
        // Four wrong passwords say four; a record that cannot be read says why.
        let four = Fixed { failures: vec![at(3, 9), at(3, 10), at(3, 11), at(3, 12)], now: at(4, 0), unreadable: false };
        assert!(state(&four).unwrap().unwrap().starts_with("locked out after 4 wrong passwords, the last at 8:12pm;"));
        assert_eq!(state(&Fixed { failures: vec![], now: at(4, 0), unreadable: true }), Err("the lockout record could not be read".into()));
        // Two wrong passwords, or three too far apart, do not lock.
        assert_eq!(said(at(3, 30)).map(|locked| locked.is_some()), Ok(true));
        assert_eq!(state(&Fixed { failures: vec![at(3, 10), at(3, 12)], now: at(4, 0), unreadable: false }), Ok(None));
        assert_eq!(state(&Fixed { failures: vec![at(3, 10), at(10, 10), at(17, 10)], now: at(18, 0), unreadable: false }), Ok(None));
    }

    #[test]
    fn the_end_of_the_lockout_is_shown_rounded_up_to_the_minute_so_that_the_time_named_is_not_already_past_for_records_dated_by_the_clock() {
        // The third wrong password at 3:12:30 universal time, 8:12pm on the clock of these tests: the lockout ends at 9:12:30, which is
        // 2:12:30am, and the person is told 2:13am. A run at 2:12am is still refused, and is told the same.
        let failures = vec![at(3, 10), at(3, 11), at(3, 12) + 30 * SECOND];
        let said = |now: u64| state(&Fixed { failures: failures.clone(), now, unreadable: false }).unwrap().unwrap();
        // 5h 25m 30s left: 5h 26m, rounded up.
        assert_eq!(said(at(3, 47)), "locked out after 3 wrong passwords, the last at 8:12pm; the password can be asked again in 5h 26m, at 2:13am");
        assert_eq!(said(at(3, 47) + 30 * SECOND), "locked out after 3 wrong passwords, the last at 8:12pm; the password can be asked again in 5h 25m, at 2:13am");
        // Ten seconds into the minute the lockout ends in, it is still on and still says a minute and the minute it ends in.
        assert!(said(at(9, 12) + 10 * SECOND).ends_with("in 1m, at 2:13am"));
        assert_eq!(state(&Fixed { failures: failures.clone(), now: at(9, 12) + 30 * SECOND, unreadable: false }), Ok(None));
        // A whole minute is unchanged by the rounding.
        assert!(state(&Fixed { failures: vec![at(3, 10), at(3, 11), at(3, 12)], now: at(3, 47), unreadable: false }).unwrap().unwrap().ends_with("in 5h 25m, at 2:12am"));
        // A record dated ahead of the clock by less than the skew is read as now, so the end named for it moves later as the clock
        // reaches it (by up to the skew), and is never more than six hours from now: the claim above is for records dated by the clock.
        let ahead = vec![at(3, 14), at(3, 14), at(3, 14)];
        let first = state(&Fixed { failures: ahead.clone(), now: at(3, 10), unreadable: false }).unwrap().unwrap();
        let later = state(&Fixed { failures: ahead, now: at(3, 15), unreadable: false }).unwrap().unwrap();
        assert!(first.ends_with("in 6h 0m, at 2:10am"), "{}", first);
        assert!(later.ends_with("in 5h 59m, at 2:14am"), "{}", later);
    }

    #[test]
    fn the_wrong_passwords_of_the_last_six_hours_are_counted_for_the_prompt() {
        let count = |failures: &[u64], now: u64| failures_in_window(&Fixed { failures: failures.to_vec(), now, unreadable: false });
        assert_eq!(count(&[], at(9, 0)), Ok(0));
        assert_eq!(count(&[at(8, 0), at(8, 30)], at(9, 0)), Ok(2));
        // Exactly six hours old is out, a unit less is in; a time a little ahead is read as now, a time far ahead is not counted.
        assert_eq!(count(&[at(3, 0), at(3, 0) + 1], at(9, 0)), Ok(1));
        assert_eq!(count(&[at(9, 0) + SKEW, at(9, 0) + SKEW + 1, u64::MAX], at(9, 0)), Ok(1));
        assert_eq!(failures_in_window(&Fixed { failures: vec![], now: 0, unreadable: true }), Err("the lockout record could not be read".into()));
    }

    #[test]
    fn the_clock_of_this_computer_gives_the_time_of_day_a_whole_number_of_quarter_hours_from_universal_time() {
        // The zone of the machine is not known here, so what is asserted is what holds in every zone: a time of day, the same
        // minute of the hour but for zones at an offset of a quarter, and an hour more for an hour more.
        for filetime in [at(3, 12), at(15, 0), at(23, 59) + 30 * SECOND] {
            let (hour, minute) = local_clock_of(filetime);
            assert!(hour < 24 && minute < 60, "{} {}", hour, minute);
            let universal = (filetime / MINUTE) % 1440;
            let local = hour as u64 * 60 + minute as u64;
            assert_eq!((local + 1440 - universal) % 15, 0, "{} {} against {}", hour, minute, universal);
        }
        let (a, b) = (local_clock_of(at(3, 12)), local_clock_of(at(3, 12) + 5 * MINUTE));
        assert_eq!((b.0 as u32 * 60 + b.1 as u32 + 1440 - (a.0 as u32 * 60 + a.1 as u32)) % 1440, 5);
        assert_eq!(local_clock_of(u64::MAX), (0, 0), "a time that is not a time");
    }

    #[test]
    fn the_folder_of_the_programs_data_is_the_registry_value_on_the_system_volume_named_from_the_object_manager_and_nothing_from_the_environment() {
        let path = |raw: &str, windows: &str| program_data_path(raw, windows);
        assert_eq!(path("%SystemDrive%\\ProgramData", "C:\\WINDOWS"), Ok("C:\\ProgramData".to_string()));
        assert_eq!(path("%SYSTEMDRIVE%\\ProgramData", "d:\\Windows"), Ok("d:\\ProgramData".to_string()));
        assert_eq!(path("E:\\Data\\Program Data\\", "C:\\WINDOWS"), Ok("E:\\Data\\Program Data".to_string()));
        for bad in ["%ALLUSERSPROFILE%\\x", "%SystemDrive%\\%PUBLIC%", "C:%SystemDrive%\\x", "Z:evil", "\\\\server\\share\\x", "C:\\a\\..\\b", "C:/x/y", "", "C:\\", "C:", "..\\x", "C:\\a\\.\\b"] {
            assert!(path(bad, "C:\\WINDOWS").is_err(), "{:?}", bad);
        }
        assert!(path("%SystemDrive%\\ProgramData", "\\\\?\\C:\\Windows").is_err(), "a system folder that is not on a drive");
        assert!(path("%SystemDrive%\\ProgramData", "").is_err());
        // The drive is replaced by the system volume, and a folder on another drive is refused: which volume a drive letter leads to is
        // not known without the device map of the logon session, which a process of the account can change.
        let device = "\\Device\\HarddiskVolume3";
        assert_eq!(anchored("C:\\ProgramData", "C:\\WINDOWS", device), Ok("\\Device\\HarddiskVolume3\\ProgramData".to_string()));
        assert_eq!(anchored("c:\\Data\\Program Data", "C:\\Windows", device), Ok("\\Device\\HarddiskVolume3\\Data\\Program Data".to_string()));
        let elsewhere = anchored("E:\\Data\\Program Data", "C:\\WINDOWS", device).expect_err("a folder on another drive");
        assert!(elsewhere.contains("is not on the system drive (C:)") && elsewhere.contains("E:\\Data\\Program Data"), "{}", elsewhere);
        // The machine's own value: a folder on the system volume named from the object manager, and not the folder of any environment
        // variable the test could set.
        let real = program_data().expect("the folder of the programs' data of this machine");
        let (volume, rest) = split_device(&real).expect("a name from the object manager");
        assert!(volume.to_lowercase().starts_with("\\device\\") && rest.starts_with('\\') && !real.contains('%'), "{}", real);
        // It is the folder that the drive leads to, as the system's device map has it in a test that does not change it.
        let on_drive = drive_form(&real);
        assert!(on_drive.len() > 3 && on_drive.as_bytes()[1] == b':', "{}", on_drive);
        let folder = Open(open_raw(&on_drive, FILE_READ_ATTRIBUTES, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS).expect("the folder of the programs' data, by its drive"));
        assert!(same_path(&final_path(folder.0).expect("its name"), &real), "{} against {}", on_drive, real);
    }

    #[test]
    fn a_name_from_the_object_manager_is_told_from_a_name_on_a_drive_and_is_split_into_its_volume_and_what_is_on_it() {
        assert_eq!(split_device("\\Device\\HarddiskVolume3\\ProgramData\\x"), Some(("\\Device\\HarddiskVolume3", "\\ProgramData\\x")));
        assert_eq!(split_device("\\device\\HarddiskVolume3"), Some(("\\device\\HarddiskVolume3", "")));
        assert_eq!(split_device("\\Device\\HarddiskVolume3\\"), Some(("\\Device\\HarddiskVolume3", "\\")));
        for not in ["C:\\Windows", "\\??\\C:\\Windows", "\\Device", "\\Device\\", "Device\\X\\y", "", "\\Devices\\X\\y", "\\\\Device\\X"] {
            assert_eq!(split_device(not), None, "{:?}", not);
        }
        assert_eq!(nt_name("C:\\Users\\x"), "\\??\\C:\\Users\\x");
        assert_eq!(nt_name("\\Device\\HarddiskVolume3\\x"), "\\Device\\HarddiskVolume3\\x");
        assert_eq!(on_drive("\\Device\\HarddiskVolume3\\ProgramData\\ProcessTreeGuard", "\\Device\\HarddiskVolume3", "C:"), "C:\\ProgramData\\ProcessTreeGuard");
        assert_eq!(on_drive("\\device\\harddiskvolume3\\x", "\\Device\\HarddiskVolume3", "C:"), "C:\\x");
        assert_eq!(on_drive("\\Device\\HarddiskVolume5\\x", "\\Device\\HarddiskVolume3", "C:"), "\\Device\\HarddiskVolume5\\x", "another volume is not given a drive");
        assert_eq!(on_drive("D:\\x", "\\Device\\HarddiskVolume3", "C:"), "D:\\x");
        assert!(same_path("\\Device\\HarddiskVolume3\\ProgramData\\A.lockout", "\\device\\harddiskvolume3\\programdata\\a.LOCKOUT"));
        assert!(!same_path("\\Device\\HarddiskVolume3\\ProgramData\\A.lockout", "\\Device\\HarddiskVolume5\\ProgramData\\A.lockout"));
        // The system volume is found as the kernel's own link names it, and is the volume of the system folder.
        let api = record_api().expect("the system calls");
        let device = system_device(api).expect("the system volume");
        let windows = Open(open_raw(&windows_folder().expect("the system folder"), FILE_READ_ATTRIBUTES, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS).expect("open it by its drive"));
        assert_eq!(split_device(&final_path(windows.0).expect("its name")).map(|(volume, _)| volume.to_lowercase()), Some(device.to_lowercase()));
    }

    #[test]
    fn the_security_identifier_of_the_account_must_be_a_name_a_file_can_have() {
        assert!(Place::new("C:\\ProgramData", "S-1-5-21-1-2-3-1001").is_ok());
        for bad in ["", "S", "1-5-21", "S-1-5-21-1\\..\\x", "S-1-5-21-1.lockout", "s-1-5", "S-1-5-21-1 ", "S-1-5-21-1:x"] {
            assert!(Place::new("C:\\ProgramData", bad).is_err(), "{:?}", bad);
        }
        let place = Place::new("C:\\ProgramData", "S-1-5-21-1-2-3-1001").unwrap();
        assert_eq!((place.folder.as_str(), place.record.as_str()), ("C:\\ProgramData\\ProcessTreeGuard", "C:\\ProgramData\\ProcessTreeGuard\\S-1-5-21-1-2-3-1001.lockout"));
    }

    #[test]
    fn the_access_lists_are_the_ones_of_the_design_and_the_system_accepts_them() {
        let sid = "S-1-5-21-1-2-3-1001";
        assert_eq!(folder_sddl(&PRODUCTION), "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a0;;;AU)");
        assert_eq!(record_sddl(&PRODUCTION, sid), "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12008d;;;S-1-5-21-1-2-3-1001)(A;;0x20000;;;OW)");
        assert!(!folder_sddl(&PRODUCTION).contains("OICI") && !record_sddl(&PRODUCTION, sid).contains("OICI"), "no entry is inherited by what is made in it");
        for sddl in [folder_sddl(&PRODUCTION), record_sddl(&PRODUCTION, sid)] {
            let made = Made::from(&sddl).expect("the system accepts the list");
            let (owner, list, protected) = parts(&made.words()).expect("a self-relative descriptor with an owner and a list");
            // The owner is the Administrators group, S-1-5-32-544: revision 1, two sub authorities, authority 5.
            assert_eq!(owner, [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 0x02, 0, 0], "{}", sddl);
            assert!(protected && list.len() > 8, "{}", sddl);
        }
        assert!(Made::from("this is not a list").is_err());
    }

    #[test]
    fn the_rights_of_each_object_are_judged_and_named() {
        // The record: read, append and what goes with reading; nothing else.
        assert_eq!(excess(Object::Record, 0x12008d), 0);
        assert_eq!(excess(Object::Record, 0x120085), 0);
        assert_eq!(rights(excess(Object::Record, 0x120087), false), ["WRITE_DATA"]);
        assert_eq!(rights(excess(Object::Record, 0x1f01ff), false), ["WRITE_DATA", "WRITE_EA", "EXECUTE", "DELETE_CHILD", "WRITE_ATTRIBUTES", "DELETE", "WRITE_DAC", "WRITE_OWNER"]);
        assert_eq!(rights(excess(Object::Record, 0x160085), false), ["WRITE_DAC"]);
        assert_eq!(rights(excess(Object::Record, 0x1301bf), false), ["WRITE_DATA", "WRITE_EA", "EXECUTE", "WRITE_ATTRIBUTES", "DELETE"]);
        assert_eq!(rights(excess(Object::Record, 0x0100_0085), false), ["OTHER_RIGHTS"]);
        // The folder of the records: list it, read its attributes, pass through it.
        assert_eq!(excess(Object::Folder, 0x1200a0), 0);
        assert_eq!(excess(Object::Folder, 0x1200a9), 0);
        assert_eq!(rights(excess(Object::Folder, 0x1200a2), true), ["ADD_FILE"]);
        assert_eq!(rights(excess(Object::Folder, 0x1200e4), true), ["ADD_SUBDIRECTORY", "DELETE_CHILD"]);
        assert_eq!(rights(excess(Object::Folder, 0x1300a0), true), ["DELETE"]);
        assert_eq!(rights(excess(Object::Folder, 0x1301a0), true), ["WRITE_ATTRIBUTES", "DELETE"]);
        // The folder of the programs' data and the folders between it and the root of the drive: folders may be made in it, and not
        // deleted or renamed (what is in it nor it), and its list and its owner are not changed.
        assert_eq!(excess(Object::ProgramData, 0x1201bf), 0);
        assert_eq!(rights(excess(Object::ProgramData, 0x1201ff), true), ["DELETE_CHILD"]);
        assert_eq!(rights(excess(Object::ProgramData, 0x1e01bf), true), ["WRITE_DAC", "WRITE_OWNER"]);
        assert_eq!(rights(excess(Object::ProgramData, 0x1301bf), true), ["DELETE"]);
        assert_eq!(rights(excess(Object::ProgramData, 0x1f01ff), true), ["DELETE_CHILD", "DELETE", "WRITE_DAC", "WRITE_OWNER"]);
        assert_eq!(excess(Object::ProgramData, 0), 0);
        // The root of the drive keeps the judgment it had: it cannot be deleted or renamed in any case, and a data volume may give
        // the account the right to delete the folder it makes in it.
        assert_eq!(excess(Object::DriveRoot, 0x1301bf), 0);
        assert_eq!(excess(Object::DriveRoot, 0x1201bf), 0);
        assert_eq!(rights(excess(Object::DriveRoot, 0x1f01ff), true), ["DELETE_CHILD", "WRITE_DAC", "WRITE_OWNER"]);
    }

    #[test]
    fn the_account_of_this_process_is_found_by_its_name_and_a_group_or_a_name_that_is_not_there_is_not() {
        let own = crate::auth::own_account_name().expect("the name of the account this test runs as");
        assert_eq!(account_sid(&own), current_user_sid().map_err(|error| error.to_string()));
        assert!(account_sid("no-such-account-ptg-8f3a").is_err());
        assert!(account_sid("").is_err());
        // A group is not a user whose password can be asked.
        let group = account_sid("BUILTIN\\Users");
        assert!(group.is_err(), "{:?}", group);
    }

    // ------------------------------------------------------ the record in a scratch folder

    #[link(name = "kernel32")]
    extern "system" {
        fn DeleteFileW(name: *const u16) -> Bool;
        fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> Bool;
        fn CreateHardLinkW(new: *const u16, existing: *const u16, security: *mut c_void) -> Bool;
        fn RemoveDirectoryW(name: *const u16) -> Bool;
        fn SetEndOfFile(file: Handle) -> Bool;
        fn SetFilePointerEx(file: Handle, distance: i64, new: *mut i64, method: u32) -> Bool;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn SetThreadToken(thread: *mut Handle, token: Handle) -> Bool;
    }

    const ACCESS_DENIED: u32 = 5;
    const DELETE: u32 = 0x10000;
    const TOKEN_IMPERSONATE: u32 = 4;

    /// This thread acts as a process of the account without administrator rights until this is dropped, whether the test runs with
    /// those rights (a continuous integration runner does) or not.
    struct Impersonating(#[allow(dead_code)] Limited);

    impl Impersonating {
        fn begin() -> Impersonating {
            let limited = Limited::with_access(record_api().expect("the system calls"), TOKEN_QUERY | TOKEN_IMPERSONATE).expect("the token of a process without administrator rights");
            assert_ne!(unsafe { SetThreadToken(std::ptr::null_mut(), (limited.0).0) }, 0, "{}", os_error());
            Impersonating(limited)
        }
    }

    impl Drop for Impersonating {
        fn drop(&mut self) {
            unsafe { SetThreadToken(std::ptr::null_mut(), std::ptr::null_mut()) };
        }
    }

    fn open_raw(path: &str, access: u32, disposition: u32, flags: u32) -> Result<Handle, u32> {
        let handle = unsafe { CreateFileW(wide(path).as_ptr(), access, FILE_SHARE_ALL, std::ptr::null_mut(), disposition, flags, std::ptr::null_mut()) };
        if handle == INVALID_HANDLE { Err(unsafe { GetLastError() }) } else { Ok(handle) }
    }

    fn opened(path: &str, access: u32, disposition: u32, flags: u32) -> Result<(), u32> {
        open_raw(path, access, disposition, flags).map(|handle| drop(Open(handle)))
    }

    fn ok_or_code(ok: Bool) -> Result<(), u32> {
        if ok == 0 { Err(unsafe { GetLastError() }) } else { Ok(()) }
    }

    /// Whether the volume keeps `path` compressed.
    fn is_compressed(path: &str) -> bool {
        use std::os::windows::fs::MetadataExt;
        std::fs::metadata(path).map_or(false, |found| found.file_attributes() & FILE_ATTRIBUTE_COMPRESSED != 0)
    }

    /// Have the volume compress (`'c'`) or uncompress (`'u'`) `path`, with the tool that does it by hand, and say whether it is now
    /// compressed as asked: it is not on a volume that cannot compress.
    fn compact(path: &str, direction: char) -> bool {
        let done = std::process::Command::new("compact").arg(format!("/{}", direction)).arg(path).stdin(std::process::Stdio::null()).output();
        done.is_ok() && is_compressed(path) == (direction == 'c')
    }

    /// Append `bytes` through a handle that has the right to append and no other: the way a process of the account can.
    fn append_raw(path: &str, bytes: &[u8]) -> Result<u32, u32> {
        let handle = Open(open_raw(path, FILE_APPEND_DATA | FILE_READ_ATTRIBUTES, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH)?);
        let mut written = 0u32;
        ok_or_code(unsafe { WriteFile(handle.0, bytes.as_ptr() as *const c_void, bytes.len() as u32, &mut written, std::ptr::null_mut()) })?;
        Ok(written)
    }

    /// What the record holds, read with the rights the account has (not the generic read, which asks for more).
    fn contents(path: &str) -> Vec<u8> {
        let file = Open(open_raw(path, FILE_READ_DATA | FILE_READ_ATTRIBUTES, OPEN_EXISTING, 0).expect("open the record to read it"));
        let mut size = 0i64;
        assert_ne!(unsafe { GetFileSizeEx(file.0, &mut size) }, 0);
        let mut bytes = vec![0u8; size as usize];
        let mut have = 0usize;
        while have < bytes.len() {
            let mut read = 0u32;
            assert_ne!(unsafe { ReadFile(file.0, bytes[have..].as_mut_ptr() as *mut c_void, (bytes.len() - have) as u32, &mut read, std::ptr::null_mut()) }, 0);
            assert!(read > 0);
            have += read as usize;
        }
        bytes
    }

    /// A scratch folder that stands for the folder of the programs' data, with the folder of the records and the record in it, made
    /// and set right by the code of the setup step under an authority of the test's own: the owner is the account running the test,
    /// since only an administrator can make the Administrators group the owner. The test keeps a handle to each of the three that can
    /// change its access list, opened before the list took that right away, to give the folder back to the account in the end.
    struct Fixture {
        root: PathBuf,
        place: Place,
        /// The account running the test, and the owner of everything the fixture makes.
        sid: String,
        /// The account the record is for: this one, or another's.
        account: String,
        keys: Vec<Handle>,
        said: Vec<String>,
    }

    /// The owner rights entry that takes the owner's own rights away, as the list of the record has it.
    const OWNER_RIGHTS: &str = "(A;;0x20000;;;OW)";

    /// An account other than the one running the tests.
    const ANOTHER: &str = "S-1-5-21-1-2-3-4321";

    impl Fixture {
        /// The record of this account, empty.
        fn new() -> Fixture {
            Fixture::build(None, b"")
        }

        /// The record of `account` (this account's when none), holding `content` before the step sets the lists right.
        fn build(account: Option<&str>, content: &[u8]) -> Fixture {
            Fixture::build_in(account, content, false)
        }

        /// As `build`, in a folder of the programs' data that the volume keeps compressed when `compressed` (what is made in it
        /// would be compressed, as it is in a folder that an administrator compressed or on a compressed volume).
        fn build_in(account: Option<&str>, content: &[u8], compressed: bool) -> Fixture {
            static COUNT: AtomicU32 = AtomicU32::new(0);
            let sid = current_user_sid().expect("the user of this test");
            let account = account.map_or_else(|| sid.clone(), str::to_string);
            let root = std::env::temp_dir().join(format!("ptg-lockout-{}-{}", std::process::id(), COUNT.fetch_add(1, Ordering::SeqCst)));
            let programdata = root.join("pd");
            std::fs::create_dir_all(&programdata).expect("make the scratch folder");
            std::fs::create_dir_all(root.join("free")).expect("make the free folder");
            if compressed {
                compact(&programdata.to_string_lossy(), 'c');
            }
            // The folders above the scratch tree are the account's own: they are looked at by their own tests, not here.
            let mut place = Place::new(&programdata.to_string_lossy(), &account).expect("a place");
            place.ancestors.clear();
            let mut fixture = Fixture { root, place, sid, account, keys: Vec::new(), said: Vec::new() };
            {
                // Made with full control for the account running the test, so that the test can open them for the right to change the list.
                let full = format!("(A;;FA;;;{})", fixture.sid);
                let trusted = [fixture.sid.as_str(), "S-1-5-32-544"];
                let authority = Authority { owner: &fixture.sid, trusted: &trusted, folder: &full, record: &full, tolerated: 0 };
                make_folder(&fixture.place, &authority, &mut |_| {}).expect("make the folder");
                make_record(&fixture.place, &fixture.account, "the account", &authority, fixture.is_this_account(), &mut |_| {}).expect("make the record");
            }
            if !content.is_empty() {
                append_raw(&fixture.place.record, content).expect("put something in the record");
            }
            for (path, folder) in [(fixture.place.programdata.clone(), true), (fixture.place.folder.clone(), true), (fixture.place.record.clone(), false)] {
                let key = open_raw(&path, WRITE_DAC | READ_CONTROL, OPEN_EXISTING, if folder { FILE_FLAG_BACKUP_SEMANTICS } else { 0 }).expect("a key");
                fixture.keys.push(key);
            }
            // The folder of the programs' data: the account may make folders in it, and may not delete them or change its list.
            fixture.set(0, &format!("D:P(A;;0x1200a6;;;{})(A;;0x20000;;;OW)", fixture.sid));
            // The record, made with full control for the account so that the keys could be opened, is given the list the step sets
            // (and the right to change it, which the step needs to open it in a test that runs without administrator rights): a
            // record that allowed more is not set right in place.
            fixture.set(2, &fixture.record_start());
            // The step, run again over what is there, sets the folder and the record right and checks them.
            let mut said = Vec::new();
            fixture.run(&mut said).expect("the step over what is there");
            fixture.said = said;
            fixture
        }

        fn is_this_account(&self) -> bool {
            self.account == self.sid
        }

        /// The step, with the authority of the test and the restricted lists. It can open the folder and the record to set their lists
        /// only while the account running the test has the right to, as an administrator always has: so it is run over a list that
        /// gives that right (the fixture's own first run, a list with `WRITE_DAC` and `WRITE_OWNER` in it).
        fn run(&self, said: &mut Vec<String>) -> Result<(), String> {
            let trusted = [self.sid.as_str(), "S-1-5-32-544"];
            let added = self.record_added();
            let authority = Authority { owner: &self.sid, trusted: &trusted, folder: OWNER_RIGHTS, record: &added, tolerated: WRITE_DAC | WRITE_OWNER };
            create_in(&self.place, &self.account, "the account", &authority, self.is_this_account(), &mut |line| said.push(line))
        }

        /// What the test's authority adds to the access list of a record. Nothing for the record of this account. For the record of
        /// another account it lets the account running the test read the attributes of what it checks, which an administrator
        /// can do without being let (the account is only the owner here, and the owner rights entry takes that away), and change
        /// its list and owner, which the step needs to open the record in a test that runs without administrator rights.
        fn record_added(&self) -> String {
            if self.is_this_account() { String::new() } else { format!("(A;;0x1c0080;;;{})", self.sid) }
        }

        /// The list a record has when the step is run over it in a test: the list the step sets, and for this account the right to
        /// change the list and the owner as well (tolerated by the authority of the test), which another account's record has in
        /// `record_added`.
        fn record_start(&self) -> String {
            if self.is_this_account() { self.record_list(0x12008d | WRITE_DAC | WRITE_OWNER) } else { format!("{}{}", self.record_list(0x12008d), self.record_added()) }
        }

        /// The access list of the record as the step sets it, with `mask` as the rights of the account.
        fn record_list(&self, mask: u32) -> String {
            format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;{:#x};;;{}){}", mask, self.account, OWNER_RIGHTS)
        }

        /// The access list of the folder as the step sets it, with `mask` as the rights of the account running the test (the step
        /// gives them to the signed-in accounts, which include it).
        fn folder_list(&self, mask: u32) -> String {
            format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;{:#x};;;{}){}", mask, self.sid, OWNER_RIGHTS)
        }

        /// Set the access list of the folder of the programs' data (0), the folder (1) or the record (2).
        fn set(&self, which: usize, sddl: &str) {
            let made = Made::from(sddl).expect("a list");
            assert_ne!(unsafe { SetKernelObjectSecurity(self.keys[which], DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, made.pointer) }, 0, "{}", os_error());
        }

        /// The record removed, as an administrator removes it, and made again as a new one with the list a test can open (see
        /// `record_start`). The record has the list that gives the account full control when this is called.
        fn start_over(&mut self) {
            // The key to the old record is let go of first: a file with a handle open is removed only when the last one is closed.
            unsafe { CloseHandle(self.keys[2]) };
            self.keys[2] = std::ptr::null_mut();
            self.set(1, &format!("D:P(A;;FA;;;{})", self.sid));
            std::fs::remove_file(&self.place.record).expect("remove the record");
            let full = format!("(A;;FA;;;{})", self.sid);
            let trusted = [self.sid.as_str(), "S-1-5-32-544"];
            let authority = Authority { owner: &self.sid, trusted: &trusted, folder: &full, record: &full, tolerated: 0 };
            make_record(&self.place, &self.account, "the account", &authority, self.is_this_account(), &mut |_| {}).expect("make the record again");
            self.keys[2] = open_raw(&self.place.record, WRITE_DAC | READ_CONTROL, OPEN_EXISTING, 0).expect("a key");
            self.set(2, &self.record_start());
        }

        fn free(&self, name: &str) -> String {
            self.root.join("free").join(name).to_string_lossy().into_owned()
        }

        fn record(&self) -> FileRecord {
            open_at(&self.place).expect("the record opens")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Ok(full) = Made::from(&format!("D:P(A;;FA;;;{})", self.sid)) {
                for key in self.keys.iter().rev() {
                    unsafe { SetKernelObjectSecurity(*key, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, full.pointer) };
                }
            }
            for key in &self.keys {
                unsafe { CloseHandle(*key) };
            }
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn a_record_set_right_by_the_step_gives_the_account_to_read_and_append_and_nothing_else_and_the_check_passes() {
        let fixture = Fixture::new();
        assert_eq!(fixture.said.len(), 3, "{:?}", fixture.said);
        assert!(fixture.said[0].starts_with("folder ") && fixture.said[0].ends_with(": permissions set"), "{:?}", fixture.said);
        assert_eq!(fixture.said[1], format!("record {}: permissions set", fixture.place.record), "{:?}", fixture.said);
        assert!(fixture.said[2].starts_with("verified: a process of this account without administrator rights can read and append the record and do nothing else"), "{:?}", fixture.said);
        assert!(fixture.said[2].ends_with("An account in the Administrators group is not protected from its own elevated programs; see SECURITY.md."), "{:?}", fixture.said);
        assert!(verify(&fixture.place, &RecordCheck::Limited).is_ok());
        // What the system grants a process of the account without administrator rights, exactly.
        let api = record_api().expect("the system calls");
        let limited = Limited::new(api).expect("the token");
        let granted = |path: &str| inspect(api, (limited.0).0, path).map(|found| found.granted);
        assert_eq!(granted(&fixture.place.record), Ok(0x12008d), "{}", rights(granted(&fixture.place.record).unwrap_or(0), false).join("|"));
        assert_eq!(granted(&fixture.place.folder), Ok(0x1200a0));
        assert_eq!(excess(Object::ProgramData, granted(&fixture.place.programdata).unwrap()), 0);
    }

    #[test]
    fn the_step_makes_the_folder_and_the_record_uncompressed_in_a_folder_that_the_volume_keeps_compressed() {
        // What is made in a compressed folder is compressed, and a compressed record is allocated in units that leave no room for the
        // next record: every password would be refused after it was typed, while the step said that it had verified the record.
        let fixture = Fixture::build_in(None, b"", true);
        if !is_compressed(&fixture.place.programdata) {
            not_asserted("this volume does not compress the scratch folder, so the clearing of compression by the step was not exercised");
            return;
        }
        assert!(!is_compressed(&fixture.place.folder), "the folder of the records");
        assert!(!is_compressed(&fixture.place.record), "the record");
        assert!(verify(&fixture.place, &RecordCheck::Limited).is_ok());
        // What is made there without the step is compressed (so the step had something to clear), and clearing makes it uncompressed.
        let made = format!("{}\\made-without-the-step", fixture.place.programdata);
        std::fs::create_dir(&made).expect("make a folder in the compressed folder");
        let file = format!("{}\\file", made);
        std::fs::write(&file, [b'\n'; 4097]).expect("make a file in the compressed folder");
        assert!(is_compressed(&made) && is_compressed(&file), "what is made in a compressed folder is compressed");
        clear_compression(&made, true).expect("clear the folder");
        clear_compression(&file, false).expect("clear the file");
        assert!(!is_compressed(&made) && !is_compressed(&file));
        // And it does nothing to what is not compressed.
        clear_compression(&file, false).expect("nothing to clear");
        // The record that was made is given the room of the next record.
        let record = fixture.record();
        drop(record.lock().expect("the lock gives the room"));
    }

    #[test]
    fn a_record_or_folder_that_the_volume_keeps_compressed_is_refused_by_the_check_and_cleared_by_the_step() {
        let fixture = Fixture::new();
        let full = format!("D:P(A;;FA;;;{})", fixture.sid);
        // The record, compressed while the account has the rights to do it (and to list the folder, which the tool that compresses a
        // file needs), then given the lists of the step again.
        fixture.set(1, &full);
        fixture.set(2, &full);
        // Newlines, as the guard pads a record with, so that there is something for the volume to compress (it keeps a short file as it is).
        std::fs::write(&fixture.place.record, [encode(file_time_now()).as_slice(), &[b'\n'; 8192]].concat()).expect("put a record in it");
        if !compact(&fixture.place.record, 'c') {
            not_asserted("this volume does not compress the scratch record, so the refusal of a compressed record was not exercised");
            return;
        }
        fixture.set(1, &fixture.folder_list(0x1200a0));
        fixture.set(2, &fixture.record_list(0x12008d));
        let refused = verify(&fixture.place, &RecordCheck::Limited).err().expect("a compressed record is refused").reason;
        assert_eq!(refused, compressed());
        assert!(refused.contains("is compressed, so the room for the next record cannot be allocated") && refused.contains("compact /u") && refused.contains(&setup_step()), "{}", refused);
        assert_eq!(open_at(&fixture.place).err(), Some(compressed()), "the guard refuses with the same reason");
        assert!(not_reserved().contains("may keep it compressed"));
        fixture.set(2, &full);
        clear_compression(&fixture.place.record, false).expect("the step clears the record");
        assert!(!is_compressed(&fixture.place.record));
        fixture.set(2, &fixture.record_list(0x12008d));
        assert!(verify(&fixture.place, &RecordCheck::Limited).is_ok());
        // The folder of the records, the same way; the step sets an existing folder right and clears it.
        fixture.set(0, &full);
        fixture.set(1, &full);
        assert!(compact(&fixture.place.folder, 'c'), "compress the folder");
        fixture.set(0, &format!("D:P(A;;0x1200a6;;;{}){}", fixture.sid, OWNER_RIGHTS));
        fixture.set(1, &fixture.folder_list(0x1200a0));
        assert_eq!(verify(&fixture.place, &RecordCheck::Limited).err().expect("a compressed folder is refused").reason, compressed());
        fixture.set(1, &full);
        let trusted = [fixture.sid.as_str(), "S-1-5-32-544"];
        let added = format!("(A;;FA;;;{})", fixture.sid);
        let authority = Authority { owner: &fixture.sid, trusted: &trusted, folder: &added, record: "", tolerated: 0 };
        make_folder(&fixture.place, &authority, &mut |_| {}).expect("the step sets the folder right");
        assert!(!is_compressed(&fixture.place.folder));
        fixture.set(1, &fixture.folder_list(0x1200a0));
        assert!(verify(&fixture.place, &RecordCheck::Limited).is_ok());
    }

    #[test]
    fn the_step_does_not_set_right_in_place_a_record_that_allowed_more_than_reading_and_appending_and_a_record_that_is_removed_is_made_again() {
        // A record whose list gave the account more than reading and appending may have been opened for writing by a program of the
        // account, and that handle stays valid when the list is changed, so the record could be truncated or rewritten for ever, and
        // what it holds cannot be restored: the step refuses it, names the rights, and leaves its owner, list and bytes as they were.
        let content = [encode(at(3, 10)).as_slice(), b"garbage without a newline"].concat();
        let mut fixture = Fixture::build(None, &content);
        assert_eq!(contents(&fixture.place.record), content);
        assert_eq!(fixture.said.len(), 3, "{:?}", fixture.said);
        assert_eq!(fixture.said[1], format!("record {}: permissions set", fixture.place.record), "a record whose list is right is set right");
        fixture.set(2, &format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{})", fixture.sid));
        fixture.set(1, &fixture.folder_list(0x1200a0 | WRITE_DAC | WRITE_OWNER));
        let api = record_api().expect("the system calls");
        let limited = Limited::new(api).expect("the token");
        let before = inspect(api, (limited.0).0, &fixture.place.record).expect("inspect");
        let mut said = Vec::new();
        let refused = fixture.run(&mut said).err().expect("a record that allowed more is not set right in place");
        assert_eq!(refused, format!("the record {} allowed WRITE_DATA, WRITE_EA, EXECUTE, DELETE_CHILD, WRITE_ATTRIBUTES, DELETE to this account, so a program of the account may hold a handle that was opened while it did \
            and writes to the record, and what the record holds cannot be trusted; it is not set right in place; {}", fixture.place.record, remove_and_setup_for(&quoted("the account"))));
        assert_eq!(said, [format!("folder {}: permissions set", fixture.place.folder)], "nothing is said of the record");
        assert_eq!(contents(&fixture.place.record), content, "what it holds is as it was");
        let after = inspect(api, (limited.0).0, &fixture.place.record).expect("inspect");
        assert_eq!((parts(&after.descriptor), after.granted), (parts(&before.descriptor), before.granted), "its owner and list are as they were");
        // The remedy the refusal names: the record is removed, and the step makes a new one.
        fixture.start_over();
        let mut again = Vec::new();
        fixture.run(&mut again).expect("the step over a record that was made again");
        assert_eq!(again.len(), 3, "{:?}", again);
        assert_eq!(again[1], format!("record {}: permissions set", fixture.place.record));
        assert_eq!(contents(&fixture.place.record), Vec::<u8>::new(), "a new record is empty");
        assert!(verify(&fixture.place, &RecordCheck::Limited).is_ok());
        // The account can append to it, and what it appends is the first of it.
        fixture.record().add(at(3, 11)).expect("add");
        assert_eq!(contents(&fixture.place.record), encode(at(3, 11)));
    }

    #[test]
    fn what_is_added_lands_at_the_end_whatever_the_handle_does_and_is_read_back_and_nothing_else_is_counted() {
        let fixture = Fixture::new();
        let record = fixture.record();
        // The times are of the last hour: the record is read against the clock of the machine, which only records of the last twelve
        // hours or so are kept from.
        let ago = |minutes: u64| file_time_now() - minutes * MINUTE;
        let (first, second, third) = (ago(30), ago(20), ago(10));
        assert_eq!(record.failures(file_time_now()), Ok(vec![]));
        record.add(first).expect("add");
        record.add(second).expect("add");
        assert_eq!(record.failures(file_time_now()), Ok(vec![first, second]));
        assert_eq!(state(&record), Ok(None));
        // A handle that moves its own position, or writes at an offset, still writes at the end: the right to append is the only one.
        let rec = fixture.place.record.clone();
        let handle = Open(open_raw(&rec, FILE_APPEND_DATA | FILE_READ_ATTRIBUTES, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH).expect("an append handle"));
        let before = contents(&rec);
        let mut position = 0i64;
        assert_ne!(unsafe { SetFilePointerEx(handle.0, 0, &mut position, 0) }, 0);
        let mut written = 0u32;
        let line = b"\njunk at the start?\n";
        assert_ne!(unsafe { WriteFile(handle.0, line.as_ptr() as *const c_void, line.len() as u32, &mut written, std::ptr::null_mut()) }, 0);
        let mut at_zero = Overlapped::with_event(std::ptr::null_mut());
        assert_ne!(unsafe { WriteFile(handle.0, b"\nanother\n".as_ptr() as *const c_void, 9, &mut written, &mut at_zero) }, 0);
        let after = contents(&rec);
        assert!(after.starts_with(&before) && after.ends_with(b"\nanother\n") && after.len() == before.len() + line.len() + 9, "the bytes that were there are unchanged");
        assert_eq!(unsafe { SetEndOfFile(handle.0) }, 0, "the handle cannot cut the record short");
        assert_eq!(unsafe { GetLastError() }, ACCESS_DENIED);
        drop(handle);
        // The third wrong password locks; a torn record before it and garbage after it change nothing.
        append_raw(&rec, b"\nF 000000000000").expect("a torn record");
        record.add(third).expect("add");
        append_raw(&rec, b"garbage\r\nF 00000000000000zz\n").expect("garbage");
        assert_eq!(record.failures(file_time_now()), Ok(vec![first, second, third]));
        let now = file_time_now();
        let locked = lockout(&record.failures(file_time_now()).unwrap(), now).expect("three wrong passwords lock");
        assert_eq!((locked.count, locked.last, locked.until), (3, third, third + WINDOW));
        // Records dated far ahead are written and ignored; nothing that is added ends the lockout.
        let far = file_time_now() + 1000 * HOUR;
        for _ in 0..5 {
            record.add(far).expect("add");
        }
        assert_eq!(record.failures(file_time_now()), Ok(vec![first, second, third]), "the records far ahead are not kept");
        assert_eq!(lockout(&record.failures(file_time_now()).unwrap(), now).map(|lock| lock.until), Some(third + WINDOW));
        // Three of them alone lock nothing.
        let other = Fixture::new();
        let alone = other.record();
        for _ in 0..3 {
            alone.add(far).expect("add");
        }
        assert_eq!(state(&alone), Ok(None));
    }

    #[test]
    fn a_record_of_any_size_is_read_whole_from_the_file_and_the_real_failures_in_it_count() {
        let fixture = Fixture::new();
        let rec = fixture.place.record.clone();
        let record = fixture.record();
        let ago = |minutes: u64| file_time_now() - minutes * MINUTE;
        let size = |path: &str| std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0);
        // The real failures first, and then more than three mebibytes of garbage behind them.
        for minutes in [30, 20, 10] {
            record.add(ago(minutes)).expect("add");
        }
        let chunk = vec![b'x'; 1 << 20];
        for _ in 0..3 {
            append_raw(&rec, &chunk).expect("garbage");
        }
        append_raw(&rec, &chunk[..1000]).expect("garbage");
        assert!(size(&rec) > 3 << 20);
        assert!(state(&record).unwrap().expect("a record over a mebibyte is read, and the failures at its start lock").starts_with("locked out after 3 wrong passwords"));
        assert_eq!(record.failures(file_time_now()).map(|failures| failures.len()), Ok(3));
        // The account can still append to it, and the check of its access control is the same.
        let before = size(&rec);
        record.add(ago(5)).expect("add");
        assert_eq!(size(&rec), before + RECORD_BYTES as u64);
        assert!(verify(&fixture.place, &RecordCheck::Limited).is_ok());
        assert_eq!(open_at(&fixture.place).map(|opened| opened.failures(file_time_now()).map(|failures| failures.len())).ok(), Some(Ok(4)));
        // The real failures last, behind the garbage.
        let late = Fixture::new();
        let late_record = late.record();
        for _ in 0..3 {
            append_raw(&late.place.record, &chunk).expect("garbage");
        }
        for minutes in [30, 20, 10] {
            late_record.add(ago(minutes)).expect("add");
        }
        assert!(state(&late_record).unwrap().is_some(), "failures behind three mebibytes of garbage lock");
    }

    #[test]
    fn every_way_to_shorten_rewrite_replace_or_remove_the_record_or_to_change_who_may_do_what_fails_for_a_process_without_administrator_rights() {
        let fixture = Fixture::new();
        let (rec, folder) = (fixture.place.record.clone(), fixture.place.folder.clone());
        let record = fixture.record();
        let ago = |minutes: u64| file_time_now() - minutes * MINUTE;
        for t in [ago(30), ago(20)] {
            record.add(t).expect("add");
        }
        let before = contents(&rec);
        let free = |name: &str| fixture.free(name);
        std::fs::write(free("replacement"), b"empty").expect("a file of the account's own");
        let replacement = free("replacement");
        let append = open_raw(&rec, FILE_APPEND_DATA | FILE_READ_ATTRIBUTES, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH).expect("an append handle");
        let append = Open(append);
        let denied = {
            let _acting = Impersonating::begin();
            let wide_path = |path: &str| wide(path);
            let moved = |from: &str, to: &str, flags: u32| ok_or_code(unsafe { MoveFileExW(wide_path(from).as_ptr(), wide_path(to).as_ptr(), flags) });
            vec![
                ("open for FILE_WRITE_DATA", opened(&rec, 2, OPEN_EXISTING, 0)),
                ("open for GENERIC_WRITE", opened(&rec, GENERIC_WRITE, OPEN_EXISTING, 0)),
                ("open for GENERIC_WRITE, FILE_APPEND_DATA and FILE_READ_DATA", opened(&rec, GENERIC_WRITE | 4 | 1, OPEN_EXISTING, 0)),
                ("open for DELETE", opened(&rec, DELETE, OPEN_EXISTING, 0)),
                ("open for WRITE_DAC", opened(&rec, WRITE_DAC, OPEN_EXISTING, 0)),
                ("open for WRITE_OWNER", opened(&rec, WRITE_OWNER, OPEN_EXISTING, 0)),
                ("open to truncate", opened(&rec, GENERIC_WRITE, 5, 0)),
                ("open to create always", opened(&rec, GENERIC_WRITE, 2, 0)),
                ("cut the record short on the append handle", ok_or_code(unsafe { SetEndOfFile(append.0) })),
                ("delete the record", ok_or_code(unsafe { DeleteFileW(wide_path(&rec).as_ptr()) })),
                ("rename the record", moved(&rec, &format!("{}.renamed", rec), 0)),
                ("move the record out of the folder", moved(&rec, &free("moved-away"), 0)),
                ("replace the record with a file of its own", moved(&replacement, &rec, 1)),
                ("make a new file in the folder", opened(&format!("{}\\new", folder), GENERIC_WRITE, CREATE_NEW, 0)),
                ("make a new folder in the folder", ok_or_code(unsafe { CreateDirectoryW(wide_path(&format!("{}\\newdir", folder)).as_ptr(), std::ptr::null_mut()) })),
                ("make a hard link to the record", ok_or_code(unsafe { CreateHardLinkW(wide_path(&free("hardlink")).as_ptr(), wide_path(&rec).as_ptr(), std::ptr::null_mut()) })),
                ("make an alternate data stream of the record", opened(&format!("{}:ads", rec), GENERIC_WRITE, 4, 0)),
                ("rename the folder", moved(&folder, &format!("{}2", folder), 0)),
                ("remove the folder", ok_or_code(unsafe { RemoveDirectoryW(wide_path(&folder).as_ptr()) })),
                ("open the folder for DELETE", opened(&folder, DELETE, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS)),
                ("open the folder for WRITE_DAC", opened(&folder, WRITE_DAC, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS)),
                ("open the folder of the programs' data for WRITE_DAC", opened(&fixture.place.programdata, WRITE_DAC, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS)),
                ("open the folder of the programs' data for WRITE_OWNER", opened(&fixture.place.programdata, WRITE_OWNER, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS)),
            ]
        };
        for (what, result) in denied {
            assert_eq!(result, Err(ACCESS_DENIED), "{}", what);
        }
        drop(append);
        assert_eq!(contents(&rec), before, "the record is as it was");
        assert!(!std::path::Path::new(&free("moved-away")).exists() && !std::path::Path::new(&free("hardlink")).exists());
        // What it can do: read, append, and add up.
        let _acting = Impersonating::begin();
        assert!(opened(&rec, FILE_READ_DATA, OPEN_EXISTING, 0).is_ok() && opened(&rec, FILE_APPEND_DATA, OPEN_EXISTING, 0).is_ok());
        assert_eq!(append_raw(&rec, &encode(ago(10))), Ok(RECORD_BYTES as u32));
        drop(_acting);
        assert_eq!(record.failures(file_time_now()).map(|failures| failures.len()), Ok(3));
    }

    #[test]
    fn a_record_that_allows_more_than_read_and_append_is_refused_with_the_rights_named_and_the_step_does_not_set_it_right_in_place() {
        let fixture = Fixture::new();
        let setup = setup_step();
        let fault = |place: &Place| verify(place, &RecordCheck::Limited).err().expect("refused");
        // What the step is run over has to leave the account the right to change the list, as an administrator has it whatever the
        // list says; so each list below carries WRITE_DAC and WRITE_OWNER besides the right it is about, and they are named too (the
        // authority of the test tolerates those two and no other).
        let can_repair = WRITE_DAC | WRITE_OWNER;
        // The record: each right that is more than read and append, by name.
        for (bits, name) in [(0x2, "WRITE_DATA"), (0x10000, "DELETE"), (0x100, "WRITE_ATTRIBUTES"), (0x10, "WRITE_EA"), (0x40, "DELETE_CHILD"), (0x20, "EXECUTE")] {
            fixture.set(2, &fixture.record_list(0x12008d | can_repair | bits));
            let wide = fault(&fixture.place);
            let allowed = rights(excess(Object::Record, 0x12008d | can_repair | bits), false).join(", ");
            assert!(allowed.contains(name) && allowed.contains("WRITE_DAC") && allowed.contains("WRITE_OWNER"), "{}: {}", name, allowed);
            assert_eq!(wide.reason, format!("the lockout record for this account allows more than read and append ({}); {}", allowed, remove_and_setup()));
            assert_eq!(open_at(&fixture.place).err(), Some(wide.reason.clone()), "the guard refuses with the same reason");
            // The step opens the folder first, so the folder has to leave the account the right to change its list too. It sets
            // the folder right and refuses the record, naming the right and the remedy, which is to remove the record.
            fixture.set(1, &fixture.folder_list(0x1200a0 | can_repair));
            let mut said = Vec::new();
            let refused = fixture.run(&mut said).err().expect("the step does not set the record right in place");
            assert_eq!(said, [format!("folder {}: permissions set", fixture.place.folder)], "{}", name);
            assert!(refused.contains(&format!("allowed {} to this account", name)) && refused.contains("it is not set right in place") && refused.ends_with(&remove_and_setup_for(&quoted("the account"))), "{}: {}", name, refused);
            assert!(verify(&fixture.place, &RecordCheck::Limited).is_err(), "{}: the record is as it was", name);
        }
        // Owner rights: the account is the owner here, and with no entry for them it could change the list, which is WRITE_DAC.
        // Only the right to change the list is more than the account may have, and that is all that is named.
        fixture.set(2, &format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12008d;;;{})", fixture.sid));
        assert!(fault(&fixture.place).reason.contains("read and append (WRITE_DAC);"), "{}", fault(&fixture.place).reason);
        fixture.set(2, &fixture.record_list(0x12008d));
        assert!(verify(&fixture.place, &RecordCheck::Limited).is_ok());
        // Rights that are too few are refused as well: the record could not be read or appended to.
        for mask in [0x120081, 0x120084, 0x120080] {
            fixture.set(2, &fixture.record_list(mask));
            let few = fault(&fixture.place);
            assert_eq!(few.reason, format!("the lockout record for this account does not let this account read it and append to it; {}", setup));
        }
        // With not even the right to read its attributes it cannot be opened for the check at all, and that is said as it is.
        fixture.set(2, &fixture.record_list(0x100000));
        assert!(fault(&fixture.place).reason.starts_with("the lockout record for this account cannot be opened: [WinError 5]"));
        fixture.set(2, &fixture.record_list(0x12008d));
        // The folder of the records.
        for (bits, name) in [(0x2, "ADD_FILE"), (0x4, "ADD_SUBDIRECTORY"), (0x40, "DELETE_CHILD"), (0x10000, "DELETE"), (0x10, "WRITE_EA")] {
            fixture.set(1, &fixture.folder_list(0x1200a0 | can_repair | bits));
            let wide = fault(&fixture.place);
            assert!(wide.reason.starts_with("the folder of the lockout records allows more than reading (") && wide.reason.contains(name) && wide.reason.ends_with(&setup), "{}: {}", name, wide.reason);
            assert!(open_at(&fixture.place).err() == Some(wide.reason.clone()));
            // And the record has to be one the step can open to set right.
            fixture.set(2, &fixture.record_list(0x12008d | can_repair));
            let mut said = Vec::new();
            fixture.run(&mut said).expect("the step sets the folder right");
            assert_eq!(said[0], format!("folder {}: permissions set", fixture.place.folder));
            assert_eq!(said[1], format!("record {}: permissions set", fixture.place.record), "the two rights the authority of the test tolerates do not stop the step");
            assert!(verify(&fixture.place, &RecordCheck::Limited).is_ok(), "{}", name);
        }
        // The folder of the programs' data: the step does not mend it, and the check says what is wrong. Folders may be made in it
        // (that is how it is by default), and may not be deleted by the account, nor may its list or its owner be changed.
        fixture.set(0, &format!("D:P(A;;0x1201e6;;;{}){}", fixture.sid, OWNER_RIGHTS));
        let data = fault(&fixture.place);
        assert_eq!(data.reason, "the folder of the programs' data of this machine lets this account delete or rename it or what is in it, or change its permissions or owner (DELETE_CHILD), so a lockout record in it cannot be protected");
        fixture.set(0, &format!("D:P(A;;0x1e00a6;;;{})", fixture.sid));
        assert!(fault(&fixture.place).reason.contains("(WRITE_DAC, WRITE_OWNER)"));
        fixture.set(0, &format!("D:P(A;;0x1200a6;;;{}){}", fixture.sid, OWNER_RIGHTS));
        assert!(verify(&fixture.place, &RecordCheck::Limited).is_ok());
    }

    #[test]
    fn a_list_that_gives_another_account_or_group_more_than_the_step_gives_is_refused_by_the_check_and_not_set_right_in_place() {
        let fixture = Fixture::new();
        let fault = || verify(&fixture.place, &RecordCheck::Limited).err().expect("refused").reason;
        let can_repair = WRITE_DAC | WRITE_OWNER;
        // Another account, and a group this account is not in, given write, read or everything: none is allowed.
        for entry in [format!("(A;;0x120116;;;{})", ANOTHER), format!("(A;;0x120089;;;{})", ANOTHER), format!("(A;;FA;;;{})", ANOTHER), "(A;;0x12008d;;;S-1-5-32-551)".to_string(), "(A;;0x2;;;WD)".to_string()] {
            let sid = entry.rsplit(';').next().unwrap().trim_end_matches(')').replace("WD", "S-1-1-0");
            fixture.set(2, &format!("{}{}", fixture.record_list(0x12008d), entry));
            let reason = fault();
            // What the other principal is given may be seen by the access check as more than this account may have (everyone includes
            // this account), and then the rights are named; otherwise the entry is.
            assert!(reason.contains("another account or group") && reason.contains(&sid) || reason.contains("allows more than read and append"), "{}: {}", entry, reason);
            assert_eq!(open_at(&fixture.place).err(), Some(reason.clone()), "the guard refuses with the same reason");
        }
        // The entry for another account is named even when what it gives is no more than the step gives this account.
        fixture.set(2, &format!("{}(A;;0x12008d;;;{})", fixture.record_list(0x12008d), ANOTHER));
        assert_eq!(fault(), format!("the access list of the lockout record has an entry for another account or group ({}), which could be given more than reading and appending; {}", ANOTHER, remove_and_setup()));
        // The step does not set such a list right in place: the other account may hold a handle opened while it allowed more.
        fixture.set(1, &fixture.folder_list(0x1200a0 | can_repair));
        fixture.set(2, &format!("{}(A;;0x12008d;;;{})", fixture.record_list(0x12008d | can_repair), ANOTHER));
        let mut said = Vec::new();
        let refused = fixture.run(&mut said).err().expect("the step does not set the record right in place");
        assert!(refused.contains(&format!("an entry in its access list for another account or group ({})", ANOTHER)) && refused.contains("it is not set right in place") && refused.ends_with(&remove_and_setup_for(&quoted("the account"))), "{}", refused);
        assert!(verify(&fixture.place, &RecordCheck::Limited).is_err(), "and the record is as it was");
        // An entry that denies takes rights away, and the entries the step makes are all allowed: the system, the Administrators
        // group, this account and the owner rights.
        fixture.set(2, &format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(D;;0x2;;;{})(A;;0x12008d;;;{}){}", ANOTHER, fixture.account, OWNER_RIGHTS));
        assert!(verify(&fixture.place, &RecordCheck::Limited).is_ok());
        // A list that cannot be read as a list of entries is refused; so is a kind of entry that the step does not make.
        assert_eq!(foreign_entry(&[0u8; 4], "S-1"), Err("the access list of the lockout record cannot be read".to_string()));
        let mut list = vec![2u8, 0, 0, 0, 1, 0, 0, 0, 5, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let length = list.len() as u16;
        list[2..4].copy_from_slice(&length.to_le_bytes());
        assert_eq!(foreign_entry(&list, "S-1"), Ok(Some("an entry of type 5".to_string())), "an entry for an object, which the step does not make");
    }

    #[test]
    fn an_account_that_holds_a_dangerous_privilege_is_refused_unless_it_is_elevated_and_the_step_warns_of_it() {
        let held: Vec<String> = ["SeChangeNotifyPrivilege", "SeDebugPrivilege", "SeShutdownPrivilege", "SeImpersonatePrivilege", "SeLoadDriverPrivilege"].iter().map(|name| name.to_string()).collect();
        assert_eq!(dangerous_among(&held), ["SeDebugPrivilege", "SeImpersonatePrivilege", "SeLoadDriverPrivilege"]);
        assert!(judge_privileges(&dangerous_among(&held[..1])).is_ok() && judge_privileges(&[]).is_ok());
        let refusal = judge_privileges(&dangerous_among(&held)).err().expect("refused").reason;
        assert_eq!(refusal, "this account holds privileges (SeDebugPrivilege, SeImpersonatePrivilege, SeLoadDriverPrivilege) that let a program of the account rewrite the lockout record, so it cannot be protected; \
            do not use the exception for this account");
        assert_eq!(privilege_warning(&dangerous_among(&held)), Some(format!("warning: {}", refusal)));
        assert_eq!(privilege_warning(&[]), None);
        // Every privilege of the list is one that the system names, and each is the name it has: the list is not misspelled.
        let api = record_api().expect("the system calls");
        let mut token: Handle = std::ptr::null_mut();
        assert_ne!(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }, 0);
        let token = Open(token);
        let own = privileges_of(api, token.0).expect("the privileges of this process");
        assert!(own.iter().any(|name| name == "SeChangeNotifyPrivilege"), "every token holds the privilege to bypass traverse checking: {:?}", own);
        assert!(own.iter().all(|name| name.starts_with("Se") && name.ends_with("Privilege")), "{:?}", own);
        for name in DANGEROUS_PRIVILEGES {
            assert!(name.starts_with("Se") && name.ends_with("Privilege") && DANGEROUS_PRIVILEGES.iter().filter(|other| **other == name).count() == 1, "{}", name);
        }
        // This process: the check refuses it exactly when it holds one and is not elevated, and the step's warning is for the same
        // list, from the token of the account (the other half of a split token when there is one).
        let dangerous = dangerous_privileges(api).expect("the dangerous privileges of this process");
        assert_eq!(dangerous, dangerous_among(&own));
        if elevated() || dangerous.is_empty() {
            assert!(verify(&Fixture::new().place, &RecordCheck::Limited).is_ok());
        } else {
            let fixture = Fixture::new();
            assert_eq!(verify(&fixture.place, &RecordCheck::Limited).err().map(|fault| fault.reason), judge_privileges(&dangerous).err().map(|fault| fault.reason));
        }
        assert!(account_dangerous_privileges().is_ok());
    }

    #[test]
    fn a_missing_record_or_folder_or_one_that_is_a_link_or_has_two_names_is_refused_and_names_the_step() {
        let fixture = Fixture::new();
        let setup = setup_step();
        let reason = |place: &Place| verify(place, &RecordCheck::Limited).err().expect("refused").reason;
        // No record for this account.
        let mut other = Place::new(&fixture.place.programdata, "S-1-5-21-1-2-3-4").expect("a place");
        other.ancestors.clear();
        assert_eq!(reason(&other), format!("no lockout record exists for this account; {}", setup));
        assert_eq!(open_at(&other).err(), Some(format!("no lockout record exists for this account; {}", setup)));
        // No folder, and no folder of the programs' data.
        let no_folder = Place { ancestors: Vec::new(), programdata: fixture.place.programdata.clone(), folder: format!("{}\\nothere", fixture.place.programdata), record: format!("{}\\nothere\\x.lockout", fixture.place.programdata) };
        assert_eq!(reason(&no_folder), format!("no lockout record exists for this account; {}", setup));
        let nothing = Place { ancestors: Vec::new(), programdata: format!("{}\\nowhere", fixture.place.programdata), folder: format!("{}\\nowhere\\f", fixture.place.programdata), record: format!("{}\\nowhere\\f\\x.lockout", fixture.place.programdata) };
        assert!(reason(&nothing).starts_with("the folder of the programs' data of this machine cannot be checked:"), "{}", reason(&nothing));
        // A hard link: the record has a second name.
        let link = fixture.free("second-name");
        fixture.set(2, &format!("D:P(A;;FA;;;{})", fixture.sid));
        std::fs::hard_link(&fixture.place.record, &link).expect("make a second name with the rights it was given");
        // The step does not take a record with two names in hand: the other name may be anywhere.
        let trusted = [fixture.sid.as_str()];
        let authority = Authority { owner: &fixture.sid, trusted: &trusted, folder: OWNER_RIGHTS, record: "", tolerated: 0 };
        let made = Made::from(&record_sddl(&authority, &fixture.sid)).expect("a list");
        let repair = set_permissions(&fixture.place.record, false, &made, &authority).err().expect("a record with two names is not taken over");
        assert!(repair.contains("has more than one name"), "{}", repair);
        fixture.set(2, &fixture.record_list(0x12008d));
        assert_eq!(reason(&fixture.place), format!("the lockout record for this account is a link, a folder or has more than one name; {}", remove_and_setup()));
        assert!(open_at(&fixture.place).is_err());
        std::fs::remove_file(&link).expect("remove the second name");
        assert!(verify(&fixture.place, &RecordCheck::Limited).is_ok());
        // A folder that is a junction to another folder.
        let target = fixture.free("target");
        std::fs::create_dir_all(&target).expect("a target");
        let junction = fixture.free("junction");
        let made = std::process::Command::new("cmd").args(["/d", "/c", "mklink", "/J", &junction, &target]).stdin(std::process::Stdio::null()).output().expect("run mklink");
        assert!(made.status.success(), "{}", String::from_utf8_lossy(&made.stdout));
        let through = Place { ancestors: Vec::new(), programdata: fixture.place.programdata.clone(), folder: junction.clone(), record: format!("{}\\x.lockout", junction) };
        assert_eq!(reason(&through), format!("the folder of the lockout records is a link or not a folder; {}", remove_and_setup()));
        let _ = std::fs::remove_dir(&junction);
        // A file where the folder should be.
        let file = fixture.free("file");
        std::fs::write(&file, b"x").expect("a file");
        let not_a_folder = Place { ancestors: Vec::new(), programdata: fixture.place.programdata.clone(), folder: file.clone(), record: format!("{}\\x.lockout", file) };
        assert_eq!(reason(&not_a_folder), format!("the folder of the lockout records is a link or not a folder; {}", remove_and_setup()));
    }

    #[test]
    fn the_step_does_not_take_over_a_folder_that_somebody_else_owns_and_a_folder_or_record_it_makes_is_set_right_from_the_first_instant() {
        let fixture = Fixture::new();
        // The folder is owned by the account of this test; an authority that trusts nobody refuses to take it over (it is opened for
        // the purpose first, which an administrator needs no list for).
        let none: [&str; 0] = [];
        let authority = Authority { owner: &fixture.sid, trusted: &none, folder: OWNER_RIGHTS, record: "", tolerated: 0 };
        fixture.set(1, &fixture.folder_list(0x1200a0 | WRITE_DAC | WRITE_OWNER));
        let refused = make_folder(&fixture.place, &authority, &mut |_| {}).err().expect("not taken over");
        assert!(refused.contains("is owned by") && refused.contains("not taken over") && refused.contains(&fixture.sid), "{}", refused);
        assert!(refused.contains("remove it as described in the README"), "{}", refused);
        fixture.set(1, &fixture.folder_list(0x1200a0));
        // A folder and a record made new carry the list they are made with, protected, and the account's own right to the record.
        let new_place = Place::new(&fixture.free("pd2"), "S-1-5-21-1-2-3-4321").expect("a place");
        std::fs::create_dir_all(&new_place.programdata).expect("a scratch folder");
        let full = format!("(A;;FA;;;{})", fixture.sid);
        let trusted = [fixture.sid.as_str()];
        let open_authority = Authority { owner: &fixture.sid, trusted: &trusted, folder: &full, record: &full, tolerated: 0 };
        let mut said = Vec::new();
        make_folder(&new_place, &open_authority, &mut |line| said.push(line)).expect("make the folder");
        make_record(&new_place, "S-1-5-21-1-2-3-4321", "someone", &open_authority, false, &mut |line| said.push(line)).expect("make the record");
        assert_eq!(said, [format!("created folder {}", new_place.folder), format!("created record {} for someone (S-1-5-21-1-2-3-4321)", new_place.record)]);
        assert_eq!(contents(&new_place.record), Vec::<u8>::new(), "a record that is made is empty");
        // The record is the list that was asked for: owner and list, byte for byte, as the check of another account's record compares.
        let expected = Made::from(&record_sddl(&open_authority, "S-1-5-21-1-2-3-4321")).expect("a list").words();
        let api = record_api().expect("the system calls");
        let limited = Limited::new(api).expect("the token");
        let found = inspect(api, (limited.0).0, &new_place.record).expect("inspect");
        assert_eq!(parts(&found.descriptor), parts(&expected));
        assert!(parts(&found.descriptor).map_or(false, |(_, _, protected)| protected));
        // Made a second time it is found there: the step sets right and does not make again.
        let mut again = Vec::new();
        make_folder(&new_place, &open_authority, &mut |line| again.push(line)).expect("the folder is there");
        make_record(&new_place, "S-1-5-21-1-2-3-4321", "someone", &open_authority, false, &mut |line| again.push(line)).expect("the record is there");
        assert_eq!(again, [format!("folder {}: permissions set", new_place.folder), format!("record {}: permissions set", new_place.record)]);
        // Give them back, to remove the scratch folder: the account made them with full control.
        for path in [&new_place.record, &new_place.folder] {
            assert!(std::fs::remove_file(path).is_ok() || std::fs::remove_dir(path).is_ok());
        }
    }

    #[test]
    fn the_record_of_another_account_is_compared_with_what_was_set_and_a_changed_list_is_refused() {
        let fixture = Fixture::build(Some(ANOTHER), b"");
        assert_eq!(fixture.said.len(), 3, "{:?}", fixture.said);
        assert_eq!(fixture.said[1], format!("record {}: permissions set", fixture.place.record), "the rights of another account's record are not asked of the system");
        assert_eq!(fixture.said[2], format!("verified: the record of the account has the permissions that let a process of that account without administrator rights read and append it and do nothing else.{}", NOT_PROTECTED));
        // The check of this account's own kind does not pass for it: this account is not the one the list names.
        assert!(verify(&fixture.place, &RecordCheck::Limited).is_err());
        let trusted = [fixture.sid.as_str()];
        let added = fixture.record_added();
        let authority = Authority { owner: &fixture.sid, trusted: &trusted, folder: OWNER_RIGHTS, record: &added, tolerated: 0 };
        let expected = Made::from(&record_sddl(&authority, ANOTHER)).expect("a list").words();
        assert!(verify(&fixture.place, &RecordCheck::Exactly(&expected)).is_ok());
        // A list that is not the one that was set is refused, even if it would be harmless, and so is one for another account.
        let me = fixture.record_added();
        for sddl in [format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120085;;;{}){}{}", ANOTHER, OWNER_RIGHTS, me), format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12008d;;;{}){}{}", fixture.sid, OWNER_RIGHTS, me),
            format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12008d;;;{}){}{}", ANOTHER, me, OWNER_RIGHTS)] {
            fixture.set(2, &sddl);
            let refused = verify(&fixture.place, &RecordCheck::Exactly(&expected)).err().expect("a different list");
            assert_eq!(refused.reason, format!("the lockout record does not have the owner and access list that were set; {}", setup_step()), "{}", sddl);
        }
        fixture.set(2, &record_sddl(&authority, ANOTHER));
        assert!(verify(&fixture.place, &RecordCheck::Exactly(&expected)).is_ok());
        // The step does not set a list that is not the one it makes right in place either: what it allowed to the account cannot be
        // asked of the system, so it is taken to have allowed more, and the record is removed and made again.
        fixture.set(1, &fixture.folder_list(0x1200a0 | WRITE_DAC | WRITE_OWNER));
        fixture.set(2, &format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{}){}{}", ANOTHER, OWNER_RIGHTS, me));
        let refused = fixture.run(&mut Vec::new()).err().expect("a list that is not the one the step sets");
        assert!(refused.contains("is not as the step makes it") && refused.contains("it is not set right in place") && refused.ends_with(&remove_and_setup_for(&quoted("the account"))), "{}", refused);
        assert!(verify(&fixture.place, &RecordCheck::Exactly(&expected)).is_err(), "the record is as it was");
        // And the record as the step makes it is set again, which changes nothing.
        fixture.set(2, &record_sddl(&authority, ANOTHER));
        fixture.set(1, &fixture.folder_list(0x1200a0 | WRITE_DAC | WRITE_OWNER));
        fixture.run(&mut Vec::new()).expect("the step over the record as it makes it");
    }

    #[test]
    fn the_real_folder_of_the_programs_data_and_the_folders_above_it_are_owned_by_one_that_is_trusted_and_do_not_let_a_process_without_administrator_rights_delete_or_take_over_the_folders_in_it() {
        // Only reads: the registry and the access lists of the folders. Nothing is made in them.
        let api = record_api().expect("the system calls");
        let limited = Limited::new(api).expect("the token");
        let folder = program_data().expect("the folder of the programs' data");
        let place = Place::new(&folder, "S-1-5-21-1-2-3-1001").expect("a place");
        assert!(!place.ancestors.is_empty(), "{}", folder);
        assert!(split_device(&place.ancestors[0]).is_some() && place.ancestors[0].ends_with('\\'), "{:?}", place.ancestors);
        // What a machine sets on its own folders is a setting of the machine, which the guard reports as a refusal when it runs: here
        // it is asserted only where the variable says that this machine must meet the requirements of the check, and otherwise said.
        let mut unmet = Vec::new();
        for (index, path) in place.ancestors.iter().chain([&place.programdata]).enumerate() {
            let found = inspect(api, (limited.0).0, path).expect("inspect the folder");
            assert_eq!(found.attributes & FILE_ATTRIBUTE_REPARSE_POINT, 0, "{}", path);
            let object = if index == 0 { Object::DriveRoot } else { Object::ProgramData };
            if excess(object, found.granted) != 0 {
                unmet.push(format!("{} lets the account have {}", drive_form(path), rights(excess(object, found.granted), true).join("|")));
            }
            let owner = owner_text(&found.descriptor);
            if !PRODUCTION.trusted.contains(&owner.as_str()) {
                unmet.push(format!("{} is owned by {}", drive_form(path), owner));
            }
        }
        if !unmet.is_empty() {
            assert!(std::env::var_os("PROCESS_TREE_GUARD_REQUIRE_PROGRAM_DATA_CHECK").map_or(true, |value| value.is_empty()), "{:?}", unmet);
            not_asserted(format!("this machine does not meet the requirements of the check of the folder of the programs' data ({}); the guard refuses every run over the cap here, with that reason. \
                Set PROCESS_TREE_GUARD_REQUIRE_PROGRAM_DATA_CHECK to require it.", unmet.join("; ")));
        }
    }

    #[test]
    fn the_folders_above_the_programs_data_are_the_folders_above_it_from_the_root_down() {
        assert_eq!(ancestors_of("C:\\ProgramData"), ["C:\\"]);
        assert_eq!(ancestors_of("E:\\Data\\Program Data"), ["E:\\", "E:\\Data"]);
        assert_eq!(ancestors_of("D:\\a\\b\\c"), ["D:\\", "D:\\a", "D:\\a\\b"]);
        assert_eq!(Place::new("C:\\ProgramData", "S-1-5-21-1").map(|place| place.ancestors), Ok(vec!["C:\\".to_string()]));
    }

    /// The owner of the folder of the Windows system, as text: a tree that a process without administrator rights cannot have made.
    fn system_owner() -> Option<(String, String)> {
        let api = record_api()?;
        let limited = Limited::new(api).ok()?;
        let windows = std::env::var("SystemRoot").ok()?;
        let found = inspect(api, (limited.0).0, &windows).ok()?;
        let owner = owner_text(&found.descriptor);
        if owner.is_empty() { None } else { Some((windows, owner)) }
    }

    #[test]
    fn a_tree_made_by_the_account_with_the_right_lists_is_refused_because_its_owner_is_not_trusted() {
        // The attack: a process without administrator rights makes a folder and a record with exactly the lists the guard accepts,
        // and its owner is the account. The check of the lists alone passes it (the unit tests below show that with the account
        // trusted); the check of the owners does not, with the owners of production.
        let fixture = Fixture::new();
        assert!(verify(&fixture.place, &RecordCheck::Limited).is_ok(), "the lists alone are accepted");
        let reason = super::verify(&fixture.place, &RecordCheck::Limited, PRODUCTION.trusted).err().expect("refused for the owner").reason;
        // The first object in the order of the check that the account made is the one refused: the folder of the programs' data of the
        // scratch tree when it was made by the account itself, and the folder of the records when the tests run with the rights of an
        // administrator (everything a process with those rights makes is owned by their group, except what is made owned by the account).
        assert!(reason.contains(" is owned by ") && reason.contains("which is not the Administrators group, the system or the installer of the system, so it cannot be trusted;"), "{}", reason);
        assert_eq!(super::open_at(&fixture.place, PRODUCTION.trusted).err(), Some(reason));
        // With the folder of the programs' data a tree that is the system's, the folder of the records is the next to be refused,
        // and then the record, each by its owner and with the step that mends it (the removal of what the account made first).
        let (windows, owner) = system_owner().expect("the owner of the Windows folder, which this test needs");
        let trusted = [owner.as_str()];
        let under_windows = Place { ancestors: Vec::new(), programdata: windows.clone(), folder: fixture.place.folder.clone(), record: fixture.place.record.clone() };
        let reason = super::verify(&under_windows, &RecordCheck::Limited, &trusted).err().expect("refused for the owner of the folder").reason;
        assert_eq!(reason, format!("the folder of the lockout records is owned by {}, which is not the Administrators group, the system or the installer of the system, so it cannot be trusted; \
            an administrator must remove it as described in the README and then run: process-tree-guard create-lockout-record {}", fixture.sid, step_account()));
        let system32 = format!("{}\\System32", windows);
        let own_record = Place { ancestors: Vec::new(), programdata: windows, folder: system32, record: fixture.place.record.clone() };
        let reason = super::verify(&own_record, &RecordCheck::Limited, &trusted).err().expect("refused for the owner of the record").reason;
        assert_eq!(reason, format!("the lockout record for this account is owned by {}, which is not the Administrators group, the system or the installer of the system, so it cannot be trusted; \
            an administrator must remove it as described in the README and then run: process-tree-guard create-lockout-record {}", fixture.sid, step_account()));
        // An owner that is unknown is named so, and the list of the owners that are trusted is exactly the three.
        assert_eq!(Fault::untrusted("the lockout record for this account", "", "x").reason, "the lockout record for this account is owned by an unknown owner, which is not the Administrators group, the system or the installer of the system, so it cannot be trusted; x");
        assert_eq!(PRODUCTION.trusted, ["S-1-5-32-544", "S-1-5-18", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"]);
    }

    #[test]
    fn a_link_planted_at_the_name_of_the_record_is_not_followed_and_what_it_leads_to_is_not_made() {
        // A folder of the records that was made first without the lists of the step, with a dangling link where the record goes: the
        // step must not create the file the link leads to (CWE-59), and refuses the link.
        let root = std::env::temp_dir().join(format!("ptg-lockout-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let programdata = root.join("pd");
        std::fs::create_dir_all(programdata.join(FOLDER_NAME)).expect("make the scratch folders");
        let sid = current_user_sid().expect("the user of this test");
        let mut place = Place::new(&programdata.to_string_lossy(), &sid).expect("a place");
        place.ancestors.clear();
        let target = root.join("target-that-must-not-be-made");
        if let Err(error) = std::os::windows::fs::symlink_file(&target, &place.record) {
            // Making a symbolic link needs the privilege for it, or Developer Mode; where this account has neither, nothing is planted.
            not_asserted(format!("a symbolic link cannot be made by this account here ({}), so the step was not shown to refuse one", error));
            let _ = std::fs::remove_dir_all(&root);
            return;
        }
        let trusted = [sid.as_str(), "S-1-5-32-544"];
        let authority = Authority { owner: &sid, trusted: &trusted, folder: "", record: "", tolerated: 0 };
        let refused = make_record(&place, &sid, "the account", &authority, true, &mut |_| {}).err().expect("a link at the name of the record is refused");
        assert!(refused.contains("is a link, which is not followed"), "{}", refused);
        assert!(std::fs::symlink_metadata(&target).is_err(), "the file the link led to was made");
        let _ = std::fs::remove_file(&place.record);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_refusal_for_a_folder_above_the_programs_data_names_it_on_the_drive_as_an_administrator_reads_it() {
        // The folders above the programs' data are looked at by their names from the object manager, which an administrator cannot
        // use: the refusal names the root of the system volume as `C:\`, not as `\Device\HarddiskVolume3\`.
        let api = record_api().expect("the system calls");
        let device = system_device(api).expect("the system volume");
        let drive: String = windows_folder().expect("the system folder").chars().take(2).collect();
        let fixture = Fixture::new();
        let place = Place { ancestors: vec![format!("{}\\", device)], programdata: fixture.place.programdata.clone(), folder: fixture.place.folder.clone(), record: fixture.place.record.clone() };
        let nobody: [&str; 0] = [];
        let reason = super::verify(&place, &RecordCheck::Limited, &nobody).err().expect("a root whose owner is not trusted").reason;
        assert!(reason.starts_with(&format!("the folder {}\\ ", drive)) && !reason.contains("\\Device\\"), "{}", reason);
        assert!(reason.contains(" is owned by ") && reason.ends_with("a lockout record in it cannot be protected"), "{}", reason);
        // A folder on another volume, or already on a drive, is named as it is.
        assert_eq!(on_drive("\\Device\\HarddiskVolume9\\Data", "\\Device\\HarddiskVolume3", "C:"), "\\Device\\HarddiskVolume9\\Data");
        assert_eq!(on_drive("\\Device\\HarddiskVolume3\\Data", "\\Device\\HarddiskVolume3", "C:"), "C:\\Data");
    }

    #[test]
    fn a_folder_above_the_programs_data_that_the_account_can_delete_from_or_that_is_a_link_or_is_not_trusted_is_refused() {
        let fixture = Fixture::new();
        // The scratch root is the account's: it can delete what is in it, so a record below it could be removed with its folder.
        let mut place = Place { ancestors: vec![fixture.root.to_string_lossy().into_owned()], programdata: fixture.place.programdata.clone(), folder: fixture.place.folder.clone(), record: fixture.place.record.clone() };
        // Its owner is the account, or the Administrators group when the tests run with the rights of an administrator: both are trusted here.
        let api = record_api().expect("the system calls");
        let limited = Limited::new(api).expect("the token");
        let root_owner = owner_text(&inspect(api, (limited.0).0, &place.ancestors[0]).expect("inspect the scratch root").descriptor);
        let wide = super::verify(&place, &RecordCheck::Limited, &[fixture.sid.as_str(), root_owner.as_str()]).err().expect("an ancestor the account can delete from");
        assert!(wide.reason.starts_with(&format!("the folder {} lets this account delete or rename it or what is in it, or change its permissions or owner (", fixture.root.display())) && wide.reason.contains("DELETE_CHILD"), "{}", wide.reason);
        // Not trusted: the account is the owner, and with nobody trusted the owner is what is refused, before the rights.
        let nobody: [&str; 0] = [];
        let untrusted = super::verify(&place, &RecordCheck::Limited, &nobody).err().expect("an ancestor whose owner is not trusted");
        assert!(untrusted.reason.contains(" is owned by ") && untrusted.reason.contains(&fixture.sid) && untrusted.reason.ends_with("a lockout record in it cannot be protected"), "{}", untrusted.reason);
        // A link above: a junction to the folder of the programs' data.
        let junction = fixture.free("junction");
        let made = std::process::Command::new("cmd").args(["/d", "/c", "mklink", "/J", &junction, &fixture.place.programdata]).stdin(std::process::Stdio::null()).output().expect("run mklink");
        assert!(made.status.success(), "{}", String::from_utf8_lossy(&made.stdout));
        place.ancestors = vec![junction.clone()];
        let link = verify(&place, &RecordCheck::Limited).err().expect("a link above");
        assert_eq!(link.reason, format!("the folder {} is a link or not a folder, so a lockout record in it cannot be protected", junction));
        let _ = std::fs::remove_dir(&junction);
        // And a folder of the programs' data that is itself a link.
        let through = fixture.free("junction2");
        let made = std::process::Command::new("cmd").args(["/d", "/c", "mklink", "/J", &through, &fixture.place.programdata]).stdin(std::process::Stdio::null()).output().expect("run mklink");
        assert!(made.status.success(), "{}", String::from_utf8_lossy(&made.stdout));
        let via = Place { ancestors: Vec::new(), programdata: through.clone(), folder: fixture.place.folder.clone(), record: fixture.place.record.clone() };
        assert_eq!(verify(&via, &RecordCheck::Limited).err().expect("a link").reason, "the folder of the programs' data of this machine is a link or not a folder, so a lockout record in it cannot be protected");
        let _ = std::fs::remove_dir(&through);
        // A file where a folder should be.
        let file = fixture.free("afile");
        std::fs::write(&file, b"x").expect("a file");
        place.ancestors = vec![file.clone()];
        assert!(verify(&place, &RecordCheck::Limited).err().expect("not a folder").reason.ends_with("is a link or not a folder, so a lockout record in it cannot be protected"));
    }

    #[test]
    fn a_record_that_another_program_holds_open_without_sharing_it_is_said_so_and_not_blamed_on_the_setup() {
        let fixture = Fixture::new();
        // A program of the account reads the record and shares only reading: the guard, which opens it to append, is refused by the
        // system with a sharing violation, and the setup step cannot mend that.
        let held = Open(open_raw_sharing(&fixture.place.record, FILE_READ_DATA, 1).expect("hold the record"));
        let refused = open_at(&fixture.place).err().expect("refused while it is held");
        assert_eq!(refused, "the lockout record for this account is held open by another program that does not share it; end that program and run again");
        assert!(!refused.contains("create-lockout-record"));
        drop(held);
        assert!(open_at(&fixture.place).is_ok(), "and it opens again when the program lets go");
        // A lock violation is not said of opening a file, which cannot run into one: it is said of a read, an append and a lock
        // (see `a_range_of_the_record_that_another_program_holds_locked_...`), and an open that fails with it is an open that failed.
        assert!(!Fault::cannot_open("the lockout record for this account", ERROR_LOCK_VIOLATION).reason.contains("held open by another program"));
        // Access denied is the setup's to mend, as before.
        assert!(Fault::cannot_open("the lockout record for this account", ACCESS_DENIED).reason.ends_with(&setup_step()));
    }

    /// Open `path` for `access` with the sharing `share` (the bits of `FILE_SHARE_*`), as a program holding it would.
    fn open_raw_sharing(path: &str, access: u32, share: u32) -> Result<Handle, u32> {
        let handle = unsafe { CreateFileW(wide(path).as_ptr(), access, share, std::ptr::null_mut(), OPEN_EXISTING, 0, std::ptr::null_mut()) };
        if handle == INVALID_HANDLE { Err(unsafe { GetLastError() }) } else { Ok(handle) }
    }

    /// Lock `length` bytes of the file `handle` is open on, from `offset`, for that handle, failing at once if another has them locked:
    /// what a program of the account does with a handle opened for reading, which the list of the record lets it.
    fn lock_range(handle: Handle, offset: u64, length: u64) -> Result<(), u32> {
        let mut at = Overlapped::with_event(std::ptr::null_mut());
        at.offset = offset as u32;
        at.offset_high = (offset >> 32) as u32;
        ok_or_code(unsafe { LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, length as u32, (length >> 32) as u32, &mut at) })
    }

    /// The most that can be locked from any offset that is a small number.
    const A_LOT: u64 = u64::MAX >> 1;

    fn size_of_file(path: &str) -> u64 {
        std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0)
    }

    #[test]
    fn a_range_of_the_record_that_another_program_holds_locked_refuses_the_run_before_the_logon_and_says_so() {
        let fixture = Fixture::new();
        let (rec, record) = (fixture.place.record.clone(), fixture.record());
        let ago = |minutes: u64| file_time_now() - minutes * MINUTE;
        record.add(ago(20)).expect("add");
        let size = size_of_file(&rec);
        assert_eq!(size, RECORD_BYTES as u64);
        // A program of the account opens the record for reading, as the list lets it, and locks everything from the end of the file
        // on. What the guard reads is not locked, so every look at the record passes; the append of a wrong password, after the
        // guess, would fail. The lock the run takes before the logon is what refuses it, with nothing guessed.
        let other = Open(open_raw(&rec, FILE_READ_DATA | FILE_READ_ATTRIBUTES, OPEN_EXISTING, 0).expect("a reader"));
        assert_eq!(lock_range(other.0, size, A_LOT), Ok(()), "a handle that can only read can lock the end of the record");
        assert_eq!(record.failures(file_time_now()).map(|failures| failures.len()), Ok(1), "the looks at the record pass");
        assert_eq!(state(&record), Ok(None));
        assert_eq!(record.add(ago(1)), Err(LOCKED_RANGE.to_string()), "and the append would fail after the guess");
        assert_eq!(size_of_file(&rec), size);
        assert_eq!(record.lock_within(Duration::from_millis(120)).err(), Some(LOCK_BUSY.to_string()));
        // The lock of the run is refused when it is asked for, in the time it is given.
        let started = Instant::now();
        assert!(record.lock_within(Duration::from_millis(200)).is_err() && started.elapsed() >= Duration::from_millis(200));
        // When the other program lets go (or ends) the lock is taken.
        drop(other);
        drop(record.lock_within(Duration::from_millis(120)).expect("the lock is taken when the range is free"));
        // A whole record locked stops the look too, with the reason that it is locked.
        let whole = Open(open_raw(&rec, FILE_READ_DATA | FILE_READ_ATTRIBUTES, OPEN_EXISTING, 0).expect("a reader"));
        assert_eq!(lock_range(whole.0, 0, A_LOT), Ok(()));
        assert_eq!(record.failures(file_time_now()), Err(LOCKED_RANGE.to_string()));
        assert_eq!(state(&record), Err(LOCKED_RANGE.to_string()));
        assert_eq!(record.lock_within(Duration::from_millis(60)).err(), Some(LOCK_BUSY.to_string()));
    }

    #[test]
    fn the_lock_of_a_run_keeps_every_other_program_out_of_the_record_until_it_is_dropped_and_not_the_run_itself() {
        let fixture = Fixture::new();
        let (rec, record) = (fixture.place.record.clone(), fixture.record());
        let ago = |minutes: u64| file_time_now() - minutes * MINUTE;
        record.add(ago(20)).expect("add");
        let held = record.lock().expect("the lock of a record nobody holds");
        // The lock has the room for the next record allocated (newlines are added to the record to do it), so the size is taken after it.
        let size = size_of_file(&rec);
        assert!(size > RECORD_BYTES as u64);
        let other = Open(open_raw(&rec, FILE_READ_DATA | FILE_READ_ATTRIBUTES, OPEN_EXISTING, 0).expect("a reader"));
        // Another program cannot read what is locked, lock any of it, or append to the record, which is a program of the account
        // adding the three records of a lockout, or a run in another session adding its own wrong password.
        let mut buffer = [0u8; RECORD_BYTES];
        let mut read = 0u32;
        let mut at = Overlapped::with_event(std::ptr::null_mut());
        let ok = unsafe { ReadFile(other.0, buffer.as_mut_ptr() as *mut c_void, buffer.len() as u32, &mut read, &mut at) };
        assert!(ok == 0 && unsafe { GetLastError() } == ERROR_LOCK_VIOLATION);
        assert_eq!(lock_range(other.0, 0, 1), Err(ERROR_LOCK_VIOLATION));
        assert_eq!(lock_range(other.0, size, A_LOT), Err(ERROR_LOCK_VIOLATION));
        assert_eq!(append_raw(&rec, &encode(ago(1))), Err(ERROR_LOCK_VIOLATION));
        assert_eq!(size_of_file(&rec), size, "nothing was added by the program that is kept out");
        // The run itself is not kept out of its own record: it reads, and appends the wrong password it found, under its lock.
        assert_eq!(record.failures(file_time_now()).map(|failures| failures.len()), Ok(1));
        record.add(ago(2)).expect("the run appends under its own lock");
        assert_eq!(record.failures(file_time_now()).map(|failures| failures.len()), Ok(2));
        drop(held);
        // Dropped, it lets the others in.
        assert_eq!(lock_range(other.0, 0, 1), Ok(()));
        drop(other);
        assert_eq!(append_raw(&rec, &encode(ago(1))), Ok(RECORD_BYTES as u32));
        assert_eq!(record.failures(file_time_now()).map(|failures| failures.len()), Ok(3));
    }

    #[test]
    fn two_runs_of_the_same_account_cannot_both_hold_the_lock_so_they_cannot_both_pass_the_look_at_two_wrong_passwords_and_both_guess() {
        let fixture = Fixture::new();
        let (first, second) = (fixture.record(), fixture.record());
        let ago = |minutes: u64| file_time_now() - minutes * MINUTE;
        for minutes in [30, 20] {
            first.add(ago(minutes)).expect("add");
        }
        let held = first.lock().expect("the first run takes the lock");
        assert_eq!(second.lock_within(Duration::from_millis(100)).err(), Some(LOCK_BUSY.to_string()), "the second is refused while the first holds it");
        // The first run's guess is wrong and is added before it lets go; the second then takes the lock, looks again, and finds the lockout.
        first.add(ago(1)).expect("the wrong password of the first");
        drop(held);
        let held = second.lock_within(Duration::from_millis(100)).expect("the second takes the lock when the first lets go");
        assert!(state(&second).expect("a look under the lock").map_or(false, |reason| reason.starts_with("locked out after 3 wrong passwords")), "and its look under the lock finds the lockout");
        drop(held);
    }

    #[test]
    fn what_a_read_an_append_and_a_lock_say_of_a_locked_range_and_of_other_errors() {
        assert_eq!(io_error("read", ERROR_LOCK_VIOLATION), "the lockout record is locked by another program or another run; wait for the run to end, or end that program, and run again");
        assert_eq!(io_error("appended to", ERROR_LOCK_VIOLATION), LOCKED_RANGE);
        assert!(io_error("read", ACCESS_DENIED).starts_with("the lockout record could not be read: [WinError 5]"));
        assert!(io_error("appended to", ACCESS_DENIED).starts_with("the lockout record could not be appended to: [WinError 5]"));
        assert_eq!(LOCK_BUSY, "the lockout record is locked by another program or another run; try again");
    }

    #[test]
    fn a_volume_with_no_room_for_a_record_refuses_the_lock_and_the_room_of_the_volume_is_read() {
        assert_eq!(room_enough(0), Err(NO_ROOM.to_string()));
        assert_eq!(room_enough(ROOM - 1), Err(NO_ROOM.to_string()));
        assert_eq!(room_enough(ROOM), Ok(()));
        assert!(NO_ROOM.starts_with("the volume of the lockout record has no room for a record"));
        // The room the volume of a scratch record has, as the caller sees it, is what the system says of the folder it is in.
        let fixture = Fixture::new();
        let record = fixture.record();
        let room = record.room().expect("the room of the volume");
        let (mut available, mut total, mut free) = (0u64, 0u64, 0u64);
        assert_ne!(unsafe { GetDiskFreeSpaceExW(wide(&fixture.place.folder).as_ptr(), &mut available, &mut total, &mut free) }, 0);
        let gap = (room as i128 - available as i128).unsigned_abs();
        assert!(room > 0 && gap < 1 << 30, "{} against {}", room, available);
        assert!(record.lock().is_ok(), "a record on a volume with room can be locked");
    }

    #[test]
    fn the_room_of_the_next_record_is_allocated_under_the_lock_before_the_logon_so_the_append_needs_none_and_the_padding_counts_for_nothing() {
        let fixture = Fixture::new();
        let (rec, record) = (fixture.place.record.clone(), fixture.record());
        let ago = |minutes: u64| file_time_now() - minutes * MINUTE;
        for minutes in [30, 20, 10] {
            record.add(ago(minutes)).expect("add");
        }
        let failures = record.failures(file_time_now()).expect("read");
        let locked = lockout(&failures, file_time_now()).expect("three wrong passwords lock");
        let (_, short) = record.sizes().expect("sizes");
        assert_eq!(short, 3 * RECORD_BYTES as u64);
        // After the lock the record is allocated at least one record past its end, whatever it was before, and what was added to make
        // it so is newlines: the failures and the lockout are what they were.
        let held = record.lock().expect("the lock");
        let (allocated, end) = record.sizes().expect("sizes");
        assert!(allocated >= end + RECORD_BYTES as u64, "allocated {} for a record of {}", allocated, end);
        assert!(end > short && end <= short + 2 * FLOOR, "the record was padded by {} bytes", end - short);
        assert_eq!(record.failures(file_time_now()), Ok(failures.clone()), "the padding is no record");
        assert_eq!(lockout(&record.failures(file_time_now()).unwrap(), file_time_now()), Some(locked), "and no lockout is shortened or lengthened by it");
        // The wrong password that follows the logon lands in room that is there: the allocation does not change.
        record.add(ago(5)).expect("add");
        assert_eq!(record.sizes(), Ok((allocated, end + RECORD_BYTES as u64)));
        drop(held);
        // (A range that is locked cannot be read by another handle, so what was written is looked at now.)
        let bytes = contents(&rec);
        assert!(bytes[short as usize..end as usize].iter().all(|byte| *byte == b'\n'), "what was added to make the room is newlines");
        assert_eq!((bytes.len() as u64, parse(&bytes[end as usize..]).len()), (end + RECORD_BYTES as u64, 1), "the record that followed is after them");
        // A record that ends within a record of its allocation is given another unit of room, one byte past the end of the old.
        let (allocated, end) = record.sizes().expect("sizes");
        append_raw(&rec, &vec![b'x'; (allocated - 5 - end) as usize]).expect("garbage that leaves five bytes of room");
        assert_eq!(record.sizes(), Ok((allocated, allocated - 5)));
        let held = record.lock().expect("the lock");
        let (now_allocated, now_end) = record.sizes().expect("sizes");
        assert!(now_allocated > allocated && now_allocated >= now_end + RECORD_BYTES as u64 && now_end == allocated + 1, "{} {} against {}", now_allocated, now_end, allocated);
        assert_eq!(record.failures(file_time_now()).map(|found| found.len()), Ok(4), "the garbage and the padding are no records");
        drop(held);
        // A record with room to spare is not padded again.
        let before = record.sizes().expect("sizes");
        drop(record.lock().expect("the lock"));
        assert_eq!(record.sizes(), Ok(before));
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetDiskFreeSpaceExW(directory: *const u16, available: *mut u64, total: *mut u64, free: *mut u64) -> Bool;
        fn SetFileInformationByHandle(file: Handle, class: i32, information: *mut c_void, size: u32) -> Bool;
    }

    #[test]
    fn what_a_process_without_administrator_rights_can_do_to_the_record_besides_reading_and_appending_is_to_lock_a_range_and_set_the_sparse_attribute() {
        let fixture = Fixture::new();
        let (rec, record) = (fixture.place.record.clone(), fixture.record());
        let ago = |minutes: u64| file_time_now() - minutes * MINUTE;
        record.add(ago(20)).expect("add");
        let before = contents(&rec);
        let _acting = Impersonating::begin();
        let control = |handle: Handle, code: u32, input: &mut [u8]| {
            let mut returned = 0u32;
            let (pointer, size) = if input.is_empty() { (std::ptr::null_mut(), 0) } else { (input.as_mut_ptr() as *mut c_void, input.len() as u32) };
            ok_or_code(unsafe { DeviceIoControl(handle, code, pointer, size, std::ptr::null_mut(), 0, &mut returned, std::ptr::null_mut()) })
        };
        // A handle that can read can lock the whole record, or the end of it: this is a denial of the use of exceptions by the account
        // (the guard cannot take its own lock, and is refused before the logon) and nothing more.
        let reader = Open(open_raw(&rec, FILE_READ_DATA | FILE_READ_ATTRIBUTES, OPEN_EXISTING, 0).expect("a reader"));
        assert_eq!(lock_range(reader.0, 0, A_LOT), Ok(()));
        drop(reader);
        // The handle the guard uses (read and append): the sparse attribute can be set, which changes no byte; nothing else that
        // changes the contents or the size is let.
        let handle = Open(open_raw(&rec, FILE_READ_DATA | FILE_APPEND_DATA | FILE_READ_ATTRIBUTES, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH).expect("the handle of the guard"));
        assert_eq!(control(handle.0, 0x9_00C4, &mut []), Ok(()), "FSCTL_SET_SPARSE");
        assert_eq!(control(handle.0, 0x9_00C4, &mut [0u8]), Ok(()), "and back");
        let mut zero = [0u8; 16];
        zero[8] = 16;
        assert_eq!(control(handle.0, 0x9_80C8, &mut zero), Err(ACCESS_DENIED), "FSCTL_SET_ZERO_DATA");
        assert_eq!(control(handle.0, 0x9_C040, &mut [1u8, 0]), Err(ACCESS_DENIED), "FSCTL_SET_COMPRESSION");
        let mut nothing = [0u8; 8];
        assert_eq!(ok_or_code(unsafe { SetFileInformationByHandle(handle.0, 6, nothing.as_mut_ptr() as *mut c_void, 8) }), Err(ACCESS_DENIED), "FileEndOfFileInfo");
        assert_eq!(ok_or_code(unsafe { SetFileInformationByHandle(handle.0, 5, nothing.as_mut_ptr() as *mut c_void, 8) }), Err(ACCESS_DENIED), "FileAllocationInfo");
        drop(_acting);
        assert_eq!(contents(&rec), before, "no byte of the record changed");
    }

    #[test]
    fn all_the_readings_of_one_run_share_the_time_the_record_is_given_and_a_run_that_has_used_it_refuses_at_once() {
        // The budget gives each read what the reads before it left, and nothing once it is gone.
        let budget = Budget::new(Duration::from_millis(150));
        let mut lefts = Vec::new();
        for _ in 0..4 {
            budget.spend(|left| {
                lefts.push(left);
                std::thread::sleep(Duration::from_millis(60));
            });
        }
        assert_eq!(lefts[0], Duration::from_millis(150));
        assert!(lefts[1] < lefts[0] && lefts[1] <= Duration::from_millis(90), "{:?}", lefts);
        assert!(lefts[2] <= Duration::from_millis(30), "{:?}", lefts);
        assert_eq!(lefts[3], Duration::ZERO, "nothing is left for the fourth: {:?}", lefts);
        // A record whose run has used what it was given refuses a read of anything, as a record that cannot be read in time, and
        // an empty record needs no time.
        let fixture = Fixture::new();
        let record = fixture.record();
        assert_eq!(record.failures(file_time_now()), Ok(vec![]));
        record.add(file_time_now() - 10 * MINUTE).expect("add");
        record.budget.spent.set(READ_LIMIT);
        let refused = record.failures(file_time_now()).err().expect("the time is used");
        assert!(refused.starts_with("the lockout record could not be read in time; an administrator must remove it as described in the README"), "{}", refused);
        assert_eq!(state(&record).err(), Some(refused));
        // The limit is the one of the document: ten seconds for the whole run.
        assert_eq!(fixture.record().budget.limit, Duration::from_secs(10));
    }

    /// A record that counts how often it is read and what time it is asked, and holds `failures`.
    struct CountsReads {
        failures: Vec<u64>,
        reads: std::cell::Cell<u32>,
        clocks: std::cell::Cell<u32>,
    }

    impl Record for CountsReads {
        fn now(&self) -> u64 {
            self.clocks.set(self.clocks.get() + 1);
            at(9, 0)
        }

        fn failures(&self, _now: u64) -> Result<Vec<u64>, String> {
            self.reads.set(self.reads.get() + 1);
            Ok(self.failures.clone())
        }

        fn add(&self, _filetime: u64) -> Result<(), String> {
            Err("this record takes nothing".into())
        }

        fn lock(&self) -> Result<Held<'_>, String> {
            Ok(Held::new(|| {}))
        }

        fn local_clock(&self, filetime: u64) -> (u16, u16) {
            let minutes = (filetime / MINUTE + 1440 - 7 * 60) % 1440;
            ((minutes / 60) as u16, (minutes % 60) as u16)
        }
    }

    #[test]
    fn one_look_is_one_reading_of_the_record_and_one_of_the_clock_and_gives_both_the_lockout_and_the_count() {
        let record = CountsReads { failures: vec![at(1, 10), at(1, 11), at(8, 30)], reads: std::cell::Cell::new(0), clocks: std::cell::Cell::new(0) };
        let (locked, recorded) = look(&record).expect("a look");
        assert_eq!((record.reads.get(), record.clocks.get()), (1, 1));
        assert_eq!((locked, recorded), (None, 1), "two long ago, one in the last six hours: no lockout");
        let record = CountsReads { failures: vec![at(8, 10), at(8, 20), at(8, 30)], reads: std::cell::Cell::new(0), clocks: std::cell::Cell::new(0) };
        let (locked, recorded) = look(&record).expect("a look");
        assert_eq!((record.reads.get(), record.clocks.get(), recorded), (1, 1, 3));
        assert!(locked.map_or(false, |reason| reason.starts_with("locked out after 3 wrong passwords, the last at 1:30am;")));
        assert_eq!(look(&Fixed { failures: vec![], now: at(9, 0), unreadable: true }).err(), Some("the lockout record could not be read".to_string()));
    }

    #[test]
    fn the_record_that_is_opened_is_judged_and_must_be_the_file_that_was_looked_at() {
        let fixture = Fixture::new();
        let sid = current_user_sid().expect("the user of this test");
        let trusted = [sid.as_str(), "S-1-5-32-544"];
        let seen = verify(&fixture.place, &RecordCheck::Limited).expect("the look at the names");
        assert!(open_checked(&fixture.place, &trusted, &seen).is_ok());
        // A file that is not the one that was looked at: the names led somewhere else the second time, or the file was replaced
        // between the look and the open (CWE-367). Whatever the other file is, it is refused.
        for other in [Identity { volume: seen.volume ^ 1, ..seen }, Identity { index_high: seen.index_high ^ 1, ..seen }, Identity { index_low: seen.index_low ^ 1, ..seen }] {
            let refused = open_checked(&fixture.place, &trusted, &other).err().expect("a different file");
            assert!(refused.starts_with("the lockout record for this account is not the file that was checked a moment before"), "{}", refused);
        }
        // The file that is open is judged, not the name: a record that allows more by the time it is opened is refused on the handle,
        // with its rights named, and so is one whose owner is not trusted.
        fixture.set(2, &fixture.record_list(0x12008d | 0x2));
        let wide = open_checked(&fixture.place, &trusted, &seen).err().expect("a record that allows writing");
        assert!(wide.starts_with("the lockout record for this account allows more than read and append (WRITE_DATA);"), "{}", wide);
        fixture.set(2, &fixture.record_list(0x12008d));
        assert!(open_checked(&fixture.place, &trusted, &seen).is_ok());
        let nobody: [&str; 0] = [];
        let refused = open_checked(&fixture.place, &nobody, &seen).err().expect("an owner that is not trusted");
        assert!(refused.contains("is owned by") && refused.contains("so it cannot be trusted"), "{}", refused);
        // The identity of a record is the identity of that file and of no other.
        let other = Fixture::new();
        assert_ne!(verify(&other.place, &RecordCheck::Limited).expect("the other"), seen);
    }

    /// `fixture`'s place with the names the object manager gives its folders: the volume of the scratch folder is named as the system
    /// names it, as the guard names the system volume.
    fn device_place(programdata: &str, account: &str) -> Place {
        let folder = Open(open_raw(programdata, FILE_READ_ATTRIBUTES, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS).expect("the folder"));
        let named = final_path(folder.0).expect("its name");
        let mut place = Place::new(&named, account).expect("a place");
        place.ancestors.clear();
        place
    }

    #[test]
    fn the_record_is_found_by_its_name_in_the_object_manager_and_the_file_that_is_opened_must_have_that_name() {
        let fixture = Fixture::new();
        let place = device_place(&fixture.place.programdata, &fixture.account);
        assert!(split_device(&place.record).is_some() && place.record.ends_with(".lockout"), "{}", place.record);
        assert!(verify(&place, &RecordCheck::Limited).is_ok(), "the names from the object manager are looked at as the names on a drive are");
        let record = open_at(&place).expect("the record opens by its name in the object manager");
        record.add(file_time_now() - 5 * MINUTE).expect("add");
        assert_eq!(record.failures(file_time_now()).map(|failures| failures.len()), Ok(1));
        // The system spells a path as it likes, in the letter case: the name that was asked for in other letters is the same name.
        let shouted = Place { ancestors: Vec::new(), programdata: place.programdata.clone(), folder: place.folder.clone(), record: place.record.to_uppercase() };
        assert!(open_at(&shouted).is_ok());
        // A name on another volume is not there.
        let other = place.record.replacen("\\Device\\HarddiskVolume", "\\Device\\HarddiskVolume9999", 1);
        let elsewhere = Place { ancestors: Vec::new(), programdata: place.programdata.clone(), folder: place.folder.clone(), record: other };
        assert!(open_at(&elsewhere).err().expect("no such volume").starts_with("no lockout record exists for this account;"));
        // The ancestors of a name from the object manager start at the volume.
        let from_root = device_place(&fixture.place.programdata, &fixture.account);
        assert_eq!(ancestors_of(&from_root.programdata).first().map(|root| split_device(root).map(|(_, rest)| rest)), Some(Some("\\")));
    }

    #[test]
    fn the_step_names_what_it_makes_on_the_drive_of_the_system_volume_when_the_place_is_named_from_the_object_manager() {
        let fixture = Fixture::new();
        let programdata = fixture.free("pd-named");
        std::fs::create_dir_all(&programdata).expect("a scratch folder");
        let place = device_place(&programdata, "S-1-5-21-1-2-3-4321");
        let api = record_api().expect("the system calls");
        let system = system_device(api).expect("the system volume");
        // The scratch folder is on the system volume where the temporary folder is (the usual case): the step names what it makes
        // by the drive of the system folder, as an administrator reads it. On another volume the name is left as it is.
        let on_system = split_device(&place.folder).map_or(false, |(volume, _)| volume.eq_ignore_ascii_case(&system));
        let shown = drive_form(&place.folder);
        if on_system {
            assert!(shown.as_bytes()[1] == b':' && shown.to_lowercase().ends_with("\\pd-named\\processtreeguard"), "{}", shown);
            let full = format!("(A;;FA;;;{})", fixture.sid);
            let trusted = [fixture.sid.as_str()];
            let authority = Authority { owner: &fixture.sid, trusted: &trusted, folder: &full, record: &full, tolerated: 0 };
            let mut said = Vec::new();
            make_folder(&place, &authority, &mut |line| said.push(line)).expect("made by the drive form of the name");
            make_record(&place, "S-1-5-21-1-2-3-4321", "someone", &authority, false, &mut |line| said.push(line)).expect("made by the drive form of the name");
            assert!(said[0].starts_with("created folder ") && said[0].as_bytes()["created folder ".len() + 1] == b':' && said[1].starts_with("created record ") && said[1].contains("S-1-5-21-1-2-3-4321"), "{:?}", said);
            assert!(Path::new(&format!("{}\\processtreeguard", programdata)).is_dir() || Path::new(&format!("{}\\ProcessTreeGuard", programdata)).is_dir());
            let mut again = Vec::new();
            make_folder(&place, &authority, &mut |line| again.push(line)).expect("the folder is there");
            make_record(&place, "S-1-5-21-1-2-3-4321", "someone", &authority, false, &mut |line| again.push(line)).expect("the record is there");
            assert!(again[0].starts_with("folder ") && again[0].ends_with(": permissions set") && again[1].starts_with("record "), "{:?}", again);
            for path in [&place.record, &place.folder] {
                assert!(std::fs::remove_file(drive_form(path)).is_ok() || std::fs::remove_dir(drive_form(path)).is_ok());
            }
        } else {
            assert_eq!(shown, place.folder);
        }
    }

    #[test]
    fn the_step_does_not_take_over_a_record_whose_owner_is_not_trusted_and_leaves_its_list_as_it_was() {
        // A user may make files in a folder of the records that was made without the lists of the step (an administrator or a program
        // made it first), and may keep a handle that writes. Setting the list and the owner of such a record would leave the handle
        // writing for ever, and the check would then pass it. The owner is looked at first, with the handle that is then used.
        let fixture = Fixture::new();
        let api = record_api().expect("the system calls");
        let limited = Limited::new(api).expect("the token");
        // The step has to be able to open the record to take it in hand; an administrator always can.
        fixture.set(2, &fixture.record_list(0x12008d | WRITE_DAC | WRITE_OWNER));
        let before = inspect(api, (limited.0).0, &fixture.place.record).expect("inspect");
        let none: [&str; 0] = [];
        let authority = Authority { owner: &fixture.sid, trusted: &none, folder: OWNER_RIGHTS, record: "", tolerated: 0 };
        let mut said = Vec::new();
        let refused = make_record(&fixture.place, &fixture.account, "the account", &authority, true, &mut |line| said.push(line)).err().expect("not taken over");
        assert_eq!(refused, format!("the record {} is owned by {}, which is not the Administrators group, the system or the installer of the system, so it is not taken over; \
            remove it as described in the README and run this again", fixture.place.record, fixture.sid));
        assert!(said.is_empty(), "nothing is said of a record that was not mended: {:?}", said);
        let after = inspect(api, (limited.0).0, &fixture.place.record).expect("inspect");
        assert_eq!(parts(&after.descriptor), parts(&before.descriptor), "the owner and the list are as they were");
        assert_eq!(after.granted, before.granted);
        // The function that takes an object in hand refuses it for the same reason, for a record as for a folder.
        let made = Made::from(&record_sddl(&authority, &fixture.account)).expect("a list");
        assert!(set_permissions(&fixture.place.record, false, &made, &authority).err().map_or(false, |why| why.contains("is owned by") && why.contains("not taken over")));
        // With the owner trusted it is mended, as before.
        fixture.set(1, &fixture.folder_list(0x1200a0 | WRITE_DAC | WRITE_OWNER));
        let mut mended = Vec::new();
        fixture.run(&mut mended).expect("the step over a record whose owner is trusted");
        assert!(mended.iter().any(|line| line.starts_with("record ") && line.contains(": permissions set")), "{:?}", mended);
    }

    #[test]
    fn a_folder_between_the_drive_and_the_programs_data_that_the_account_can_delete_or_rename_is_refused_and_so_is_the_folder_of_the_programs_data_itself() {
        let fixture = Fixture::new();
        let api = record_api().expect("the system calls");
        let limited = Limited::new(api).expect("the token");
        // The root of the system drive, which the account can neither delete nor take over, then the scratch root, which stands for a
        // folder on the way down. Its list gives the account the right to delete it and not the right to delete what is in it.
        let drive = format!("{}\\", windows_folder().expect("the system folder").chars().take(2).collect::<String>());
        let owners = [fixture.sid.as_str(), &owner_text(&inspect(api, (limited.0).0, &drive).expect("inspect the drive").descriptor), "S-1-5-32-544"].map(str::to_string);
        let trusted: Vec<&str> = owners.iter().map(String::as_str).collect();
        let root = fixture.root.to_string_lossy().into_owned();
        let key = Open(open_raw(&root, WRITE_DAC | READ_CONTROL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS).expect("the owner can take the scratch root in hand"));
        let set_root = |sddl: &str| {
            let made = Made::from(sddl).expect("a list");
            assert_ne!(unsafe { SetKernelObjectSecurity(key.0, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, made.pointer) }, 0, "{}", os_error());
        };
        let place = Place { ancestors: vec![drive.clone(), root.clone()], programdata: fixture.place.programdata.clone(), folder: fixture.place.folder.clone(), record: fixture.place.record.clone() };
        // Without the right to delete the folder, nor what is in it, nor to change its list: accepted.
        set_root(&format!("D:P(A;;0x1201bf;;;{}){}", fixture.sid, OWNER_RIGHTS));
        assert!(super::verify(&place, &RecordCheck::Limited, &trusted).is_ok(), "{:?}", super::verify(&place, &RecordCheck::Limited, &trusted));
        // With the right to delete the folder itself (a data volume gives a user that on the folder it makes), which lets it rename the
        // folder and swap what is below it.
        set_root(&format!("D:P(A;;0x1301bf;;;{}){}", fixture.sid, OWNER_RIGHTS));
        let refused = super::verify(&place, &RecordCheck::Limited, &trusted).err().expect("an ancestor the account can delete");
        assert_eq!(refused.reason, format!("the folder {} lets this account delete or rename it or what is in it, or change its permissions or owner (DELETE), so a lockout record in it cannot be protected", root));
        // The first folder, the root of the drive, keeps the judgment it had.
        let only_root = Place { ancestors: vec![root.clone()], programdata: fixture.place.programdata.clone(), folder: fixture.place.folder.clone(), record: fixture.place.record.clone() };
        assert!(super::verify(&only_root, &RecordCheck::Limited, &trusted).is_ok(), "the first ancestor is the root of the drive and is judged as one");
        // The folder of the programs' data is judged like the folders between: the right to delete it is refused.
        fixture.set(0,&format!("D:P(A;;0x1301a6;;;{}){}", fixture.sid, OWNER_RIGHTS));
        let data = super::verify(&Place { ancestors: Vec::new(), ..place_of(&fixture) }, &RecordCheck::Limited, &trusted).err().expect("the folder of the programs' data can be deleted");
        assert_eq!(data.reason, "the folder of the programs' data of this machine lets this account delete or rename it or what is in it, or change its permissions or owner (DELETE), so a lockout record in it cannot be protected");
        fixture.set(0, &format!("D:P(A;;0x1200a6;;;{}){}", fixture.sid, OWNER_RIGHTS));
        set_root(&format!("D:P(A;;FA;;;{})", fixture.sid));
    }

    /// The place of `fixture` as it is, without anything above the folder of the programs' data.
    fn place_of(fixture: &Fixture) -> Place {
        Place { ancestors: Vec::new(), programdata: fixture.place.programdata.clone(), folder: fixture.place.folder.clone(), record: fixture.place.record.clone() }
    }
}
