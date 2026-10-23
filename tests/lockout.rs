// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! Behaviour tests for the lockout of the password exception (series L, L1 to L11): the record of wrong passwords of an account,
//! the one-time elevated step that makes it, the refusal of every run over the cap whose record is missing or cannot be used, and
//! the lockout that the third wrong password within six hours starts. The parity table is in tests/PARITY.md.
//!
//! No test here shows a prompt: every run over the cap says `--authenticate console` and has a standard input that is null. No test
//! writes to the record of the machine it runs on unless `PROCESS_TREE_GUARD_RUN_LOCKOUT_RECORD_TEST` is set (the continuous integration
//! and release workflows set it): L1 and L2 only read, or are refused, and L3 to L11 call `allow_writes` after `writes_are_wanted` is true, and `allow_writes` panics
//! before anything is written when the variable is not set. L3 to L11 remove the whole folder of the records, which holds the record
//! of every account of the machine, so they reset every account's lockout there: the variable is for runners that are used for the
//! tests alone. The wrong passwords in L7 to L9 are written to the record by a program that has the rights of the user without
//! administrator rights; no password is ever entered or tried.

mod common;

use common::*;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// The tests of this file take turns: L3 to L11 remove and make the record of the machine, which the others read.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The variable that allows the tests that make, change and remove the record of the machine. They need an elevated process.
const RUN_VARIABLE: &str = "PROCESS_TREE_GUARD_RUN_LOCKOUT_RECORD_TEST";

/// The probes that `lockout_probe` in src/bin/testkit.rs reports, one line each (P1 to P21f); a probe dropped from the helper changes the count.
const PROBE_LINES: usize = 38;

fn writes_are_wanted() -> bool {
    variable_set(RUN_VARIABLE)
}

/// Panics unless the variable is set: called before anything writes to the record of the machine.
fn allow_writes() {
    assert!(writes_are_wanted(), "a test would write to the lockout record of this machine without {} being set", RUN_VARIABLE);
}

/// A run over the cap that can never show a prompt (the console method, a standard input that is null), whose command writes `marker`.
fn over_cap_run(marker: &str) -> Out {
    run_guard(&["--extendable", "--max-extension", "86400", "--authenticate", "console", "--timeout", "5", "--", testkit(), "mark", marker, "20"])
}

/// The one log line a refusal of an exception writes, from a standard error text.
fn refusal_line(err: &str) -> String {
    let lines: Vec<String> = extension_lines(err).into_iter().filter(|line| line.contains("decision=exception-")).collect();
    if lines.len() == 1 { lines.into_iter().next().unwrap_or_default() } else { String::new() }
}

/// Whether `text` has `needle`, whatever the letter case of the drive and the folders: the system spells a path as it likes.
fn mentions(text: &str, needle: &str) -> bool {
    text.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
}

fn shown(result: &Out) -> String {
    format!("exit {} in {:.2} s: {} {}", result.code, result.elapsed.as_secs_f64(), result.out().trim(), result.err().trim())
}

fn run_program(program: &str, args: &[&str]) -> Out {
    let mut command = Command::new(program);
    command.args(args);
    exec(command)
}

/// What the helper prints for `args`, trimmed.
fn helper(args: &[&str]) -> String {
    run_program(testkit(), args).out().trim().to_string()
}

/// Whether this process has an elevated token.
fn elevated() -> bool {
    helper(&["elevated"]) == "elevated"
}

/// The folder of the lockout records and the record of the user running the tests, as the guard places them.
fn record_locations() -> (String, String) {
    let text = helper(&["record-path"]);
    let mut lines = text.lines();
    (lines.next().unwrap_or("").trim().to_string(), lines.next().unwrap_or("").trim().to_string())
}

/// The minutes after midnight of a time written as the guard writes it (`8:12pm`).
fn minutes_of(clock: &str) -> Option<u32> {
    let (time, pm) = match (clock.strip_suffix("pm"), clock.strip_suffix("am")) {
        (Some(time), _) => (time, true),
        (_, Some(time)) => (time, false),
        _ => return None,
    };
    let (hour, minute) = time.split_once(':')?;
    let (hour, minute): (u32, u32) = (hour.parse().ok()?, minute.parse().ok()?);
    (1..=12).contains(&hour).then_some(())?;
    (minute < 60).then_some(())?;
    Some((hour % 12 + if pm { 12 } else { 0 }) * 60 + minute)
}

/// The parts of the message of a lockout in `err`: the count, the time of the last wrong password, the time left and the time
/// the lockout ends, after "exception refused: locked out after N wrong passwords, the last at T; the password can be asked again in L, at E; the run did not start".
fn lockout_message(err: &str) -> Option<(u32, String, String, String)> {
    let text = err.split("exception refused: locked out after ").nth(1)?;
    let (count, rest) = text.split_once(" wrong passwords, the last at ")?;
    let (last, rest) = rest.split_once("; the password can be asked again in ")?;
    let (left, rest) = rest.split_once(", at ")?;
    let (until, _) = rest.split_once("; the run did not start")?;
    Some((count.parse().ok()?, last.to_string(), left.to_string(), until.to_string()))
}

/// True when `left` (`5h 59m`) is a time left of a lockout that began a moment ago: nearly six hours.
fn nearly_six_hours(left: &str) -> bool {
    let Some((hours, minutes)) = left.split_once("h ") else { return false };
    match (hours.parse::<u32>(), minutes.strip_suffix('m').and_then(|minutes| minutes.parse::<u32>().ok())) {
        (Ok(6), Some(0)) => true,
        (Ok(5), Some(minutes)) => minutes >= 50 && minutes < 60,
        _ => false,
    }
}

/// True when the time the lockout ends is six hours after the time of the last wrong password on the clock, or an hour either way
/// where the clock changes in between (summer time). The end is shown rounded up to the minute, as the time left is, so it is 361
/// minutes after the minute of the last (360 only if the last fell on an exact minute, which the clock of a real run does not).
fn six_hours_later(last: &str, until: &str) -> bool {
    let (Some(last), Some(until)) = (minutes_of(last), minutes_of(until)) else { return false };
    let difference = (until + 1440 - last) % 1440;
    [300, 301, 360, 361, 420, 421].contains(&difference)
}

#[test]
fn the_helpers_of_these_tests_read_the_message_the_guard_writes() {
    let err = "PROCESS_GUARD_ERROR: exception refused: locked out after 3 wrong passwords, the last at 8:12pm; the password can be asked again in 5h 25m, at 2:12am; the run did not start";
    assert_eq!(lockout_message(err), Some((3, "8:12pm".to_string(), "5h 25m".to_string(), "2:12am".to_string())));
    assert_eq!(lockout_message("exception refused: no lockout record exists for this account; the run did not start"), None);
    assert!(six_hours_later("8:12pm", "2:13am") && six_hours_later("8:12pm", "2:12am") && six_hours_later("11:59pm", "6:00am") && six_hours_later("12:00am", "6:01am"));
    assert!(!six_hours_later("8:12pm", "2:14am") && !six_hours_later("8:12pm", "2:11am") && !six_hours_later("8:12pm", "8:12pm"));
    assert!(nearly_six_hours("6h 0m") && nearly_six_hours("5h 59m") && nearly_six_hours("5h 50m"));
    assert!(!nearly_six_hours("5h 49m") && !nearly_six_hours("6h 1m") && !nearly_six_hours("40m"));
    assert_eq!((minutes_of("12:05am"), minutes_of("12:00pm"), minutes_of("11:59pm"), minutes_of("1:00pm")), (Some(5), Some(720), Some(1439), Some(780)));
    assert_eq!((minutes_of("13:00pm"), minutes_of("8:60am"), minutes_of("8:12"), minutes_of("")), (None, None, None, None));
    assert!(mentions("Created Folder C:\\ProgramData\\X", "created folder c:\\programdata\\x") && !mentions("a", "b"));
}

/// The order of the decision, as a machine with no record tells it: the record is looked at after the refusal of a run that another
/// guard started, so with the record missing the reason is still that one and not the record's. G94 and G99 assert the same
/// refusals where the record is there, and would still pass if the record were looked at first; only a machine with no record
/// tells the two orders apart. `dir` holds the copy of the guard that the second check makes, and `marker` is a file the command
/// would write.
fn refused_for_the_guard_above(checks: &mut Checks, id: &str, dir: &TempDir, marker: &Path, marker_text: &str) {
    let inner = [guard(), "--extendable", "--max-extension", "86400", "--authenticate", "console", "--timeout", "5", "--", testkit(), "mark", marker_text, "20"];
    let under = guarded("30", &inner);
    checks.check(id, "with the record missing, a plain guard around an extendable guard over the cap (the shape of G94): the inner guard is refused because another guard started it, \
        with attempt 0, and not for the record; its command never runs",
        under.code == 125 && !marker.exists() && refusal_line(&under.err()).contains("attempt=0") && refusal_line(&under.err()).contains(&format!("reason=\"{}", WRAPPED_REASON))
            && !under.err().contains(MISSING_REASON), shown(&under));
    let copy = copy_role(dir.path(), ROLES[0], "process-tree-guard-auto");
    let mut args = vec!["--timeout", "30", "--"];
    args.extend(inner);
    refuse_prompt(&args);
    let mut command = Command::new(&copy);
    command.args(&args);
    let named = exec(command);
    checks.check(id, "and the same under a copy named process-tree-guard-auto (the shape of G99): refused because another guard started it, not for the record, and the command never runs",
        named.code == 125 && !marker.exists() && refusal_line(&named.err()).contains("attempt=0") && refusal_line(&named.err()).contains(&format!("reason=\"{}", WRAPPED_REASON))
            && !named.err().contains(MISSING_REASON), shown(&named));
}

// ------------------------------------------------------------------------------------- L1 and L2, which never write

#[test]
fn l1_the_setup_command_without_administrator_rights_is_refused_with_125_and_makes_nothing() {
    let _turn = serial();
    let mut checks = Checks::new("lockout record setup without administrator rights");
    // The command needs the rights of an administrator. Where this process has them (a runner on continuous integration does), it is run by
    // a child of the user without them, and only after the helper has shown that the child has none: the setup is never started elevated here.
    let mut command = Command::new(testkit());
    command.args(["restricted", testkit(), "elevated"]);
    let child_is_limited = exec(command).out().trim() == "limited";
    let run = |args: &[&str]| -> Option<Out> {
        if !elevated() {
            return Some(run_guard(args));
        }
        if !child_is_limited {
            return None;
        }
        let mut command = Command::new(testkit());
        command.args(["restricted", guard()]).args(args);
        Some(exec(command))
    };
    match run(&["create-lockout-record"]) {
        Some(result) => {
            checks.check("L1", "create-lockout-record without administrator rights exits 125 and says that it needs them and how to get them",
                result.code == 125 && result.out().is_empty() && result.err().contains("PROCESS_GUARD_ERROR: create-lockout-record needs administrator rights; run it from an elevated terminal"), shown(&result));
            if let Some(named) = run(&["create-lockout-record", "someone"]) {
                checks.check("L1", "and the same with an account named",
                    named.code == 125 && named.out().is_empty() && named.err().contains("needs administrator rights"), shown(&named));
            }
        }
        None => {
            checks.notice("NOT ASSERTED L1 for the refusal without administrator rights: this process is elevated and the helper could not start a child without those rights, \
                so the setup was not started (it would have made a record)");
        }
    }
    // These never reach the elevation test, so they are safe whoever runs them: the help, a wrong number of arguments, and the programs that have no such command.
    let help = run_guard(&["create-lockout-record", "--help"]);
    checks.check("L1", "create-lockout-record --help prints its usage and exits 0 with nothing made", help.code == 0 && help.out().contains("usage: process-tree-guard create-lockout-record [ACCOUNT]"), shown(&help));
    let short = run_guard(&["create-lockout-record", "-h"]);
    checks.check("L1", "and -h does the same", short.code == 0 && short.out().contains("create-lockout-record [ACCOUNT]"), shown(&short));
    let many = run_guard(&["create-lockout-record", "one", "two"]);
    checks.check("L1", "two accounts are a usage error: 125 and the usage, before anything else is looked at", many.code == 125 && many.err().contains("usage: process-tree-guard create-lockout-record [ACCOUNT]"), shown(&many));
    let usage = run_guard(&["--help"]);
    checks.check("L1", "the usage of the guard names the command", usage.code == 0 && usage.out().contains("process-tree-guard create-lockout-record [ACCOUNT]"), shown(&usage));
    for name in [ROLES[1], ROLES[3]] {
        let other = run_program(role(name), &["create-lockout-record"]);
        checks.check("L1", &format!("{} has no such command: 125, and nothing made", name), other.code == 125 && !other.err().contains("administrator rights"), shown(&other));
    }
    let dir = TempDir::new("l1-");
    let auto = copy_guard(dir.path(), "process-tree-guard-auto");
    let wrapped = run_program(&auto, &["create-lockout-record"]);
    checks.check("L1", "a copy under a name that ends in -auto is automatic mode and runs the word as a command of a shell, which is not found: it fails, and nothing is made",
        wrapped.code != 0 && !wrapped.err().contains("administrator rights") && !wrapped.out().contains("created"), shown(&wrapped));
    checks.finish();
}

#[test]
fn l2_a_run_over_the_cap_with_no_record_is_refused_with_the_step_that_makes_one_and_never_prompts() {
    let _turn = serial();
    let mut checks = Checks::new("run over the cap with no lockout record");
    // At or below the cap nothing changes, whatever the record is: this runs everywhere.
    let below = run_guard(&["--extendable", "--max-extension", "21600", "--authenticate", "console", "--timeout", "5", "--", testkit(), "print", "ran"]);
    checks.check("L2", "a run at the default cap is not affected by the record: the command runs and passes its exit code", below.code == 0 && below.out().contains("ran"), shown(&below));
    if let Some(above) = guard_above_the_tests() {
        checks.notice(format!("NOT ASSERTED L2 for the refusal: {} is above these tests, so each guard they start is refused for that first", above));
        checks.finish();
        return;
    }
    if !learned_reason().starts_with(MISSING_REASON) {
        checks.notice(format!("NOT ASSERTED L2 for the refusal: the account has a lockout record here (the guard these tests start is refused for: {}); L3 asserts it where {} is set",
            learned_reason(), RUN_VARIABLE));
        checks.finish();
        return;
    }
    let dir = TempDir::new("l2-");
    let marker = dir.join("ran.txt");
    let marker_text = text(&marker);
    let result = over_cap_run(&marker_text);
    let line = refusal_line(&result.err());
    checks.check("L2", "a run over the cap with no record: exit 125, the command never runs and nothing is printed on standard output",
        result.code == 125 && !marker.exists() && result.out().is_empty(), shown(&result));
    checks.check("L2", "the error names the step that makes the record",
        result.err().contains(&format!("exception refused: {}; the run did not start", missing_reason())), shown(&result));
    checks.check("L2", "one exception-refused line, attempt 0 (nothing was shown), with that reason",
        line.contains("decision=exception-refused attempt=0") && line.contains(&format!("reason=\"{}\"", missing_reason())), line.clone());
    checks.check("L2", "no prompt was begun: neither the message of the prompt nor the standard input is mentioned",
        !result.err().contains("Process Tree Guard is asked to run") && !result.err().contains(NO_CONSOLE_REASON), shown(&result));
    checks.timing("L2", "the refusal is at once", result.elapsed.as_secs_f64() < 5.0 * UNIT + GRACE, shown(&result));
    // The deadline role is the same, in both layouts of the programs.
    for layout in LAYOUTS {
        let tree = Tree::new(layout, "l2-");
        let deadline = tree.exe(ROLES[1]);
        let mut command = Command::new(&deadline);
        command.args(["--extendable", "--max-extension", "86400", "--authenticate", "console", "--timeout", "5", "--", testkit(), "mark", marker_text.as_str(), "20"]);
        let other = exec(command);
        checks.check("L2", &format!("the deadline role in the {} is refused the same way", layout.name()),
            other.code == 125 && !marker.exists() && refusal_line(&other.err()).contains(&format!("reason=\"{}\"", missing_reason())), shown(&other));
    }
    refused_for_the_guard_above(&mut checks, "L2", &dir, &marker, &marker_text);
    // By the other method too, on a window station that nobody can see (the test of G95): the record is looked at before the station.
    if variable_set("PROCESS_TREE_GUARD_RUN_DESKTOP_PROMPT_TEST") {
        let mut command = Command::new(testkit());
        command.args(["hidden-station-guard", guard(), "86400", "5", testkit(), "mark", marker_text.as_str(), "20"]);
        let hidden = exec(command);
        if hidden.code != 96 {
            checks.check("L2", "the desktop method is refused for the record before the window station is looked at",
                hidden.code == 125 && !marker.exists() && refusal_line(&hidden.err()).contains(&format!("reason=\"{}\"", missing_reason())), shown(&hidden));
        } else {
            checks.notice(format!("NOT ASSERTED L2 for the desktop method: no window station could be made here: {}", shown(&hidden)));
        }
    } else {
        checks.notice("NOT ASSERTED L2 for the desktop method: PROCESS_TREE_GUARD_RUN_DESKTOP_PROMPT_TEST is not set");
    }
    checks.finish();
}

// ---------------------------------------------------------------- L3 to L11, which make and remove the record of the machine

/// The record of the machine as these tests leave it: removed, made again by the step, and checked. Dropped on every path, a panic included.
struct FreshRecord {
    folder: String,
}

/// Whether `folder` is named as the folder of the records: a recursive removal is made only of a folder with this name.
fn is_record_folder(folder: &str) -> bool {
    folder.to_ascii_lowercase().ends_with("\\processtreeguard")
}

impl Drop for FreshRecord {
    fn drop(&mut self) {
        if is_record_folder(&self.folder) {
            let _ = std::fs::remove_dir_all(&self.folder);
        }
        let mut command = Command::new(guard());
        command.arg("create-lockout-record");
        let _ = exec(command);
    }
}

/// Run the setup step, as the user of this process (which is elevated).
fn setup() -> Out {
    allow_writes();
    run_guard(&["create-lockout-record"])
}

/// Remove the folder of the records, as an administrator does to start again.
fn remove_folder(folder: &str) -> bool {
    allow_writes();
    is_record_folder(folder) && (!Path::new(folder).exists() || std::fs::remove_dir_all(folder).is_ok())
}

/// Remove the record of the user alone, as an administrator does to reset one lockout: the records of other accounts are left as they are.
fn remove_record(record: &str) -> bool {
    allow_writes();
    !Path::new(record).exists() || std::fs::remove_file(record).is_ok()
}

/// A program of the user without administrator rights, as the helper makes it.
fn as_the_user(args: &[&str]) -> Out {
    allow_writes();
    let mut full = vec!["restricted", testkit()];
    full.extend_from_slice(args);
    run_program(testkit(), &full)
}

fn record_size(record: &str) -> Option<u64> {
    std::fs::metadata(record).ok().map(|meta| meta.len())
}

/// A program of the user without administrator rights that holds a lock on a range of the record, as one that can only read it can:
/// the whole record (`all`) or from its end on (`end`). It lets go when this is dropped (its standard input ends), and in any case
/// after 60 seconds.
struct Holder {
    child: Child,
}

impl Drop for Holder {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.wait();
    }
}

/// Start the holder and wait until it says it holds the lock; None if it could not.
fn hold(record: &str, which: &str) -> Option<Holder> {
    allow_writes();
    let mut child = Command::new(testkit()).args(["restricted", testkit(), "lockout-hold", record, which])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
    let mut line = String::new();
    BufReader::new(child.stdout.take()?).read_line(&mut line).ok()?;
    if line.trim() == "held" {
        Some(Holder { child })
    } else {
        drop(child.stdin.take());
        let _ = child.wait();
        None
    }
}

#[test]
fn l3_to_l11_the_record_is_made_by_the_step_and_nothing_a_program_of_the_user_can_do_shortens_or_removes_a_lockout() {
    let _turn = serial();
    let mut checks = Checks::new("lockout record on this machine");
    if !writes_are_wanted() {
        checks.notice(format!("NOT ASSERTED L3 to L11: these tests make, change and remove the lockout record of this machine (the whole folder, with the records of every account), \
            and run only where {} is set and the process is elevated (the continuous integration and release workflows set it)", RUN_VARIABLE));
        checks.finish();
        return;
    }
    allow_writes();
    if let Some(above) = guard_above_the_tests() {
        checks.check("L3", &format!("no guard is above the tests, so that the guard a test starts reaches the lockout record (it is required where {} is set)", RUN_VARIABLE), false, above);
        checks.finish();
        return;
    }
    checks.check("L3", &format!("the process is elevated, as {} requires: the step is run from an elevated terminal", RUN_VARIABLE), elevated(), "");
    if !elevated() {
        checks.finish();
        return;
    }
    let (folder, record) = record_locations();
    let shaped = folder.ends_with("\\ProcessTreeGuard") && record.starts_with(&folder) && record.ends_with(".lockout");
    checks.check("L3", "the place of the record is known: the folder of the programs' data from the registry, and the security identifier of the user", shaped, format!("{} / {}", folder, record));
    // Nothing is removed on a place of any other shape.
    if !shaped {
        checks.finish();
        return;
    }
    let _fresh = FreshRecord { folder: folder.clone() };
    let dir = TempDir::new("l3-");
    let free = dir.join("free");
    std::fs::create_dir_all(&free).expect("make a folder of the user's own");
    let marker = dir.join("ran.txt");
    let marker_text = text(&marker);

    // L3: the folder is removed, and a run over the cap is refused with the step that makes the record, before any prompt.
    checks.check("L3", "the folder of the records is removed", remove_folder(&folder), folder.clone());
    let missing = over_cap_run(&marker_text);
    checks.check("L3", "a run over the cap with no record is refused with 125, the step that makes it, and its command never runs",
        missing.code == 125 && !marker.exists() && missing.err().contains(&format!("exception refused: {}; the run did not start", missing_reason()))
            && refusal_line(&missing.err()).contains("attempt=0"), shown(&missing));
    refused_for_the_guard_above(&mut checks, "L3", &dir, &marker, &marker_text);

    // L4: the step makes the folder and the record, says so, and checks them as the guard does.
    let made = setup();
    checks.check("L4", "the step exits 0 and says what it made: the folder, the record for the account with its security identifier, and the check",
        made.code == 0 && made.out().lines().count() == 3 && mentions(&made.out(), &format!("created folder {}", folder)) && mentions(&made.out(), &format!("created record {} for ", record))
            && made.out().contains("verified: a process of this account without administrator rights can read and append the record and do nothing else"), shown(&made));
    checks.check("L4", "the folder and the record are there, and the record is empty", Path::new(&folder).is_dir() && record_size(&record) == Some(0), record.clone());
    let ready = over_cap_run(&marker_text);
    checks.check("L4", "and the guard now gets as far as the test of its standard input (the refusal is for that, not for the record)",
        ready.code == 125 && !marker.exists() && ready.err().contains(NO_CONSOLE_REASON) && !ready.err().contains("create-lockout-record"), shown(&ready));

    // L5: the step run again is the same; it does not set right in place a record that allowed too much (a handle opened for writing
    // while it did stays valid when the list is changed): it names the rights and says to remove the record, and removing it and running the step makes a new one.
    let again = setup();
    checks.check("L5", "the step run again exits 0, says that it set the permissions of the folder and of the record (it made nothing), and checks them",
        again.code == 0 && again.out().lines().count() == 3 && mentions(&again.out(), &format!("folder {}: permissions set", folder)) && mentions(&again.out(), &format!("record {}: permissions set", record))
            && again.out().contains("verified:") && !again.out().contains("created"), shown(&again));
    checks.check("L5", "and the record is as it was", record_size(&record) == Some(0), record.clone());
    let one = as_the_user(&["lockout-append", record.as_str(), "1", "-2"]);
    let held = std::fs::read(&record).unwrap_or_default();
    checks.check("L5", "a child without administrator rights appends one wrong password, two hours old", one.code == 0 && held.len() == 20, shown(&one));
    let widened = run_program("icacls.exe", &[record.as_str(), "/grant", "*S-1-1-0:(W)"]);
    checks.check("L5", "the record is given a write right for everyone, as a mistake or an attack by an administrator would", widened.code == 0, shown(&widened));
    let wide = over_cap_run(&marker_text);
    checks.check("L5", "a run over the cap is refused, with 125: the record allows more than read and append, the rights are named, and the way to mend it is named: remove the record and run the step",
        wide.code == 125 && !marker.exists() && wide.err().contains("the lockout record for this account allows more than read and append (") && wide.err().contains("WRITE_DATA")
            && wide.err().contains("an administrator must remove it as described in the README and then run: process-tree-guard create-lockout-record"), shown(&wide));
    let refused = setup();
    checks.check("L5", "the step does not set it right in place: 125, the rights the record allowed are named, and it says that the record is not set right in place and to remove it",
        refused.code == 125 && mentions(&refused.err(), &format!("the record {} allowed ", record)) && refused.err().contains("WRITE_DATA") && refused.err().contains("it is not set right in place")
            && refused.err().contains("remove it as described in the README") && !refused.out().contains("verified:"), shown(&refused));
    checks.check("L5", "and the record is untouched: the bytes it holds are the bytes it held, and it still allows what it allowed (the guard still refuses it)",
        std::fs::read(&record).ok().as_deref() == Some(held.as_slice()) && over_cap_run(&marker_text).err().contains("allows more than read and append ("), record.clone());
    let removed = remove_record(&record);
    let replaced = setup();
    checks.check("L5", "an administrator removes the record and runs the step: it is made again, and verified",
        removed && replaced.code == 0 && mentions(&replaced.out(), &format!("created record {} for ", record)) && replaced.out().contains("verified:") && record_size(&record) == Some(0), shown(&replaced));
    let restored = over_cap_run(&marker_text);
    checks.check("L5", "and the guard gets as far as its standard input again", restored.err().contains(NO_CONSOLE_REASON), shown(&restored));

    // L6: what a program of the user without administrator rights can and cannot do with the record.
    let probes = as_the_user(&["lockout-probe", record.as_str(), folder.as_str(), text(&free).as_str()]);
    checks.check("L6", "in a child without administrator rights: the append lands at the end, and every operation that would shorten, rewrite, rename, replace, delete or re-permission the record, \
        or make anything in its folder, fails with access denied",
        probes.code == 0 && probes.out().contains("PROBES all as expected") && !probes.out().contains("UNEXPECTED") && probes.out().lines().filter(|line| line.starts_with('P') && !line.starts_with("PROBES") && line.contains("as expected")).count() == PROBE_LINES, probes.out());
    let ids = ["P20 ", "P20b", "P20c", "P20d", "P20e", "P20f", "P21 ", "P21b", "P21c", "P21d", "P21e", "P21f"];
    checks.check("L6", "and a range of the record can be locked by a program that can read it, which stops the read, the append and the lock of another handle (error 33); the sparse attribute \
        can be set and changes no byte, and zeroing, compressing, cutting short and reducing the allocation fail with error 5 (probes P20 to P21f)",
        ids.iter().all(|id| probes.out().lines().any(|line| line.starts_with(id) && line.contains("as expected"))), probes.out());
    checks.check("L6", "and the record, which took two lines of the probes that are no records, still has the access list it was given",
        record_size(&record).map_or(false, |size| size > 0) && Path::new(&folder).is_dir(), record.clone());
    let after_probes = over_cap_run(&marker_text);
    checks.check("L6", "the guard still gets as far as its standard input: lines that are no records are no wrong passwords", after_probes.err().contains(NO_CONSOLE_REASON), shown(&after_probes));

    // L7: three wrong passwords, written by a child without administrator rights, lock the account; the message is exact.
    let fresh = remove_record(&record) && setup().code == 0;
    checks.check("L7", "the record is made again for this part", fresh, "");
    let three = as_the_user(&["lockout-append", record.as_str(), "3", "0"]);
    checks.check("L7", "a child without administrator rights appends three records of wrong passwords", three.code == 0 && three.out().contains("appended 3"), shown(&three));
    let size_locked = record_size(&record);
    let locked = over_cap_run(&marker_text);
    let message = lockout_message(&locked.err());
    checks.check("L7", "the guard refuses with 125, before any prompt, and its command never runs",
        locked.code == 125 && !marker.exists() && locked.out().is_empty() && !locked.err().contains(NO_CONSOLE_REASON) && !locked.err().contains("Process Tree Guard is asked to run"), shown(&locked));
    checks.check("L7", "the message gives the number of wrong passwords, the local time of the last, the time left rounded up and the local time the lockout ends, rounded up to the minute: \
        3, a time of day, nearly 6h, and that time of day six hours later, rounded up to the minute",
        message.as_ref().map_or(false, |(count, last, left, until)| *count == 3 && minutes_of(last).is_some() && nearly_six_hours(left) && six_hours_later(last, until)), format!("{:?} / {}", message, locked.err()));
    let line = refusal_line(&locked.err());
    checks.check("L7", "one exception-refused line, attempt 0, with the same reason; the time is a time of day with am or pm, as the person reads it",
        line.contains("decision=exception-refused attempt=0") && line.contains("reason=\"locked out after 3 wrong passwords, the last at "), line.clone());
    checks.timing("L7", "the refusal is at once: it never waits", locked.elapsed.as_secs_f64() < 5.0 * UNIT + GRACE, shown(&locked));

    // L8: every attempt while locked prints it again, and none extends the lockout.
    let mut same = true;
    for round in 1..=3 {
        let again = over_cap_run(&marker_text);
        let repeated = lockout_message(&again.err());
        same &= again.code == 125 && !marker.exists() && repeated.as_ref().zip(message.as_ref()).map_or(false, |(now, first)| now.0 == first.0 && now.1 == first.1 && now.3 == first.3);
        checks.check("L8", &format!("attempt {} while locked: exit 125, no prompt, and the same count, the same last time and the same end as the first message", round), same, shown(&again));
    }
    checks.check("L8", "and the record is as large as it was: an attempt while locked adds nothing, so the lockout is not extended", record_size(&record) == size_locked, format!("{:?} / {:?}", record_size(&record), size_locked));

    // L9: a record dated in the future ends no lockout and starts none, garbage changes nothing, and a record of more than three mebibytes is read whole, whether the failures are before or after the garbage.
    let reset = remove_record(&record) && setup().code == 0;
    checks.check("L9", "the record is made again for this part", reset, "");
    let ahead = as_the_user(&["lockout-append", record.as_str(), "3", "1000"]);
    let not_locked = over_cap_run(&marker_text);
    checks.check("L9", "three records dated a thousand hours ahead lock nothing: the guard gets as far as its standard input", ahead.code == 0 && not_locked.err().contains(NO_CONSOLE_REASON), shown(&not_locked));
    let junk = as_the_user(&["lockout-garbage", record.as_str(), "5000"]);
    let still_not = over_cap_run(&marker_text);
    checks.check("L9", "garbage appended to the record changes nothing", junk.code == 0 && still_not.err().contains(NO_CONSOLE_REASON), shown(&still_not));
    let near = as_the_user(&["lockout-append", record.as_str(), "3", "0.05"]);
    let within_skew = over_cap_run(&marker_text);
    checks.check("L9", "three records dated a few minutes ahead are read as now: the lockout is there and lasts six hours from now, not more",
        near.code == 0 && lockout_message(&within_skew.err()).map_or(false, |(count, _, left, until)| count == 3 && nearly_six_hours(&left) && minutes_of(&until).is_some()), shown(&within_skew));
    // Records dated just beyond the skew (five minutes and thirty seconds ahead) are ignored, and are kept in no one's place: a flood of them behind
    // three real wrong passwords does not hide the lockout those make, for the minute or so before they would be read as now.
    let flooded = remove_record(&record) && setup().code == 0;
    let real = as_the_user(&["lockout-append", record.as_str(), "3", "0"]);
    let started = Instant::now();
    let flood = as_the_user(&["lockout-append", record.as_str(), "5000", "0.0917"]);
    let hidden = over_cap_run(&marker_text);
    // The records are dated 330 seconds ahead, thirty seconds past the skew of 300: once more than about that time has passed since they were
    // written, they are inside the skew and are read as now, which is a different property (the count is then the whole flood, up to 4096).
    if started.elapsed() > Duration::from_secs(20) {
        checks.notice(format!("NOT ASSERTED L9 flood beyond the skew: {:.0} seconds passed between the append and the look of the guard, more than 20, so the records are no longer beyond the skew", started.elapsed().as_secs_f64()));
    } else {
        checks.check("L9", "5000 records dated five minutes and thirty seconds ahead, appended behind three real wrong passwords, do not hide the lockout: the guard refuses with the count of 3 and does not reach its standard input",
            flooded && real.code == 0 && flood.code == 0 && !marker.exists() && !hidden.err().contains(NO_CONSOLE_REASON) && hidden.code == 125
                && lockout_message(&hidden.err()).map_or(false, |(count, ..)| count == 3), shown(&hidden));
    }
    // A record of any size is read whole: garbage, however much of it, neither ends a lockout nor refuses the run.
    let big = remove_record(&record) && setup().code == 0;
    let filler = as_the_user(&["lockout-garbage", record.as_str(), "3500000"]);
    let counted = as_the_user(&["lockout-append", record.as_str(), "3", "0"]);
    let behind = over_cap_run(&marker_text);
    checks.check("L9", "a record of more than three mebibytes, with three recent wrong passwords after the garbage, is read whole and locks",
        big && filler.code == 0 && counted.code == 0 && record_size(&record).map_or(false, |size| size > 3_500_000) && lockout_message(&behind.err()).map_or(false, |(count, ..)| count == 3), shown(&behind));
    let first = remove_record(&record) && setup().code == 0 && as_the_user(&["lockout-append", record.as_str(), "3", "0"]).code == 0;
    let after = as_the_user(&["lockout-garbage", record.as_str(), "3500000"]);
    let before = over_cap_run(&marker_text);
    checks.check("L9", "and so is one with them before the garbage: appended bytes do not push the real failures out of what is read",
        first && after.code == 0 && !marker.exists() && lockout_message(&before.err()).map_or(false, |(count, ..)| count == 3), shown(&before));

    // L11: a program of the user that can only read the record holds a range of it locked. The guard takes its own lock of the whole
    // record before a logon and is refused when it cannot (the unit tests drive that, since no test enters a password); here the
    // looks that come before any prompt are shown to stop at once when the whole record is locked, and not to stop when only the end is.
    let reset = remove_record(&record) && setup().code == 0 && as_the_user(&["lockout-append", record.as_str(), "1", "-2"]).code == 0;
    checks.check("L11", "the record is made again for this part, with one wrong password two hours old in it", reset, "");
    if let Some(holder) = hold(&record, "end") {
        let end_locked = over_cap_run(&marker_text);
        checks.check("L11", "a range from the end of the record locked by a program that can read it does not stop the looks: the guard gets as far as its standard input, as it did",
            end_locked.err().contains(NO_CONSOLE_REASON) && end_locked.code == 125 && !marker.exists(), shown(&end_locked));
        drop(holder);
    } else {
        checks.check("L11", "a program without administrator rights can lock the end of the record (probe P20)", false, "the holder did not start");
    }
    if let Some(holder) = hold(&record, "all") {
        let all_locked = over_cap_run(&marker_text);
        checks.check("L11", "the whole record locked by a program that can read it: a run over the cap is refused with 125 before any prompt, with the reason that the record is locked by another program, \
            and its command never runs",
            all_locked.code == 125 && !marker.exists() && all_locked.out().is_empty() && !all_locked.err().contains(NO_CONSOLE_REASON)
                && all_locked.err().contains("exception refused: the lockout record is locked by another program or another run; wait for the run to end, or end that program, and run again; the run did not start"), shown(&all_locked));
        let line = refusal_line(&all_locked.err());
        checks.check("L11", "one exception-refused line, attempt 0, with that reason, and the record is as it was",
            line.contains("decision=exception-refused attempt=0") && line.contains("reason=\"the lockout record is locked by another program or another run; wait for the run to end, or end that program, and run again\"")
                && record_size(&record) == Some(20), line.clone());
        drop(holder);
    } else {
        checks.check("L11", "a program without administrator rights can lock the whole record (probe P20d)", false, "the holder did not start");
    }
    let released = over_cap_run(&marker_text);
    checks.check("L11", "and when the program lets go the guard gets as far as its standard input again", released.err().contains(NO_CONSOLE_REASON), shown(&released));

    // L10: a program of the user without administrator rights makes a folder and a record of its own with exactly the lists the
    // guard accepts, and keeps a handle that can write to the record. Its owner is the user, so the guard refuses it.
    let cleared = remove_folder(&folder);
    let sid = record.rsplit('\\').next().and_then(|name| name.strip_suffix(".lockout")).unwrap_or("").to_string();
    let forged = as_the_user(&["lockout-forge", folder.as_str(), record.as_str(), sid.as_str()]);
    checks.check("L10", "a child without administrator rights makes the folder and a record with the lists of the step, owned by the user, and keeps a handle that still writes to it",
        cleared && forged.code == 0 && forged.out().contains("forged ") && forged.out().contains("tightened=true") && Path::new(&record).exists(), shown(&forged));
    let planted = over_cap_run(&marker_text);
    checks.check("L10", "the guard refuses it with 125 before any prompt: the folder is owned by the user, which is not the Administrators group, the system or the installer of the system, and the step to run is named",
        planted.code == 125 && !marker.exists() && planted.out().is_empty() && !planted.err().contains(NO_CONSOLE_REASON)
            && planted.err().contains(&format!("exception refused: the folder of the lockout records is owned by {}, which is not the Administrators group, the system or the installer of the system, so it cannot be trusted; \
                an administrator must remove it as described in the README and then run: process-tree-guard create-lockout-record", sid)), shown(&planted));
    let line = refusal_line(&planted.err());
    checks.check("L10", "one exception-refused line, attempt 0, with that reason", line.contains("decision=exception-refused attempt=0") && line.contains("is owned by"), line.clone());
    let refused_step = setup();
    checks.check("L10", "and the step does not take the folder over, for the same reason: it says to remove it, and makes nothing",
        refused_step.code == 125 && refused_step.err().contains("is not taken over") && refused_step.err().contains("remove it as described in the README"), shown(&refused_step));
    // A folder that an administrator made first, as any program that runs elevated does with `New-Item`, without the lists of the step: a
    // user may make files in it (the entry of the folder of the programs' data for the users is inherited). A program of the user plants
    // its own record in it, owned by the user, and could keep a handle that writes. The step sets the folder right (an administrator
    // owns it) and does not take the record over, whatever list the record has; the guard refuses the record for its owner.
    let cleared = remove_folder(&folder) && std::fs::create_dir(&folder).is_ok();
    let seeded = as_the_user(&["lockout-plant", record.as_str(), sid.as_str()]);
    checks.check("L10", "a folder made first by an administrator, and a record of the user's own planted in it by a child without administrator rights",
        cleared && seeded.code == 0 && seeded.out().contains("planted ") && Path::new(&record).exists(), shown(&seeded));
    let refused_record = setup();
    checks.check("L10", "the step does not take the planted record over: 125, the record named with its owner, \"is not taken over\", and the way to remove it",
        refused_record.code == 125 && mentions(&refused_record.err(), &format!("the record {} is owned by {}, which is not the Administrators group, the system or the installer of the system, so it is not taken over", record, sid))
            && refused_record.err().contains("remove it as described in the README"), shown(&refused_record));
    let planted_record = over_cap_run(&marker_text);
    checks.check("L10", "and the guard refuses the record for its owner, before any prompt",
        planted_record.code == 125 && !marker.exists() && !planted_record.err().contains(NO_CONSOLE_REASON)
            && planted_record.err().contains(&format!("exception refused: the lockout record for this account is owned by {}, which is not the Administrators group, the system or the installer of the system, so it cannot be trusted; ", sid)),
        shown(&planted_record));
    // The machine is left with a fresh record by `FreshRecord`; the run after it is the proof.
    drop(_fresh);
    let last = over_cap_run(&marker_text);
    checks.check("L9", "the machine is left with a fresh record: the guard gets as far as its standard input", last.err().contains(NO_CONSOLE_REASON) && Path::new(&record).exists() && record_size(&record) == Some(0), shown(&last));
    checks.finish();
}
