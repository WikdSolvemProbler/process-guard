// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! Helper process for the process guard tests.
//!
//! One small executable stands in for every child the tests need: sleepers,
//! exit codes, standard stream relays, argument reporters, markers that record
//! their process identifier, wide and deep process trees, and bulk output.
//! The first argument selects the subcommand. A usage error exits with 97.
//!
//! Markers are written to a temporary name and renamed into place, so a reader
//! never sees a half written file.

use std::ffi::{c_void, OsStr};
use std::fs;
use std::io::{Read, Write};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{exit, Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

#[link(name = "kernel32")]
extern "system" {
    fn GetStdHandle(which: u32) -> *mut c_void;
    fn CloseHandle(handle: *mut c_void) -> i32;
}

const USAGE_EXIT: i32 = 97;
const WAIT_TIMEOUT_EXIT: i32 = 98;
const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;

fn usage(message: &str) -> ! {
    eprintln!("testkit: {}", message);
    exit(USAGE_EXIT);
}

fn need(rest: &[String], count: usize, form: &str) {
    if rest.len() != count {
        usage(&format!("usage: testkit {}", form));
    }
}

fn need_at_least(rest: &[String], count: usize, form: &str) {
    if rest.len() < count {
        usage(&format!("usage: testkit {}", form));
    }
}

fn number<T: std::str::FromStr>(text: &str, what: &str) -> T {
    text.parse().unwrap_or_else(|_| usage(&format!("{} is not a valid number: {}", what, text)))
}

/// A 32 bit code written in decimal or with a 0x prefix.
fn code(text: &str) -> u32 {
    let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => text.parse::<u32>(),
    };
    parsed.unwrap_or_else(|_| usage(&format!("not a 32 bit code: {}", text)))
}

/// A finite, non-negative number of seconds, small enough for a Duration.
fn seconds(text: &str) -> f64 {
    match text.parse::<f64>() {
        Ok(value) if value.is_finite() && (0.0..=1.0e7).contains(&value) => value,
        _ => usage(&format!("not a valid number of seconds: {}", text)),
    }
}

fn pause(value: f64) {
    sleep(Duration::from_secs_f64(value));
}

fn args_after(skip: usize) -> Vec<String> {
    std::env::args_os().skip(skip).map(|a| a.to_string_lossy().into_owned()).collect()
}

/// Compact JavaScript Object Notation (JSON) array of strings. Quote,
/// backslash and control characters are escaped; other text is written as it is.
fn json_array(items: &[String]) -> String {
    let mut out = String::from("[");
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('"');
        for c in item.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
    }
    out.push(']');
    out
}

/// Write `contents` beside `target` under a temporary name, then rename it into place.
fn publish(target: &Path, contents: &str) {
    let mut temporary = target.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    if let Err(error) = fs::write(&temporary, contents).and_then(|_| fs::rename(&temporary, target)) {
        eprintln!("testkit: cannot write {}: {}", target.display(), error);
        exit(1);
    }
}

fn publish_own_id(target: &Path) {
    publish(target, &std::process::id().to_string());
}

fn fail_spawn(error: &std::io::Error) -> ! {
    eprintln!("testkit: [WinError {}] {}", error.raw_os_error().unwrap_or(0), error);
    exit(1);
}

fn start(program: &OsStr, args: &[&str], flags: u32, quiet: bool) -> Child {
    let mut command = Command::new(program);
    command.args(args).creation_flags(flags);
    if quiet {
        command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    }
    command.spawn().unwrap_or_else(|error| fail_spawn(&error))
}

/// Start another copy of this executable with null standard streams.
fn start_self(args: &[&str]) -> Child {
    let me = std::env::current_exe().unwrap_or_else(|error| fail_spawn(&error));
    start(me.as_os_str(), args, 0, true)
}

fn count_marker_files(dir: &Path) -> usize {
    fs::read_dir(dir)
        .map(|entries| entries.flatten().filter(|e| e.path().extension().map_or(false, |x| x == "pid")).count())
        .unwrap_or(0)
}

/// A file that exists, or a folder holding at least one marker file.
fn marker_present(path: &Path) -> bool {
    if path.is_dir() {
        count_marker_files(path) > 0
    } else {
        path.exists()
    }
}

fn main() {
    let args = args_after(1);
    let (name, rest) = match args.split_first() {
        Some((name, rest)) => (name.as_str(), rest),
        None => usage("a subcommand is required"),
    };
    match name {
        "sleep" => {
            need(rest, 1, "sleep SECONDS");
            pause(seconds(&rest[0]));
        }
        "exit" => {
            need(rest, 1, "exit CODE");
            exit(code(&rest[0]) as i32);
        }
        "print" => println!("{}", rest.join(" ")),
        "relay" => {
            need(rest, 1, "relay CODE");
            let mut data = Vec::new();
            let _ = std::io::stdin().read_to_end(&mut data);
            let mut out = std::io::stdout();
            let _ = out.write_all(&data);
            let _ = out.write_all(b"\n");
            let _ = out.flush();
            eprintln!("error-stream");
            exit(code(&rest[0]) as i32);
        }
        "cat" => {
            let (stdin, stdout) = (std::io::stdin(), std::io::stdout());
            let (mut input, mut output) = (stdin.lock(), stdout.lock());
            if std::io::copy(&mut input, &mut output).and_then(|_| output.flush()).is_err() {
                exit(1);
            }
        }
        "stdin-empty" => {
            let mut data = Vec::new();
            let _ = std::io::stdin().read_to_end(&mut data);
            println!("{}", if data.is_empty() { "True" } else { "False" });
        }
        "args-json" => println!("{}", json_array(rest)),
        "args-exit" => {
            need_at_least(rest, 1, "args-exit CODE ARGS...");
            let status = code(&rest[0]);
            println!("{}", json_array(&rest[1..]));
            exit(status as i32);
        }
        "arg-len" => {
            need(rest, 1, "arg-len ARG");
            println!("{}", rest[0].chars().count());
        }
        "mark" => {
            need(rest, 2, "mark FILE SECONDS");
            let wait = seconds(&rest[1]);
            publish_own_id(Path::new(&rest[0]));
            pause(wait);
        }
        "mark-dir" => {
            need(rest, 2, "mark-dir DIR SECONDS");
            let wait = seconds(&rest[1]);
            publish_own_id(&Path::new(&rest[0]).join(format!("{}.pid", std::process::id())));
            pause(wait);
        }
        "bloat" => {
            need(rest, 3, "bloat MEGABYTES FILE SECONDS");
            let megabytes: usize = number(&rest[0], "MEGABYTES");
            let wait = seconds(&rest[2]);
            // Touch every page, so the system has real memory to reclaim when this process ends.
            let mut block: Vec<u8> = Vec::new();
            block.resize(megabytes << 20, 1);
            publish_own_id(Path::new(&rest[1]));
            pause(wait);
            std::hint::black_box(&block);
        }
        "spawn" | "spawn-quiet" => {
            need_at_least(rest, 3, "spawn FLAGS HOLD PROGRAM [ARGS...]");
            let (flags, hold) = (code(&rest[0]), seconds(&rest[1]));
            let args: Vec<&str> = rest[3..].iter().map(String::as_str).collect();
            let _child = start(OsStr::new(&rest[2]), &args, flags, name == "spawn-quiet");
            pause(hold);
        }
        "spawn-marked" | "spawn-marked-quiet" => {
            // Hold until MARK appears (a file, or a folder that gains a marker file), so a
            // slow process start cannot make the caller give up early.
            need_at_least(rest, 4, "spawn-marked FLAGS MARK MAXSECONDS PROGRAM [ARGS...]");
            let (flags, limit) = (code(&rest[0]), seconds(&rest[2]));
            let args: Vec<&str> = rest[4..].iter().map(String::as_str).collect();
            let _child = start(OsStr::new(&rest[3]), &args, flags, name == "spawn-marked-quiet");
            let begun = Instant::now();
            while !marker_present(Path::new(&rest[1])) {
                if begun.elapsed().as_secs_f64() > limit {
                    eprintln!("testkit: no marker at {}", rest[1]);
                    exit(WAIT_TIMEOUT_EXIT);
                }
                sleep(Duration::from_millis(20));
            }
        }
        "wide" => {
            need(rest, 4, "wide COUNT IDS CHILD_SECONDS HOLD_SECONDS");
            let count: usize = number(&rest[0], "COUNT");
            seconds(&rest[2]);
            let hold = seconds(&rest[3]);
            let mut children = Vec::with_capacity(count);
            let mut ids = String::new();
            for _ in 0..count {
                let child = start_self(&["sleep", &rest[2]]);
                ids.push_str(&format!("{}\n", child.id()));
                children.push(child);
            }
            publish(Path::new(&rest[1]), &ids);
            pause(hold);
        }
        "deep" => {
            need(rest, 4, "deep LEVEL MAX DIR SECONDS");
            let level: u32 = number(&rest[0], "LEVEL");
            let max: u32 = number(&rest[1], "MAX");
            let wait = seconds(&rest[3]);
            publish_own_id(&Path::new(&rest[2]).join(format!("{}.pid", level)));
            let _child = if level < max {
                Some(start_self(&["deep", &(level + 1).to_string(), &rest[1], &rest[2], &rest[3]]))
            } else {
                None
            };
            pause(wait);
        }
        "fan" | "fan-wait" => {
            need(rest, 3, "fan COUNT DIR HOLD | fan-wait COUNT DIR CODE");
            let count: usize = number(&rest[0], "COUNT");
            let children: Vec<Child> = (0..count).map(|_| start_self(&["mark-dir", &rest[1], "60"])).collect();
            if name == "fan" {
                pause(seconds(&rest[2]));
            } else {
                let status = code(&rest[2]);
                let begun = Instant::now();
                while count_marker_files(Path::new(&rest[1])) < count {
                    if begun.elapsed() > Duration::from_secs(30) {
                        eprintln!("testkit: markers did not appear");
                        exit(WAIT_TIMEOUT_EXIT);
                    }
                    sleep(Duration::from_millis(20));
                }
                exit(status as i32);
            }
            drop(children);
        }
        "out-bytes" => {
            need(rest, 1, "out-bytes N");
            let mut remaining: u64 = number(&rest[0], "N");
            let chunk = vec![b'x'; 1 << 20];
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            while remaining > 0 {
                let part = remaining.min(chunk.len() as u64) as usize;
                if out.write_all(&chunk[..part]).is_err() {
                    exit(1);
                }
                remaining -= part as u64;
            }
            if out.flush().is_err() {
                exit(1);
            }
        }
        "flood" => {
            let chunk = vec![b'y'; 65536];
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            loop {
                if out.write_all(&chunk).and_then(|_| out.flush()).is_err() {
                    exit(1);
                }
            }
        }
        "close-stdout-exit" => {
            need(rest, 1, "close-stdout-exit CODE");
            let status = code(&rest[0]);
            unsafe { CloseHandle(GetStdHandle(STD_OUTPUT_HANDLE)) };
            exit(status as i32);
        }
        _ => usage(&format!("unknown subcommand: {}", name)),
    }
}
