// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! `process-tree-guard-deadline`: the deadline role. It is `process-tree-guard`
//! with `--timeout` or automatic mode, and has no hook mode. The engine is in the
//! library crate.

fn main() {
    std::process::exit(process_tree_guard::main_deadline());
}
