// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! `process-tree-guard-contain`: the contain role. It runs one command in a job of
//! its own as a child of an extendable run, and its `--timeout` is a request to
//! that run. The engine is in the library crate.

fn main() {
    std::process::exit(process_tree_guard::main_contain());
}
