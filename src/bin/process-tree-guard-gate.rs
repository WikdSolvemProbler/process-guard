// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! `process-tree-guard-gate`: the hook role. `process-tree-guard-gate VENDOR` is
//! `process-tree-guard hook VENDOR`. The engine is in the library crate.

fn main() {
    std::process::exit(process_tree_guard::main_gate());
}
