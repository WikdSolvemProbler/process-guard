// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Peter Shiller

//! `process-tree-guard`: the full command. Every mode runs in this process, with
//! no extra process hop. The engine is in the library crate.

fn main() {
    std::process::exit(process_tree_guard::main_full());
}
