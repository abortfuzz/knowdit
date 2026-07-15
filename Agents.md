# Overall rules for agents

## Core Principle

- Unless explicitly approved, agents shall not edit this file in any way.
- No AI written documents (comments are allowed and encouraged for agents), unless explicity approved.

## General Coding Style For Rust

- No 1-2 line helper.
- Think about the data flow first and design the data structs. Then construct the control flows.
- Avoid functions that are used only once, unless the logic is complex enough. Always consider reusable components and functions.
- Avoid free functions, always attach functions to some structs, i.e., member functions. This makes functions as transformers of the data flows.
- No adhoc `json!` constructed json, always prefer `#[derive(Serialize, Deserialize)]` for structs.
- Use `tracing` for any logs, avoid direct usage of `println!` and `eprintln!`, though `println!` and `eprintln!` are allowed in `brainary` crate, i.e., during the CLI invocation and providing status/progress to users.
- No `unwrap` in any case, always prefer `Result<...>` or `Option<T>` 
- Avoid lifetime parameter if possible and accept cheap copies using types like `String` and `PathBuf`.
- Always prefer BTreeMap.


