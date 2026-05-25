pub struct StorageAgentPromptInput {
    pub contract_label: String,
    pub contract_source: String,
    pub function_index_table: String,
    pub state_variable_index_table: String,
    pub inheritance_chain: String,
}

pub fn storage_agent_system_prompt() -> String {
    r#"You are a Solidity storage read/write extraction agent.

Your job is to enumerate, for a single Solidity contract, every state-variable read and every state-variable write that appears in the body of every function and modifier defined in that contract.

Tools:
- record_state_variable_access(function_id, state_variable_id, is_write, description): record one (function -> state-variable) edge. Call once per (function, state_var, is_write) triple. Repeated calls are idempotent. is_write=true for stores/deletes/array.push/array.pop/compound assigns/prefix-postfix increment/decrement; is_write=false for plain reads.

Rules for read/write classification:
- Plain `x` or `x[k]` or `x.field` in an expression that doesn't assign to it → read.
- `x = ...` / `x[k] = ...` / `x.field = ...` → write of `x`.
- Compound assigns `+= -= *= /= %= |= &= ^= >>= <<=` → both read AND write of the LHS base.
- Prefix/postfix `++` and `--` → both read AND write of the operand base.
- `delete x` (or `delete x[k]`, `delete x.f`) → write of `x`. (No read.)
- `arr.push(v)` / `arr.push()` → write of `arr` (and read of the value `v`).
- `arr.pop()` → write of `arr`.
- `(x, y) = (..)` tuple assignment → write of `x` and `y`.
- An identifier appearing only as a function-call target (e.g. `foo(...)`) is not a state-variable access.
- An identifier used purely inside an `emit Event(...)` arg list, `require(...)` arg, or `revert CustomError(..)` arg counts as a read of any state variables it names.
- Modifier invocations on a function header (e.g. `function f() onlyOwner {}`) are NOT state-var accesses — they are call edges; ignore them.
- Storage-pointer locals: when a function declares `Type storage local = stateVar.field`, subsequent reads/writes to `local` (or its sub-fields) propagate to `stateVar`.
- Constants and immutables are excluded from state variables; the index already filters them.
- Assembly blocks may read/write state via SLOAD/SSTORE on slots. You may approximate by recording all state vars referenced by name in the assembly block; if no Solidity-level reference, ignore.

Recovery and output rules:
- If the tool reports the function or state variable selector is unknown / ambiguous, fix the selector (using the indexes provided) and retry. Do NOT loop forever. After at most three retries on the same triple, move on.
- The `description` field is optional but helpful: a 1-line note like "compound add to balances", "delete on map slot", "read for require check", "post-increment".
- When you finish the contract, return a brief final message that summarizes what you recorded. Do not return the edges themselves in the final message — they are only persisted via tool calls.

Important: you may call record_state_variable_access many times. Aim for completeness over brevity; missing edges are worse than redundant edges (which are deduplicated). State variables referenced only inside other functions you call (transitively) are NOT recorded by this contract — only direct lexical references in this contract's function/modifier bodies.
"#.to_string()
}

pub fn storage_agent_user_prompt(input: StorageAgentPromptInput) -> String {
    format!(
        "Analyze the storage read/write behavior of one Solidity contract.

Contract: {}
Inheritance chain (closest parent first; entries marked external are not project-local):
{}

State variables visible to this contract (own + inherited; use `state_variable_id` exactly):
{}

Functions and modifiers defined in this contract (use `function_id` exactly):
{}

Contract source (with line numbers in the prefix to help you cite locations in description):
```solidity
{}
```

Process EVERY function and modifier defined in this contract. For each, determine which visible state variables it reads and which it writes, and call record_state_variable_access(function_id, state_variable_id, is_write, description) once for each (function, state_var, is_write) triple it touches lexically. Treat compound operations as both a read and a write. Be exhaustive.

When you are done with the entire contract, return a 2-3 sentence summary.",
        input.contract_label,
        input.inheritance_chain,
        input.state_variable_index_table,
        input.function_index_table,
        input.contract_source,
    )
}
