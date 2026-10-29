# Operations register

Every vector case names an `op`. This register maps each `op` to the Rust
function that runs it, the WASM method that exposes it, and the shape of the
case's `input`. The Rust, Node and browser runners are table-driven from this
list. A case may only use an `op` that is listed here.

Rows are added by the task that introduces the operation. The first column
holds the op name in backticks.

| Op | Rust function | WASM method | `input` shape |
|---|---|---|---|
