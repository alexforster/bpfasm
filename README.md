<!--
Copyright © Alex Forster <alex@alexforster.com>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# bpfasm

Berkley Packet Filter (BPF) assembler

**Author:** Alex Forster \<alex@alexforster.com\><br/>
**License:** MIT OR Apache-2.0

[![crates.io version](https://img.shields.io/crates/v/bpfasm.svg)](https://crates.io/crates/bpfasm)
[![docs.rs](https://docs.rs/bpfasm/badge.svg)](https://docs.rs/bpfasm)

## Example Usage

```rust
let source = r#"
    ldh [12]            ; load ethertype into accumulator
    jne #0x0800, drop   ; if accumulator != 0x0800: goto drop
    ldb [23]            ; load ipproto into accumulator
    jneq #0x06, drop    ; if accumulator != 0x06: goto drop
    pass: ret #-1       ; pass
    drop: ret #0        ; drop
"#;

let extensions = bpfasm::extensions::linux();

let instructions = bpfasm::assemble(source, &extensions).expect("syntax error");

println!(
    "{},{}",
    instructions.len(),
    instructions.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(",")
);

// Output:
// 6,40 0 0 12,21 0 3 2048,48 0 0 23,21 0 1 6,6 0 0 4294967295,6 0 0 0
```
