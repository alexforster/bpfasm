// Copyright © Alex Forster <alex@alexforster.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

pub fn fuzz(data: &[u8]) {
    let extensions = bpfasm::extensions::linux();
    let source = match std::str::from_utf8(data) {
        Ok(source) => source,
        Err(_) => return,
    };
    match bpfasm::assemble(source, &extensions) {
        Ok(instructions) => instructions,
        Err(_) => return,
    };
}

fn main() {
    loop {
        honggfuzz::fuzz!(|data: &[u8]| {
            fuzz(data);
        });
    }
}
