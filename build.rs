// Copyright © Alex Forster <alex@alexforster.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fs;
use std::io::Write;
use std::path;

use pest_generator::derive_parser;
use quote::quote;

fn main() {
    println!("rerun-if-changed=src/grammar.pest");

    let manifest_dir = path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let grammar_pest_path = manifest_dir.join("src/grammar.pest");
    let parser_rs_path = manifest_dir.join("src/parser.rs");

    let parser_rs_tokens = {
        let grammar_pest_path = grammar_pest_path.to_string_lossy();
        derive_parser(
            quote! {
                #[grammar = #grammar_pest_path]
                pub struct Parser;
            },
            false,
        )
    };

    fs::File::create(parser_rs_path)
        .expect("could not create src/parser.rs")
        .write_fmt(format_args!("pub struct Parser;\n{}\n", parser_rs_tokens))
        .expect("could not write to src/parser.rs");
}
