// Copyright © Alex Forster <alex@alexforster.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

mod assembler;
pub use assembler::{assemble, AssemblerError};

pub mod extensions;

mod instruction;
pub use instruction::Instruction;

mod parser;
use parser::{Parser, Rule};
