// Copyright © Alex Forster <alex@alexforster.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;
use std::num;
use std::str;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Instruction {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{} {} {} {}", self.code, self.jt, self.jf, self.k))
    }
}

impl From<u64> for Instruction {
    fn from(insn: u64) -> Self {
        Self {
            code: (insn >> 48 & 0xFFFF) as u16,
            jt: (insn >> 40 & 0xFF) as u8,
            jf: (insn >> 32 & 0xFF) as u8,
            k: (insn & 0xFFFFFFFF) as u32,
        }
    }
}

impl str::FromStr for Instruction {
    type Err = num::ParseIntError;

    fn from_str(insn: &str) -> Result<Self, Self::Err> {
        let mut iter = insn.splitn(4, ' ');
        Ok(Self {
            code: u16::from_str(iter.next().unwrap_or(""))?,
            jt: u8::from_str(iter.next().unwrap_or(""))?,
            jf: u8::from_str(iter.next().unwrap_or(""))?,
            k: u32::from_str(iter.next().unwrap_or(""))?,
        })
    }
}
