// Copyright © Alex Forster <alex@alexforster.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections;

use pest::iterators::*;
use pest::*;

use crate::*;

#[derive(Debug, thiserror::Error)]
pub enum AssemblerError {
    #[error(transparent)]
    Parse(#[from] pest::error::Error<Rule>),
}

const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_ST: u16 = 0x02;
const BPF_STX: u16 = 0x03;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_MISC: u16 = 0x07;

const BPF_W: u16 = 0x00;
const BPF_H: u16 = 0x08;
const BPF_B: u16 = 0x10;

const BPF_IMM: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_IND: u16 = 0x40;
const BPF_MEM: u16 = 0x60;
const BPF_LEN: u16 = 0x80;
const BPF_MSH: u16 = 0xa0;

const BPF_ADD: u16 = 0x00;
const BPF_SUB: u16 = 0x10;
const BPF_MUL: u16 = 0x20;
const BPF_DIV: u16 = 0x30;
const BPF_OR: u16 = 0x40;
const BPF_AND: u16 = 0x50;
const BPF_LSH: u16 = 0x60;
const BPF_RSH: u16 = 0x70;
const BPF_NEG: u16 = 0x80;
const BPF_MOD: u16 = 0x90;
const BPF_XOR: u16 = 0xa0;

const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;

const BPF_K: u16 = 0x00;
const BPF_X: u16 = 0x08;
const BPF_A: u16 = 0x10;

const BPF_TAX: u16 = 0x00;
const BPF_COP: u16 = 0x20;
const BPF_COPX: u16 = 0x40;
const BPF_TXA: u16 = 0x80;

fn pair_to_u32(pair: Pair<Rule>) -> Result<u32, AssemblerError> {
    let err = || {
        pest::error::Error::new_from_span(
            pest::error::ErrorVariant::CustomError { message: format!("invalid integer literal {:?}", pair.as_str()) },
            pair.as_span(),
        )
        .into()
    };
    match pair.as_rule() {
        Rule::Binary => u32::from_str_radix(&pair.as_str()[2..], 2).map_err(|_| err()),
        Rule::Octal => u32::from_str_radix(&pair.as_str()[1..], 8).map_err(|_| err()),
        Rule::Decimal => i32::from_str_radix(pair.as_str(), 10).map(|i| i as u32).map_err(|_| err()),
        Rule::Hexadecimal => u32::from_str_radix(&pair.as_str()[2..], 16).map_err(|_| err()),
        _ => Err(err()),
    }
}

fn insn(code: u16, mut operands: Pairs<Rule>) -> Result<Instruction, AssemblerError> {
    let k = match operands.next() {
        Some(pair) => pair_to_u32(pair)?,
        None => 0,
    };

    Ok(Instruction { code, jt: 0, jf: 0, k })
}

fn xinsn(
    code: u16,
    mut operands: Pairs<Rule>,
    extensions: &collections::HashMap<String, u32>,
) -> Result<Instruction, AssemblerError> {
    let k = match operands.next() {
        Some(extension) => match extensions.get(extension.as_str()) {
            Some(i) => Ok(*i),
            None => Err(pest::error::Error::new_from_span(
                pest::error::ErrorVariant::CustomError {
                    message: format!("invalid extension {:?}", extension.as_str()),
                },
                extension.as_span(),
            )),
        },
        None => Ok(0),
    }?;

    Ok(Instruction { code, jt: 0, jf: 0, k })
}

fn jainsn(
    pc: usize,
    code: u16,
    mut operands: Pairs<Rule>,
    labels: &collections::HashMap<String, u32>,
) -> Result<Instruction, AssemblerError> {
    let k = match operands.next() {
        Some(label) => match labels.get(label.as_str()) {
            Some(i) if *i as usize > pc => Ok((*i as usize - pc - 1) as u32),
            Some(_) => Err(pest::error::Error::new_from_span(
                pest::error::ErrorVariant::CustomError { message: format!("unreachable label {:?}", label.as_str()) },
                label.as_span(),
            )),
            None => Err(pest::error::Error::new_from_span(
                pest::error::ErrorVariant::CustomError { message: format!("undeclared label {:?}", label.as_str()) },
                label.as_span(),
            )),
        },
        None => Ok(0),
    }?;

    Ok(Instruction { code, jt: 0, jf: 0, k })
}

fn jinsn(
    pc: usize,
    code: u16,
    immediate: bool,
    mut operands: Pairs<Rule>,
    labels: &collections::HashMap<String, u32>,
) -> Result<Instruction, AssemblerError> {
    let k = if immediate {
        match operands.next() {
            Some(pair) => pair_to_u32(pair)?,
            None => 0,
        }
    } else {
        0
    };

    let jt = match operands.next() {
        Some(label) => match labels.get(label.as_str()) {
            Some(i) if *i as usize > pc => Ok((*i as usize - pc - 1) as u8),
            Some(_) => Err(pest::error::Error::new_from_span(
                pest::error::ErrorVariant::CustomError { message: format!("unreachable label {:?}", label.as_str()) },
                label.as_span(),
            )),
            None => Err(pest::error::Error::new_from_span(
                pest::error::ErrorVariant::CustomError { message: format!("undeclared label {:?}", label.as_str()) },
                label.as_span(),
            )),
        },
        None => Ok(0),
    }?;

    let jf = match operands.next() {
        Some(label) => match labels.get(label.as_str()) {
            Some(i) if *i as usize > pc => Ok((*i as usize - pc - 1) as u8),
            Some(_) => Err(pest::error::Error::new_from_span(
                pest::error::ErrorVariant::CustomError { message: format!("unreachable label {:?}", label.as_str()) },
                label.as_span(),
            )),
            None => Err(pest::error::Error::new_from_span(
                pest::error::ErrorVariant::CustomError { message: format!("undeclared label {:?}", label.as_str()) },
                label.as_span(),
            )),
        },
        None => Ok(0),
    }?;

    Ok(Instruction { code, jt, jf, k })
}

fn jtinsn(
    pc: usize,
    code: u16,
    immediate: bool,
    mut operands: Pairs<Rule>,
    labels: &collections::HashMap<String, u32>,
) -> Result<Instruction, AssemblerError> {
    let k = if immediate {
        match operands.next() {
            Some(pair) => pair_to_u32(pair)?,
            None => 0,
        }
    } else {
        0
    };

    let jt = match operands.next() {
        Some(label) => match labels.get(label.as_str()) {
            Some(i) if *i as usize > pc => Ok((*i as usize - pc - 1) as u8),
            Some(_) => Err(pest::error::Error::new_from_span(
                pest::error::ErrorVariant::CustomError { message: format!("unreachable label {:?}", label.as_str()) },
                label.as_span(),
            )),
            None => Err(pest::error::Error::new_from_span(
                pest::error::ErrorVariant::CustomError { message: format!("undeclared label {:?}", label.as_str()) },
                label.as_span(),
            )),
        },
        None => Ok(0),
    }?;

    Ok(Instruction { code, jt, jf: 0, k })
}

fn jfinsn(
    pc: usize,
    code: u16,
    immediate: bool,
    mut operands: Pairs<Rule>,
    labels: &collections::HashMap<String, u32>,
) -> Result<Instruction, AssemblerError> {
    let k = if immediate {
        match operands.next() {
            Some(pair) => pair_to_u32(pair)?,
            None => 0,
        }
    } else {
        0
    };

    let jf = match operands.next() {
        Some(label) => match labels.get(label.as_str()) {
            Some(i) if *i as usize > pc => Ok((*i as usize - pc - 1) as u8),
            Some(_) => Err(pest::error::Error::new_from_span(
                pest::error::ErrorVariant::CustomError { message: format!("unreachable label {:?}", label.as_str()) },
                label.as_span(),
            )),
            None => Err(pest::error::Error::new_from_span(
                pest::error::ErrorVariant::CustomError { message: format!("undeclared label {:?}", label.as_str()) },
                label.as_span(),
            )),
        },
        None => Ok(0),
    }?;

    Ok(Instruction { code, jt: 0, jf, k })
}

pub fn assemble<S: AsRef<str>>(
    source: S,
    extensions: &collections::HashMap<String, u32>,
) -> Result<Vec<Instruction>, AssemblerError> {
    let mut labels = collections::HashMap::default();
    let mut insns: Vec<Instruction> = Vec::default();

    let pairs = crate::Parser::parse(Rule::Program, source.as_ref())?;

    let mut pc = 0;

    for pair in pairs.clone() {
        let rule = pair.as_rule();
        let span = pair.as_span();
        match rule {
            Rule::Label => {
                let name = pair.into_inner().next().unwrap().as_str();
                if let Some(_) = labels.insert(name.into(), pc as u32) {
                    Err(pest::error::Error::new_from_span(
                        pest::error::ErrorVariant::CustomError { message: format!("redeclared label {:?}", name) },
                        span,
                    ))?;
                }
                continue;
            }
            _ => {
                pc += 1;
            }
        }
    }

    pc = 0;

    for pair in pairs {
        let rule = pair.as_rule();
        let mut inner_pairs = pair.into_inner();
        match rule {
            Rule::LD => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::PacketOffset => insn(BPF_LD | BPF_W | BPF_ABS, operands)?,
                    Rule::IndirectPacketOffset => insn(BPF_LD | BPF_W | BPF_IND, operands)?,
                    Rule::MemoryAddress => insn(BPF_LD | BPF_MEM, operands)?,
                    Rule::Immediate => insn(BPF_LD | BPF_IMM, operands)?,
                    Rule::Length => insn(BPF_LD | BPF_W | BPF_LEN, operands)?,
                    Rule::Extension => xinsn(BPF_LD | BPF_W | BPF_ABS, operands, extensions)?,
                    _ => unreachable!(),
                });
            }
            Rule::LDI => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::Immediate => insn(BPF_LD | BPF_IMM, operands)?,
                    _ => unreachable!(),
                });
            }
            Rule::LDH => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::PacketOffset => insn(BPF_LD | BPF_H | BPF_ABS, operands)?,
                    Rule::IndirectPacketOffset => insn(BPF_LD | BPF_H | BPF_IND, operands)?,
                    Rule::Extension => xinsn(BPF_LD | BPF_H | BPF_ABS, operands, extensions)?,
                    _ => unreachable!(),
                });
            }
            Rule::LDB => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::PacketOffset => insn(BPF_LD | BPF_B | BPF_ABS, operands)?,
                    Rule::IndirectPacketOffset => insn(BPF_LD | BPF_B | BPF_IND, operands)?,
                    Rule::Extension => xinsn(BPF_LD | BPF_B | BPF_ABS, operands, extensions)?,
                    _ => unreachable!(),
                });
            }
            Rule::LDX => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::MemoryAddress => insn(BPF_LDX | BPF_MEM, operands)?,
                    Rule::PacketOffsetMSH => insn(BPF_LDX | BPF_MSH | BPF_B, operands)?,
                    Rule::Immediate => insn(BPF_LDX | BPF_IMM, operands)?,
                    Rule::Length => insn(BPF_LDX | BPF_W | BPF_LEN, operands)?,
                    _ => unreachable!(),
                });
            }
            Rule::LDXI => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::Immediate => insn(BPF_LDX | BPF_IMM, operands)?,
                    _ => unreachable!(),
                });
            }
            Rule::LDXB => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::PacketOffsetMSH => insn(BPF_LDX | BPF_MSH | BPF_B, operands)?,
                    _ => unreachable!(),
                });
            }
            Rule::ST => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::MemoryAddress => insn(BPF_ST, operands)?,
                    _ => unreachable!(),
                });
            }
            Rule::STX => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::MemoryAddress => insn(BPF_STX, operands)?,
                    _ => unreachable!(),
                });
            }
            Rule::JMP => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::Jump => jainsn(pc, BPF_JMP | BPF_JA, operands, &labels)?,
                    _ => unreachable!(),
                });
            }
            Rule::JEQ => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::JumpIndexRegister => jinsn(pc, BPF_JMP | BPF_JEQ | BPF_X, false, operands, &labels)?,
                    Rule::JumpIfIndexRegister => jtinsn(pc, BPF_JMP | BPF_JEQ | BPF_X, false, operands, &labels)?,
                    Rule::JumpImmediate => jinsn(pc, BPF_JMP | BPF_JEQ | BPF_K, true, operands, &labels)?,
                    Rule::JumpIfImmediate => jtinsn(pc, BPF_JMP | BPF_JEQ | BPF_K, true, operands, &labels)?,
                    _ => unreachable!(),
                });
            }
            Rule::JNEQ => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::JumpIfIndexRegister => jfinsn(pc, BPF_JMP | BPF_JEQ | BPF_X, false, operands, &labels)?,
                    Rule::JumpIfImmediate => jfinsn(pc, BPF_JMP | BPF_JEQ | BPF_K, true, operands, &labels)?,
                    _ => unreachable!(),
                });
            }
            Rule::JLT => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::JumpIfIndexRegister => jfinsn(pc, BPF_JMP | BPF_JGE | BPF_X, false, operands, &labels)?,
                    Rule::JumpIfImmediate => jfinsn(pc, BPF_JMP | BPF_JGE | BPF_K, true, operands, &labels)?,
                    _ => unreachable!(),
                });
            }
            Rule::JLE => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::JumpIfIndexRegister => jfinsn(pc, BPF_JMP | BPF_JGT | BPF_X, false, operands, &labels)?,
                    Rule::JumpIfImmediate => jfinsn(pc, BPF_JMP | BPF_JGT | BPF_K, true, operands, &labels)?,
                    _ => unreachable!(),
                });
            }
            Rule::JGT => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::JumpIndexRegister => jinsn(pc, BPF_JMP | BPF_JGT | BPF_X, false, operands, &labels)?,
                    Rule::JumpIfIndexRegister => jtinsn(pc, BPF_JMP | BPF_JGT | BPF_X, false, operands, &labels)?,
                    Rule::JumpImmediate => jinsn(pc, BPF_JMP | BPF_JGT | BPF_K, true, operands, &labels)?,
                    Rule::JumpIfImmediate => jtinsn(pc, BPF_JMP | BPF_JGT | BPF_K, true, operands, &labels)?,
                    _ => unreachable!(),
                });
            }
            Rule::JGE => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::JumpIndexRegister => jinsn(pc, BPF_JMP | BPF_JGE | BPF_X, false, operands, &labels)?,
                    Rule::JumpIfIndexRegister => jtinsn(pc, BPF_JMP | BPF_JGE | BPF_X, false, operands, &labels)?,
                    Rule::JumpImmediate => jinsn(pc, BPF_JMP | BPF_JGE | BPF_K, true, operands, &labels)?,
                    Rule::JumpIfImmediate => jtinsn(pc, BPF_JMP | BPF_JGE | BPF_K, true, operands, &labels)?,
                    _ => unreachable!(),
                });
            }
            Rule::JSET => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::JumpIndexRegister => jinsn(pc, BPF_JMP | BPF_JSET | BPF_X, false, operands, &labels)?,
                    Rule::JumpIfIndexRegister => jtinsn(pc, BPF_JMP | BPF_JSET | BPF_X, false, operands, &labels)?,
                    Rule::JumpImmediate => jinsn(pc, BPF_JMP | BPF_JSET | BPF_K, true, operands, &labels)?,
                    Rule::JumpIfImmediate => jtinsn(pc, BPF_JMP | BPF_JSET | BPF_K, true, operands, &labels)?,
                    _ => unreachable!(),
                });
            }
            Rule::ADD => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::IndexRegister => insn(BPF_ALU | BPF_ADD | BPF_X, operands)?,
                    Rule::Immediate => insn(BPF_ALU | BPF_ADD | BPF_K, operands)?,
                    _ => unreachable!(),
                });
            }
            Rule::SUB => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::IndexRegister => insn(BPF_ALU | BPF_SUB | BPF_X, operands)?,
                    Rule::Immediate => insn(BPF_ALU | BPF_SUB | BPF_K, operands)?,
                    _ => unreachable!(),
                });
            }
            Rule::MUL => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::IndexRegister => insn(BPF_ALU | BPF_MUL | BPF_X, operands)?,
                    Rule::Immediate => insn(BPF_ALU | BPF_MUL | BPF_K, operands)?,
                    _ => unreachable!(),
                });
            }
            Rule::DIV => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::IndexRegister => insn(BPF_ALU | BPF_DIV | BPF_X, operands)?,
                    Rule::Immediate => insn(BPF_ALU | BPF_DIV | BPF_K, operands)?,
                    _ => unreachable!(),
                });
            }
            Rule::MOD => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::IndexRegister => insn(BPF_ALU | BPF_MOD | BPF_X, operands)?,
                    Rule::Immediate => insn(BPF_ALU | BPF_MOD | BPF_K, operands)?,
                    _ => unreachable!(),
                });
            }
            Rule::NEG => {
                insns.push(insn(BPF_ALU | BPF_NEG, inner_pairs)?);
            }
            Rule::AND => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::IndexRegister => insn(BPF_ALU | BPF_AND | BPF_X, operands)?,
                    Rule::Immediate => insn(BPF_ALU | BPF_AND | BPF_K, operands)?,
                    _ => unreachable!(),
                });
            }
            Rule::OR => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::IndexRegister => insn(BPF_ALU | BPF_OR | BPF_X, operands)?,
                    Rule::Immediate => insn(BPF_ALU | BPF_OR | BPF_K, operands)?,
                    _ => unreachable!(),
                });
            }
            Rule::XOR => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::IndexRegister => insn(BPF_ALU | BPF_XOR | BPF_X, operands)?,
                    Rule::Immediate => insn(BPF_ALU | BPF_XOR | BPF_K, operands)?,
                    _ => unreachable!(),
                });
            }
            Rule::LSH => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::IndexRegister => insn(BPF_ALU | BPF_LSH | BPF_X, operands)?,
                    Rule::Immediate => insn(BPF_ALU | BPF_LSH | BPF_K, operands)?,
                    _ => unreachable!(),
                });
            }
            Rule::RSH => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::IndexRegister => insn(BPF_ALU | BPF_RSH | BPF_X, operands)?,
                    Rule::Immediate => insn(BPF_ALU | BPF_RSH | BPF_K, operands)?,
                    _ => unreachable!(),
                });
            }
            Rule::TAX => {
                insns.push(insn(BPF_MISC | BPF_TAX, inner_pairs)?);
            }
            Rule::TXA => {
                insns.push(insn(BPF_MISC | BPF_TXA, inner_pairs)?);
            }
            Rule::COP => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::Immediate => insn(BPF_MISC | BPF_COP, operands)?,
                    Rule::Extension => xinsn(BPF_MISC | BPF_COP, operands, extensions)?,
                    _ => unreachable!(),
                });
            }
            Rule::COPX => {
                insns.push(insn(BPF_MISC | BPF_COPX, inner_pairs)?);
            }
            Rule::RET => {
                let expression = inner_pairs.next().unwrap();
                let rule = expression.as_rule();
                let operands = expression.into_inner();
                insns.push(match rule {
                    Rule::Immediate => insn(BPF_RET | BPF_K, operands)?,
                    Rule::IndexRegister => insn(BPF_RET | BPF_X, operands)?,
                    Rule::AccumulatorRegister => insn(BPF_RET | BPF_A, operands)?,
                    _ => unreachable!(),
                });
            }
            Rule::Label => {
                continue;
            }
            Rule::EOI => {
                break;
            }
            _ => unreachable!(),
        }

        pc += 1;
    }

    Ok(insns)
}
