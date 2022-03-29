// Copyright © Alex Forster <alex@alexforster.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::*;

pub fn linux() -> HashMap<String, u32> {
    let mut extensions = HashMap::default();

    extensions.insert("pto".to_string(), 0xFFFFF000 + 0); // SKF_AD_PROTOCOL
    extensions.insert("proto".to_string(), 0xFFFFF000 + 0); // SKF_AD_PROTOCOL
    extensions.insert("type".to_string(), 0xFFFFF000 + 4); // SKF_AD_PKTTYPE
    extensions.insert("poff".to_string(), 0xFFFFF000 + 52); // SKF_AD_PAY_OFFSET
    extensions.insert("ifx".to_string(), 0xFFFFF000 + 8); // SKF_AD_IFINDEX
    extensions.insert("ifidx".to_string(), 0xFFFFF000 + 8); // SKF_AD_IFINDEX
    extensions.insert("nla".to_string(), 0xFFFFF000 + 12); // SKF_AD_NLATTR
    extensions.insert("nlan".to_string(), 0xFFFFF000 + 16); // SKF_AD_NLATTR_NEST
    extensions.insert("mark".to_string(), 0xFFFFF000 + 20); // SKF_AD_MARK
    extensions.insert("Q".to_string(), 0xFFFFF000 + 24); // SKF_AD_QUEUE
    extensions.insert("que".to_string(), 0xFFFFF000 + 24); // SKF_AD_QUEUE
    extensions.insert("queue".to_string(), 0xFFFFF000 + 24); // SKF_AD_QUEUE
    extensions.insert("hat".to_string(), 0xFFFFF000 + 28); // SKF_AD_HATYPE
    extensions.insert("hatype".to_string(), 0xFFFFF000 + 28); // SKF_AD_HATYPE
    extensions.insert("rxh".to_string(), 0xFFFFF000 + 32); // SKF_AD_RXHASH
    extensions.insert("rxhash".to_string(), 0xFFFFF000 + 32); // SKF_AD_RXHASH
    extensions.insert("cpu".to_string(), 0xFFFFF000 + 36); // SKF_AD_CPU
    extensions.insert("vlant".to_string(), 0xFFFFF000 + 44); // SKF_AD_VLAN_TAG
    extensions.insert("vlan_tci".to_string(), 0xFFFFF000 + 44); // SKF_AD_VLAN_TAG
    extensions.insert("vlanp".to_string(), 0xFFFFF000 + 48); // SKF_AD_VLAN_TAG_PRESENT
    extensions.insert("vlan_pr".to_string(), 0xFFFFF000 + 48); // SKF_AD_VLAN_TAG_PRESENT
    extensions.insert("vlan_avail".to_string(), 0xFFFFF000 + 48); // SKF_AD_VLAN_TAG_PRESENT
    extensions.insert("vlan_tpid".to_string(), 0xFFFFF000 + 60); // SKF_AD_VLAN_TPID
    extensions.insert("rand".to_string(), 0xFFFFF000 + 56); // SKF_AD_RANDOM

    extensions
}
