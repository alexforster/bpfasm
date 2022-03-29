// Copyright © Alex Forster <alex@alexforster.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn test() {
    let programs = [
        [
            r#"
            ldh [12]
            jne #0x806, drop
            ret #-1
            drop: ret #0
            "#,
            "4,40 0 0 12,21 0 1 2054,6 0 0 4294967295,6 0 0 0",
        ],
        [
            r#"
            ldh [12]
            jne #0x800, drop
            ldb [23]
            jneq #6, drop
            ret #-1
            drop: ret #0
            "#,
            "6,40 0 0 12,21 0 3 2048,48 0 0 23,21 0 1 6,6 0 0 4294967295,6 0 0 0",
        ],
        [
            r#"
            start:
            ldh [12]
            jne #0x800, drop
            ldb [23]
            jneq #6, drop
            ldh [20]
            jset #0x1fff, drop
            ldxb 4 * ([14] & 0xf)
            ldh [x + 14]
            jeq #0x16, pass
            ldh [x + 16]
            jne #0x16, drop
            pass: ret #-1
            drop: ret #0
            "#,
            "13,40 0 0 12,21 0 10 2048,48 0 0 23,21 0 8 6,40 0 0 20,69 6 0 8191,177 0 0 14,72 0 0 14,21 2 0 22,72 0 0 16,21 0 1 22,6 0 0 4294967295,6 0 0 0",
        ],
        [
            r#"
            ld [4]                  /* offsetof(struct seccomp_data, arch) */
            jne #0xc000003e, bad    /* AUDIT_ARCH_X86_64 */
            ld [0]                  /* offsetof(struct seccomp_data, nr) */
            jeq #15, good           /* __NR_rt_sigreturn */
            jeq #231, good          /* __NR_exit_group */
            jeq #60, good           /* __NR_exit */
            jeq #0, good            /* __NR_read */
            jeq #1, good            /* __NR_write */
            jeq #5, good            /* __NR_fstat */
            jeq #9, good            /* __NR_mmap */
            jeq #14, good           /* __NR_rt_sigprocmask */
            jeq #13, good           /* __NR_rt_sigaction */
            jeq #35, good           /* __NR_nanosleep */
            bad: ret #0             /* SECCOMP_RET_KILL */
            good: ret #0x7fff0000   /* SECCOMP_RET_ALLOW */
            "#,
            "15,32 0 0 4,21 0 11 3221225534,32 0 0 0,21 10 0 15,21 9 0 231,21 8 0 60,21 7 0 0,21 6 0 1,21 5 0 5,21 4 0 9,21 3 0 14,21 2 0 13,21 1 0 35,6 0 0 0,6 0 0 2147418112",
        ],
        [
            r#"
            ld poff
            ret a
            "#,
            "2,32 0 0 4294963252,22 0 0 0",
        ],
        [
            r#"
            ld vlanp
            jeq #0, drop
            ret #-1
            drop: ret #0
            "#,
            "4,32 0 0 4294963248,21 1 0 0,6 0 0 4294967295,6 0 0 0",
        ],
        [
            r#"
            ld #vlanp
            jeq #0, drop
            ld vlant
            jneq #10, drop
            ret #-1
            drop: ret #0
            "#,
            "6,32 0 0 4294963248,21 3 0 0,32 0 0 4294963244,21 0 1 10,6 0 0 4294967295,6 0 0 0",
        ],
        [
            r#"
            ldh #proto       /* A = skb->protocol */
            
            jneq #0, skip    /* check for NETLINK_ROUTE */
            ldb [4]          /* A = nlmsg_type */
            
            jneq #0x10, skip /* check type == RTNL_NEWLINK */
            ldx #16          /* X = offset(ifinfomsg) */
            
            ldb [x + 4]      /* offset(ifi_index) */
            jneq #0x3, skip  /* check ifindex == 3 */
            
            ld #32           /* A = len(nlmsghdr) + len(ifinfomsg), payload offset */
            ldx #16          /* X = IFLA_OPERSTATE */
            ld #nla          /* A = offset(IFLA_OPERSTATE) */
            jeq #0, skip
            tax
            ld M[1]
            and x
            ldb [x + 4]      /* A = value(IFLA_OPERSTATE) */
            jneq #0x6, skip  /* check oper state is UP */
            
            ret #-1
            skip: ret #0
            "#,
            "18,40 0 0 4294963200,21 0 15 0,48 0 0 4,21 0 13 16,1 0 0 16,80 0 0 4,21 0 10 3,0 0 0 32,1 0 0 16,32 0 0 4294963212,21 6 0 0,7 0 0 0,96 0 0 1,92 0 0 0,80 0 0 4,21 0 1 6,6 0 0 4294967295,6 0 0 0",
        ],
        [
            r#"
            ; icmp random packet sampling, 1 in 4
            ldh 	[12]
            jne 	#0x800, drop
            ldb 	[23]
            jneq 	#1, drop
            ; get a random uint32 number
            ld 		rand
            mod 	#4
            jneq 	#1, drop
            ret 	#-1
            drop: 	ret 	#0
            "#,
            "9,40 0 0 12,21 0 6 2048,48 0 0 23,21 0 4 1,32 0 0 4294963256,148 0 0 4,21 0 1 1,6 0 0 4294967295,6 0 0 0",
        ],
        [
            r#"
            ld [4]
            ld [x + 4]
            ld M[4]
            ld #4
            ld len
            ld proto
            ldi #4
            ldh [4]
            ldh [x + 4]
            ldh proto
            ldb [4]
            ldb [x + 4]
            ldb proto
            ldx M[4]
            ldx 4 * ([4] & 0xF)
            ldx #4
            ldx len
            ldxi #4
            ldxb 4 * ([4] & 0xF)
            st M[4]
            stx M[4]
            jmp jump_target_1
            ja jump_target_2
            jeq x, jump_target_3, jump_target_1
            jeq x, jump_target_2
            jeq #4, jump_target_3, jump_target_1
            jeq #4, jump_target_2
            jneq x, jump_target_3
            jne x, jump_target_1
            jneq #4, jump_target_2
            jne #4, jump_target_3
            jlt x, jump_target_1
            jlt #4, jump_target_2
            jle x, jump_target_3
            jle #4, jump_target_1
            jgt x, jump_target_2
            jgt #4, jump_target_3
            jge x, jump_target_1
            jge x, jump_target_2
            jset x, jump_target_3, jump_target_1
            jset x, jump_target_2
            jset #4, jump_target_3, jump_target_1
            jset #4, jump_target_2
            add x
            add #4
            sub x
            sub #4
            mul x
            mul #4
            div x
            div #4
            mod x
            mod #4
            neg
            and x
            and #4
            or x
            or #4
            xor x
            xor #4
            lsh x
            lsh #4
            rsh x
            rsh #4
            tax
            txa
            jump_target_1: ret a
            jump_target_2: ret x
            jump_target_3: ret #4
            "#,
            "69,32 0 0 4,64 0 0 4,96 0 0 4,0 0 0 4,128 0 0 0,32 0 0 4294963200,0 0 0 4,40 0 0 4,72 0 0 4,40 0 0 4294963200,48 0 0 4,80 0 0 4,48 0 0 4294963200,97 0 0 4,177 0 0 4,1 0 0 4,129 0 0 0,1 0 0 4,177 0 0 4,2 0 0 4,3 0 0 4,5 0 0 44,5 0 0 44,29 44 42 0,29 42 0 0,21 42 40 4,21 40 0 4,29 0 40 0,29 0 37 0,21 0 37 4,21 0 37 4,61 0 34 0,53 0 34 4,45 0 34 0,37 0 31 4,45 31 0 0,37 31 0 4,61 28 0 0,61 28 0 0,77 28 26 0,77 26 0 0,69 26 24 4,69 24 0 4,12 0 0 0,4 0 0 4,28 0 0 0,20 0 0 4,44 0 0 0,36 0 0 4,60 0 0 0,52 0 0 4,156 0 0 0,148 0 0 4,132 0 0 0,92 0 0 0,84 0 0 4,76 0 0 0,68 0 0 4,172 0 0 0,164 0 0 4,108 0 0 0,100 0 0 4,124 0 0 0,116 0 0 4,7 0 0 0,135 0 0 0,22 0 0 0,14 0 0 0,6 0 0 4",
        ]
    ];

    let extensions = bpfasm::extensions::linux();

    for [source, expected] in programs {
        let instructions = bpfasm::assemble(source, &extensions).expect("compiler error");
        let actual = format!(
            "{},{}",
            instructions.len(),
            instructions.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(",")
        );
        assert_eq!(actual, expected);
    }
}
