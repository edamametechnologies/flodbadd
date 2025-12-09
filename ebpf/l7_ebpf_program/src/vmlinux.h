/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * Minimal vmlinux.h for L7 eBPF Network Session Tracking
 * 
 * This file provides minimal kernel structure definitions needed for
 * the eBPF program to compile without a full BTF-generated vmlinux.h.
 * 
 * These definitions work with Linux kernel 5.3+.
 */

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

/* ============== Compiler Attributes ============== */

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* ============== Basic Types ============== */

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;

/* Checksum types needed by bpf_helper_defs.h */
typedef __u16 __sum16;
typedef __u32 __wsum;

typedef _Bool bool;
#define true 1
#define false 0

/* ============== BPF Map Types ============== */

enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PROG_ARRAY = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_HASH = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_RINGBUF = 27,
};

/* BPF map update flags */
#define BPF_ANY     0
#define BPF_NOEXIST 1
#define BPF_EXIST   2

/* ============== Address Families ============== */

#define AF_INET     2
#define AF_INET6    10

/* ============== Network Structures ============== */

struct in6_addr {
    union {
        __u8 u6_addr8[16];
        __be16 u6_addr16[8];
        __be32 u6_addr32[4];
    };
};

/* ============== Forward Declarations ============== */

struct sock;
struct task_struct;

/* ============== Byte Order Macros ============== */

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
static __always_inline __u16 ___bpf_swab16(__u16 val) {
    return (val << 8) | (val >> 8);
}
#define bpf_htons(x) ___bpf_swab16(x)
#define bpf_ntohs(x) ___bpf_swab16(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_htons(x) (x)
#define bpf_ntohs(x) (x)
#else
#error "Unknown byte order"
#endif

/* ============== PT_REGS Definitions ============== */

/*
 * Architecture-specific register access macros.
 * These must match the target architecture.
 */

#if defined(__TARGET_ARCH_x86) || defined(__x86_64__)

/* x86_64 pt_regs structure */
struct pt_regs {
    unsigned long r15, r14, r13, r12, rbp, rbx;
    unsigned long r11, r10, r9, r8, rax, rcx, rdx, rsi, rdi;
    unsigned long orig_rax, rip, cs, eflags, rsp, ss;
};

#define PT_REGS_PARM1(x) ((x)->rdi)
#define PT_REGS_PARM2(x) ((x)->rsi)
#define PT_REGS_PARM3(x) ((x)->rdx)
#define PT_REGS_PARM4(x) ((x)->rcx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_PARM6(x) ((x)->r9)
#define PT_REGS_RC(x)    ((x)->rax)
#define PT_REGS_IP(x)    ((x)->rip)

#elif defined(__TARGET_ARCH_arm64) || defined(__aarch64__)

/* ARM64 pt_regs and user_pt_regs structures */
struct pt_regs {
    unsigned long regs[31];
    unsigned long sp;
    unsigned long pc;
    unsigned long pstate;
    unsigned long orig_x0;
};

/* user_pt_regs is required by bpf_tracing.h for arm64 */
struct user_pt_regs {
    unsigned long regs[31];
    unsigned long sp;
    unsigned long pc;
    unsigned long pstate;
};

#define PT_REGS_PARM1(x) ((x)->regs[0])
#define PT_REGS_PARM2(x) ((x)->regs[1])
#define PT_REGS_PARM3(x) ((x)->regs[2])
#define PT_REGS_PARM4(x) ((x)->regs[3])
#define PT_REGS_PARM5(x) ((x)->regs[4])
#define PT_REGS_PARM6(x) ((x)->regs[5])
#define PT_REGS_RC(x)    ((x)->regs[0])
#define PT_REGS_IP(x)    ((x)->pc)

#else
#error "Unsupported architecture - define __TARGET_ARCH_x86 or __TARGET_ARCH_arm64"
#endif

#endif /* __VMLINUX_H__ */
