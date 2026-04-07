// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

/*
 * Extension program (freplace) that performs an LPM trie lookup.
 * When attached to a sleepable LSM host program, this runs under
 * rcu_read_lock_trace() — exposing the missing RCU check in
 * trie_lookup_elem().
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct trie_key {
	__u32 prefixlen;
	__u32 data;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct trie_key);
	__type(value, __u32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 256);
} lpm_trie SEC(".maps");

int lookup_result;

SEC("freplace")
int check_ip(void)
{
	struct trie_key key = { .prefixlen = 32, .data = 0x0a000001 /* 10.0.0.1 */ };
	__u32 *val;

	val = bpf_map_lookup_elem(&lpm_trie, &key);
	lookup_result = val ? *val : -1;

	return 0;
}

char _license[] SEC("license") = "GPL";
