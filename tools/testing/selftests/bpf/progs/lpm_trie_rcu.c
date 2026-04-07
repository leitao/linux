// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

/*
 * Sleepable LSM program that calls a global function which will be
 * replaced by an extension program (freplace) performing an LPM trie
 * lookup. This reproduces the "suspicious RCU usage" warning in
 * trie_lookup_elem(): the extension is verified as non-sleepable
 * (allowing LPM trie), but at runtime it inherits the caller's
 * rcu_read_lock_trace() context.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

int lookup_done;
int lookup_ret;

__weak __noinline
int check_ip(void)
{
	/* Placeholder — replaced by lpm_trie_rcu_ext.c via freplace */
	return 0;
}

SEC("lsm.s/socket_connect")
int BPF_PROG(lpm_trie_lookup_sleepable, struct socket *sock,
	     struct sockaddr *address, int addrlen)
{
	int ret;

	ret = check_ip();
	barrier_var(ret);
	lookup_ret = ret;
	lookup_done = 1;
	return 0;
}

char _license[] SEC("license") = "GPL";
