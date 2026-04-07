// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

/*
 * Test that LPM trie lookups from sleepable BPF programs do not trigger
 * "suspicious RCU usage" warnings.
 *
 * An extension program (freplace) that uses an LPM trie map is attached
 * to a global function in a sleepable LSM program. The extension passes
 * the verifier's sleepable map check (it is non-sleepable itself), but
 * at runtime it inherits the caller's rcu_read_lock_trace() context.
 * trie_lookup_elem() must accept that RCU lock flavor.
 */

#include <test_progs.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "lpm_trie_rcu.skel.h"
#include "lpm_trie_rcu_ext.skel.h"

void test_lpm_trie_rcu(void)
{
	struct lpm_trie_rcu_ext *ext_skel = NULL;
	struct lpm_trie_rcu *skel = NULL;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(0x7f000001),
	};
	int err, fd, tgt_fd;

	skel = lpm_trie_rcu__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	tgt_fd = bpf_program__fd(skel->progs.lpm_trie_lookup_sleepable);

	ext_skel = lpm_trie_rcu_ext__open();
	if (!ASSERT_OK_PTR(ext_skel, "ext_open"))
		goto out;

	err = bpf_program__set_attach_target(ext_skel->progs.check_ip,
					     tgt_fd, "check_ip");
	if (!ASSERT_OK(err, "set_attach_target"))
		goto out;

	err = lpm_trie_rcu_ext__load(ext_skel);
	if (!ASSERT_OK(err, "ext_load"))
		goto out;

	err = lpm_trie_rcu__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto out;

	err = lpm_trie_rcu_ext__attach(ext_skel);
	if (!ASSERT_OK(err, "ext_attach"))
		goto out;

	/* Trigger the LSM hook via connect() */
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (!ASSERT_GE(fd, 0, "socket"))
		goto out;

	connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	close(fd);

	/*
	 * If the kernel has CONFIG_PROVE_RCU, a buggy trie_lookup_elem()
	 * will have printed "suspicious RCU usage" to dmesg by now.
	 * Verify the BPF programs actually ran.
	 */
	ASSERT_EQ(skel->bss->lookup_done, 1, "lookup_done");

out:
	lpm_trie_rcu_ext__destroy(ext_skel);
	lpm_trie_rcu__destroy(skel);
}
