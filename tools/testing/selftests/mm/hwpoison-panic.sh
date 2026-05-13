#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Verify vm.panic_on_unrecoverable_memory_failure by injecting a hwpoison
# error on a kernel-owned (PG_reserved) page and confirming the kernel
# panics.
#
# This test is DESTRUCTIVE: a successful run crashes the kernel.  It is
# meant to be executed inside a disposable VM (e.g. virtme-ng) with a
# serial console captured by the harness.  It is skipped unless the
# caller opts in via RUN_DESTRUCTIVE=1.
#
# Test passes externally: the kernel must panic with
#   "Memory failure: <pfn>: unrecoverable page"
# A return from the inject means the panic did not fire and the test
# fails.
#
# Author: Breno Leitao <leitao@debian.org>

set -u

ksft_skip=4
sysctl_path=/proc/sys/vm/panic_on_unrecoverable_memory_failure
inject_path=/sys/devices/system/memory/hard_offline_page

ksft_print() { echo "# $*"; }
ksft_exit_skip() { ksft_print "$*"; exit "$ksft_skip"; }
ksft_exit_fail() { echo "not ok 1 $*"; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
	ksft_exit_skip "must run as root"
fi

if [ ! -w "$sysctl_path" ]; then
	ksft_exit_skip "$sysctl_path not present (kernel without the sysctl?)"
fi

if [ ! -w "$inject_path" ]; then
	ksft_exit_skip "$inject_path not present (no MEMORY_HOTPLUG?)"
fi

if [ "${RUN_DESTRUCTIVE:-0}" != "1" ]; then
	ksft_exit_skip "destructive test; re-run with RUN_DESTRUCTIVE=1 inside a disposable VM"
fi

# Pick a PFN inside the kernel image rodata region of /proc/iomem.
# This is preferred over a top-level "Reserved" entry because top-level
# Reserved ranges are often firmware holes that have no backing struct
# page; pfn_to_online_page() returns NULL on those and memory_failure()
# bails out with -ENXIO before reaching the panic path.
#
# "Kernel rodata" is reported as a sub-resource of "System RAM" on every
# major architecture, which guarantees:
#   - the PFN is backed by struct page (within an online memory range);
#   - PG_reserved is set on the page (kernel image area);
#   - the memory is read-only, so setting PG_hwpoison on it does not
#     corrupt writable kernel state if the panic somehow does not fire.
#
# /proc/iomem entries look like (indented for sub-resources):
#     "  02500000-02ffffff : Kernel rodata"
pick_reserved_phys_addr() {
	awk -v pagesize="$(getconf PAGE_SIZE)" '
	/: Kernel rodata[[:space:]]*$/ {
		sub(/^[[:space:]]+/, "")
		n = split($0, a, /[- ]/)
		start = strtonum("0x" a[1])
		end   = strtonum("0x" a[2])
		if (end <= start)
			next
		# Page-align upward and emit the first byte of that page.
		pfn = int((start + pagesize - 1) / pagesize)
		printf "0x%x\n", pfn * pagesize
		exit 0
	}
	' /proc/iomem
}

phys_addr=$(pick_reserved_phys_addr)
if [ -z "$phys_addr" ]; then
	ksft_exit_skip "no \"Kernel rodata\" entry in /proc/iomem"
fi

ksft_print "enabling $sysctl_path"
prior=$(cat "$sysctl_path")
echo 1 > "$sysctl_path" || ksft_exit_fail "failed to enable sysctl"

ksft_print "injecting hwpoison at phys 0x$(printf '%x' "$phys_addr") (Kernel rodata)"
ksft_print "expecting kernel panic: 'Memory failure: <pfn>: unrecoverable page'"

# If this returns, the kernel did not panic → test failed.  Restore the
# sysctl before reporting so the system is left as we found it.
if echo "$phys_addr" > "$inject_path"; then
	echo "$prior" > "$sysctl_path"
	ksft_exit_fail "inject returned without panic; sysctl ineffective"
fi

# Write failed (e.g. -EINVAL on offlining a non-online region): also a
# failure for this test, since we expected the panic path.
echo "$prior" > "$sysctl_path"
ksft_exit_fail "inject failed before reaching the panic path"
