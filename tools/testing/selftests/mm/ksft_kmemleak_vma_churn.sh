#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Regression test for kmemleak reporting live VMAs as leaks.
#
# A thread stack's guard page is a VMA that is never faulted in: it has no
# anon_vma and no file, so the only pointer to it is a slot in a maple tree
# node, and every write to the mm's tree replaces that node with a copy.
# kmemleak's first pass usually reaches a node only after it was replaced
# and freed. The pass over modified objects is there to pick up the new
# copy, but it used to scan the copies only after walking every object, by
# which time they had been replaced and freed as well. A process that keeps
# changing its mappings then got its guard VMAs reported scan after scan.
#
# kmemleak_vma_churn builds glibc-style thread stacks and keeps mapping and
# unmapping a page next to every guard page. To make a VM scan like a big,
# busy machine, it also keeps creating files in a tmpfs, so that each scan
# has objects allocated while it runs, and holds many single-page VMAs, so
# that each scan has a lot to walk. Every VMA the helper owns stays mapped
# until the test kills it, so any kmemleak report of one of them is a false
# positive. min_unref_scans=1 makes a single missed scan enough to show up.
#
# Author: Breno Leitao <leitao@debian.org>

# KTAP output helpers (ktap_skip_all, ktap_exit_fail_msg, ktap_test_pass, ...).
DIR="$(dirname "$(readlink -f "$0")")"
# shellcheck source=../kselftest/ktap_helpers.sh
source "${DIR}"/../kselftest/ktap_helpers.sh

KMEMLEAK=/sys/kernel/debug/kmemleak
PARAM=/sys/module/kmemleak/parameters/min_unref_scans
MAX_MAP=/proc/sys/vm/max_map_count
HELPER="${DIR}"/kmemleak_vma_churn
FILES=200000	# sliding window of files in the tmpfs
VMAS=1000000	# single-page VMAs held by the helper
SCANS=10
AGE=6		# seconds; must exceed kmemleak's 5s minimum object age

ktap_print_header

skip() {
	ktap_skip_all "$1"
	exit "$KSFT_SKIP"
}

[ "$(id -u)" -eq 0 ] || skip "must run as root"
[ -r "$KMEMLEAK" ] || skip "no kmemleak debugfs (CONFIG_DEBUG_KMEMLEAK)"
[ -w "$PARAM" ] || skip "min_unref_scans module parameter not present"
[ -x "$HELPER" ] || skip "kmemleak_vma_churn not built"
# The helper's VMAs and files plus kmemleak's metadata take about 1GB.
mem_kb=$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)
[ "$mem_kb" -ge $((2 << 20)) ] || skip "needs 2GB of available memory"

# kmemleak can be present but disabled at runtime; a "scan" then returns
# EPERM. Probe once and skip if so.
echo scan > "$KMEMLEAK" 2>/dev/null ||
	skip "kmemleak is disabled (check dmesg or kmemleak= boot arg)"

prev=$(cat "$PARAM")
prev_max_map=$(cat "$MAX_MAP")
dir=$(mktemp -d)
out=$(mktemp)
pid=
# shellcheck disable=SC2317  # invoked indirectly via trap
cleanup() {
	if [ -n "$pid" ]; then
		pkill -KILL -P "$pid" 2>/dev/null
		kill -KILL "$pid" 2>/dev/null
		wait "$pid" 2>/dev/null
	fi
	umount "$dir" 2>/dev/null || umount -l "$dir" 2>/dev/null
	rmdir "$dir" 2>/dev/null
	rm -f "$out"
	echo "$prev_max_map" > "$MAX_MAP"
	echo "$prev" > "$PARAM" 2>/dev/null		# restore the parameter
	echo scan=on > "$KMEMLEAK" 2>/dev/null		# re-enable auto scan
}
trap cleanup EXIT

# Only our manual scans should run, and one missed scan is enough to report.
echo scan=off > "$KMEMLEAK" 2>/dev/null
echo 1 > "$PARAM"

mount -t tmpfs -o nr_inodes=0 none "$dir" || skip "cannot mount a tmpfs"
[ "$prev_max_map" -gt $((VMAS + 65536)) ] ||
	echo $((VMAS + 65536)) > "$MAX_MAP"

"$HELPER" "$dir" "$FILES" "$VMAS" > "$out" &
pid=$!
for _ in $(seq 300); do
	grep -q ready "$out" && break
	kill -0 "$pid" 2>/dev/null ||
		ktap_exit_fail_msg "kmemleak_vma_churn failed to start"
	sleep 1
done
grep -q ready "$out" ||
	ktap_exit_fail_msg "kmemleak_vma_churn did not get ready"
sleep "$AGE"

# Reports of VMAs allocated by the helper (comm is cut to 15 characters).
count_vmas() {
	awk '
		/^unreferenced object/ { if (c && v) n++; c = v = 0 }
		/comm "kmemleak_vma_ch"/ { c = 1 }
		/ vm_area_(alloc|dup)\+/ { v = 1 }
		END { if (c && v) n++; print n + 0 }
	' "$KMEMLEAK"
}

for i in $(seq "$SCANS"); do
	echo scan > "$KMEMLEAK"
	n=$(count_vmas)
	[ "$n" -eq 0 ] ||
		ktap_exit_fail_msg "scan $i: $n live VMA(s) reported as leaks"
done
kill -0 "$pid" 2>/dev/null ||
	ktap_exit_fail_msg "kmemleak_vma_churn exited early"

ktap_set_plan 1
ktap_test_pass "no live VMA reported in $SCANS scans"
ktap_finished
