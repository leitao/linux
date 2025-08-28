#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

# This test creates two netdevsim virtual interfaces, assigns one of them (the
# "destination interface") to a new namespace, and assigns IP addresses to both
# interfaces.
#
# It listens on the destination interface using socat and configures a dynamic
# target on netconsole, pointing to the destination IP address.
#
# Finally, it checks whether the message was received properly on the
# destination interface.  Note that this test may pollute the kernel log buffer
# (dmesg) and relies on dynamic configuration and namespaces being configured.
#
# Author: Breno Leitao <leitao@debian.org>

set -euo pipefail

SCRIPTDIR=$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")

source "${SCRIPTDIR}"/lib/sh/lib_netcons.sh

# Number of times the main loop run
ITERATIONS=${1:-1000}

# Create, enable and delete some targets. This is called as a
# threaded function
create_and_delete_random_target() {
	RND_PREFIX=$(mktemp -u netcons_rnd_XXXX_)
	COUNT=1

	if [ -d "${NETCONS_CONFIGFS}/${RND_PREFIX}${COUNT}"  ] || [ -d "${NETCONS_CONFIGFS}/${RND_PREFIX}0" ]; then
		echo "Function didn't finish yet, skipping it." >&2
		return
	fi

	# enable COUNT targets
	for i in $(seq 0 ${COUNT})
	do
		RND_TARGET="${RND_PREFIX}"${i}
		RND_TARGET_PATH="${NETCONS_CONFIGFS}"/"${RND_TARGET}"

		# Basic population so the target can come up
		mkdir "${RND_TARGET_PATH}"
		echo "${DSTIP}" > "${RND_TARGET_PATH}"/remote_ip
		echo "${SRCIP}" > "${RND_TARGET_PATH}"/local_ip
		echo "${DSTMAC}" > "${RND_TARGET_PATH}"/remote_mac
		echo "${SRCIF}" > "${RND_TARGET_PATH}"/dev_name

		echo 1 > "${RND_TARGET_PATH}"/enabled
	done

	echo "netconsole selftest: ${COUNT} adddition target was created" > /dev/kmsg
	# disable them all
	for i in $(seq 0 ${COUNT})
	do
		RND_TARGET="${RND_PREFIX}"${i}
		RND_TARGET_PATH="${NETCONS_CONFIGFS}"/"${RND_TARGET}"
		echo 0 > "${RND_TARGET_PATH}"/enabled
		rmdir "${RND_TARGET_PATH}"
	done
}

# Disable and enable the target mid-air, while messages
# are being transmitted.
toggler() {
	for i in $(seq 4)
	do
		if [ ! -d "${NETCONS_PATH}" ]
		then
			break
		fi
		echo 0 > "${NETCONS_PATH}"/enabled 2> /dev/null || true
		# Try to enable a bit harder
		for j in $(seq 5)
		do
			echo 1 > "${NETCONS_PATH}"/enabled 2> /dev/null || true
		done
	done
}

modprobe netdevsim 2> /dev/null || true
modprobe netconsole 2> /dev/null || true

# Check for basic system dependency and exit if not found
check_for_dependencies
# Set current loglevel to KERN_INFO(6), and default to KERN_NOTICE(5)
echo "6 5" > /proc/sys/kernel/printk
# Remove the namespace, interfaces and netconsole target on exit
trap cleanup EXIT

FORMAT="extended"
IP_VERSION="ipv6"

# Create one namespace and two interfaces
set_network "${IP_VERSION}"
# Create a dynamic target for netconsole
create_dynamic_target "${FORMAT}"

for i in $(seq $ITERATIONS)
do
	echo "${MSG}: ${TARGET} ${i}" > /dev/kmsg

	if (( i % 50 == 0 )); then
		toggler &
		toggler_pid=$!
	fi

	if (( i % 50 == 0 )); then
		# create some targets, enable them, send msg and disable
		# all in a parallel thread
		create_and_delete_random_target &
		random_pid=$!
	fi
done
wait "${toggler_pid}" "${random_pid}"

exit "${ksft_pass}"
