// SPDX-License-Identifier: GPL-2.0
/*
 * Test getsockopt_iter conversions across protocol families.
 *
 * AF_PACKET PACKET_HDRLEN: bidirectional optval (userspace writes tpacket
 * version in, kernel reads it and writes header size back), exercising the
 * copy_from_iter + iov_iter_revert + copy_to_iter path.
 *
 * CAN raw CAN_RAW_FILTER: undersized buffer returns -ERANGE with the
 * required size in optlen, exercising the wrapper's unconditional optlen
 * writeback on error.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/ethernet.h>

#include "../kselftest_harness.h"

/* --- AF_PACKET tests --- */

FIXTURE(packet_sock)
{
	int fd;
};

FIXTURE_SETUP(packet_sock)
{
	self->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (self->fd < 0 && errno == EPERM)
		SKIP(return, "need CAP_NET_RAW");
	ASSERT_GE(self->fd, 0);
}

FIXTURE_TEARDOWN(packet_sock)
{
	if (self->fd >= 0)
		close(self->fd);
}

/* Bidirectional optval: write tpacket version, read back header size. */
TEST_F(packet_sock, hdrlen_v1)
{
	int val = TPACKET_V1;
	socklen_t len = sizeof(val);

	ASSERT_EQ(getsockopt(self->fd, SOL_PACKET, PACKET_HDRLEN,
			     &val, &len), 0);
	EXPECT_EQ(len, sizeof(int));
	EXPECT_EQ(val, (int)sizeof(struct tpacket_hdr));
}

TEST_F(packet_sock, hdrlen_v3)
{
	int val = TPACKET_V3;
	socklen_t len = sizeof(val);

	ASSERT_EQ(getsockopt(self->fd, SOL_PACKET, PACKET_HDRLEN,
			     &val, &len), 0);
	EXPECT_EQ(len, sizeof(int));
	EXPECT_EQ(val, (int)sizeof(struct tpacket3_hdr));
}

TEST_F(packet_sock, hdrlen_invalid)
{
	int val = 999;
	socklen_t len = sizeof(val);

	EXPECT_EQ(getsockopt(self->fd, SOL_PACKET, PACKET_HDRLEN,
			     &val, &len), -1);
	EXPECT_EQ(errno, EINVAL);
}

/* Struct option with optlen writeback. */
TEST_F(packet_sock, statistics)
{
	struct tpacket_stats stats;
	socklen_t len = sizeof(stats);

	memset(&stats, 0xff, sizeof(stats));
	ASSERT_EQ(getsockopt(self->fd, SOL_PACKET, PACKET_STATISTICS,
			     &stats, &len), 0);
	EXPECT_EQ(len, sizeof(stats));
	EXPECT_EQ(stats.tp_packets, 0);
	EXPECT_EQ(stats.tp_drops, 0);
}

/* Simple int option. */
TEST_F(packet_sock, version)
{
	int val = -1;
	socklen_t len = sizeof(val);

	ASSERT_EQ(getsockopt(self->fd, SOL_PACKET, PACKET_VERSION,
			     &val, &len), 0);
	EXPECT_EQ(len, sizeof(int));
	EXPECT_EQ(val, TPACKET_V1);
}

/* --- CAN raw tests --- */

FIXTURE(can_raw)
{
	int fd;
};

FIXTURE_SETUP(can_raw)
{
	self->fd = socket(PF_CAN, SOCK_RAW, CAN_RAW);
	if (self->fd < 0)
		SKIP(return, "cannot create CAN raw socket: %s",
		     strerror(errno));
}

FIXTURE_TEARDOWN(can_raw)
{
	if (self->fd >= 0)
		close(self->fd);
}

/* Simple int option. */
TEST_F(can_raw, loopback_default)
{
	int val = -1;
	socklen_t len = sizeof(val);

	ASSERT_EQ(getsockopt(self->fd, SOL_CAN_RAW, CAN_RAW_LOOPBACK,
			     &val, &len), 0);
	EXPECT_EQ(len, sizeof(int));
	EXPECT_EQ(val, 1);
}

/* Set one filter, retrieve it back. */
TEST_F(can_raw, filter_set_get)
{
	struct can_filter filt_set = { .can_id = 0x123, .can_mask = 0x7ff };
	struct can_filter filt_get = {};
	socklen_t len;

	ASSERT_EQ(setsockopt(self->fd, SOL_CAN_RAW, CAN_RAW_FILTER,
			     &filt_set, sizeof(filt_set)), 0);

	len = sizeof(filt_get);
	ASSERT_EQ(getsockopt(self->fd, SOL_CAN_RAW, CAN_RAW_FILTER,
			     &filt_get, &len), 0);
	EXPECT_EQ(len, sizeof(struct can_filter));
	EXPECT_EQ(filt_get.can_id, 0x123);
	EXPECT_EQ(filt_get.can_mask, 0x7ff);
}

/* Undersized buffer: -ERANGE with required size in optlen. */
TEST_F(can_raw, filter_erange)
{
	struct can_filter filts[2] = {
		{ .can_id = 0x100, .can_mask = 0x7ff },
		{ .can_id = 0x200, .can_mask = 0x7ff },
	};
	struct can_filter buf;
	socklen_t len;

	ASSERT_EQ(setsockopt(self->fd, SOL_CAN_RAW, CAN_RAW_FILTER,
			     filts, sizeof(filts)), 0);

	len = sizeof(buf);
	EXPECT_EQ(getsockopt(self->fd, SOL_CAN_RAW, CAN_RAW_FILTER,
			     &buf, &len), -1);
	EXPECT_EQ(errno, ERANGE);
	EXPECT_EQ(len, 2 * sizeof(struct can_filter));
}

TEST_HARNESS_MAIN
