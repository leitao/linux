// SPDX-License-Identifier: GPL-2.0
/*
 * pipe_bench - exercise pipe->mutex contention under concurrent writers.
 *
 * N writer threads hammer a single pipe with multi-page writes; one reader
 * drains. Each writer records its own write() latency histogram. Multi-page
 * writes (msgsize >= PAGE_SIZE) force the loop in anon_pipe_write() to call
 * alloc_page(GFP_HIGHUSER | __GFP_ACCOUNT) under pipe->mutex, which is the
 * critical section the patch shrinks.
 *
 * Output is a single line per metric so two runs can be diffed directly.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int g_writers = 8;
static size_t g_msgsize = 16 * 4096;
static int g_duration = 10;
static int g_pipe_size = 1024 * 1024;

static atomic_int g_stop = 0;
static int g_pipe[2];

#define HIST_BUCKETS 32

struct wstats {
	uint64_t writes;
	uint64_t bytes;
	uint64_t lat_sum_ns;
	uint64_t lat_max_ns;
	uint64_t lat_hist[HIST_BUCKETS];
};

static inline uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static inline int log2_bucket(uint64_t v)
{
	int b = 0;
	if (!v)
		return 0;
	while (v >>= 1)
		b++;
	return b < HIST_BUCKETS ? b : HIST_BUCKETS - 1;
}

static void *writer(void *arg)
{
	struct wstats *s = arg;
	char *buf = aligned_alloc(4096, g_msgsize);
	if (!buf)
		return NULL;
	memset(buf, 0xAA, g_msgsize);

	while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
		uint64_t t0 = now_ns();
		ssize_t n = write(g_pipe[1], buf, g_msgsize);
		uint64_t dt = now_ns() - t0;
		if (n > 0) {
			s->writes++;
			s->bytes += n;
			s->lat_sum_ns += dt;
			if (dt > s->lat_max_ns)
				s->lat_max_ns = dt;
			s->lat_hist[log2_bucket(dt)]++;
		} else if (n < 0 && errno == EPIPE) {
			break;
		}
	}
	free(buf);
	return NULL;
}

static void *reader(void *arg)
{
	(void)arg;
	char *buf = aligned_alloc(4096, g_msgsize);
	if (!buf)
		return NULL;
	/* Drain until EOF (write end closed by main). g_stop is not checked
	 * here on purpose: writers may be blocked in write() with the pipe
	 * full when g_stop is set, so the reader must keep draining until
	 * main closes the write end. */
	for (;;) {
		ssize_t n = read(g_pipe[0], buf, g_msgsize);
		if (n <= 0)
			break;
	}
	free(buf);
	return NULL;
}

static void summarize(struct wstats *all, int nw)
{
	uint64_t total_writes = 0, total_bytes = 0, total_lat = 0;
	uint64_t max_lat = 0;
	uint64_t agg[HIST_BUCKETS] = {0};

	for (int i = 0; i < nw; i++) {
		total_writes += all[i].writes;
		total_bytes += all[i].bytes;
		total_lat += all[i].lat_sum_ns;
		if (all[i].lat_max_ns > max_lat)
			max_lat = all[i].lat_max_ns;
		for (int b = 0; b < HIST_BUCKETS; b++)
			agg[b] += all[i].lat_hist[b];
	}

	uint64_t p50_target = total_writes * 50 / 100;
	uint64_t p99_target = total_writes * 99 / 100;
	uint64_t p999_target = total_writes * 999 / 1000;
	uint64_t cum = 0, p50 = 0, p99 = 0, p999 = 0;

	for (int b = 0; b < HIST_BUCKETS; b++) {
		cum += agg[b];
		if (!p50 && cum >= p50_target)
			p50 = 1ULL << b;
		if (!p99 && cum >= p99_target)
			p99 = 1ULL << b;
		if (!p999 && cum >= p999_target)
			p999 = 1ULL << b;
	}

	double sec = g_duration;
	printf("config: writers=%d msgsize=%zu duration=%d pipe_size=%d\n",
	       g_writers, g_msgsize, g_duration, g_pipe_size);
	printf("writes: total=%llu rate=%.0f/s\n",
	       (unsigned long long)total_writes, total_writes / sec);
	printf("throughput_MBps: %.2f\n",
	       (total_bytes / sec) / (1024.0 * 1024.0));
	printf("lat_avg_ns: %llu\n",
	       (unsigned long long)(total_writes ? total_lat / total_writes : 0));
	printf("lat_p50_ns_upper: %llu\n", (unsigned long long)p50);
	printf("lat_p99_ns_upper: %llu\n", (unsigned long long)p99);
	printf("lat_p999_ns_upper: %llu\n", (unsigned long long)p999);
	printf("lat_max_ns: %llu\n", (unsigned long long)max_lat);
}

int main(int argc, char **argv)
{
	int opt;
	while ((opt = getopt(argc, argv, "w:s:d:p:")) != -1) {
		switch (opt) {
		case 'w': g_writers = atoi(optarg); break;
		case 's': g_msgsize = atol(optarg); break;
		case 'd': g_duration = atoi(optarg); break;
		case 'p': g_pipe_size = atoi(optarg); break;
		default:
			fprintf(stderr,
				"usage: %s [-w writers] [-s msgsize] [-d secs] [-p pipe_size]\n",
				argv[0]);
			return 1;
		}
	}

	signal(SIGPIPE, SIG_IGN);
	setvbuf(stdout, NULL, _IOLBF, 0);
	setvbuf(stderr, NULL, _IOLBF, 0);

	if (pipe(g_pipe) < 0) {
		perror("pipe");
		return 1;
	}
	if (fcntl(g_pipe[1], F_SETPIPE_SZ, g_pipe_size) < 0)
		perror("F_SETPIPE_SZ (continuing)");

	pthread_t *wt = calloc(g_writers, sizeof(*wt));
	struct wstats *ws = calloc(g_writers, sizeof(*ws));
	pthread_t rt;

	pthread_create(&rt, NULL, reader, NULL);
	for (int i = 0; i < g_writers; i++)
		pthread_create(&wt[i], NULL, writer, &ws[i]);

	fprintf(stderr, "pid=%d\n", getpid());
	fflush(stderr);

	sleep(g_duration);
	atomic_store(&g_stop, 1);

	/* Close write end first so any writer blocked in write() gets EPIPE
	 * and exits, and so the reader sees EOF after draining. */
	close(g_pipe[1]);
	for (int i = 0; i < g_writers; i++)
		pthread_join(wt[i], NULL);
	pthread_join(rt, NULL);
	close(g_pipe[0]);

	summarize(ws, g_writers);
	fflush(stdout);
	return 0;
}
