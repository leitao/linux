// SPDX-License-Identifier: GPL-2.0
/*
 * SLUB false-sharing microbenchmark.
 *
 * Pins one pthread per available CPU. Each thread loops calling
 * eventfd(EFD_CLOEXEC) + close() at the highest rate it can. Both
 * syscalls go through small-object SLUB kmem_caches (eventfd_ctx,
 * file, dentry), so the workload hammers the per-NUMA-node
 * kmem_cache_node.list_lock and the partial list head sitting on the
 * same cacheline.
 *
 * Reports total and per-CPU ops/sec. This is a microbenchmark, not a
 * correctness test: by default it always passes after reporting the
 * number, so the CI signal is "did the workload run." Set
 * SLUB_BENCH_THRESHOLD=<ops/sec/cpu> to convert it into a regression
 * gate, and SLUB_BENCH_SECONDS=<n> to change the run length (default 5).
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

#include "../kselftest.h"

static int duration_sec = 5;
static unsigned long threshold_per_cpu;	/* 0 = report only, always pass */
static atomic_int run;
static pthread_barrier_t start_barrier;

struct worker {
	pthread_t thread;
	int cpu;
	unsigned long ops;
};

static void *worker_fn(void *arg)
{
	struct worker *w = arg;
	cpu_set_t set;
	unsigned long n = 0;

	CPU_ZERO(&set);
	CPU_SET(w->cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set) < 0)
		ksft_exit_fail_msg("sched_setaffinity(cpu=%d): %s\n",
				   w->cpu, strerror(errno));

	pthread_barrier_wait(&start_barrier);

	while (atomic_load_explicit(&run, memory_order_acquire)) {
		int fd = eventfd(0, EFD_CLOEXEC);

		if (fd < 0)
			break;
		close(fd);
		n++;
	}

	w->ops = n;
	return NULL;
}

int main(int argc, char **argv)
{
	cpu_set_t available;
	struct worker *workers;
	struct timespec t0, t1;
	double elapsed, total_ops = 0, ops_per_sec, per_cpu;
	int ncpus, online = 0, i;
	const char *env;

	ksft_print_header();
	ksft_set_plan(1);

	env = getenv("SLUB_BENCH_SECONDS");
	if (env)
		duration_sec = atoi(env);
	env = getenv("SLUB_BENCH_THRESHOLD");
	if (env)
		threshold_per_cpu = strtoul(env, NULL, 10);

	if (sched_getaffinity(0, sizeof(available), &available) < 0)
		ksft_exit_fail_msg("sched_getaffinity: %s\n", strerror(errno));
	ncpus = CPU_COUNT(&available);
	if (ncpus < 2)
		ksft_exit_skip("need at least 2 CPUs, have %d\n", ncpus);

	workers = calloc(ncpus, sizeof(*workers));
	if (!workers)
		ksft_exit_fail_msg("oom allocating workers\n");

	pthread_barrier_init(&start_barrier, NULL, ncpus + 1);
	atomic_store(&run, 1);

	for (i = 0; i < CPU_SETSIZE && online < ncpus; i++) {
		if (!CPU_ISSET(i, &available))
			continue;
		workers[online].cpu = i;
		if (pthread_create(&workers[online].thread, NULL,
				   worker_fn, &workers[online]))
			ksft_exit_fail_msg("pthread_create %d failed\n", online);
		online++;
	}

	pthread_barrier_wait(&start_barrier);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	sleep(duration_sec);
	atomic_store(&run, 0);
	clock_gettime(CLOCK_MONOTONIC, &t1);

	for (i = 0; i < online; i++)
		pthread_join(workers[i].thread, NULL);

	elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
	for (i = 0; i < online; i++) {
		ksft_print_msg("cpu %3d: %12lu ops (%.0f ops/sec)\n",
			       workers[i].cpu, workers[i].ops,
			       workers[i].ops / elapsed);
		total_ops += workers[i].ops;
	}

	ops_per_sec = total_ops / elapsed;
	per_cpu = ops_per_sec / online;
	ksft_print_msg("total: %.0f ops/sec across %d cpus (%.0f ops/sec/cpu)\n",
		       ops_per_sec, online, per_cpu);

	if (threshold_per_cpu == 0 || per_cpu >= (double)threshold_per_cpu)
		ksft_test_result_pass("slub_false_sharing: %.0f ops/sec/cpu (threshold %lu)\n",
				      per_cpu, threshold_per_cpu);
	else
		ksft_test_result_fail("slub_false_sharing: %.0f ops/sec/cpu < %lu\n",
				      per_cpu, threshold_per_cpu);

	free(workers);
	ksft_finished();
	return 0;
}
