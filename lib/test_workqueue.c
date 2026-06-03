// SPDX-License-Identifier: GPL-2.0

/*
 * Test module for stress and performance analysis of workqueue.
 *
 * Benchmarks queue_work() throughput on an unbound workqueue to measure
 * pool->lock contention under different affinity scope configurations
 * (e.g., cache vs cache_shard).
 *
 * Each producer thread submits its whole batch of work items back to back
 * (one distinct work_struct per item, no per-item wait), so many items stay
 * in flight at once and several CPUs hammer the same pool->lock concurrently.
 * This is the contended, batched-submit workload the wakeup-deferral path is
 * meant to speed up -- a synchronous one-item-at-a-time ping-pong would block
 * each producer on completion and never build up the lock contention.
 *
 * The affinity scope is changed between runs via the workqueue's sysfs
 * affinity_scope attribute (WQ_SYSFS).
 *
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates
 * Copyright (c) 2026 Breno Leitao <leitao@debian.org>
 *
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/moduleparam.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/cpumask.h>
#include <linux/sched.h>
#include <linux/sort.h>
#include <linux/fs.h>

#define WQ_NAME "bench_wq"
#define SCOPE_PATH "/sys/bus/workqueue/devices/" WQ_NAME "/affinity_scope"

static int nr_threads;
module_param(nr_threads, int, 0444);
MODULE_PARM_DESC(nr_threads,
		 "Number of threads to spawn (default: 0 = num_online_cpus())");

static int wq_items = 50000;
module_param(wq_items, int, 0444);
MODULE_PARM_DESC(wq_items,
		 "Number of work items each thread queues (default: 50000)");

/*
 * Submission mode:
 *
 *   batch    - each producer submits its whole run of work items back to
 *              back without waiting, so many items are in flight at once and
 *              several CPUs contend for the same pool->lock concurrently.
 *              Stresses pool->lock / enqueue throughput (default).
 *
 *   pingpong - each producer queues one item and waits for it to complete
 *              before queuing the next.  At most nr_threads items are ever
 *              in flight, so this measures the producer<->worker scheduling
 *              round-trip latency rather than pool->lock contention.
 */
enum bench_mode {
	MODE_BATCH,
	MODE_PINGPONG,
};

static char *mode = "batch";
module_param(mode, charp, 0444);
MODULE_PARM_DESC(mode,
		 "Submission mode: 'batch' (default) or 'pingpong'");

static enum bench_mode bench_mode = MODE_BATCH;

static struct workqueue_struct *bench_wq;
static atomic_t run_remaining;
static DECLARE_COMPLETION(start_comp);
static DECLARE_COMPLETION(all_done_comp);

struct thread_ctx;

struct bench_work {
	struct work_struct work;
	struct thread_ctx *ctx;
};

struct thread_ctx {
	struct bench_work *works;
	u64 *latencies;
	struct completion work_done;	/* pingpong: per-item completion */
	int cpu;
	int items;
};

static void bench_work_fn(struct work_struct *work)
{
	struct bench_work *bw = container_of(work, struct bench_work, work);

	/*
	 * In pingpong mode the producer is blocked waiting on this exact item;
	 * wake it so it can submit the next one.
	 */
	if (bench_mode == MODE_PINGPONG) {
		complete(&bw->ctx->work_done);
		return;
	}

	/*
	 * Batch mode: the work itself is intentionally trivial so the benchmark
	 * stays dominated by queue_work()/pool->lock cost, not by the payload.
	 * The last item to execute across all producers ends the run.
	 */
	if (atomic_dec_and_test(&run_remaining))
		complete(&all_done_comp);
}

static int bench_kthread_fn(void *data)
{
	struct thread_ctx *ctx = data;
	ktime_t t_start, t_end;
	int i;

	/* Wait for all threads to be ready */
	wait_for_completion(&start_comp);

	if (kthread_should_stop())
		return 0;

	for (i = 0; i < ctx->items; i++) {
		/*
		 * batch:    one distinct work_struct per item, all in flight.
		 * pingpong: reuse a single work_struct, one item at a time.
		 */
		struct bench_work *bw = (bench_mode == MODE_BATCH) ?
					&ctx->works[i] : &ctx->works[0];

		if (bench_mode == MODE_PINGPONG)
			reinit_completion(&ctx->work_done);

		INIT_WORK(&bw->work, bench_work_fn);

		t_start = ktime_get();
		queue_work(bench_wq, &bw->work);
		t_end = ktime_get();

		ctx->latencies[i] = ktime_to_ns(ktime_sub(t_end, t_start));

		if (bench_mode == MODE_PINGPONG)
			wait_for_completion(&ctx->work_done);
	}

	/*
	 * In pingpong mode every item has already completed synchronously, so
	 * the last producer to finish its run ends the benchmark.  (In batch
	 * mode the run is ended by the last work item in bench_work_fn().)
	 */
	if (bench_mode == MODE_PINGPONG && atomic_dec_and_test(&run_remaining))
		complete(&all_done_comp);

	/*
	 * Wait for kthread_stop() so the module text isn't freed
	 * while we're still executing.
	 */
	while (!kthread_should_stop())
		schedule();

	return 0;
}

static int cmp_u64(const void *a, const void *b)
{
	u64 va = *(const u64 *)a;
	u64 vb = *(const u64 *)b;

	if (va < vb)
		return -1;
	if (va > vb)
		return 1;
	return 0;
}

static int __init set_affn_scope(const char *scope)
{
	struct file *f;
	loff_t pos = 0;
	ssize_t ret;

	f = filp_open(SCOPE_PATH, O_WRONLY, 0);
	if (IS_ERR(f)) {
		pr_err("test_workqueue: open %s failed: %ld\n",
		       SCOPE_PATH, PTR_ERR(f));
		return PTR_ERR(f);
	}

	ret = kernel_write(f, scope, strlen(scope), &pos);
	filp_close(f, NULL);

	if (ret < 0) {
		pr_err("test_workqueue: write '%s' failed: %zd\n", scope, ret);
		return ret;
	}

	return 0;
}

static int __init run_bench(int n_threads, const char *scope, const char *label)
{
	struct task_struct **tasks;
	unsigned long total_items;
	struct thread_ctx *ctxs;
	u64 *all_latencies;
	ktime_t start, end;
	int cpu, i, j, ret;
	s64 elapsed_us;
	int n_works;

	ret = set_affn_scope(scope);
	if (ret)
		return ret;

	ctxs = kcalloc(n_threads, sizeof(*ctxs), GFP_KERNEL);
	if (!ctxs)
		return -ENOMEM;

	tasks = kcalloc(n_threads, sizeof(*tasks), GFP_KERNEL);
	if (!tasks) {
		kfree(ctxs);
		return -ENOMEM;
	}

	total_items = (unsigned long)n_threads * wq_items;
	/* run_remaining is an atomic_t; keep the in-flight count in range */
	if (total_items > INT_MAX) {
		kfree(tasks);
		kfree(ctxs);
		return -EINVAL;
	}

	/*
	 * batch keeps every item in flight, so it needs one work_struct per
	 * item; pingpong reuses a single one per producer.
	 */
	n_works = (bench_mode == MODE_BATCH) ? wq_items : 1;

	all_latencies = kvmalloc_array(total_items, sizeof(u64), GFP_KERNEL);
	if (!all_latencies) {
		kfree(tasks);
		kfree(ctxs);
		return -ENOMEM;
	}

	/* Allocate per-thread latency and work-item arrays */
	for (i = 0; i < n_threads; i++) {
		int w;

		ctxs[i].latencies = kvmalloc_array(wq_items, sizeof(u64),
						   GFP_KERNEL);
		ctxs[i].works = ctxs[i].latencies ?
			kvmalloc_array(n_works, sizeof(*ctxs[i].works),
				       GFP_KERNEL) : NULL;
		if (!ctxs[i].latencies || !ctxs[i].works) {
			kvfree(ctxs[i].works);
			kvfree(ctxs[i].latencies);
			while (--i >= 0) {
				kvfree(ctxs[i].works);
				kvfree(ctxs[i].latencies);
			}
			kvfree(all_latencies);
			kfree(tasks);
			kfree(ctxs);
			return -ENOMEM;
		}

		/* Back-pointer lets bench_work_fn() find its producer */
		for (w = 0; w < n_works; w++)
			ctxs[i].works[w].ctx = &ctxs[i];
		init_completion(&ctxs[i].work_done);
	}

	/*
	 * batch:    counted down by each work item as it executes.
	 * pingpong: counted down by each producer as it finishes its run.
	 */
	atomic_set(&run_remaining,
		   bench_mode == MODE_BATCH ? total_items : n_threads);
	reinit_completion(&all_done_comp);
	reinit_completion(&start_comp);

	/* Create kthreads, each bound to a different online CPU */
	i = 0;
	for_each_online_cpu(cpu) {
		if (i >= n_threads)
			break;

		ctxs[i].cpu = cpu;
		ctxs[i].items = wq_items;

		tasks[i] = kthread_create(bench_kthread_fn, &ctxs[i],
					  "wq_bench/%d", cpu);
		if (IS_ERR(tasks[i])) {
			ret = PTR_ERR(tasks[i]);
			pr_err("test_workqueue: failed to create kthread %d: %d\n",
			       i, ret);
			/* Unblock threads waiting on start_comp before stopping them */
			complete_all(&start_comp);
			while (--i >= 0)
				kthread_stop(tasks[i]);
			goto out_free;
		}

		kthread_bind(tasks[i], cpu);
		wake_up_process(tasks[i]);
		i++;
	}

	/* Start timing and release all threads */
	start = ktime_get();
	complete_all(&start_comp);

	/* Wait for every queued work item to execute, then stop the clock */
	wait_for_completion(&all_done_comp);
	end = ktime_get();
	elapsed_us = ktime_us_delta(end, start);

	/* Drain any remaining work before freeing the work_struct arrays */
	flush_workqueue(bench_wq);

	/* Ensure all kthreads have fully exited before module memory is freed */
	for (i = 0; i < n_threads; i++)
		kthread_stop(tasks[i]);

	/* Merge all per-thread latencies and sort for percentile calculation */
	j = 0;
	for (i = 0; i < n_threads; i++) {
		memcpy(&all_latencies[j], ctxs[i].latencies,
		       wq_items * sizeof(u64));
		j += wq_items;
	}

	sort(all_latencies, total_items, sizeof(u64), cmp_u64, NULL);

	pr_info("test_workqueue:   %-16s %llu items/sec\tp50=%llu\tp90=%llu\tp95=%llu ns\n",
		label,
		elapsed_us ? div_u64(total_items * 1000000ULL, elapsed_us) : 0,
		all_latencies[total_items * 50 / 100],
		all_latencies[total_items * 90 / 100],
		all_latencies[total_items * 95 / 100]);

	ret = 0;
out_free:
	for (i = 0; i < n_threads; i++) {
		kvfree(ctxs[i].works);
		kvfree(ctxs[i].latencies);
	}
	kvfree(all_latencies);
	kfree(tasks);
	kfree(ctxs);

	return ret;
}

static const char * const bench_scopes[] = {
	"cpu", "smt", "cache_shard", "cache", "numa", "system",
};

static int __init test_workqueue_init(void)
{
	int n_threads = min(nr_threads ?: num_online_cpus(), num_online_cpus());
	int i;

	if (wq_items <= 0) {
		pr_err("test_workqueue: wq_items must be > 0\n");
		return -EINVAL;
	}

	if (!strcmp(mode, "batch")) {
		bench_mode = MODE_BATCH;
	} else if (!strcmp(mode, "pingpong")) {
		bench_mode = MODE_PINGPONG;
	} else {
		pr_err("test_workqueue: invalid mode '%s' (use 'batch' or 'pingpong')\n",
		       mode);
		return -EINVAL;
	}

	bench_wq = alloc_workqueue(WQ_NAME, WQ_UNBOUND | WQ_SYSFS, 0);
	if (!bench_wq)
		return -ENOMEM;

	pr_info("test_workqueue: running %d threads, %d items/thread, mode=%s\n",
		n_threads, wq_items, mode);

	for (i = 0; i < ARRAY_SIZE(bench_scopes); i++)
		run_bench(n_threads, bench_scopes[i], bench_scopes[i]);

	destroy_workqueue(bench_wq);

	/* Return -EAGAIN so the module doesn't stay loaded after the benchmark */
	return -EAGAIN;
}

module_init(test_workqueue_init);
MODULE_AUTHOR("Breno Leitao <leitao@debian.org>");
MODULE_DESCRIPTION("Stress/performance benchmark for workqueue subsystem");
MODULE_LICENSE("GPL");
