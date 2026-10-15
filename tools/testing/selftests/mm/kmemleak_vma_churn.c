// SPDX-License-Identifier: GPL-2.0
/*
 * Helper for ksft_kmemleak_vma_churn.sh: keep live VMAs whose only
 * reference is a maple tree slot that is rewritten all the time.
 *
 * Each worker builds thread stacks the way glibc does: map the whole stack
 * PROT_NONE, then mprotect() everything above the guard page. Each guard
 * page ends up in its own VMA that is never faulted in, with no anon_vma
 * and no file, so a slot in a maple tree node is the only pointer to it.
 * The worker then keeps mapping and unmapping a page next to every guard,
 * which replaces the node holding the guard with a new copy on each call.
 * One more process keeps a sliding window of files in the given directory,
 * so that each kmemleak scan has objects allocated while it runs, and
 * another one holds many single-page VMAs, so that each scan has a lot to
 * walk. Both stand in for the busy, large machines where the false positive
 * was seen.
 *
 * Prints "ready" once everything is set up, then runs until it is killed.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#define WORKERS		4
#define GUARDS		32
#define STACK_SIZE	(1024 * 1024)

static long page_size;

static void worker(int ready_fd)
{
	size_t gap = 64 * page_size;	/* room for churn below each guard */
	size_t slot = gap + page_size + STACK_SIZE;
	char *guard[GUARDS];
	char *base;
	int i;

	base = mmap(NULL, slot * GUARDS, PROT_NONE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (base == MAP_FAILED)
		goto fail;
	munmap(base, slot * GUARDS);

	for (i = 0; i < GUARDS; i++) {
		char *s = base + i * slot + gap;

		if (mmap(s, page_size + STACK_SIZE, PROT_NONE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK |
			 MAP_FIXED_NOREPLACE, -1, 0) != s)
			goto fail;
		if (mprotect(s + page_size, STACK_SIZE, PROT_READ | PROT_WRITE))
			goto fail;
		/* fault in the stack, never the guard */
		s[page_size] = 1;
		guard[i] = s;
	}
	if (write(ready_fd, "1", 1) != 1)
		exit(1);
	close(ready_fd);

	for (;;) {
		for (i = 0; i < GUARDS; i++) {
			void *p = mmap(guard[i] - 2 * page_size, page_size,
				       PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS |
				       MAP_FIXED_NOREPLACE, -1, 0);

			if (p != MAP_FAILED)
				munmap(p, page_size);
		}
		usleep(2000);
	}
fail:
	perror("worker");
	if (write(ready_fd, "0", 1) != 1)
		exit(1);
	exit(1);
}

static void storm(const char *dir, long files)
{
	char path[PATH_MAX];
	long i;
	int fd;

	for (i = 0; ; i++) {
		snprintf(path, sizeof(path), "%s/%ld", dir, i);
		fd = open(path, O_CREAT | O_WRONLY, 0600);
		if (fd < 0) {
			perror(path);
			exit(1);
		}
		close(fd);
		if (i >= files) {
			snprintf(path, sizeof(path), "%s/%ld", dir, i - files);
			unlink(path);
		}
	}
}

static void ballast(int ready_fd, long vmas)
{
	long i;

	/* alternate protections so that neighbours never merge */
	for (i = 0; i < vmas; i++) {
		if (mmap(NULL, page_size, i & 1 ? PROT_READ : PROT_NONE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED) {
			perror("ballast");
			if (write(ready_fd, "0", 1) != 1)
				exit(1);
			exit(1);
		}
	}
	if (write(ready_fd, "1", 1) != 1)
		exit(1);
	close(ready_fd);
	pause();
	exit(0);
}

int main(int argc, char **argv)
{
	long files, vmas;
	int fds[2], i;
	char c;

	if (argc != 4) {
		fprintf(stderr, "usage: %s <tmpfs dir> <files> <vmas>\n",
			argv[0]);
		return 2;
	}
	files = atol(argv[2]);
	vmas = atol(argv[3]);
	page_size = sysconf(_SC_PAGESIZE);
	if (pipe(fds))
		return 1;

	/* WORKERS workers, then the ballast, then the file storm */
	for (i = 0; i < WORKERS + 2; i++) {
		pid_t pid = fork();

		if (pid < 0)
			return 1;
		if (pid)
			continue;
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		close(fds[0]);
		if (i < WORKERS)
			worker(fds[1]);
		if (i == WORKERS)
			ballast(fds[1], vmas);
		close(fds[1]);
		storm(argv[1], files);
	}
	close(fds[1]);

	for (i = 0; i < WORKERS + 1; i++)
		if (read(fds[0], &c, 1) != 1 || c != '1')
			return 1;
	printf("ready\n");
	fflush(stdout);
	pause();
	return 0;
}
