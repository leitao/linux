// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2018, Breno Leitao, IBM Corp.
 * Licensed under GPLv2.
 *
 * Sigfuz(tm): This is a Powerpc signal fuzzer.
 */

#include <stdio.h>
#include <limits.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <pthread.h>
#include "utils.h"

/* Selftest defaults */
#define COUNT_MAX	2000		/* Number of interactions */
#define THREADS		8		/* Number of threads */

/* Arguments options */
#define ARG_MESS_WITH_TM_AT	0x1
#define ARG_MESS_WITH_TM_BEFORE	0x2
#define ARG_MESS_WITH_MSR_AT	0x4
#define ARG_FOREVER		0x10
#define ARG_COMPLETE		(ARG_MESS_WITH_TM_AT |		\
				ARG_MESS_WITH_TM_BEFORE |	\
				ARG_MESS_WITH_MSR_AT)

static int args;
static int nthread = THREADS;
static int count_max = COUNT_MAX;

/* checkpoint context */
static ucontext_t *tmp_uc;

/* Returns a 64-bits random number */
static inline long long r(void)
{
	long long n = rand();

	n = n<<32;
	n |= rand();

	return n;
}

/* Return true with 1/x probability */
static int one_in_chance(int x)
{
	return rand()%x == 0;
}

/* Change TM states */
static void mess_with_tm(void)
{
	/* Starts a transaction 33% of the time */
	if (one_in_chance(3)) {
		asm ("tbegin.	;"
		     "beq 8	;");

		/* And suspended half of them */
		if (one_in_chance(2))
			asm("tsuspend.	;");
	}

	/* Call 'tend' in 5% of the runs */
	if (one_in_chance(20))
		asm("tend.	;");
}

/* Signal handler that will be invoked with raise() */
static void trap_signal_handler(int signo, siginfo_t *si, void *uc)
{
	ucontext_t *ucp = uc;

	ucp->uc_link = tmp_uc;

	/*
	 * Set uc_link in three possible ways:
	 *  - Setting a single 'int' in the whole chunk
	 *  - Cloning ucp into uc_link
	 *  - Allocating a new memory chunk
	 */
	if (one_in_chance(3))
		memset(ucp->uc_link, rand(), sizeof(ucontext_t));
	else if (one_in_chance(2))
		memcpy(ucp->uc_link, uc, sizeof(ucontext_t));
	else if (one_in_chance(2)) {
		if (tmp_uc != NULL) {
			free(tmp_uc);
			tmp_uc = NULL;
		}
		tmp_uc = malloc(sizeof(ucontext_t));
		ucp->uc_link = tmp_uc;
		/* Trying to cause a major page fault at Kernel level */
		madvise(ucp->uc_link, sizeof(ucontext_t), MADV_DONTNEED);
	}

	if (args & ARG_MESS_WITH_MSR_AT) {
		/* Changing the checkpointed registers */
		if (one_in_chance(4)) {
			ucp->uc_link->uc_mcontext.gp_regs[PT_MSR] |= MSR_TS_S;
		} else {
			if (one_in_chance(2)) {
				ucp->uc_link->uc_mcontext.gp_regs[PT_MSR] |=
						 MSR_TS_T;
			} else if (one_in_chance(2)) {
				ucp->uc_link->uc_mcontext.gp_regs[PT_MSR] |=
						MSR_TS_T | MSR_TS_S;
			}
		}

		/* Checking the current register context */
		if (one_in_chance(2)) {
			ucp->uc_mcontext.gp_regs[PT_MSR] |= MSR_TS_S;
		} else if (one_in_chance(2)) {
			if (one_in_chance(2))
				ucp->uc_mcontext.gp_regs[PT_MSR] |=
					MSR_TS_T;
			else if (one_in_chance(2))
				ucp->uc_mcontext.gp_regs[PT_MSR] |=
					MSR_TS_T | MSR_TS_S;
		}

	}

	if (one_in_chance(20)) {
		/* Nested transaction start */
		if (one_in_chance(5))
			mess_with_tm();

		/* Return without changing any other context info */
		return;
	}

	if (one_in_chance(10))
		ucp->uc_mcontext.gp_regs[PT_MSR] = r();
	if (one_in_chance(10))
		ucp->uc_mcontext.gp_regs[PT_NIP] = r();
	if (one_in_chance(10))
		ucp->uc_link->uc_mcontext.gp_regs[PT_MSR] = r();
	if (one_in_chance(10))
		ucp->uc_link->uc_mcontext.gp_regs[PT_NIP] = r();

	ucp->uc_mcontext.gp_regs[PT_TRAP] = r();
	ucp->uc_mcontext.gp_regs[PT_DSISR] = r();
	ucp->uc_mcontext.gp_regs[PT_DAR] = r();
	ucp->uc_mcontext.gp_regs[PT_ORIG_R3] = r();
	ucp->uc_mcontext.gp_regs[PT_XER] = r();
	ucp->uc_mcontext.gp_regs[PT_RESULT] = r();
	ucp->uc_mcontext.gp_regs[PT_SOFTE] = r();
	ucp->uc_mcontext.gp_regs[PT_DSCR] = r();
	ucp->uc_mcontext.gp_regs[PT_CTR] = r();
	ucp->uc_mcontext.gp_regs[PT_LNK] = r();
	ucp->uc_mcontext.gp_regs[PT_CCR] = r();
	ucp->uc_mcontext.gp_regs[PT_REGS_COUNT] = r();

	ucp->uc_link->uc_mcontext.gp_regs[PT_TRAP] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_DSISR] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_DAR] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_ORIG_R3] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_XER] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_RESULT] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_SOFTE] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_DSCR] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_CTR] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_LNK] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_CCR] = r();
	ucp->uc_link->uc_mcontext.gp_regs[PT_REGS_COUNT] = r();

	if (args & ARG_MESS_WITH_TM_BEFORE) {
		if (one_in_chance(2))
			mess_with_tm();
	}
}

static void seg_signal_handler(int signo, siginfo_t *si, void *uc)
{
	/* Clear exit for process that segfaults */
	exit(0);
}


static void *sigfuz_test(void *thrid)
{
	struct sigaction trap_sa, seg_sa;
	int ret, i = 0;
	pid_t t;

	tmp_uc = malloc(sizeof(ucontext_t));

	/* Main signal handler */
	trap_sa.sa_flags = SA_SIGINFO;
	trap_sa.sa_sigaction = trap_signal_handler;

	/* SIGSEGV signal handler */
	seg_sa.sa_flags = SA_SIGINFO;
	seg_sa.sa_sigaction = seg_signal_handler;

	/* The signal handler will enable MSR_TS */
	sigaction(SIGUSR1, &trap_sa, NULL);

	/* If it does not crash, it will segfault, avoid it to retest */
	sigaction(SIGSEGV, &seg_sa, NULL);

	while (i < count_max) {
		t = fork();

		if (t == 0) {
			/* Once seed per process */
			srand(time(NULL) + getpid());
			if (args & ARG_MESS_WITH_TM_AT) {
				if (one_in_chance(2))
					mess_with_tm();
			}
			raise(SIGUSR1);
			exit(0);
		} else {
			waitpid(t, &ret, 0);
		}
		if (!(args & ARG_FOREVER))
			i++;
	}

	/* If not freed already, free now */
	if (tmp_uc != NULL) {
		free(tmp_uc);
		tmp_uc = NULL;
	}

	return NULL;
}


static int signal_fuzzer(void)
{
	int t, rc;
	pthread_t *threads;

	threads = malloc(nthread*sizeof(pthread_t));

	for (t = 0; t < nthread; t++) {
		rc = pthread_create(&threads[t], NULL, sigfuz_test,
				    (void *)&t);
		if (rc)
			perror("Thread creation error\n");
	}

	for (t = 0; t < nthread; t++) {
		rc = pthread_join(threads[t], NULL);
		if (rc)
			perror("Thread join error\n");
	}

	free(threads);

	return EXIT_SUCCESS;
}

static void show_help(char *name)
{
	printf("%s: Sigfuzzer for powerpc\n", name);
	printf("Usage:\n");
	printf("\t-b\t Mess with TM before raising a SIGUSR1 signal\n");
	printf("\t-a\t Mess with TM after raising a SIGUSR1 signal\n");
	printf("\t-m\t Mess with MSR[TS] bits at machine context\n");
	printf("\t-x\t Mess with everything above\n");
	printf("\t-f\t Run forever and does not exit\n");
	printf("\t-i\t Amount of interactions.	(Default = %d)\n", COUNT_MAX);
	printf("\t-t\t Amount of threads.	(Default = %d)\n", THREADS);
	exit(-1);
}

int main(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "bamxt:fi:h")) != -1) {
		if (opt == 'b') {
			printf("Mess with TM before signal\n");
			args |= ARG_MESS_WITH_TM_BEFORE;
		} else if (opt == 'a') {
			printf("Mess with TM at signal handler\n");
			args |= ARG_MESS_WITH_TM_AT;
		} else if (opt == 'm') {
			printf("Mess with MSR[TS] bits at machine context\n");
			args |= ARG_MESS_WITH_MSR_AT;
		} else if (opt == 'x') {
			printf("Running complete fuzzer\n");
			args |= ARG_COMPLETE;
		} else if (opt == 't') {
			nthread = atoi(optarg);
			printf("Threads = %d\n", nthread);
		} else if (opt == 'f') {
			args |= ARG_FOREVER;
			printf("Press ^C to stop\n");
		} else if (opt == 'i') {
			count_max = atoi(optarg);
			printf("Running for %d interactions\n", count_max);
		} else if (opt == 'h') {
			show_help(argv[0]);
		}

	}

	/* Default test suite */
	if (!args)
		args = ARG_COMPLETE;

	test_harness(signal_fuzzer, "signal_fuzzer");

}
