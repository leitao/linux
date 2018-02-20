/*
 * Copyright 2018, Cyril Bur, IBM Corp.
 * Licensed under GPLv2.
 *
 * This test uses a signal handler to make a thread go from
 * transactional state to nothing state. In practice userspace, why
 * would userspace ever do this? In theory, they can.
 */

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "utils.h"
#include "tm.h"

static bool passed;

static void signal_usr1(int signum, siginfo_t *info, void *uc)
{
	ucontext_t *ucp = uc;
	struct pt_regs *regs = ucp->uc_mcontext.regs;

	passed = true;

	/* I really hope I got that right, we wan't to clear both the MSR_TS bits */
	regs->msr &= ~(3ULL << 33);
	/* Set CR0 to 0b0010 */
	regs->ccr &= ~(0xDULL << 28);
}

int test_drop(void)
{
	struct sigaction act;

	SKIP_IF(!have_htm());

	act.sa_sigaction = signal_usr1;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_SIGINFO;
	if (sigaction(SIGUSR1, &act, NULL) < 0) {
		perror("sigaction sigusr1");
		exit(1);
	}


	asm __volatile__(
		"tbegin.;"
		"beq    1f; "
		"tsuspend.;"
		"1: ;"
		: : : "memory", "cr0");

	if (!passed && !tcheck_transactional()) {
		fprintf(stderr, "Not in suspended state: 0x%1x\n", tcheck());
		exit(1);
	}

	kill(getpid(), SIGUSR1);

	/* If we reach here, we've passed.  Otherwise we've probably crashed
	 * the kernel */

	return 0;
}

int main(int argc, char *argv[])
{
	return test_harness(test_drop, "tm_signal_drop_transaction");
}
