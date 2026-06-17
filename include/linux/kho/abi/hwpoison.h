/* SPDX-License-Identifier: GPL-2.0-only */

/**
 * DOC: HWPoison KHO ABI
 *
 * The "hwpoison" subtree stores the list of pages that the previous kernel
 * hard-offlined via memory_failure(). It is registered via kho_add_subtree()
 * with a plain &struct kho_hwpoison_metadata blob, keeping it independent
 * from the core KHO ABI so the format can evolve without affecting other
 * KHO consumers.
 *
 * The metadata header is a plain C struct rather than an FDT blob for
 * simplicity and direct field access. The variable-length PFN array is
 * carried separately via the preserved &struct kho_vmalloc referenced from
 * the header.
 *
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2026 Breno Leitao <leitao@debian.org>
 */

#ifndef _LINUX_KHO_ABI_HWPOISON_H
#define _LINUX_KHO_ABI_HWPOISON_H

#include <linux/kho/abi/kexec_handover.h>
#include <linux/types.h>

#define KHO_HWPOISON_METADATA_VERSION 1

/**
 * struct kho_hwpoison_metadata - hwpoison list passed between kernels
 * @version: ABI version of this struct (must be first field)
 * @_pad:    Reserved, must be zero
 * @count:   Number of valid PFNs in the @pfns array
 * @pfns:    Preserved vmalloc handle for a u64[] of PFNs (length @count)
 *
 * The producer keeps the header up to date with every poison or unpoison
 * event. The consumer in the next kernel re-runs memory_failure() on each
 * PFN before the buddy allocator can hand any of them out.
 */
struct kho_hwpoison_metadata {
	u32 version;
	u32 _pad;
	u64 count;
	struct kho_vmalloc pfns;
} __packed;

#define KHO_HWPOISON_NODE_NAME "hwpoison"

#endif /* _LINUX_KHO_ABI_HWPOISON_H */
