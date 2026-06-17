// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Persist the hwpoison PFN list across kexec via KHO.
 *
 * On hard-offline events the PFN is appended to a vmalloc array that is
 * preserved across kexec by KHO. The metadata header that describes the
 * array is itself a KHO-preserved page registered as the "hwpoison"
 * subtree, following the same plain-struct ABI pattern as kexec-metadata.
 *
 * The next kernel finds the metadata, reads the vmalloc handle out of it,
 * and re-runs memory_failure() for each PFN before the buddy allocator
 * can hand any of them out.
 */

#define pr_fmt(fmt) "hwpoison-kho: " fmt

#include <linux/init.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/hwpoison.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/vmalloc.h>

#include "internal.h"

#define HWPOISON_KHO_MIN_PFNS	512

struct hwpoison_kho {
	struct mutex lock; /* serializes all updates to the fields below */
	u64 *pfns;
	u64 capacity;
	struct kho_hwpoison_metadata *hdr;
	bool published;
	bool replaying;
};

static struct hwpoison_kho hk = {
	.lock = __MUTEX_INITIALIZER(hk.lock),
};

static int hwpoison_kho_publish(void)
{
	int err;

	if (hk.replaying || hk.published)
		return 0;

	err = kho_add_subtree(KHO_HWPOISON_NODE_NAME, hk.hdr, sizeof(*hk.hdr));
	if (err)
		return err;

	hk.published = true;
	return 0;
}

static int hwpoison_kho_grow(u64 want)
{
	u64 new_cap = hk.capacity ? hk.capacity : HWPOISON_KHO_MIN_PFNS;
	struct kho_vmalloc new_kho;
	u64 *new_pfns;
	int err;

	while (new_cap < want)
		new_cap *= 2;

	new_pfns = vmalloc_array(new_cap, sizeof(*new_pfns));
	if (!new_pfns)
		return -ENOMEM;

	err = kho_preserve_vmalloc(new_pfns, &new_kho);
	if (err) {
		vfree(new_pfns);
		return err;
	}

	if (hk.pfns) {
		memcpy(new_pfns, hk.pfns, hk.hdr->count * sizeof(*hk.pfns));
		kho_unpreserve_vmalloc(&hk.hdr->pfns);
		vfree(hk.pfns);
	}

	hk.pfns = new_pfns;
	hk.hdr->pfns = new_kho;
	hk.capacity = new_cap;
	return 0;
}

static int hwpoison_kho_ensure_hdr(void)
{
	if (hk.hdr)
		return 0;

	hk.hdr = kho_alloc_preserve(sizeof(*hk.hdr));
	if (IS_ERR(hk.hdr)) {
		int err = PTR_ERR(hk.hdr);

		hk.hdr = NULL;
		return err;
	}

	hk.hdr->version = KHO_HWPOISON_METADATA_VERSION;
	return 0;
}

void hwpoison_kho_record(unsigned long pfn)
{
	int err;

	if (!kho_is_enabled())
		return;

	guard(mutex)(&hk.lock);

	err = hwpoison_kho_ensure_hdr();
	if (err) {
		pr_warn_ratelimited("PFN %#lx not preserved: hdr alloc %d\n",
				    pfn, err);
		return;
	}

	if (hk.hdr->count + 1 > hk.capacity) {
		err = hwpoison_kho_grow(hk.hdr->count + 1);
		if (err) {
			pr_warn_ratelimited("PFN %#lx not preserved: grow %d\n",
					    pfn, err);
			return;
		}
	}

	hk.pfns[hk.hdr->count++] = pfn;

	err = hwpoison_kho_publish();
	if (err)
		pr_warn_ratelimited("PFN %#lx not preserved: publish %d\n",
				    pfn, err);
}

void hwpoison_kho_unrecord(unsigned long pfn)
{
	u64 i;

	if (!kho_is_enabled())
		return;

	guard(mutex)(&hk.lock);

	if (!hk.pfns || !hk.hdr)
		return;

	for (i = 0; i < hk.hdr->count; i++) {
		if (hk.pfns[i] != pfn)
			continue;
		hk.pfns[i] = hk.pfns[--hk.hdr->count];
		return;
	}
}

static void __init hwpoison_kho_replay(const struct kho_hwpoison_metadata *src)
{
	u64 count = src->count;
	u64 *pfns, i;

	pfns = kho_restore_vmalloc(&src->pfns);
	if (!pfns)
		return;

	pr_info("re-poisoning %llu pages from previous kernel\n", count);

	scoped_guard(mutex, &hk.lock)
		hk.replaying = true;

	for (i = 0; i < count; i++) {
		int err = memory_failure(pfns[i], 0);

		if (err && err != -EHWPOISON)
			pr_warn("re-poison PFN %#llx failed: %d\n",
				pfns[i], err);
	}

	scoped_guard(mutex, &hk.lock) {
		hk.replaying = false;
		hwpoison_kho_publish();
	}

	vfree(pfns);
}

static int __init hwpoison_kho_init(void)
{
	const struct kho_hwpoison_metadata *src;
	phys_addr_t phys;
	size_t size;
	int err;

	if (!kho_is_enabled())
		return 0;

	err = kho_retrieve_subtree(KHO_HWPOISON_NODE_NAME, &phys, &size);
	if (err == -ENOENT)
		return 0;
	if (err) {
		pr_warn("retrieve failed: %d\n", err);
		return 0;
	}

	if (size < sizeof(u32)) {
		pr_warn("blob too small (%zu bytes)\n", size);
		return 0;
	}

	src = phys_to_virt(phys);
	if (src->version != KHO_HWPOISON_METADATA_VERSION) {
		pr_warn("metadata version %u not supported (expected %u)\n",
			src->version, KHO_HWPOISON_METADATA_VERSION);
		return 0;
	}
	if (size < sizeof(*src)) {
		pr_warn("blob too small for v%u (%zu < %zu)\n",
			src->version, size, sizeof(*src));
		return 0;
	}

	hwpoison_kho_replay(src);
	return 0;
}
late_initcall(hwpoison_kho_init);
