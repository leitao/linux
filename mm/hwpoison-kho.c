// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Persist the hwpoison PFN list across kexec via KHO.
 *
 * On hard-offline events (memory_failure() succeeds) the PFN is appended
 * to a vmalloc array that is preserved across kexec by KHO. Early in the
 * next kernel the list is replayed via memory_failure() so the same pages
 * are taken off the buddy allocator before any allocator hands them out.
 */

#define pr_fmt(fmt) "hwpoison-kho: " fmt

#include <linux/init.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/kexec_handover.h>
#include <linux/libfdt.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/vmalloc.h>

#include "internal.h"

#define HWPOISON_KHO_FDT	"hwpoison"
#define HWPOISON_KHO_COMPAT	"hwpoison-v1"
#define HWPOISON_KHO_MIN_PFNS	512

struct hwpoison_kho {
	struct mutex lock; /* serializes all updates to the fields below */
	u64 *pfns;
	u64 count;
	u64 capacity;
	struct kho_vmalloc pfns_kho;
	void *fdt;
	bool published;
	bool replaying;
};

static struct hwpoison_kho hk = {
	.lock = __MUTEX_INITIALIZER(hk.lock),
};

static int hwpoison_kho_write_fdt(void)
{
	int err = 0;

	err |= fdt_create(hk.fdt, PAGE_SIZE);
	err |= fdt_finish_reservemap(hk.fdt);
	err |= fdt_begin_node(hk.fdt, "");
	err |= fdt_property_string(hk.fdt, "compatible", HWPOISON_KHO_COMPAT);
	err |= fdt_property(hk.fdt, "count", &hk.count, sizeof(hk.count));
	err |= fdt_property(hk.fdt, "pfns", &hk.pfns_kho, sizeof(hk.pfns_kho));
	err |= fdt_end_node(hk.fdt);
	err |= fdt_finish(hk.fdt);

	return err ? -ENOMEM : 0;
}

static int hwpoison_kho_publish(void)
{
	int err;

	if (hk.replaying)
		return 0;

	err = hwpoison_kho_write_fdt();
	if (err)
		return err;

	if (hk.published)
		return 0;

	err = kho_add_subtree(HWPOISON_KHO_FDT, hk.fdt, PAGE_SIZE);
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
		memcpy(new_pfns, hk.pfns, hk.count * sizeof(*hk.pfns));
		kho_unpreserve_vmalloc(&hk.pfns_kho);
		vfree(hk.pfns);
	}

	hk.pfns = new_pfns;
	hk.pfns_kho = new_kho;
	hk.capacity = new_cap;
	return 0;
}

static int hwpoison_kho_ensure_fdt(void)
{
	if (hk.fdt)
		return 0;

	hk.fdt = kho_alloc_preserve(PAGE_SIZE);
	if (IS_ERR(hk.fdt)) {
		int err = PTR_ERR(hk.fdt);

		hk.fdt = NULL;
		return err;
	}

	return 0;
}

void hwpoison_kho_record(unsigned long pfn)
{
	int err;

	if (!kho_is_enabled())
		return;

	guard(mutex)(&hk.lock);

	err = hwpoison_kho_ensure_fdt();
	if (err) {
		pr_warn_ratelimited("PFN %#lx not preserved: fdt alloc %d\n",
				    pfn, err);
		return;
	}

	if (hk.count + 1 > hk.capacity) {
		err = hwpoison_kho_grow(hk.count + 1);
		if (err) {
			pr_warn_ratelimited("PFN %#lx not preserved: grow %d\n",
					    pfn, err);
			return;
		}
	}

	hk.pfns[hk.count++] = pfn;

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

	if (!hk.pfns)
		return;

	for (i = 0; i < hk.count; i++) {
		if (hk.pfns[i] != pfn)
			continue;
		hk.pfns[i] = hk.pfns[--hk.count];
		hwpoison_kho_publish();
		return;
	}
}

static void __init hwpoison_kho_replay(const void *fdt)
{
	const struct kho_vmalloc *pfns_kho;
	const u64 *count_p;
	u64 count, i;
	int node, len;
	u64 *pfns;

	node = fdt_path_offset(fdt, "/");
	if (node < 0 ||
	    fdt_node_check_compatible(fdt, node, HWPOISON_KHO_COMPAT)) {
		pr_warn("incompatible hwpoison subtree, skipping\n");
		return;
	}

	count_p = fdt_getprop(fdt, node, "count", &len);
	if (!count_p || len != sizeof(*count_p))
		return;
	count = *count_p;

	pfns_kho = fdt_getprop(fdt, node, "pfns", &len);
	if (!pfns_kho || len != sizeof(*pfns_kho))
		return;

	pfns = kho_restore_vmalloc(pfns_kho);
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
	phys_addr_t fdt_phys;
	int err;

	if (!kho_is_enabled())
		return 0;

	err = kho_retrieve_subtree(HWPOISON_KHO_FDT, &fdt_phys, NULL);
	if (err == -ENOENT)
		return 0;
	if (err) {
		pr_warn("retrieve failed: %d\n", err);
		return 0;
	}

	hwpoison_kho_replay(phys_to_virt(fdt_phys));
	return 0;
}
late_initcall(hwpoison_kho_init);
