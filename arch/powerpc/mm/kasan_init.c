#define pr_fmt(fmt) "kasan: " fmt
#include <linux/kernel.h>
#include <linux/memblock.h>
#include <linux/kasan.h>

bool __kasan_enabled = false;
unsigned char kasan_zero_page[PAGE_SIZE] __page_aligned_bss;
void __init kasan_init(void)
{
	unsigned long k_start, k_end;
	struct memblock_region *reg;
	unsigned long page_size = 1 << mmu_psize_defs[mmu_vmemmap_psize].shift;


	for_each_memblock(memory, reg) {
		void *p;
		void *start = __va(reg->base);
		void *end = __va(reg->base + reg->size);
		int node = pfn_to_nid(virt_to_pfn(start));

		if (start >= end)
			break;

		k_start = (unsigned long)kasan_mem_to_shadow(start);
		k_end = (unsigned long)kasan_mem_to_shadow(end);
		for (; k_start < k_end; k_start += page_size) {
			p = vmemmap_alloc_block(page_size, node);
			if (!p) {
				pr_info("Disabled Kasan, for lack of free mem\n");
				/* Free the stuff or panic ? */
				return;
			}
			htab_bolt_mapping(k_start, k_start + page_size,
					  __pa(p), pgprot_val(PAGE_KERNEL),
					  mmu_vmemmap_psize, mmu_kernel_ssize);
		}
	}
	/*
	 * At this point kasan is fully initialized. Enable error messages
	 */
	init_task.kasan_depth = 0;
	__kasan_enabled = true;
	pr_info("Kernel address sanitizer initialized\n");
}
