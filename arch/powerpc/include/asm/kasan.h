#ifndef __ASM_KASAN_H
#define __ASM_KASAN_H

#ifndef __ASSEMBLY__

#ifdef CONFIG_KASAN
/*
 * KASAN_SHADOW_START: We use a new region for kasan mapping
 * KASAN_SHADOW_END: KASAN_SHADOW_START + 1/8 of kernel virtual addresses.
 */
#define KASAN_SHADOW_START      (KASAN_REGION_ID << REGION_SHIFT)
#define KASAN_SHADOW_END        (KASAN_SHADOW_START + (1UL << (PGTABLE_RANGE - 3)))
/*
 * This value is used to map an address to the corresponding shadow
 * address by the following formula:
 *     shadow_addr = (address >> 3) + KASAN_SHADOW_OFFSET;
 *
 * This applies to the linear mapping.
 * Hence 0xc000000000000000 -> 0xe000000000000000
 * We use an internal zero page as the shadow address for vmall and vmemmap
 * region, since we don't track both of them now.
 *
 */
#define KASAN_SHADOW_KERNEL_OFFSET	((KASAN_REGION_ID << REGION_SHIFT) - \
					 (KERNEL_REGION_ID << (REGION_SHIFT - 3)))

extern unsigned char kasan_zero_page[PAGE_SIZE];
#define kasan_mem_to_shadow kasan_mem_to_shadow
static inline void *kasan_mem_to_shadow(const void *addr)
{
	unsigned long offset = 0;

	switch (REGION_ID(addr)) {
	case KERNEL_REGION_ID:
		offset = KASAN_SHADOW_KERNEL_OFFSET;
		break;
	default:
		return (void *)kasan_zero_page;
	}
	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
		+ offset;
}

#define kasan_shadow_to_mem kasan_shadow_to_mem
static inline void *kasan_shadow_to_mem(const void *shadow_addr)
{
	unsigned long offset = 0;

	switch (REGION_ID(shadow_addr)) {
	case KASAN_REGION_ID:
		offset = KASAN_SHADOW_KERNEL_OFFSET;
		break;
	default:
		pr_err("Shadow memory whose origin not found %p\n", shadow_addr);
		BUG();
	}
	return (void *)(((unsigned long)shadow_addr - offset)
			<< KASAN_SHADOW_SCALE_SHIFT);
}

#define kasan_enabled kasan_enabled
extern bool __kasan_enabled;
static inline bool kasan_enabled(void)
{
	return __kasan_enabled;
}

void kasan_init(void);
#else
static inline void kasan_init(void) { }
#endif

#endif
#endif
