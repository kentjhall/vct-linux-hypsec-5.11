#include "hypsec.h"

/*
 * PTAlloc
 */

u64 __hyp_text alloc_s2pt_pud(u32 vmid)
{
	u64 next = get_pud_next(vmid);
	u64 end = pud_pool_end(vmid);
	u64 ret = next;

	if (next + PAGE_SIZE <= end) {
		set_pud_next(vmid, 1);
	}
	else {
	        print_string("\rwe used all s2 pages\n");
		printhex_ul(vmid);
		ret = INVALID64;
	}

	return ret;
}

u64 __hyp_text alloc_s2pt_pmd(u32 vmid)
{
	u64 next = get_pmd_next(vmid);
	u64 end = pmd_pool_end(vmid);
	u64 ret = next;

	if (next + PAGE_SIZE <= end) {
		set_pmd_next(vmid, 1);
	}
	else {
	        print_string("\rwe used all s2 pages\n");
		printhex_ul(vmid);
		ret = INVALID64;
	}

	return ret;
}

u64 __hyp_text alloc_s2pt_pte(u32 vmid)
{
	u64 next = get_pte_next(vmid);
	u64 end = pte_pool_end(vmid);
	u64 ret = next;

	if (next + PAGE_SIZE <= end) {
		set_pte_next(vmid, 1);
	}
	else {
	        print_string("\rwe used all s2 pages\n");
		printhex_ul(vmid);
		ret = INVALID64;
	}

	return ret;
}
