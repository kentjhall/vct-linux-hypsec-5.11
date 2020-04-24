#include "hypsec.h"

/*
 * PageManager
 */

u32 __hyp_text get_pfn_owner(u64 pfn)
{
	u64 index = get_s2_page_index(pfn * PAGE_SIZE);
	u32 ret = INVALID_MEM;
	if (index != INVALID_MEM) {
		ret = get_s2_page_vmid(index);
	}
	return ret;
}

void __hyp_text set_pfn_owner(u64 pfn, u32 vmid)
{
	u64 index = get_s2_page_index(pfn * PAGE_SIZE);
	if (index != INVALID_MEM)
		set_s2_page_vmid(index, vmid);
}

u32 __hyp_text get_pfn_count(u64 pfn)
{
	u64 index = get_s2_page_index(pfn * PAGE_SIZE);
	u32 ret = INVALID_MEM;
	if (index != INVALID_MEM) {
		ret = get_s2_page_count(index);
	}
	return ret;
}

void __hyp_text set_pfn_count(u64 pfn, u32 count)
{
	u64 index = get_s2_page_index(pfn * PAGE_SIZE);
	if (index != INVALID_MEM) {
		set_s2_page_count(index, count);
	}
}
