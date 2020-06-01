#include "hypsec.h"

/*
 * PageIndex
 */

u64 __hyp_text get_s2_page_index(u64 addr)
{
	//u32 region_index = mem_region_search(addr);
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	u64 ret = INVALID64;
	u64 start = el2_data->phys_mem_start;
	u64 end = el2_data->phys_mem_size + start; 
	/*if (region_index != INVALID_MEM) {
		u64 page_index = get_mem_region_index(region_index);
		if (page_index != INVALID64) {
			u64 base = get_mem_region_base(region_index);
			ret = page_index + (addr - base) / PAGE_SIZE;
		}
	}*/
	if (addr >= start && addr < end) {
		u64 page_index = (addr - start) >> PAGE_SHIFT;
		ret = page_index;
	}

	return ret;
}
