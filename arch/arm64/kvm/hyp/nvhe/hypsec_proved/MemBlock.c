#include "hypsec.h"

/*
 * MemRegion
 */

//TODO: need to clean this up
u32 mem_region_search(u64 addr)
{
	u32 total_regions = get_mem_region_cnt();
	u32 i = 0U, res = INVALID_MEM;

	while (i < total_regions)
	{
		u64 base = get_mem_region_base(i);
		u64 size = get_mem_region_size(i);
		if (base <= addr && addr < base + size)
		{
			res = i;
		}
		i = i + 1U;
	}
	return res;
}
