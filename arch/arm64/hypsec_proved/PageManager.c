#include "hypsec.h"

/*
 * PageManager
 */

asm (
	".text \n\t"
	".pushsection \".hyp.text\", \"ax\" \n\t"
);

u32 get_pfn_owner(u64 pfn)
{
    u64 index = get_s2_page_index(pfn * PAGE_SIZE);
    u32 ret = INVALID;
    if (index != INVALID) {
	ret = get_s2_page_vmid(index);
    }
    return ret;
}

void set_pfn_owner(u64 pfn, u64 num, u32 vmid)
{
    while (num > 0U)
    {
        u64 index = get_s2_page_index(pfn * PAGE_SIZE);
        if (index != INVALID) set_s2_page_vmid(index, vmid);
        pfn += 1U;
        num -= 1U;
    }
}

u32 get_pfn_count(u64 pfn)
{
    u64 index = get_s2_page_index(pfn * PAGE_SIZE);
    u32 ret = INVALID;
    if (index != INVALID) {
	ret = get_s2_page_count(index);
    }
    return ret;
}

void set_pfn_count(u64 pfn, u32 count)
{
    u64 index = get_s2_page_index(pfn * PAGE_SIZE);
    if (index != INVALID) {
	set_s2_page_count(index, count);
    }
}

asm (
	".popsection\n\t"
);
