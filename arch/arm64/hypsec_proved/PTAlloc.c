#include "hypsec.h"

/*
 * PTAlloc
 */

asm (
	".text \n\t"
	".pushsection \".hyp.text\", \"ax\" \n\t"
);

u64 alloc_s2pt_page(u32 vmid)
{
    u64 next = get_pt_next(vmid);
    u64 end = pool_end(vmid);
    u64 ret = next;

    if (next + PAGE_SIZE <= end) {
        set_pt_next(vmid, next + PAGE_SIZE);
    }
    else {
	ret = INVALID64;
    }
    return ret;
}

asm (
	".popsection\n\t"
);
