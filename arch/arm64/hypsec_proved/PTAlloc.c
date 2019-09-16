#include "hypsec.h"

/*
 * PTAlloc
 */

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
