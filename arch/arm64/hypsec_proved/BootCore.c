#include "hypsec.h"

/*
 * BootCore
 */

u32 __hyp_text gen_vmid()
{
    u32 vmid;
    acquire_lock_core();
    vmid = get_next_vmid();
    if (vmid < MAX_VM_NUM) {
        set_next_vmid(vmid + 1U);
    }
    else {
        vmid = INVALID;
    }
    release_lock_core();
    return vmid;
}

u64 __hyp_text alloc_remap_addr(u64 pgnum)
{
    u64 remap;
    acquire_lock_core();
    remap = get_next_remap_ptr();
    set_next_remap_ptr(remap + pgnum * PAGE_SIZE);
    remap += EL2_REMAP_START;
    release_lock_core();
    return remap;
}
