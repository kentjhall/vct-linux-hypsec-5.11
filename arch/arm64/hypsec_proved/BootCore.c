#include "hypsec.h"

/*
 * BootCore
 */

u32 gen_vmid()
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

u32 alloc_shadow_ctxt()
{
    u32 ctxtid;
    acquire_lock_core();
    ctxtid = get_next_ctxt();
    if (ctxtid < MAX_CTXT_NUM) {
        set_next_ctxt(ctxtid + 1U);
        set_shadow_ctxt(ctxtid, DIRTY, INVALID64);
    }
    else {
        ctxtid = INVALID;
    }
    release_lock_core();
    return ctxtid;
}

u64 alloc_remap_addr(u64 pgnum)
{
    u64 remap;
    acquire_lock_core();
    remap = get_next_remap_ptr();
    set_next_remap_ptr(remap + pgnum * PAGE_SIZE);
    release_lock_core();
    return remap;
}

