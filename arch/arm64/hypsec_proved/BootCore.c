#include "hypsec.h"

/*
 * BootCore
 */

asm (
	".text \n\t"
	".pushsection \".hyp.text\", \"ax\" \n\t"
);

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

u64 alloc_remap_addr(u64 pgnum)
{
    u64 remap;
    acquire_lock_core();
    remap = get_next_remap_ptr();
    set_next_remap_ptr(remap + pgnum * PAGE_SIZE);
    release_lock_core();
    return remap;
}

asm (
	".popsection\n\t"
);
