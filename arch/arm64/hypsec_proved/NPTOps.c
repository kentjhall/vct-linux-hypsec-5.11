#include "hypsec.h"

/*
 * NPTOps
 */

void init_s2pt(u32 vmid)
{
    acquire_lock_pt(vmid);
    init_npt(vmid);
    release_lock_pt(vmid);
}

u64 get_vm_vttbr(u32 vmid)
{
    u64 vttbr;
    acquire_lock_pt(vmid);
    vttbr = get_pt_vttbr(vmid);
    release_lock_pt(vmid);
    return vttbr;
}

u32 get_level_s2pt(u32 vmid, u64 addr)
{
    u32 ret;
    acquire_lock_pt(vmid);
    ret = get_npt_level(vmid, addr);
    release_lock_pt(vmid);
    return ret;
}

u64 walk_s2pt(u32 vmid, u64 addr)
{
    u64 ret;
    acquire_lock_pt(vmid);
    ret = walk_npt(vmid, addr);
    release_lock_pt(vmid);
    return ret;
}

void mmap_s2pt(u32 vmid, u64 addr, u32 level, u64 pte)
{
    acquire_lock_pt(vmid);
    set_npt(vmid, addr, level, pte);
    release_lock_pt(vmid);
}

void set_pfn_host(u64 gfn, u64 num, u64 pfn, u64 prot)
{
    u32 level;
    acquire_lock_pt(HOSTVISOR);
    while (num > 0UL) {
        level = get_npt_level(HOSTVISOR, gfn * PAGE_SIZE);
        if (level != 0) {
            set_npt(HOSTVISOR, gfn * PAGE_SIZE, 3, pfn * PAGE_SIZE + prot);
        }
        if (pfn != 0) pfn++;
        gfn++;
        num--;
    }
    release_lock_pt(HOSTVISOR);
}

asm (
	".popsection\n\t"
);
