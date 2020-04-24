#include "hypsec.h"

/*
 * NPTOps
 */

void __hyp_text init_s2pt(u32 vmid)
{
    acquire_lock_pt(vmid);
    init_npt(vmid);
    release_lock_pt(vmid);
}

u64 __hyp_text get_vm_vttbr(u32 vmid)
{
    u64 vttbr;
    acquire_lock_pt(vmid);
    vttbr = get_pt_vttbr(vmid);
    release_lock_pt(vmid);
    return vttbr;
}

u32 __hyp_text get_level_s2pt(u32 vmid, u64 addr)
{
    u32 ret;
    acquire_lock_pt(vmid);
    ret = get_npt_level(vmid, addr);
    release_lock_pt(vmid);
    return ret;
}

u64 __hyp_text walk_s2pt(u32 vmid, u64 addr)
{
    u64 ret;
    acquire_lock_pt(vmid);
    ret = walk_npt(vmid, addr);
    release_lock_pt(vmid);
    return ret;
}

void __hyp_text mmap_s2pt(u32 vmid, u64 addr, u32 level, u64 pte)
{
	acquire_lock_pt(vmid);
	set_npt(vmid, addr, level, pte);
	release_lock_pt(vmid);
}

extern void kvm_tlb_flush_vmid_ipa_host(phys_addr_t ipa);
void __hyp_text clear_pfn_host(u64 pfn)
{
	u32 level;

	acquire_lock_pt(HOSTVISOR);

	level = get_npt_level(HOSTVISOR, pfn * PAGE_SIZE);
        if (level != 0) {
		set_npt(HOSTVISOR, pfn * PAGE_SIZE, 3, pgprot_val(PAGE_GUEST));
		kvm_tlb_flush_vmid_ipa_host(pfn * PAGE_SIZE);
        }

	release_lock_pt(HOSTVISOR);
}
