#include "hypsec.h"

/*
 * NPTOps
 */

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

void clear_pfn_host(u64 pfn)
{
	u64 pte;

	acquire_lock_pt(HOSTVISOR);

	pte = walk_npt(HOSTVISOR, pfn * PAGE_SIZE);
	if (pte != 0UL)
	{
		//TODO: why don't we set pte to 0?
		set_npt(HOSTVISOR, pfn * PAGE_SIZE, 3U, 0);
		kvm_tlb_flush_vmid_ipa_host(pfn * PAGE_SIZE);
        }

	release_lock_pt(HOSTVISOR);
}
