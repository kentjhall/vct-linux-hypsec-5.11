#include "hypsec.h"

/*
 * MmioSPTOps 
 */

void init_spt(u32 cbndx, u32 index)
{
	acquire_lock_spt();
	clear_smmu_pt(cbndx, index);
	release_lock_spt();
}

u64 walk_spt(u32 cbndx, u32 index, u64 addr)
{
	u64 ret;

	acquire_lock_spt();
	ret = walk_smmu_pt(cbndx, index, addr);
	release_lock_spt();
	return ret;
}

void map_spt(u32 cbndx, u32 index, u64 addr, u64 pte)
{
	acquire_lock_spt();
	set_smmu_pt(cbndx, index, addr, pte);
	release_lock_spt();
}

u64 unmap_spt(u32 cbndx, u32 index, u64 addr) 
{
	u64 ret;

	acquire_lock_spt();
	ret = walk_smmu_pt(cbndx, index, addr);
	if (ret != 0UL)
	{
		set_smmu_pt(cbndx, index, addr, 0UL);
	}
	release_lock_spt();
	return check64(ret);
}
