#include "hypsec.h"
#include "MmioOps.h"

void __hyp_text mmap_smmu(u32 vmid, u64 ttbr, u64 addr, u64 pte)
{
	acquire_lock_pt(vmid);
	set_smmu_pt(vmid, addr, ttbr, pte);
	release_lock_pt(vmid);
}

u64 __hyp_text walk_smmu(u32 vmid, u64 ttbr, u64 addr)
{
	u64 pte;
	acquire_lock_pt(vmid);
	pte = walk_smmu_pt(vmid, addr, ttbr);
	release_lock_pt(vmid);
	return pte;
}

u32 __hyp_text check_smmu_pfn(u64 pfn, u32 vmid)
{
	u32 owner;
	owner = get_pfn_owner(pfn);
	if (owner != INVALID_MEM && owner && owner != vmid)
		return 0;

	return 1;
}

void __hyp_text handle_smmu_write(u32 hsr, u64 fault_ipa, u32 len, u32 index)
{
	u64 size = get_smmu_size(index);
	u64 val = 0;
	u32 ret;	
	u32 offset = fault_ipa & (size - 1);
	u32 cbndx = smmu_get_cbndx(index, offset);

	if (offset < (size >> 1)) {
		ret = handle_smmu_global_access(hsr, fault_ipa, 
						offset, true, index);
	} else {
		ret = handle_smmu_cb_access(hsr, fault_ipa, cbndx,
					    offset, true, index);
		if (ret == 2)
			val = get_smmu_cfg_hw_ttbr(cbndx, index);
	}

	if (ret)
		__handle_smmu_write(hsr, fault_ipa, len, val);
}

void __hyp_text handle_smmu_read(u32 hsr, u64 fault_ipa, u32 len, u32 index)
{
	u64 size = get_smmu_size(index);
	u32 offset = fault_ipa & (size - 1);
	u32 ret;
	u32 cbndx = smmu_get_cbndx(index, offset);

	if (offset < (size >> 1)) {
		ret = handle_smmu_global_access(hsr, fault_ipa,
						offset, true, index);
	} else {
		ret = handle_smmu_cb_access(hsr, fault_ipa, cbndx,
					    offset, true, index);
	}

	if (ret)
		__handle_smmu_read(hsr, fault_ipa, len);
}
