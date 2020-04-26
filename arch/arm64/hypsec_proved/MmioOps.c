#include "hypsec.h"
#include "MmioOps.h"

u64 __hyp_text emulate_mmio(u64 addr, u32 hsr)
{
	u64 ret;
	acquire_lock_smmu();
	ret = is_smmu_range(addr);
	if (ret == INVALID_MEM)
		return ret;
	else
		handle_host_mmio(addr, ret, hsr);
	release_lock_smmu();
	return ret;
}

/* TODO: how do we make sure it's ok to free now? */
void __hyp_text  __el2_free_smmu_pgd(u32 cbndx, u32 index)
{
	u32 vmid;
	acquire_lock_smmu();

	vmid = get_smmu_cfg_vmid(cbndx, index);
	if (HOSTVISOR < vmid && vmid < COREVISOR) {
		u32 power = get_vm_poweron(vmid);
		if (power == 1)
			v_panic();
	}
	set_smmu_cfg_vmid(cbndx, index, 0);
	set_smmu_cfg_ttbr(cbndx, index, 0);
	set_smmu_cfg_hw_ttbr(cbndx, index, 0);
	release_lock_smmu();

}

void __hyp_text  __el2_alloc_smmu_pgd(u32 cbndx, u32 vmid, u32 index)
{
	u32 target_vmid, num_context_banks;

	acquire_lock_smmu();

	num_context_banks = get_smmu_num_context_banks(index);
	if (cbndx < num_context_banks) {
		target_vmid = get_smmu_cfg_vmid(cbndx, index);
		if (target_vmid == 0) {
			set_smmu_cfg_vmid(cbndx, index, vmid);
			init_smmu_pt(cbndx, index);
			//set_smmu_cfg_hw_ttbr(cbndx, index, new_ttbr);
		}
	} else
		v_panic();

	release_lock_smmu();
}

void __hyp_text __el2_arm_lpae_map(u64 iova, u64 paddr,
				   u64 prot, u32 cbndx, u32 index)
{
	u32 vmid;
	u64 pfn, pte, ttbr;

	acquire_lock_smmu();

	vmid = get_smmu_cfg_vmid(cbndx, index);
	ttbr = get_smmu_cfg_hw_ttbr(cbndx, index);
	pfn = paddr / PAGE_SIZE;
	//assign_pfn_to_smmu(vmid, pfn);
	pte = smmu_init_pte(prot, paddr);
	set_smmu_pt(cbndx, index, iova, pte);
	
	release_lock_smmu();
	return;
}

u64 __hyp_text __el2_arm_lpae_iova_to_phys(u64 iova, u32 cbndx, u32 index)
{
	u64 pte;
	acquire_lock_smmu();
	pte = walk_smmu_pt(cbndx, index, iova);
	release_lock_smmu();
	return (phys_page(pte) | iova); 
}

void __hyp_text __el2_arm_lpae_clear(u64 iova, u32 cbndx, u32 index)
{
	acquire_lock_smmu();
	set_smmu_pt(cbndx, index, iova, 0UL);
	release_lock_smmu();	
}
