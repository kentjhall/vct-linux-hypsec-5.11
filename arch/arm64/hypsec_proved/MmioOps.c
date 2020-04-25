#include "hypsec.h"
#include "MmioOps.h"

u32 __hyp_text emulate_mmio(u64 addr, u32 hsr)
{
	u32 ret;
	ret = is_smmu_range(addr);
	if (ret == INVALID_MEM)
		return ret;
	else
		handle_host_mmio(addr, ret, hsr);
	return ret;
}

/* TODO: how do we make sure it's ok to free now? */
void __hyp_text  __el2_free_smmu_pgd(u32 cbndx, u32 index)
{
	set_smmu_cfg_vmid(cbndx, index, 0);
	set_smmu_cfg_ttbr(cbndx, index, 0);
	set_smmu_cfg_hw_ttbr(cbndx, index, 0);
}

void __hyp_text  __el2_alloc_smmu_pgd(u32 cbndx, u32 vmid, u32 index)
{
	u32 target_vmid, num_context_banks;
	u64 new_ttbr;

	if (vmid >= EL2_MAX_VMID)
		__hyp_panic();
	
	/* TODO: replace the following */
	num_context_banks = get_smmu_num_context_banks(index);
	if (cbndx >= num_context_banks) {
		print_string("\r__el2_alloc_smmu_pgd: invalid cbndx\n");
		return;
	}

	/* TODO: replace the following with smmu specific bank */
	target_vmid = get_smmu_cfg_vmid(cbndx, index);
	if (!target_vmid) {
		set_smmu_cfg_vmid(cbndx, index, vmid);
	}

	/* Allocate a new hw ttbr */
	//new_ttbr = (u64)alloc_stage2_page(1);
	new_ttbr = (u64)init_smmu_pt(vmid);
	set_smmu_cfg_hw_ttbr(cbndx, index, new_ttbr);
}

void __hyp_text __el2_arm_lpae_map(u64 iova, u64 paddr,
				   u32 size, u64 prot, u32 cbndx, u32 index)
{
	u64 s = 0;
	u32 vmid;
	u64 pfn, pte, ioaddr, addr, ttbr;

	vmid = get_smmu_cfg_vmid(cbndx, index);
	ttbr = get_smmu_cfg_hw_ttbr(cbndx, index);

	acquire_lock_s2page();
	while (s < size) {	
		addr = paddr + s;
		ioaddr = iova + s;
		pfn = addr >> PAGE_SHIFT;
		if (!check_smmu_pfn(pfn, vmid))
			v_panic();
		
		pte = smmu_init_pte(prot, addr);
		mmap_smmu(vmid, ttbr, ioaddr, pte);

		s += PAGE_SIZE;
	}
	release_lock_s2page();
	return;
}

u64 __hyp_text __el2_arm_lpae_iova_to_phys(u64 iova, u32 cbndx, u32 index)
{
	u64 ttbr = get_smmu_cfg_hw_ttbr(cbndx, index);
	u64 vmid = get_smmu_cfg_vmid(cbndx, index);
	u64 pte = walk_smmu(vmid, ttbr, iova);
	return (phys_page(pte) | iova); 
}

void __hyp_text __el2_arm_lpae_clear(u64 iova, u32 size, u64 prot, u32 cbndx, u32 index)
{
	unsigned long s = 0;
	int vmid;
	u64 pte, ioaddr, ttbr;

	vmid = get_smmu_cfg_vmid(cbndx, index);
	ttbr = get_smmu_cfg_hw_ttbr(cbndx, index);

	while (s < size) {	
		ioaddr = iova + s;
		pte = smmu_init_pte(prot, 0);
		mmap_smmu(vmid, ttbr, ioaddr, pte);

		s += PAGE_SIZE;
	}
	return;
}
