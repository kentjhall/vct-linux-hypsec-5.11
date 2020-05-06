#include "hypsec.h"
#include "MmioOps.h"

u64 __hyp_text emulate_mmio(u64 addr, u32 hsr)
{
	u64 ret;
	acquire_lock_smmu();
	ret = is_smmu_range(addr);
	if (ret != INVALID64) {
		handle_host_mmio(ret, hsr);
	}
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
			print_string("\ralloc smmu pgd\n");
			printhex_ul(index);
			printhex_ul(cbndx);
			set_smmu_cfg_vmid(cbndx, index, vmid);
			init_smmu_pt(cbndx, index);
			//set_smmu_cfg_hw_ttbr(cbndx, index, new_ttbr);
		}
	} else {
		print_string("\rsmmu pgd alloc panic\n");
		v_panic();
	}

	release_lock_smmu();
}

void __hyp_text __el2_arm_lpae_map(u64 iova, u64 paddr,
				   u64 prot, u32 cbndx, u32 index)
{
	u32 vmid;
	u64 pfn, pte, ttbr, gfn;

	pfn = paddr / PAGE_SIZE;
	gfn = iova / PAGE_SIZE;

	acquire_lock_smmu();

	vmid = get_smmu_cfg_vmid(cbndx, index);
	if (vmid == HOSTVISOR) {
		if (pfn == gfn) {
			//assign_pfn_to_smmu(vmid, gfn, pfn);
			//print_string("\rsmmu map host\n");
			//printhex_ul(iova);
			pte = smmu_init_pte(prot, paddr);
			set_smmu_pt(cbndx, index, iova, pte);
		}
	} else {
		//acquire_lock_vm(vmid);
		//if (get_vm_state(vmid) == READY) {
			//assign_pfn_to_smmu(vmid, gfn, pfn);
			//print_string("\rsmmu map vm\n");
			//printhex_ul(iova);
			pte = smmu_init_pte(prot, paddr);
			//printhex_ul(pte);
			set_smmu_pt(cbndx, index, iova, pte);
		//}
		//else {
		//	print_string("\rsmmu map: VM state is not ready\n");
	    	//	v_panic();
		//}
		//release_lock_vm(vmid);
	}

	release_lock_smmu();
	return;
}

u64 __hyp_text __el2_arm_lpae_iova_to_phys(u64 iova, u32 cbndx, u32 index)
{
	u64 pte;
	acquire_lock_smmu();
	//print_string("\rsmmu walk\n");
	//printhex_ul(iova);
	pte = walk_smmu_pt(cbndx, index, iova);
	release_lock_smmu();

	if (pte == 0UL)
		return pte;
	else
		return (phys_page(pte) | iova & (PAGE_SIZE - 1));
}

/* FIXME: apply changes in XP's upstream code */
void __hyp_text __el2_arm_lpae_clear(u64 iova, u32 cbndx, u32 index)
{
	acquire_lock_smmu();
	//print_string("\rsmmu clear vm\n");
	//printhex_ul(iova);
	set_smmu_pt(cbndx, index, iova, 0UL);
	release_lock_smmu();	
}
