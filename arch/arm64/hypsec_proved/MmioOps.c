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
	u32 vmid, power;
	acquire_lock_smmu();

	vmid = get_smmu_cfg_vmid(cbndx, index);
	power = get_vm_poweron(vmid);
	if (power == 0)
		set_smmu_cfg_vmid(cbndx, index, V_INVALID);
	else
		v_panic();
	release_lock_smmu();
}

void __hyp_text  __el2_alloc_smmu_pgd(u32 cbndx, u32 vmid, u32 index)
{
	u32 target_vmid, num_context_banks;

	acquire_lock_smmu();

	num_context_banks = get_smmu_num_context_banks(index);
	if (cbndx >= num_context_banks) {
		print_string("\rsmmu pgd alloc panic\n");
		v_panic();
	} else {
		target_vmid = get_smmu_cfg_vmid(cbndx, index);
		if (target_vmid == V_INVALID) {
			print_string("\ralloc_smmu_pgd\n");
			printhex_ul(vmid);
			set_smmu_cfg_vmid(cbndx, index, vmid);
			init_smmu_pt(cbndx, index);
		}
	}

	release_lock_smmu();
}

void __hyp_text smmu_assign_page(u32 cbndx, u32 index, u64 pfn, u64 gfn)
{
	u32 vmid;

	acquire_lock_smmu();
	vmid = get_smmu_cfg_vmid(cbndx, index);
	assign_smmu(vmid, pfn, gfn);
	release_lock_smmu();
}

/*
void __hyp_text __el2_arm_lpae_map(u64 iova, u64 paddr,
				   u64 prot, u32 cbndx, u32 index)
{
	u32 vmid;
	u64 pfn, pte, gfn;

	pfn = paddr / PAGE_SIZE;
	gfn = iova / PAGE_SIZE;

	acquire_lock_smmu();

	vmid = get_smmu_cfg_vmid(cbndx, index);
	
	acquire_lock_vm(vmid);
	if (get_vm_state(vmid) == READY) {
		assign_pfn_to_smmu(vmid, gfn, pfn);
		pte = smmu_init_pte(prot, paddr);
		set_smmu_pt(cbndx, index, iova, pte);
	}
	else {
		print_string("\rsmmu map: VM state is not ready\n");
		v_panic();
	}
	release_lock_vm(vmid);

	release_lock_smmu();
	return;
}

u64 __hyp_text __el2_arm_lpae_iova_to_phys(u64 iova, u32 cbndx, u32 index)
{
	u64 pte;

	acquire_lock_smmu();

	pte = walk_smmu_pt(cbndx, index, iova);
	release_lock_smmu();

	if (pte == 0UL)
		return pte;
	else
		return (phys_page(pte) | (iova & (PAGE_SIZE - 1)));
}
*/

void __hyp_text smmu_map_page(u32 cbndx, u32 index, u64 iova, u64 pte)
{
	u32 vmid;

	acquire_lock_smmu();
	vmid = get_smmu_cfg_vmid(cbndx, index);
	map_smmu(vmid, cbndx, index, iova, pte);
	release_lock_smmu();
}

u64 __hyp_text __el2_arm_lpae_iova_to_phys(u64 iova, u32 cbndx, u32 index)
{
	u64 pte, ret;

	pte = walk_spt(cbndx, index, iova);
	if (pte == 0)
		ret = 0;
	else
		ret = phys_page(pte) | (iova % PAGE_SIZE);

	return ret;
}

/* FIXME: apply changes in XP's upstream code */
void __hyp_text __el2_arm_lpae_clear(u64 iova, u32 cbndx, u32 index)
{
	u32 vmid;
	
	acquire_lock_smmu();
	vmid = get_smmu_cfg_vmid(cbndx, index);
	clear_smmu(vmid, cbndx, index, iova);
	release_lock_smmu();	
}
