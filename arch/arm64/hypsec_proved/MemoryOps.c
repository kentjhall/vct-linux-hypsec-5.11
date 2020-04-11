#include "hypsec.h"

/*
 * MemoryOps
 */

void __hyp_text __clear_vm_range(u32 vmid, u64 start, u64 size)
{
	u64 pfn = start >> PAGE_SHIFT;
	u64 num = size / PAGE_SIZE;
	while (num > 0UL)  {
		clear_vm_page(vmid, pfn);
		pfn += 1UL;
		num -= 1UL;
	}
}

void __hyp_text __clear_vm_stage2_range(u32 vmid, u64 start, u64 size)
{
	u32 poweron = get_vm_poweron(vmid);
	if (size == KVM_PHYS_SIZE && poweron == 0U) {
		u32 n = get_mem_region_cnt(), i = 0U;
		while (i < n) {
			u64 base = get_mem_region_base(i);
			u64 sz = get_mem_region_size(i);
			__clear_vm_range(vmid, base, sz);
			i++;
		}
	}
}

#define PMD_PAGE_NUM	512
void __hyp_text prot_and_map_vm_s2pt(u32 vmid, u64 fault_addr, u64 new_pte, u32 level, u32 iabt)
{
	u64 target_addr = phys_page(new_pte);
	u64 target_pfn = target_addr / PAGE_SIZE;
	u32 ret;

	if (new_pte == 0)
		return;

	if (level == 2) {
		u64 target_addr_off = fault_addr & (PMD_SIZE - 1);
		u64 apfn = target_pfn + (target_addr_off >> PAGE_SHIFT);
		ret = assign_pfn_to_vm(vmid, target_pfn, apfn, PMD_PAGE_NUM);
                /* partially overlap */
		if (ret == 1) {
			new_pte += target_addr_off;
			level = 3;
			ret = 0;
		}
	} else {
		ret = assign_pfn_to_vm(vmid, target_pfn, target_pfn, 1);
	}

	if (!ret)
		map_pfn_vm(vmid, fault_addr, new_pte, level, iabt);
}

void __hyp_text v_grant_stage2_sg_gpa(u32 vmid, u64 addr, u64 size)
{
    u64 len = (size & (PAGE_SIZE - 1) ? 1 : 0);
    if (size >> PAGE_SHIFT)
	len += size >> PAGE_SHIFT;

    while (len > 0UL)
    {
        u64 pte = walk_s2pt(vmid, addr);
	u32 level = 0;
        u64 pte_pa = phys_page(pte);
	if (pte & PMD_MARK)
		level = 2;
	else if (pte & PTE_MARK)
		level = 3;

        if (pte_pa != 0UL)
        {
            u64 pfn = pte_pa / PAGE_SIZE;
            if (level == 2U) {
                pfn += (addr & (PMD_SIZE - 1)) / PAGE_SIZE;
            }
            grant_vm_page(vmid, pfn);
        }
        addr += PAGE_SIZE;
        len -= 1UL;
    }
}

void __hyp_text v_revoke_stage2_sg_gpa(u32 vmid, u64 addr, u64 size)
{
    u64 len = (size & (PAGE_SIZE - 1) ? 1 : 0);
    if (size >> PAGE_SHIFT)
	len += size >> PAGE_SHIFT;

    while (len > 0UL)
    {
        u64 pte = walk_s2pt(vmid, addr);
	u32 level = 0;
        u64 pte_pa = phys_page(pte);
	if (pte & PMD_MARK)
		level = 2;
	else if (pte & PTE_MARK)
		level = 3;
        if (pte_pa != 0UL)
        {
            u64 pfn = pte_pa / PAGE_SIZE;
            if (level == 2U) {
                pfn += (addr & (PMD_SIZE - 1)) / PAGE_SIZE;
            }
            revoke_vm_page(vmid, pfn);
        }
        addr += PAGE_SIZE;
        len -= 1UL;
    }
}
