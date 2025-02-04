#include "hypsec.h"

/*
 * MemoryOps
 */

void clear_vm_range(u32 vmid, u64 pfn, u64 num)
{
	while (num > 0UL)
	{
		clear_vm_page(vmid, pfn);
		pfn += 1UL;
		num -= 1UL;
	}
}

void prot_and_map_vm_s2pt(u32 vmid, u64 addr, u64 pte, u32 level)
{
	u64 pfn, gfn, num, target_addr;

	target_addr = phys_page(pte);
	pfn = target_addr / PAGE_SIZE;
	gfn = addr / PAGE_SIZE;

	//TODO: Xupeng does not have this, shall we?
	if (pte == 0)
	{
		return;
	}

	if (level == 2U)
	{
		/* gfn is aligned to 2MB size */
		gfn = gfn / PTRS_PER_PMD * PTRS_PER_PMD;
		num = PMD_PAGE_NUM;
		while (num > 0UL)
		{
			assign_pfn_to_vm(vmid, gfn, pfn);
			gfn += 1UL;
			pfn += 1UL;
			num -= 1UL;
		}
	}
	else
	{
		assign_pfn_to_vm(vmid, gfn, pfn);
		level = 3U;
	}

	map_pfn_vm(vmid, addr, pte, level);
}

void grant_stage2_sg_gpa(u32 vmid, u64 addr, u64 size)
{
	u32 level;
	u64 pte, pte_pa, pfn, len;

	len = (size + 4095) / PAGE_SIZE;
	while (len > 0UL)
	{
		pte = walk_s2pt(vmid, addr);
		level = 0;
		pte_pa = phys_page(pte);
		//TODO: FIXME: Xupeng did "level = get_level_s2pt(vmid, addr);"
		if (pte & PMD_MARK)
		{
			level = 2;
		}
		else if (pte & PTE_MARK)
		{
			level = 3;
		}

		if (pte_pa != 0UL)
		{
			pfn = pte_pa / PAGE_SIZE;
			if (level == 2U)
			{
				pfn += addr / PAGE_SIZE & 511;
			}
			grant_vm_page(vmid, pfn);
		}
		addr += PAGE_SIZE;
		len -= 1UL;
	}
}

void revoke_stage2_sg_gpa(u32 vmid, u64 addr, u64 size)
{
	u32 level;
	u64 pte, pte_pa, pfn, len;

	len = (size + 4095) / PAGE_SIZE;
	while (len > 0UL)
	{
		pte = walk_s2pt(vmid, addr);
		level = 0;
		pte_pa = phys_page(pte);
		//TODO: FIXME: Xupeng did "level = get_level_s2pt(vmid, addr);"
		if (pte & PMD_MARK)
		{
			level = 2;
		}
		else if (pte & PTE_MARK)
		{
			level = 3;
		}

		if (pte_pa != 0UL)
		{
			pfn = pte_pa / PAGE_SIZE;
			if (level == 2U)
			{
				pfn += addr / PAGE_SIZE & 511;
			}
			revoke_vm_page(vmid, pfn);
		}
		addr += PAGE_SIZE;
		len -= 1UL;
	}
}
