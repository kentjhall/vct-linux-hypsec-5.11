#include "hypsec.h"

/*
 * MemoryOps
 */

void __hyp_text clear_vm_range(u32 vmid, u64 pfn, u64 num)
{
	while (num > 0UL)
	{
		clear_vm_page(vmid, pfn);
		pfn += 1UL;
		num -= 1UL;
	}
}

#define PMD_PAGE_NUM	512
void __hyp_text prot_and_map_vm_s2pt(u32 vmid, u64 addr, u64 pte, u32 level)
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

void __hyp_text grant_stage2_sg_gpa(u32 vmid, u64 addr, u64 size)
{
	u32 level;
	u64 pte, pte_pa, pfn, len;
	//u64 len = (size & (PAGE_SIZE - 1) ? 1 : 0);
	//if (size >> PAGE_SHIFT)
	//	len += size >> PAGE_SHIFT;

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
				//pfn += (addr & (PMD_SIZE - 1)) / PAGE_SIZE;
				pfn += addr / PAGE_SIZE & 511;
			}
			grant_vm_page(vmid, pfn);
		}
		addr += PAGE_SIZE;
		len -= 1UL;
	}
}

void __hyp_text revoke_stage2_sg_gpa(u32 vmid, u64 addr, u64 size)
{
	u32 level;
	u64 pte, pte_pa, pfn, len;
	//u64 len = (size & (PAGE_SIZE - 1) ? 1 : 0);
	//if (size >> PAGE_SHIFT)
	//	len += size >> PAGE_SHIFT;

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
				//pfn += (addr & (PMD_SIZE - 1)) / PAGE_SIZE;
				pfn += addr / PAGE_SIZE & 511;
			}
			revoke_vm_page(vmid, pfn);
		}
		addr += PAGE_SIZE;
		len -= 1UL;
	}
}

//TODO: FIXME: Xupeng does not have this
void __hyp_text __clear_vm_range(u32 vmid, u64 start, u64 size)
{
	u64 pfn = start >> PAGE_SHIFT;
	u64 num = size / PAGE_SIZE;
	while (num > 0UL)
	{
		clear_vm_page(vmid, pfn);
		pfn += 1UL;
		num -= 1UL;
	}
}

//TODO: FIXME: Xupeng does not have this
void __hyp_text __clear_vm_stage2_range(u32 vmid, u64 start, u64 size)
{
	u32 poweron = get_vm_poweron(vmid);
	if (size == KVM_PHYS_SIZE && poweron == 0U)
	{
		u32 n = get_mem_region_cnt(), i = 0U;
		while (i < n)
		{
			u64 base = get_mem_region_base(i);
			u64 sz = get_mem_region_size(i);
			u64 flags = get_mem_region_flag(i);
			if ((flags & MEMBLOCK_NOMAP) == 0)
			{
				__clear_vm_range(vmid, base, sz);
			}

			i++;
		}
	}
}
