#include "hypsec.h"

/*
 * MemoryOps
 */

void __hyp_text __clear_vm_stage2_range(u32 vmid, u64 start, u64 size)
{
    u32 poweron = get_vm_poweron(vmid);
    if (size == KVM_PHYS_SIZE && poweron == 0U) {
        u32 cnt = get_mem_region_cnt();
        u32 i = 0U;
        while (i < cnt)
        {
            u64 flag = get_mem_region_flag(i);
            if ((flag & MEMBLOCK_NOMAP) == 0UL)
            {
                u64 b = get_mem_region_base(i);
                u64 s = get_mem_region_size(i);
                u64 pfn = b / PAGE_SIZE;
                u64 num = s / PAGE_SIZE;
                while (num > 0UL)
                {
                    clear_phys_mem(pfn);
                    clear_vm_page(vmid, pfn);
                    pfn += 1UL;
                    num -= 1UL;
                }
            }
            i += 1U;
        }
    }
}

void __hyp_text prot_and_map_vm_s2pt(u32 vmid, u64 fault_addr, u64 new_pte, u32 level, u32 iabt)
{
    u64 target_addr = phys_page(new_pte);
    u64 target_pfn = target_addr / PAGE_SIZE;
    assign_pfn_to_vm(vmid, target_pfn);
    map_pfn_vm(vmid, fault_addr, new_pte, level, iabt);
}

void __hyp_text v_grant_stage2_sg_gpa(u32 vmid, u64 addr, u64 size)
{
    u64 len = size / PAGE_SIZE;
    while (len > 0UL)
    {
        u64 pte = walk_s2pt(vmid, addr);
        u32 level = get_level_s2pt(vmid, addr);
        u64 pte_pa = phys_page(pte);
        if (pte_pa != 0UL)
        {
            u64 pfn = pte_pa / PAGE_SIZE;
            if (level == 2U) {
                pfn += (pte_pa & PMD_PAGE_MASK) / PAGE_SIZE;
            }
            grant_vm_page(vmid, pfn);
        }
        addr += PAGE_SIZE;
        len -= 1UL;
    }
}

void __hyp_text v_revoke_stage2_sg_gpa(u32 vmid, u64 addr, u64 size)
{
    u64 len = size / PAGE_SIZE;
    while (len > 0UL)
    {
        u64 pte = walk_s2pt(vmid, addr);
        u32 level = get_level_s2pt(vmid, addr);
        u64 pte_pa = phys_page(pte);
        if (pte_pa != 0UL)
        {
            u64 pfn = pte_pa / PAGE_SIZE;
            if (level == 2U) {
                pfn += (pte_pa & PMD_PAGE_MASK) / PAGE_SIZE;
            }
            revoke_vm_page(vmid, pfn);
        }
        addr += PAGE_SIZE;
        len -= 1UL;
    }
}
