#include "hypsec.h"

/*
 * BootAux
 */

void __hyp_text v_unmap_image_from_host_s2pt(u32 vmid, u64 remap_addr, u64 num)
{
    while (num >= 0UL)
    {
        u64 pte = walk_s2pt(COREVISOR, remap_addr);
        u64 pa = phys_page(pte);
        if (pa == 0UL) v_panic();
        assign_pfn_to_vm(vmid, pa / PAGE_SIZE);
        remap_addr += PAGE_SIZE;
        num--;
    }
}

void __hyp_text v_load_image_to_shadow_s2pt(u32 vmid, u64 target_addr, u64 remap_addr, u64 num)
{
    while (num > 0UL)
    {
        u64 pte = walk_s2pt(COREVISOR, remap_addr);
        u64 pa = phys_page(pte);
        if (pa == 0UL) v_panic();
        map_pfn_vm(vmid, target_addr, pa | PTE_S2_RDWR, 3U, 1U);
        remap_addr += PAGE_SIZE;
        target_addr += PAGE_SIZE;
        num--;
    }
}
