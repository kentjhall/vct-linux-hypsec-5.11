#include "hypsec.h"

/*
 * BootAux
 */

void __hyp_text v_unmap_image_from_host_s2pt(u32 vmid, u64 remap_addr, u64 num)
{
    while (num > 0UL)
    {
        u64 pte = walk_s2pt(COREVISOR, remap_addr);
        u64 pa = phys_page(pte);
        if (pa == 0UL) v_panic();
        assign_pfn_to_vm(vmid, pa / PAGE_SIZE, pa / PAGE_SIZE, 1);
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
        map_pfn_vm(vmid, target_addr, pa, 3U);
        remap_addr += PAGE_SIZE;
        target_addr += PAGE_SIZE;
        num--;
    }
}

void __hyp_text unmap_and_load_vm_image(u32 vmid, u64 target_addr, u64 remap_addr, u64 num)
{
	u32 ret;

	while (num > 0UL)
	{
		u64 pte = walk_s2pt(COREVISOR, remap_addr);
		u64 pa = phys_page(pte);
		if (pa == 0UL) {
			v_panic();
		} else {
			ret = assign_pfn_to_vm(vmid, pa / PAGE_SIZE, pa / PAGE_SIZE, 1);
			if (ret == 0UL)
				map_pfn_vm(vmid, target_addr, pa, 3U);
		}
		remap_addr += PAGE_SIZE;
		target_addr += PAGE_SIZE;
		num--;
	}
}
