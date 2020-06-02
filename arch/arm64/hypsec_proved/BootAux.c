#include "hypsec.h"

/*
 * BootAux
 */

void __hyp_text unmap_and_load_vm_image(u32 vmid, u64 target_addr, u64 remap_addr, u64 num)
{
	u32 ret;
	u64 gfn; 
	u64 start = (target_addr & ~(PMD_SIZE - 1));
	u64 end = target_addr + num * PAGE_SIZE;
	u64 mb_num = (end - start + (PMD_SIZE - 1)) / PMD_SIZE;

	while (mb_num > 0UL) {
		u64 pte = walk_s2pt(COREVISOR, remap_addr);
		u64 pa = phys_page(pte);
		u64 pfn = (pa & ~(PMD_SIZE - 1)) / PAGE_SIZE;
		gfn = start >> PAGE_SHIFT;
		if (pfn == 0UL) {
			v_panic();
		} else {
			//TODO: call to prot_and_map_vm_s2pt
			//ret = assign_pfn_to_vm(vmid, gfn, pfn, 512);
			//if (ret == 0UL)
			//	map_pfn_vm(vmid, start, pa, 2U);
			prot_and_map_vm_s2pt(vmid, gfn * PAGE_SIZE, pfn * PAGE_SIZE, 2U);
		}
		start += PMD_SIZE;
		remap_addr = remap_addr + (start - target_addr);
		target_addr = start;
		mb_num--;
	}

	/*while (num > 0UL)
	{
		u64 pte = walk_s2pt(COREVISOR, remap_addr);
		u64 pa = phys_page(pte);
		u64 pfn = pa / PAGE_SIZE;
		gfn = (target_addr & ~(PMD_SIZE - 1)) >> PAGE_SHIFT;
		if (pfn == 0UL) {
			v_panic();
		} else {
			//print_string("\rmap boot images\n");
	        	//printhex_ul(pfn);
			set_pfn_to_vm(vmid, gfn, pfn, 1);
			//ret = assign_pfn_to_vm(vmid, gfn, pfn, pfn, 1);
			//if (ret == 0UL)
			//	map_pfn_vm(vmid, target_addr, pa, 3U);
		}
		remap_addr += PAGE_SIZE;
		target_addr += PAGE_SIZE;
		num--;
	}*/
}
