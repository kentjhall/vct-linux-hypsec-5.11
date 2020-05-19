#include "hypsec.h"

/*
 * MemManagerAux
 */

u32 __hyp_text check_pfn_to_vm(u32 vmid, u64 gfn, u64 pfn, u64 pgnum)
{
	u32 ret = 0U;

	while (pgnum > 0UL) {
		u32 owner = get_pfn_owner(pfn);
		u32 count = get_pfn_count(pfn);
		if (owner == HOSTVISOR) {
			//pfn is mapped to a hostvisor SMMU table
			if (count != 0U) {
				print_string("\rassign pfn used by host smmu device\n");
				v_panic();
			}
			else {
			    set_pfn_owner(pfn, vmid);
			    clear_pfn_host(pfn);
			    set_pfn_map(pfn, gfn);
			}
		} else if (owner == vmid) {
			u64 map = get_pfn_map(pfn);
			/* the page was mapped to another gfn already! */
			// if gfn == map, it means someone in my VM has mapped it
			if (gfn == map) {
 				if (count == INVALID_MEM) {
					set_pfn_count(pfn, 0U);
				}
				else {
					ret = 1U;
				}
			}
			else {
				print_string("\rmap != gfn || count != INVALID_MEM\n");
				v_panic();
			}
		} else  {
			v_panic();
		}
		pgnum -= 1UL;
		pfn += 1UL;
		gfn += 1UL;
	}
	return ret;
}

void __hyp_text set_pfn_to_vm(u32 vmid, u64 gfn, u64 pfn, u64 pgnum)
{
    u32 owner;
    while (pgnum > 0UL) {
	owner = get_pfn_owner(pfn);
	if (owner == HOSTVISOR) {
	    set_pfn_owner(pfn, vmid);
	    clear_pfn_host(pfn);
            set_pfn_map(pfn, gfn);
	}
	set_pfn_count(pfn, 0U);
	pfn += 1UL;
        gfn += 1UL;
	pgnum -= 1UL;
    }
}
