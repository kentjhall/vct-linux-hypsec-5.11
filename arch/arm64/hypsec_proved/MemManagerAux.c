#include "hypsec.h"

/*
 * MemManagerAux
 */

/*
u32 __hyp_text check_pfn_to_vm(u32 vmid, u64 pfn, u32 pgnum, u64 apfn)
{
       u32 i = 0;
       u32 ret = 0;
       u32 owner;

       while (i < pgnum) {
               owner = get_pfn_owner(pfn);
               if (owner != HOSTVISOR) {
                       if (owner != vmid)
                               v_panic();
                       else {
                               // ret = 2 -> apfn.owenr != HOSTVISOR
                               // ret = 1 -> apfn.owner == HOSTVISOR but not all pages owner == HOSTVISOR
                               // ret = 0 -> all pages' owner == HOSTVISOR
                               if (pfn == apfn)
                                       ret = 2;
                               else if (ret == 0)
                                       ret = 1;
                       }
               }
               pfn++;
               i++;
       }

       return ret;
}

void __hyp_text set_pfn_to_vm(u32 vmid, u64 pfn, u64 pgnum)
{
	while (pgnum > 0UL) {
		set_pfn_owner(pfn, vmid);
		clear_pfn_host(pfn);
		pfn++;
		pgnum--;

	}
}
*/

u32 __hyp_text check_pfn_to_vm(u32 vmid, u64 gfn, u64 pfn, u64 pgnum, u64 apfn)
{
	u32 ret = 0U;
	while (pgnum > 0UL) {
		u32 owner = get_pfn_owner(pfn);
		u32 count = get_pfn_count(pfn);
		u64 map = get_pfn_map(pfn);
		if (owner == HOSTVISOR) {
			if (count != 0U)
				ret = 3U;
		} else if (owner == vmid) {
			/* the page was mapped to another gfn already! */
			if (gfn != map) {
				print_string("\rgfn\n");
				printhex_ul(gfn);
				print_string("\rmap\n");
				printhex_ul(map);
				ret = 3U;
			} else {
				/*
				 * if some page within (pfn, pfn + (PAGE_SIZE * pgnum)) 
				 * was mapped earlier (e.g. ret = 1) and pfn is now
				 * owned by VM's device (mapped in cbndx of SMMU), we
				 * map apfn instead of pfn to VM s2pt.
				 */
				if (ret < 2U && count != INVALID_MEM) {
					if (pfn == apfn)
						ret = 2U;
					else
						ret = 1U;
				}
			}	
		} else {
			ret = 3U;
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
