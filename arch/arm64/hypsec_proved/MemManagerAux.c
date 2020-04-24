#include "hypsec.h"

/*
 * MemManagerAux
 */

/* TODO: Move to a bottom layer. */
u32 __hyp_text check_pfn_to_vm(u32 vmid, u64 pfn, u32 pgnum, u64 apfn)
{
       u32 i = 0;
       u32 ret = 0;
       u32 owner, count;

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
