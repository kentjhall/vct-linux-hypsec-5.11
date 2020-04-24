#include "hypsec.h"

/*
 * NPTWalk
 */

void __hyp_text init_npt(u32 vmid)
{
	u64 vttbr, vttbr_pa, vmid64, next;

	vttbr = get_pt_vttbr(vmid);
	if (vttbr == 0) {
		vttbr_pa = pool_start(vmid);
		vmid64 = ((u64)(vmid & 255U) << VTTBR_VMID_SHIFT);
		vttbr = vttbr_pa | vmid64;
		next = get_pt_next(vmid);
		if (next == vttbr_pa) {
			set_pt_vttbr(vmid, vttbr);
			set_pt_next(vmid, 1);
		}
		else
			v_panic();
	}
}

u32 __hyp_text get_npt_level(u32 vmid, u64 addr)
{
	u64 vttbr, pgd, pud, pmd;u32 ret;

	vttbr = get_pt_vttbr(vmid);
	pgd = walk_pgd(vmid, vttbr, addr, 0U);
	pud = walk_pud(vmid, pgd, addr, 0U);
	pmd = walk_pmd(vmid, pud, addr, 0U);

    	if (v_pmd_table(pmd) == PMD_TYPE_TABLE) {
		u64 pte = walk_pte(vmid, pmd, addr);
		if (phys_page(pte) == 0UL)
			ret = 0U;
		else
			ret = 3U;
	}
	else {
		if (phys_page(pmd) == 0UL)
			ret = 0U;
		else
			ret = 2U;
	}

	return ret;
}

u64 __hyp_text walk_npt(u32 vmid, u64 addr)
{
	u64 vttbr, pgd, pud, pmd, ret, pte;

	vttbr = get_pt_vttbr(vmid);
	pgd = walk_pgd(vmid, vttbr, addr, 0U);
	pud = walk_pud(vmid, pgd, addr, 0U);
	pmd = walk_pmd(vmid, pud, addr, 0U);

	if (v_pmd_table(pmd) == PMD_TYPE_TABLE) {
        	pte = walk_pte(vmid, pmd, addr);
        	ret = pte;
    	}
    	else {
        	ret = pmd;
	}

	return ret;
}

void __hyp_text set_npt(u32 vmid, u64 addr, u32 level, u64 pte)
{
	u64 vttbr, pgd, pud, pmd;

	vttbr = get_pt_vttbr(vmid);	
	pgd = walk_pgd(vmid, vttbr, addr, 1U);
	pud = walk_pud(vmid, pgd, addr, 1U);

	if (level == 2U)
	{
		pmd = walk_pmd(vmid, pud, addr, 0U);
		if (v_pmd_table(pmd) == PMD_TYPE_TABLE) 
			v_panic();
		else
	   		v_set_pmd(vmid, pud, addr, pte);
	}
	else
	{
		pmd = walk_pmd(vmid, pud, addr, 1U);
		if (v_pmd_table(pmd) == PMD_TYPE_TABLE)
			v_set_pte(vmid, pmd, addr, pte);
		else
			v_panic();
	}
}
