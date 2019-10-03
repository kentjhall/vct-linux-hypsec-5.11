#include "hypsec.h"

/*
 * NPTWalk
 */

void __hyp_text init_npt(u32 vmid)
{
    u64 vttbr_pa = pool_start(vmid);
    u64 vmid64 = ((u64)(vmid & 255U) << VTTBR_VMID_SHIFT);
    u64 vttbr = vttbr_pa | vmid64;
    u64 next = get_pt_next(vmid);
    if (next == vttbr_pa) {
        set_pt_vttbr(vmid, vttbr);
        set_pt_next(vmid, vttbr_pa + 2UL * PAGE_SIZE);
    }
    else {
        v_panic();
    }
}

u32 __hyp_text get_npt_level(u32 vmid, u64 addr)
{
    u64 vttbr = get_pt_vttbr(vmid);
    u64 pgd = walk_pgd(vmid, vttbr, addr, 0U);
    u64 pmd = walk_pmd(vmid, pgd, addr, 0U);
    u32 ret;
    if (v_pmd_table(pmd) == 1UL) {
        if (phys_page(pmd) == 0UL) ret = 0U;
        else ret = 2U;
    }
    else {
        u64 pte = walk_pte(vmid, pmd, addr);
        if (phys_page(pte) == 0UL) ret = 0U;
        else ret = 3U;
    }
    return ret;
}

u64 __hyp_text walk_npt(u32 vmid, u64 addr)
{
    u64 vttbr = get_pt_vttbr(vmid);
    u64 pgd = walk_pgd(vmid, vttbr, addr, 0U);
    u64 pmd = walk_pmd(vmid, pgd, addr, 0U);
    u64 ret;
    if (v_pmd_table(pmd) == 1UL) {
        ret = pmd;
    }
    else {
        u64 pte = walk_pte(vmid, pmd, addr);
        ret = pte;
    }
    return ret;
}

void __hyp_text set_npt(u32 vmid, u64 addr, u32 level, u64 pte)
{
	u64 vttbr = get_pt_vttbr(vmid);
	u64 pgd = walk_pgd(vmid, vttbr, addr, 1U);
	if (level == 2U)
	{
		v_set_pmd(vmid, pgd, addr, pte);
	}
	else
	{
		u64 pmd = walk_pmd(vmid, pgd, addr, 1U);
		if (v_pmd_table(pmd) == 0UL) {
			v_set_pte(vmid, pmd, addr, pte);
		}
		else {
			v_panic();
		}
	}
}
