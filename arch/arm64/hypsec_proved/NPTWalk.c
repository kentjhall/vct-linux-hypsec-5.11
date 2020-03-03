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
        set_pt_next(vmid, 2);
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
    if (vmid == COREVISOR)
        v_panic();
    if (v_pmd_table(pmd) == 0UL) {
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
    u64 vttbr, pgd, pud, pmd, ret;

    if (vmid < COREVISOR) {
        vttbr = get_pt_vttbr(vmid);
    } else {
        vttbr = read_sysreg(ttbr0_el2);
    }
    pgd = walk_pgd(vmid, vttbr, addr, 0U);

    if (vmid == COREVISOR) {
	pud = walk_pud(vmid, pgd, addr, 0U);
	pgd = pud;
    }

    pmd = walk_pmd(vmid, pgd, addr, 0U);
    if (v_pmd_table(pmd) == 0UL) {
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
	u64 vttbr, pgd, pud, pmd;

	if (vmid < COREVISOR) {
		vttbr = get_pt_vttbr(vmid);
	} else {
		vttbr = read_sysreg(ttbr0_el2);
	}
	pgd = walk_pgd(vmid, vttbr, addr, 1U);

	if (level == 2U)
	{
		v_set_pmd(vmid, pgd, addr, pte);
	}
	else
	{
		if (vmid == COREVISOR) {
			pud = walk_pud(vmid, pgd, addr, 1U);
			pmd = walk_pmd(vmid, pud, addr, 1U);
			v_set_pte(vmid, pmd, addr, pte);
		} else {
			pmd = walk_pmd(vmid, pgd, addr, 1U);
			v_set_pte(vmid, pmd, addr, pte);
		}
	}
}
