#include "hypsec.h"

/*
 * PTWalk
 */

asm (
	".text \n\t"
	".pushsection \".hyp.text\", \"ax\" \n\t"
);

u64 walk_pgd(u32 vmid, u64 vttbr, u64 addr, u32 alloc)
{
    u64 vttbr_pa = phys_page(vttbr);
    u64 ret = 0UL;
    if (vttbr_pa != 0UL) {
        u64 pgd_idx = pgd_idx(addr);
        u64 pgd = pt_load(vmid, vttbr_pa + pgd_idx * 8UL);
        u64 pgd_pa = phys_page(pgd);
        if (pgd_pa == 0UL && alloc == 1U)
        {
            pgd_pa = alloc_s2pt_page(vmid);
            pgd = pgd_pa | PUD_TYPE_TABLE;
            pt_store(vmid, vttbr_pa + pgd_idx * 8UL, pgd);
        }
	ret = pgd;
    }
    return ret;
}

u64 walk_pmd(u32 vmid, u64 pgd, u64 addr, u32 alloc)
{
    u64 pgd_pa = phys_page(pgd);
    u64 ret = 0UL;
    if (pgd_pa != 0UL) {
        u64 pmd_idx = pmd_idx(addr);
        u64 pmd = pt_load(vmid, pgd_pa + pmd_idx * 8);
        u64 pmd_pa = phys_page(pmd);
        if (pmd_pa == 0UL && alloc == 1U)
        {
            pmd_pa = alloc_s2pt_page(vmid);
            pmd = pmd_pa | PMD_TYPE_TABLE;
            pt_store(vmid, pgd_pa + pmd_idx * 8UL, pmd);
        }
	ret = pmd;
    }
    return ret;
}

u64 walk_pte(u32 vmid, u64 pmd, u64 addr)
{
    u64 pmd_pa = phys_page(pmd);
    u64 ret = 0UL;
    if (pmd_pa != 0UL) {
        u64 pte_idx = pte_idx(addr);
        ret = pt_load(vmid, pmd_pa + pte_idx * 8UL);
    }
    return ret;
}

void v_set_pmd(u32 vmid, u64 pgd, u64 addr, u64 pmd)
{
    u64 pgd_pa = phys_page(pgd);
    u64 pmd_idx = pmd_idx(addr);
    pt_store(vmid, pgd_pa + pmd_idx * 8UL, pmd);
}

void v_set_pte(u32 vmid, u64 pmd, u64 addr, u64 pte)
{
    u64 pmd_pa = phys_page(pmd);
    u64 pte_idx = pte_idx(addr);
    pt_store(vmid, pmd_pa + pte_idx * 8UL, pte);
}

asm (
	".popsection\n\t"
);
