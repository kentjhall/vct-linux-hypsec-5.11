#include "hypsec.h"

/*
 * MemManager
 */

extern void reject_invalid_mem_access(phys_addr_t addr);

void __hyp_text map_page_host(u64 addr)
{
	u64 pfn = addr / PAGE_SIZE;
	u64 new_pte = 0UL, perm;
	u32 owner, count;

	acquire_lock_s2page();
	owner = get_pfn_owner(pfn);
	count = get_pfn_count(pfn);
	if (owner == INVALID_MEM) {
		perm = pgprot_val(PAGE_S2_DEVICE);
		perm |= S2_RDWR;
		new_pte = (addr & PAGE_MASK) + perm;
		mmap_s2pt(HOSTVISOR, addr, 3U, new_pte);
	} else {
		if (owner == HOSTVISOR || count > 0U) {
			perm = pgprot_val(PAGE_S2_KERNEL);
			new_pte = pfn * PAGE_SIZE + perm;
			mmap_s2pt(HOSTVISOR, addr, 3U, new_pte);
		} else {
			reject_invalid_mem_access(addr);
			//v_panic();
		}
	}
	release_lock_s2page();
}

void __hyp_text clear_vm_page(u32 vmid, u64 pfn)
{
    u32 owner, level;
    u64 perm;
    acquire_lock_s2page();
    owner = get_pfn_owner(pfn);
    if (owner == vmid) {
        set_pfn_owner(pfn, HOSTVISOR);
        set_pfn_count(pfn, 0U);
        perm = pgprot_val(PAGE_NONE);
        level = get_npt_level(vmid, pfn * PAGE_SIZE);
        mmap_s2pt(vmid, pfn * PAGE_SIZE, level, perm);
    }
    release_lock_s2page();
}

u32 __hyp_text assign_pfn_to_vm(u32 vmid, u64 pfn, u64 apfn, u32 pgnum)
{
	u32 ret;

	acquire_lock_s2page();
	ret = check_pfn_to_vm(vmid, pfn, pgnum, apfn);
	/* if pfn is new, we simply assign it */
	if (ret == 0) {
		set_pfn_to_vm(vmid, pfn, pgnum);
	}
	/* if pfn is partially overlapped */
	else if (ret == 1) {
		set_pfn_to_vm(vmid, apfn, 1);
		//ret = 1;
	/* if pfn is mapped, we neither assign nor map it */
	} else if (ret != 2) {
		v_panic();
	}
	release_lock_s2page();
	return ret;
}

extern void t_mmap_s2pt(phys_addr_t addr, u64 desc, int level, u32 vmid);
void __hyp_text map_pfn_vm(u32 vmid, u64 addr, u64 pte, u32 level)
{
	u64 paddr = phys_page(pte);

	/* We give the VM RWX permission now. */
	u64 perm = pgprot_val(PAGE_S2_KERNEL);

	if (level == 2U) {
		/* FIXME: verified code has pte = paddr | perm; */
		pte = paddr + perm;
		pte &= ~PMD_TABLE_BIT;
	} else if (level == 3U) {
		pte = paddr + perm;
	}
	mmap_s2pt(vmid, addr, level, pte);
}

void __hyp_text grant_vm_page(u32 vmid, u64 pfn)
{
    u32 owner, count;
    acquire_lock_s2page();
    owner = get_pfn_owner(pfn);
    count = get_pfn_count(pfn);
    if (owner == vmid && count < MAX_SHARE_COUNT) {
        set_pfn_count(pfn, count + 1U);
    }
    release_lock_s2page();
}

void __hyp_text revoke_vm_page(u32 vmid, u64 pfn)
{
    u32 owner, count;
    acquire_lock_s2page();
    owner = get_pfn_owner(pfn);
    count = get_pfn_count(pfn);
    if (owner == vmid && count > 0U) {
        set_pfn_count(pfn, count - 1U);
        if (count == 1U) {
            clear_pfn_host(pfn);
        }
    }
    release_lock_s2page();
}
