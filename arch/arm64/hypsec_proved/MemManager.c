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
        set_pfn_owner(pfn, 1UL, HOSTVISOR);
        set_pfn_count(pfn, 0U);
        perm = pgprot_val(PAGE_NONE);
        level = get_npt_level(vmid, pfn * PAGE_SIZE);
        mmap_s2pt(vmid, pfn * PAGE_SIZE, level, perm);
    }
    release_lock_s2page();
}

u32 __hyp_text assign_pfn_to_vm(u32 vmid, u64 pfn, u32 pgnum)
{
	u32 owner, count, i = 0;
	u64 perm;
	u32 ret = 1;

	acquire_lock_s2page();
	while (i < pgnum) {
		owner = get_pfn_owner(pfn);
		count = get_pfn_count(pfn);
		/*
		 * There could be some other VCPU that has the faulted pfn
		 * mapped and changed the owner before we come here.
		 */
		if (owner == HOSTVISOR && count == 0U) {
			set_pfn_owner(pfn, 1UL, vmid);
			perm = pgprot_val(PAGE_GUEST);
			set_pfn_host(pfn, 1UL, 0UL, perm);
		} else if (owner == vmid) {
			ret = 0;
		} else
			v_panic();

		pfn++;
		i++;
	}
	release_lock_s2page();
	return ret;
}

extern void t_mmap_s2pt(phys_addr_t addr, u64 desc, int level, u32 vmid);
void __hyp_text map_pfn_vm(u32 vmid, u64 addr, u64 new_pte, u32 level, u32 exec)
{
    u64 paddr = new_pte;
    u64 pte = 0, perm;

    /* We give the VM RWX permission now. */
    perm = pgprot_val(PAGE_S2_KERNEL);

    if (level == 2U) {
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
    u64 perm;
    acquire_lock_s2page();
    owner = get_pfn_owner(pfn);
    count = get_pfn_count(pfn);
    if (owner == vmid && count > 0U) {
        set_pfn_count(pfn, count - 1U);
        if (count == 1U) {
            perm = pgprot_val(PAGE_GUEST);
            set_pfn_host(pfn, 1UL, 0UL, perm);
        }
    }
    release_lock_s2page();
}
