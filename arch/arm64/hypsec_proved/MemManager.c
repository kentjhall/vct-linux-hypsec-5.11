#include "hypsec.h"

/*
 * MemManager
 */

extern void __hyp_text t_mmap_s2pt(phys_addr_t addr, u64 desc, int level, u32 vmid);

void __hyp_text map_page_host(u64 addr)
{
	u64 pfn = addr / PAGE_SIZE;
	u64 new_pte = 0UL, perm;
	u32 owner, count;

	acquire_lock_s2page();
	owner = get_pfn_owner(pfn);
	count = get_pfn_count(pfn);
	if (owner == HOSTVISOR || count > 0U) {
	//if (addr >= 0x40000000) {
		perm = pgprot_val(PAGE_S2_KERNEL);
		new_pte = pfn * PAGE_SIZE + perm;
		//new_pte = pte_val(pfn_pte(pfn, PAGE_S2_KERNEL));
		//t_mmap_s2pt(addr, new_pte, 3, HOSTVISOR);
		//printhex_ul(addr);
		mmap_s2pt(HOSTVISOR, addr, 3U, new_pte);
	} else {
		perm = pgprot_val(PAGE_S2_DEVICE);
		perm |= S2_RDWR;
		new_pte = (addr & PAGE_MASK) + perm;
		mmap_s2pt(HOSTVISOR, addr, 3U, new_pte);
		//t_mmap_s2pt(addr, new_pte, 3, HOSTVISOR);
	}
	release_lock_s2page();
}

void __hyp_text clear_vm_page(u32 vmid, u64 pfn)
{
    u32 owner;
    u64 perm;
    acquire_lock_s2page();
    owner = get_pfn_owner(pfn);
    if (owner == vmid) {
        set_pfn_owner(pfn, 1UL, HOSTVISOR);
        set_pfn_count(pfn, 0U);
        perm = pgprot_val(PAGE_NONE);
        set_pfn_host(pfn, 1UL, 0UL, perm);
    }
    release_lock_s2page();
}

void __hyp_text assign_pfn_to_vm(u32 vmid, u64 pfn)
{
    u32 owner, count;
    u64 perm;
    acquire_lock_s2page();
    owner = get_pfn_owner(pfn);
    count = get_pfn_count(pfn);
    if (owner == HOSTVISOR && count == 0U) {
        set_pfn_owner(pfn, 1UL, vmid);
        perm = pgprot_val(PAGE_GUEST);
        set_pfn_host(pfn, 1UL, 0UL, perm);
    }
    else {
        v_panic();
    }
    release_lock_s2page();
}

extern void t_mmap_s2pt(phys_addr_t addr, u64 desc, int level, u32 vmid);
void __hyp_text map_pfn_vm(u32 vmid, u64 addr, u64 new_pte, u32 level, u32 exec)
{
    //u64 paddr = phys_page(new_pte);
    u64 paddr = new_pte;
    u64 pte;
    //u64 write = writable(new_pte);

    if (mem_region_search(paddr) == INVALID) {
        pte = paddr + pgprot_val(PAGE_S2_DEVICE) + S2_RDWR;
    }
    else {
        if (level == 2U) {
	    pte = paddr + pgprot_val(PAGE_S2_KERNEL); 
	    pte &= ~PMD_TABLE_BIT; 
	    /*print_string("\rmap pmd to gpa\n");
	    printhex_ul(addr);
	    print_string("\rentry\n");
	    printhex_ul(pte);*/
            //pte = paddr + pgprot_val(PAGE_S2) + write * PMD_S2_RDWR + exec * PMD_S2_XN;
        } else if (level == 3U) {
	    pte = paddr + pgprot_val(PAGE_S2_KERNEL); 
	    /*print_string("\rmap pte to gpa\n");
	    printhex_ul(addr);
	    print_string("\rentry\n");
	    printhex_ul(pte);*/
            //pte = paddr + pgprot_val(PAGE_S2) + write * PTE_S2_RDWR + exec * PTE_S2_XN;
	}
    }
    mmap_s2pt(vmid, addr, level, pte);
    //t_mmap_s2pt(addr, pte, level, vmid);
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
