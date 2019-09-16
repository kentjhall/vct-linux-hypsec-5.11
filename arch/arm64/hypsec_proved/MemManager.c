#include "hypsec.h"

/*
 * MemManager
 */

void map_page_host(u64 addr)
{
    u64 pfn = addr / PAGE_SIZE;
    u64 new_pte = 0UL;
    acquire_lock_s2page();
    u32 owner = get_pfn_owner(pfn);
    u32 count = get_pfn_count(pfn);
    if (owner == HOSTVISOR || count > 0U) {
        new_pte = pfn * PAGE_SIZE + PAGE_S2_KERNEL;
        mmap_s2pt(HOSTVISOR, addr, 3U, new_pte);
    }
    else {
        new_pte = (addr & PAGE_MASK) + PAGE_S2_DEVICE + S2_RDWR;
        mmap_s2pt(HOSTVISOR, addr, 3U, new_pte);
    }
    release_lock_s2page();
}

void clear_vm_page(u32 vmid, u64 pfn)
{
    acquire_lock_s2page();
    u32 owner = get_pfn_owner(pfn);
    if (owner == vmid) {
        set_pfn_owner(pfn, 1UL, HOSTVISOR);
        set_pfn_count(pfn, 0U);
        set_pfn_host(pfn, 1UL, 0UL, PAGE_NONE);
    }
    release_lock_s2page();
}

void assign_pfn_to_vm(u32 vmid, u64 pfn)
{
    acquire_lock_s2page();
    u32 owner = get_pfn_owner(pfn);
    u32 count = get_pfn_count(pfn);
    if (owner == HOSTVISOR && count == 0U) {
        set_pfn_owner(pfn, 1UL, vmid);
        set_pfn_host(pfn, 1UL, 0UL, PAGE_GUEST);
    }
    else {
        panic();
    }
    release_lock_s2page();
}

void map_pfn_vm(u32 vmid, u64 addr, u64 new_pte, u32 level, u32 exec)
{
    u64 paddr = phys_page(new_pte);
    u64 pte;
    u64 write = writable(new_pte);

    if (mem_region_search(paddr) == INVALID) {
        pte = paddr + PAGE_S2_DEVICE + PTE_S2_RDWR;
    }
    else {
        if (level == 2U)
            pte = paddr + PAGE_S2 + write * PMD_S2_RDWR + exec * PMD_S2_XN;
        else
            pte = paddr + PAGE_S2 + write * PTE_S2_RDWR + exec * PTE_S2_XN;
    }
    mmap_s2pt(vmid, addr, level, pte);
}

void grant_vm_page(u32 vmid, u64 pfn)
{
    acquire_lock_s2page();
    u32 owner = get_pfn_owner(pfn);
    u32 count = get_pfn_count(pfn);
    if (owner == vmid && count < MAX_SHARE_COUNT) {
        set_pfn_count(pfn, count + 1U);
    }
    release_lock_s2page();
}

void revoke_vm_page(u32 vmid, u64 pfn)
{
    acquire_lock_s2page();
    u32 owner = get_pfn_owner(pfn);
    u32 count = get_pfn_count(pfn);
    if (owner == vmid && count > 0U) {
        set_pfn_count(pfn, count - 1U);
        if (count == 1U) {
            set_pfn_host(pfn, 1UL, 0UL, PAGE_GUEST);
        }
    }
    release_lock_s2page();
}

