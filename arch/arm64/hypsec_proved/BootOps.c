#include "hypsec.h"

/*
 * BootOps
 */

u32 vm_is_inc_exe(u32 vmid)
{
    acquire_lock_vm(vmid);
    u32 inc_exe = get_vm_inc_exe(vmid);
    release_lock_vm(vmid);
    return inc_exe;
}

void boot_from_inc_exe(u32 vmid)
{
    acquire_lock_vm(vmid);
    set_vm_inc_exe(vmid, 1U);
    release_lock_vm(vmid);
}

u32 set_vcpu_active(u32 vmid, u32 vcpuid)
{
    u32 ret = 0U;
    acquire_lock_vm(vmid);
    u32 vm_state = get_vm_state(vmid);
    u32 vcpu_state = get_vcpu_state(vmid, vcpuid);
    if (vm_state == VERIFIED && vcpu_state == READY) {
        set_vcpu_state(vmid, vcpuid, ACTIVE);
        ret = 1U;
    }
    release_lock_vm(vmid);
    return ret;
}

u32 set_vcpu_inactive(u32 vmid, u32 vcpuid)
{
    u32 ret = 0U;
    acquire_lock_vm(vmid);
    u32 vcpu_state = get_vcpu_state(vmid, vcpuid);
    if (vcpu_state == ACTIVE) {
        set_vcpu_state(vmid, vcpuid, READY);
        ret = 0U;
    }
    release_lock_vm(vmid);
    return ret;
}

u64 search_load_info(u32 vmid, u64 addr)
{
    acquire_lock_vm(vmid);
    u32 load_info_cnt = get_vm_next_load_idx(vmid);
    u32 load_idx = 0U;
    u64 ret = 0UL;
    while (load_idx < load_info_cnt)
    {
        u64 base = get_vm_load_addr(vmid, load_idx);
        u64 size = get_vm_load_size(vmid, load_idx);
        u64 remap_addr = get_vm_remap_addr(vmid, load_idx);
        if (addr >= base && addr < base + size)
        {
            ret = (addr - base) + remap_addr;
        }
        load_idx += 1U;
    }
    release_lock_vm(vmid);
    return ret;
} 

u32 register_vcpu(u32 vmid, u32 vcpuid)
{
    u32 ret = 0U;
    acquire_lock_vm(vmid);
    u32 vm_state = get_vm_state(vmid);
    u32 vcpu_state = get_vcpu_state(vmid, vcpuid);
    if (vm_state != READY || vcpu_state != UNUSED) {
        ret = INVALID;
    }
    else {
        u64 vcpu = get_shared_vcpu(vmid, vcpuid);
        set_vm_vcpu(vmid, vcpuid, vcpu);
        u32 ctxtid = alloc_shadow_ctxt();
        if (ctxtid == INVALID) {
            ret = INVALID;
        }
        else {
            set_vcpu_ctxtid(vmid, vcpuid, ctxtid);
            set_vcpu_state(vmid, vcpuid, READY);
        }
    }
    release_lock_vm(vmid);
    return ret;
}

u32 register_kvm()
{
    u32 vmid = gen_vmid();
    u32 ret = vmid;
    if (vmid == INVALID) {
        ret = 0U;
    }
    else {
        acquire_lock_vm(vmid);
        u32 state = get_vm_state(vmid);
        if (state != UNUSED) {
            ret = 0U;
        }
        else {
            set_vm_inc_exe(vmid, 0U);
            u64 kvm = get_shared_kvm(vmid);
            set_vm_kvm(vmid, kvm);
            init_s2pt(vmid);
            set_vm_state(vmid, READY);
        }
        release_lock_vm(vmid);
    }
    return ret;
}

void set_boot_info(u32 vmid, u64 load_addr, u64 size)
{
    acquire_lock_vm(vmid);
    u32 state = get_vm_state(vmid);
    if (state == READY)
    {
        u32 load_idx = get_vm_next_load_idx(vmid);
        if (load_idx < MAX_LOAD_INFO_NUM)
        {
            set_vm_next_load_idx(vmid, load_idx + 1U);
            u64 page_count = (size + PAGE_SIZE - 1UL) / PAGE_SIZE;
            u64 remap_addr = alloc_remap_addr(page_count);
            set_vm_load_addr(vmid, load_idx, load_addr);
            set_vm_load_size(vmid, load_idx, size);
            set_vm_remap_addr(vmid, load_idx, remap_addr);
            set_vm_mapped_pages(vmid, load_idx, 0U);
        }
    }
    release_lock_vm(vmid);
}

void remap_vm_image(u32 vmid, u32 load_idx, u64 pfn)
{
    acquire_lock_vm(vmid);
    u32 state = get_vm_state(vmid);
    if (state == READY)
    {
        u32 load_info_cnt = get_vm_next_load_idx(vmid);
        if (load_idx < load_info_cnt)
        {
            u64 size = get_vm_load_size(vmid, load_idx);
            u64 page_count = (size + PAGE_SIZE - 1UL) / PAGE_SIZE;
            u64 mapped = get_vm_mapped_pages(vmid, load_idx);
            u64 remap_addr = get_vm_remap_addr(vmid, load_idx);
            u64 target = remap_addr + mapped * PAGE_SIZE;
            if (mapped < page_count)
            {
                mmap_s2pt(COREVISOR, target, 3U, pfn * PAGE_SIZE + PAGE_HYP);
                set_vm_mapped_pages(vmid, load_idx, mapped + 1UL);
            }
        }
    }
    release_lock_vm(vmid);
}

void verify_and_load_images(u32 vmid)
{
    acquire_lock_vm(vmid);
    u32 state = get_vm_state(vmid);
    if (state == READY)
    {
        u32 load_info_cnt = get_vm_next_load_idx(vmid);
        u32 load_idx = 0U;
        while (load_idx < load_info_cnt)
        {
            u64 load_addr = get_vm_load_addr(vmid, load_idx);
            u64 remap_addr = get_vm_remap_addr(vmid, load_idx);
            u64 mapped = get_vm_mapped_pages(vmid, load_idx);
            unmap_image_from_host_s2pt(vmid, remap_addr, mapped);
            u32 valid = verify_image(vmid, remap_addr);
            if (valid == 1U) {
                load_image_to_shadow_s2pt(vmid, load_addr, remap_addr, mapped);
            }
            load_idx += 1U;
        }
        set_vm_state(vmid, VERIFIED);
    }
    release_lock_vm(vmid);
}

