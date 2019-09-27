#include "hypsec.h"

/*
 * BootOps
 */

u32 vm_is_inc_exe(u32 vmid)
{
    u32 inc_exe;
    acquire_lock_vm(vmid);
    inc_exe = get_vm_inc_exe(vmid);
    release_lock_vm(vmid);
    return inc_exe;
}

void boot_from_inc_exe(u32 vmid)
{
    acquire_lock_vm(vmid);
    set_vm_inc_exe(vmid, 1U);
    release_lock_vm(vmid);
}

void set_vcpu_active(u32 vmid, u32 vcpuid)
{
    u32 vm_state, vcpu_state;
    acquire_lock_vm(vmid);
    vm_state = get_vm_state(vmid);
    vcpu_state = get_vcpu_state(vmid, vcpuid);
    if (vm_state == VERIFIED && vcpu_state == READY) {
        set_vcpu_state(vmid, vcpuid, ACTIVE);
    }
	else {
		v_panic();
	}
    release_lock_vm(vmid);
}

void set_vcpu_inactive(u32 vmid, u32 vcpuid)
{
    u32 vcpu_state;
    acquire_lock_vm(vmid);
    vcpu_state = get_vcpu_state(vmid, vcpuid);
    if (vcpu_state == ACTIVE) {
        set_vcpu_state(vmid, vcpuid, READY);
    }
	else {
		v_panic();
	}
    release_lock_vm(vmid);
}

u64 v_search_load_info(u32 vmid, u64 addr)
{
    u32 load_info_cnt, load_idx;
    u64 ret; 
    acquire_lock_vm(vmid);
    load_info_cnt = get_vm_next_load_idx(vmid);
    load_idx = 0U;
    ret = 0UL;
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
    u32 vm_state, vcpu_state;
    u64 vcpu;
    acquire_lock_vm(vmid);
    vm_state = get_vm_state(vmid);
    vcpu_state = get_vcpu_state(vmid, vcpuid);
    if (vm_state != READY || vcpu_state != UNUSED) {
		v_panic();
    }
    else {
        vcpu = get_shared_vcpu(vmid, vcpuid);
        set_vm_vcpu(vmid, vcpuid, vcpu);
		set_vcpu_state(vmid, vcpuid, READY);
    }
    release_lock_vm(vmid);
    return 0U;
}

u32 register_kvm()
{
    u32 vmid = gen_vmid();
    u32 state;
    u64 kvm;
    if (vmid == INVALID) {
		v_panic();
    }
    else {
        acquire_lock_vm(vmid);
        state = get_vm_state(vmid);
        if (state != UNUSED) {
			v_panic();
        }
        else {
            set_vm_inc_exe(vmid, 0U);
            kvm = get_shared_kvm(vmid);
            set_vm_kvm(vmid, kvm);
            init_s2pt(vmid);
            set_vm_state(vmid, READY);
        }
        release_lock_vm(vmid);
    }
    return vmid;
}

void set_boot_info(u32 vmid, u64 load_addr, u64 size)
{
    u32 state, load_idx;
    u64 page_count, remap_addr;
    acquire_lock_vm(vmid);
    state = get_vm_state(vmid);
    if (state == READY)
    {
        load_idx = get_vm_next_load_idx(vmid);
        if (load_idx < MAX_LOAD_INFO_NUM)
        {
            set_vm_next_load_idx(vmid, load_idx + 1U);
            page_count = (size + PAGE_SIZE - 1UL) / PAGE_SIZE;
            remap_addr = alloc_remap_addr(page_count);
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
    u32 state, load_info_cnt;
    u64 size, page_count, mapped, remap_addr, target;
    acquire_lock_vm(vmid);
    state = get_vm_state(vmid);
    if (state == READY)
    {
        load_info_cnt = get_vm_next_load_idx(vmid);
        if (load_idx < load_info_cnt)
        {
            size = get_vm_load_size(vmid, load_idx);
            page_count = (size + PAGE_SIZE - 1UL) / PAGE_SIZE;
            mapped = get_vm_mapped_pages(vmid, load_idx);
            remap_addr = get_vm_remap_addr(vmid, load_idx);
            target = remap_addr + mapped * PAGE_SIZE;
            if (mapped < page_count)
            {
                mmap_s2pt(COREVISOR, target, 3U, pfn * PAGE_SIZE + pgprot_val(PAGE_HYP));
                set_vm_mapped_pages(vmid, load_idx, mapped + 1UL);
            }
        }
    }
    release_lock_vm(vmid);
}

void verify_and_load_images(u32 vmid)
{
    u32 state, load_info_cnt, load_idx, valid;
    u64 load_addr, remap_addr, mapped;
    acquire_lock_vm(vmid);
    state = get_vm_state(vmid);
    if (state == READY)
    {
        load_info_cnt = get_vm_next_load_idx(vmid);
        load_idx = 0U;
        while (load_idx < load_info_cnt)
        {
            load_addr = get_vm_load_addr(vmid, load_idx);
            remap_addr = get_vm_remap_addr(vmid, load_idx);
            mapped = get_vm_mapped_pages(vmid, load_idx);
            v_unmap_image_from_host_s2pt(vmid, remap_addr, mapped);
            valid = verify_image(vmid, remap_addr);
            if (valid == 1U) {
                v_load_image_to_shadow_s2pt(vmid, load_addr, remap_addr, mapped);
            }
            load_idx += 1U;
        }
        set_vm_state(vmid, VERIFIED);
    }
    release_lock_vm(vmid);
}

