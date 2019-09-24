#include "hypsec.h"

void _panic(void) {
    __hyp_panic();
}

#if 0
void    clear_phys_mem(u64 pfn) {
    memset(kern_hyp_va(pfn), 0, PAGE_SIZE);
}

u64     get_shared_kvm(u32 vmid) {
    return SHARED_KVM_START + vmid * sizeof(struct kvm);
}

u64     get_shared_vcpu(u32 vmid, u32 vcpuid) {
    return SHARED_VCPU_START + (vmid * VCPU_PER_VM + vcpuid) * sizeof(struct kvm_vcpu);
}

u32     verify_image(u32 vmid, u64 addr) {
    // TODO:
    return ed25519_verify(load_info.signature, kern_img, load_info.size, vm_info->public_key);
}

u64     get_sys_reg_desc_val(u32 index) {
    // TODO
    return host_sys_reg_descs[index];
}

u64	get_exception_vector(u64 pstate) {
    // TODO
	return 0;
}
#endif

// TODO: PT structure
void acquire_lock_pt(u32 vmid);
void release_lock_pt(u32 vmid);

//TODO: Fix the following functions
u64 get_pt_next(u32 vmid) {
	BUG();
	return 0;
};

void set_pt_next(u32 vmid, u64 next) {
	BUG();
};

u64 pt_load(u32 vmid, u64 addr) {
	BUG();
	return 0;
};

void pt_store(u32 vmid, u64 addr, u64 value) {
	BUG();
};

u64 get_pt_vttbr(u32 vmid);
void set_pt_vttbr(u32 vmid, u64 vttbr);


u32 get_mem_region_cnt(void) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->regions_cnt;
}

u64 get_mem_region_base(u32 index) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->regions[index].base;
}
u64 get_mem_region_size(u32 index) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->regions[index].size;
}

u64 get_mem_region_index(u32 index) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->s2_memblock_info[index].index;
}

u64 get_mem_region_flag(u32 index) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->regions[index].flags;
}

void    acquire_lock_s2page(void) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    stage2_spin_lock(&el2_data->s2pages_lock);
}

void    release_lock_s2page(void) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    stage2_spin_unlock(&el2_data->s2pages_lock);
}

u32     get_s2_page_vmid(u64 index) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->s2_pages[index].vmid;
}

void    set_s2_page_vmid(u64 index, u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->s2_pages[index].vmid = vmid;
}

u32     get_s2_page_count(u64 index) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->s2_pages[index].count;
}

void    set_s2_page_count(u64 index, u32 count) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->s2_pages[index].count = count;
}

#if 0
void    acquire_lock_vm(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    stage2_spin_lock(&el2_data->vm_info[vmid].vm_lock);
}

void    release_lock_vm(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    stage2_spin_unlock(&el2_data->vm_info[vmid].vm_lock);
}

u32     get_vcpu_ctxtid(u32 vmid, u32 vcpuid, u32 ctxtid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].int_vcpus[vcpuid].ctxtid;
}

// TODO: CTXT Info
u32     get_ctxt_vmid(u32 ctxtid);
u32     get_ctxt_vcpuid(u32 ctxtid);
void    set_vcpu_ctxtid(u32 vmid, u32 vcpuid, u32 ctxtid);

u32     get_vm_state(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].state;
}

void    set_vm_state(u32 vmid, u32 state) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].state = state;
}

u32     get_vcpu_state(u32 vmid, u32 vcpuid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].int_vcpus[vcpuid].state;
}

void    set_vcpu_state(u32 vmid, u32 vcpuid, u32 state) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].int_vcpus[vcpuid].state = state;
}

u32     get_vm_power(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].powered_on;
}

u32     get_vm_inc_exe(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].inc_exe;
}

void    set_vm_inc_exe(u32 vmid, u32 inc_exe) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].inc_exe = inc_exe;
}

u64     get_vm_kvm(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].kvm;
}

void    set_vm_kvm(u32 vmid, u64 kvm) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
   el2_data->vm_info[vmid].kvm = kvm;
}

u64     get_vm_vcpu(u32 vmid, u32 vcpuid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].int_vcpus[vcpuid].vcpu;
}

void    set_vm_vcpu(u32 vmid, u32 vcpuid, u64 vcpu) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].int_vcpus[vcpuid].vcpu = vcpu;
}

u32     get_vm_next_load_idx(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].load_info_cnt;
}

void    set_vm_next_load_idx(u32 vmid, u32 load_idx) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].load_info_cnt = load_idx;
}

u64     get_vm_load_addr(u32 vmid, u32 load_idx) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].load_info[load_idx].load_addr;
}

void    set_vm_load_addr(u32 vmid, u32 load_idx, u64 load_addr) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].load_info[load_idx].load_addr = load_addr;
}

u64     get_vm_load_size(u32 vmid, u32 load_idx) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].load_info[load_idx].size;
}

void    set_vm_load_size(u32 vmid, u32 load_idx, u64 size) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].load_info[load_idx].size = size;
}

u64     get_vm_remap_addr(u32 vmid, u32 load_idx) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].load_info[load_idx].el2_remap_addr;
}

void    set_vm_remap_addr(u32 vmid, u32 load_idx, u64 remap_addr) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].load_info[load_idx].el2_remap_addr = remap_addr;
}

u64     get_vm_mapped_pages(u32 vmid, u32 load_idx) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].load_info[load_idx].el2_mapped_pages;
}

void    set_vm_mapped_pages(u32 vmid, u32 load_idx, u64 mapped) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].load_info[load_idx].el2_mapped_pages = mapped;
}

void    acquire_lock_core(void) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    stage2_spin_lock(&el2_data->abs_lock);
}

void    release_lock_core(void) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    stage2_spin_unlock(&el2_data->abs_lock);
}

u32     get_next_vmid(void) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->next_vmid;
}

void    set_next_vmid(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->next_vmid = vmid;
}

u32     get_next_ctxt(void) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->used_shadow_vcpu_ctxt;
}

void    set_next_ctxt(u32 ctxtid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->used_shadow_vcpu_ctxt = ctxtid;
}

u64     get_next_remap_ptr(void) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->last_remap_ptr;
}

void    set_next_remap_ptr(u64 remap) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->last_remap_ptr = remap;
}

u64     get_shadow_ctxt(u32 ctxtid, u32 index);
void    set_shadow_ctxt(u32 ctxtid, u32 index, u64 value);
u64     get_int_ctxt(u32 ctxtid, u32 index);
void    set_int_ctxt(u32 ctxtid, u32 index, u64 value);
void    clear_shadow_gp_regs(u32 ctxtid);
void    int_to_shadow_fp_regs(u32 ctxtid);
void    int_to_shadow_decrypt(u32 ctxtid);
void    shadow_to_int_encrypt(u32 ctxtid);
u32     get_shadow_dirty_bit(u32 ctxtid, u32 index);
void    set_shadow_dirty_bit(u32 ctxtid, u32 index, u32 value);
u64     get_int_new_pte(u32 ctxtid);
u32     get_int_new_level(u32 ctxtid);
#endif
