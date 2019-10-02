#include "hypsec.h"

void v_panic(void) {
    __hyp_panic();
}

void clear_phys_mem(u64 pfn) {
    el2_memset((void *)kern_hyp_va(pfn << PAGE_SHIFT), 0, PAGE_SIZE);
}

u64 get_shared_kvm(u32 vmid) {
    return SHARED_KVM_START + vmid * sizeof(struct kvm);
}

u64 get_shared_vcpu(u32 vmid, u32 vcpuid) {
    return SHARED_VCPU_START + (vmid * VCPU_PER_VM + vcpuid) * sizeof(struct kvm_vcpu);
}

u32 verify_image(u32 vmid, u64 addr) {
    // TODO:
    //return ed25519_verify(load_info.signature, kern_img, load_info.size, vm_info->public_key);
    return 0;
}

/*
u64 get_sys_reg_desc_val(u32 index) {
    // TODO: make the following work
    int vcpuid = 0, vmid = 0;
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].shadow_ctxt[vcpuid]->sys_regs[index];
}
*/

u64 get_exception_vector(u64 pstate) {
    // TODO
	return 0;
}

void acquire_lock_pt(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    stage2_spin_lock(&el2_data->vm_info[vmid].shadow_pt_lock);
};

void release_lock_pt(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    stage2_spin_unlock(&el2_data->vm_info[vmid].shadow_pt_lock);
};

u64 get_pt_next(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].used_pages;
};

void set_pt_next(u32 vmid, u64 next) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].used_pages = next;
};

// TODO: make the following work
u64 pt_load(u32 vmid, u64 addr) {
	BUG();
	return 0;
};

// TODO: make the following work
void pt_store(u32 vmid, u64 addr, u64 value) {
	BUG();
};

u64 get_pt_vttbr(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].vttbr;
	return 0;
};

void set_pt_vttbr(u32 vmid, u64 vttbr) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].vttbr = vttbr;
};

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

void    acquire_lock_vm(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    stage2_spin_lock(&el2_data->vm_info[vmid].vm_lock);
}

void    release_lock_vm(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    stage2_spin_unlock(&el2_data->vm_info[vmid].vm_lock);
}

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

void     set_vm_power(u32 vmid, u32 power) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].powered_on = power;
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

u64 	get_vm_kvm(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return (u64)el2_data->vm_info[vmid].kvm;
}

void    set_vm_kvm(u32 vmid, u64 kvm) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].kvm = (struct kvm*)kvm;
}

u64     get_vm_vcpu(u32 vmid, u32 vcpuid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return (u64)el2_data->vm_info[vmid].int_vcpus[vcpuid].vcpu;
}

void    set_vm_vcpu(u32 vmid, u32 vcpuid, u64 vcpu) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].int_vcpus[vcpuid].vcpu = (struct kvm_vcpu*)vcpu;
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

u64     get_next_remap_ptr(void) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->last_remap_ptr;
}

void    set_next_remap_ptr(u64 remap) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->last_remap_ptr = remap;
}

u64 __hyp_text get_shadow_ctxt(u32 vmid, u32 vcpuid, u32 index)
{
       struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
       int offset = VCPU_IDX(vmid, vcpuid);
       return el2_data->shadow_vcpu_ctxt[offset].regs[index]; 
};

//TODO: Define the following
void __hyp_text set_shadow_ctxt(u32 vmid, u32 vcpuid, u32 index, u64 value) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	int offset = VCPU_IDX(vmid, vcpuid);
	el2_data->shadow_vcpu_ctxt[offset].regs[index] = value;
}

u32 __hyp_text get_shadow_esr(u32 vmid, u32 vcpuid) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	int offset = VCPU_IDX(vmid, vcpuid);
	return el2_data->shadow_vcpu_ctxt[offset].esr;
}

u32 __hyp_text get_int_esr(u32 vmid, u32 vcpuid) {
	struct shared_data *shared_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	struct kvm_vcpu *vcpu;
	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	vcpu = &shared_data->vcpu_pool[offset];
	return vcpu->arch.fault.esr_el2;
}

//make sure we only use get_int_ctxt to access general purposes regs
u64 __hyp_text get_int_gpr(u32 vmid, u32 vcpuid, u32 index) {
	struct shared_data *shared_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	struct kvm_vcpu *vcpu;
	if (index >= 32)
		__hyp_panic();
	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	vcpu = &shared_data->vcpu_pool[offset];
	return vcpu->arch.ctxt.gp_regs.regs.regs[index];
}

u64 __hyp_text get_int_pc(u32 vmid, u32 vcpuid) {
	struct shared_data *shared_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	struct kvm_vcpu *vcpu;
	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	vcpu = &shared_data->vcpu_pool[offset];
	return vcpu->arch.ctxt.gp_regs.regs.pc;
}

u64 __hyp_text get_int_pstate(u32 vmid, u32 vcpuid) {
	struct shared_data *shared_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	struct kvm_vcpu *vcpu;
	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	vcpu = &shared_data->vcpu_pool[offset];
	return vcpu->arch.ctxt.gp_regs.regs.pstate;
}

void __hyp_text set_int_gpr(u32 vmid, u32 vcpuid, u32 index, u64 value) {
	struct shared_data *shared_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	struct kvm_vcpu *vcpu;
	if (index >= 32)
		__hyp_panic();
	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	vcpu = &shared_data->vcpu_pool[offset];
	vcpu->arch.ctxt.gp_regs.regs.regs[index] = value;
}

void    clear_shadow_gp_regs(u32 vmid, u32 vcpuid) {

}

void    int_to_shadow_fp_regs(u32 vmid, u32 vcpuid) {

}

u32 __hyp_text get_shadow_dirty_bit(u32 vmid, u32 vcpuid) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	int offset = VCPU_IDX(vmid, vcpuid);
	return el2_data->shadow_vcpu_ctxt[offset].dirty;
}

void __hyp_text set_shadow_dirty_bit(u32 vmid, u32 vcpuid, u64 value) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	int offset = VCPU_IDX(vmid, vcpuid);
	el2_data->shadow_vcpu_ctxt[offset].dirty = value;
}

u64     get_int_new_pte(u32 vmid, u32 vcpuid) {
	return 0;
}

u32     get_int_new_level(u32 vmid, u32 vcpuid) {
	return 0;
}

void __hyp_text set_per_cpu(int vmid, int vcpu_id)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	int pcpuid = read_cpuid_mpidr() & MPIDR_HWID_BITMASK;
	el2_data->per_cpu_data[pcpuid].vmid = vmid;
	el2_data->per_cpu_data[pcpuid].vcpu_id = vcpu_id;
};

int __hyp_text get_cur_vmid(void)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	int pcpuid = read_cpuid_mpidr() & MPIDR_HWID_BITMASK;
	return el2_data->per_cpu_data[pcpuid].vmid;
};

int __hyp_text get_cur_vcpu_id(void)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	int pcpuid = read_cpuid_mpidr() & MPIDR_HWID_BITMASK;
	return el2_data->per_cpu_data[pcpuid].vcpu_id;
};
#if 0
void    int_to_shadow_decrypt(u32 vmid, u32 vcpuid);
void    shadow_to_int_encrypt(u32 vmid, u32 vcpuid);
#endif
