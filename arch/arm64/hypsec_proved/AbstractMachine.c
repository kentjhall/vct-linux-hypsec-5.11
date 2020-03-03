#include "hypsec.h"
#include "hacl-20/Hacl_Ed25519.h"

void __hyp_text v_panic(void) {
	//__hyp_panic();
	u32 vmid = get_cur_vmid();
	u32 vcpuid = get_cur_vcpu_id();
	if (vmid) {
		print_string("\rvm\n");
		printhex_ul(get_shadow_ctxt(vmid, vcpuid, V_PC));
	} else {
		print_string("\rhost\n");
		printhex_ul(read_sysreg(elr_el2));
	}
	printhex_ul(ESR_ELx_EC(read_sysreg(esr_el2)));
}

void __hyp_text clear_phys_mem(u64 pfn) {
    el2_memset((void *)kern_hyp_va(pfn << PAGE_SHIFT), 0, PAGE_SIZE);
}

u64 __hyp_text get_shared_kvm(u32 vmid) {
    //return SHARED_KVM_START + vmid * sizeof(struct kvm);
    u64 shared_kvm_start = (u64)kvm_ksym_ref(shared_data_start);
    return shared_kvm_start + vmid * sizeof(struct kvm);
}

u64 __hyp_text get_shared_vcpu(u32 vmid, u32 vcpuid) {
    //return SHARED_VCPU_START + (vmid * VCPU_PER_VM + vcpuid) * sizeof(struct kvm_vcpu);
    u64 vcpu_off = sizeof(struct kvm) * EL2_MAX_VMID;
    u64 shared_vcpu_start = (u64)kvm_ksym_ref(shared_data_start) + vcpu_off;
    return shared_vcpu_start + (vmid * VCPU_PER_VM + vcpuid) * sizeof(struct kvm_vcpu);
}

u64 __hyp_text get_sys_reg_desc_val(u32 index) {
    // TODO
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->s2_sys_reg_descs[index].val;
}

u64 __hyp_text get_exception_vector(u64 pstate) {
    // TODO
	return 0;
}

void __hyp_text acquire_lock_pt(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    stage2_spin_lock(&el2_data->vm_info[vmid].shadow_pt_lock);
};

void __hyp_text release_lock_pt(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    stage2_spin_unlock(&el2_data->vm_info[vmid].shadow_pt_lock);
};

u64 __hyp_text pool_start(u32 vmid) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->vm_info[vmid].page_pool_start;
}

u64 __hyp_text pool_end(u32 vmid) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	u64 pool_start = el2_data->vm_info[vmid].page_pool_start;
	if (vmid == COREVISOR)
		return pool_start + STAGE2_CORE_PAGES_SIZE;
	else if (vmid == HOSTVISOR)
		return pool_start + STAGE2_CORE_PAGES_SIZE + STAGE2_HOST_POOL_SIZE;
	return pool_start + PT_POOL_PER_VM;
}

u64 __hyp_text get_pt_next(u32 vmid) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	u64 pool_start = el2_data->vm_info[vmid].page_pool_start;
	u64 used_pages = el2_data->vm_info[vmid].used_pages;
	return pool_start + used_pages * PAGE_SIZE;
};

void __hyp_text set_pt_next(u32 vmid, u64 next) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	el2_data->vm_info[vmid].used_pages += next;
};

// TODO: make the following work
u64 __hyp_text pt_load(u32 vmid, u64 addr) {
	unsigned long *ptr = __el2_va(addr);
	return (u64)*ptr;
};

// TODO: make the following work
void __hyp_text pt_store(u32 vmid, u64 addr, u64 value) {
	unsigned long *ptr = __el2_va(addr);
	*ptr = value;
};

u64 __hyp_text get_pt_vttbr(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].vttbr;
};

void __hyp_text set_pt_vttbr(u32 vmid, u64 vttbr) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].vttbr = vttbr;
};

u32 __hyp_text get_mem_region_cnt(void) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->regions_cnt;
}

u64 __hyp_text get_mem_region_base(u32 index) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->regions[index].base;
}
u64 __hyp_text get_mem_region_size(u32 index) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->regions[index].size;
}

u64 __hyp_text get_mem_region_index(u32 index) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->s2_memblock_info[index].index;
}

u64 __hyp_text get_mem_region_flag(u32 index) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	return el2_data->regions[index].flags;
}

void __hyp_text acquire_lock_s2page(void) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    stage2_spin_lock(&el2_data->s2pages_lock);
}

void __hyp_text release_lock_s2page(void) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    stage2_spin_unlock(&el2_data->s2pages_lock);
}

u32 __hyp_text get_s2_page_vmid(u64 index) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->s2_pages[index].vmid;
}

void __hyp_text set_s2_page_vmid(u64 index, u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->s2_pages[index].vmid = vmid;
}

u32 __hyp_text get_s2_page_count(u64 index) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->s2_pages[index].count;
}

void __hyp_text set_s2_page_count(u64 index, u32 count) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->s2_pages[index].count = count;
}

void __hyp_text acquire_lock_vm(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    stage2_spin_lock(&el2_data->vm_info[vmid].vm_lock);
}

void __hyp_text release_lock_vm(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    stage2_spin_unlock(&el2_data->vm_info[vmid].vm_lock);
}

u32 __hyp_text get_vm_state(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].state;
}

void __hyp_text set_vm_state(u32 vmid, u32 state) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].state = state;
}

uint8_t* __hyp_text get_vm_public_key(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].public_key;
}

void __hyp_text set_vm_public_key(u32 vmid) {
    unsigned char *public_key_hex = "2ef2440a2b5766436353d07705b602bfab55526831460acb94798241f2104f3a";
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_hex2bin(el2_data->vm_info[vmid].public_key, public_key_hex, 32);
}

u32 __hyp_text get_vcpu_state(u32 vmid, u32 vcpuid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].int_vcpus[vcpuid].state;
}

void __hyp_text set_vcpu_state(u32 vmid, u32 vcpuid, u32 state) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].int_vcpus[vcpuid].state = state;
}

void __hyp_text set_vm_power(u32 vmid, u32 power) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].powered_on = power;
}

u32 __hyp_text get_vm_power(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].powered_on;
}

u32 __hyp_text get_vm_inc_exe(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].inc_exe;
}

void __hyp_text set_vm_inc_exe(u32 vmid, u32 inc_exe) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].inc_exe = inc_exe;
}

u64 __hyp_text get_vm_kvm(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return (u64)el2_data->vm_info[vmid].kvm;
}

void __hyp_text set_vm_kvm(u32 vmid, u64 kvm) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].kvm = (struct kvm*)kvm;
}

u64 __hyp_text get_vm_vcpu(u32 vmid, u32 vcpuid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return (u64)el2_data->vm_info[vmid].int_vcpus[vcpuid].vcpu;
}

void __hyp_text set_vm_vcpu(u32 vmid, u32 vcpuid, u64 vcpu) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].int_vcpus[vcpuid].vcpu = (struct kvm_vcpu*)vcpu;
}

u32 __hyp_text get_vm_next_load_idx(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].load_info_cnt;
}

void __hyp_text set_vm_next_load_idx(u32 vmid, u32 load_idx) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].load_info_cnt = load_idx;
}

u64 __hyp_text get_vm_load_addr(u32 vmid, u32 load_idx) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].load_info[load_idx].load_addr;
}

void __hyp_text set_vm_load_addr(u32 vmid, u32 load_idx, u64 load_addr) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].load_info[load_idx].load_addr = load_addr;
}

u64 __hyp_text get_vm_load_size(u32 vmid, u32 load_idx) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].load_info[load_idx].size;
}

void __hyp_text set_vm_load_size(u32 vmid, u32 load_idx, u64 size) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].load_info[load_idx].size = size;
}

u64 __hyp_text get_vm_remap_addr(u32 vmid, u32 load_idx) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].load_info[load_idx].el2_remap_addr;
}

void __hyp_text set_vm_remap_addr(u32 vmid, u32 load_idx, u64 remap_addr) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].load_info[load_idx].el2_remap_addr = remap_addr;
}

u64 __hyp_text get_vm_mapped_pages(u32 vmid, u32 load_idx) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].load_info[load_idx].el2_mapped_pages;
}

void __hyp_text set_vm_mapped_pages(u32 vmid, u32 load_idx, u64 mapped) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->vm_info[vmid].load_info[load_idx].el2_mapped_pages = mapped;
}

uint8_t* __hyp_text get_vm_load_signature(u32 vmid, u32 load_idx) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->vm_info[vmid].load_info[load_idx].signature;
}

void __hyp_text set_vm_load_signature(u32 vmid, u32 load_idx) {
    unsigned char *signature_hex = "35e9848eb618e7150566716662b2f7d8944f0a4e8582ddeb2b209d2bae6b63d5f51ebf1dc54742227e45f7bbb9d4ba1d1f83b52b87a4ce99180aa9a548e7dd05";
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_hex2bin(el2_data->vm_info[vmid].load_info[load_idx].signature,
		signature_hex, 64);
}

void __hyp_text acquire_lock_core(void) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    stage2_spin_lock(&el2_data->abs_lock);
}

void __hyp_text release_lock_core(void) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    stage2_spin_unlock(&el2_data->abs_lock);
}

u32 __hyp_text get_next_vmid(void) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->next_vmid;
}

void __hyp_text set_next_vmid(u32 vmid) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->next_vmid = vmid;
}

u64 __hyp_text get_next_remap_ptr(void) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    return el2_data->last_remap_ptr;
}

void __hyp_text set_next_remap_ptr(u64 remap) {
    struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
    el2_data->last_remap_ptr = remap;
}

u64 __hyp_text get_shadow_ctxt(u32 vmid, u32 vcpuid, u32 index)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	int offset = VCPU_IDX(vmid, vcpuid);
	u64 val;
	if (index < V_FAR_EL2)
		val = el2_data->shadow_vcpu_ctxt[offset].regs[index]; 
	else if (index == V_FAR_EL2)
		val = el2_data->shadow_vcpu_ctxt[offset].far_el2;
	else if (index == V_HPFAR_EL2)
		val = el2_data->shadow_vcpu_ctxt[offset].hpfar;
	else if (index == V_HCR_EL2)
		val = el2_data->shadow_vcpu_ctxt[offset].hcr_el2;
	else if (index == V_EC)
		val = el2_data->shadow_vcpu_ctxt[offset].ec;
	else if (index == V_DIRTY)
		val = el2_data->shadow_vcpu_ctxt[offset].dirty;
	else if (index == V_FLAGS)
		val = el2_data->shadow_vcpu_ctxt[offset].flags;
	else if (index >= SYSREGS_START) {
		index -= SYSREGS_START;
		val = el2_data->shadow_vcpu_ctxt[offset].sys_regs[index];
	} else {
		print_string("\rinvalid get shadow ctxt\n");
		val = INVALID64;
	}

	return val;
};

//TODO: Define the following
void __hyp_text set_shadow_ctxt(u32 vmid, u32 vcpuid, u32 index, u64 value) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	int offset = VCPU_IDX(vmid, vcpuid);
	//el2_data->shadow_vcpu_ctxt[offset].regs[index] = value;
	if (index < V_FAR_EL2)
		el2_data->shadow_vcpu_ctxt[offset].regs[index] = value; 
	else if (index == V_FAR_EL2)
		el2_data->shadow_vcpu_ctxt[offset].far_el2 = value;
	else if (index == V_HPFAR_EL2)
		el2_data->shadow_vcpu_ctxt[offset].hpfar = value;
	else if (index == V_HCR_EL2)
		el2_data->shadow_vcpu_ctxt[offset].hcr_el2 = value;
	else if (index == V_EC)
		el2_data->shadow_vcpu_ctxt[offset].ec = value;
	else if (index == V_DIRTY)
		el2_data->shadow_vcpu_ctxt[offset].dirty = value;
	else if (index == V_FLAGS)
		el2_data->shadow_vcpu_ctxt[offset].flags = value;
	else if (index >= SYSREGS_START) {
		index -= SYSREGS_START;
		el2_data->shadow_vcpu_ctxt[offset].sys_regs[index] = value;
	} else
		print_string("\rinvalid set shadow ctxt\n");
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

void __hyp_text clear_shadow_gp_regs(u32 vmid, u32 vcpuid) {
	struct el2_data *el2_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	el2_memset(el2_data->shadow_vcpu_ctxt[offset].regs,
			0, sizeof(struct kvm_regs));
}

void __hyp_text int_to_shadow_fp_regs(u32 vmid, u32 vcpuid) {

}

u32 __hyp_text get_shadow_dirty_bit(u32 vmid, u32 vcpuid) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	int offset = VCPU_IDX(vmid, vcpuid);
	return el2_data->shadow_vcpu_ctxt[offset].dirty;
}

void __hyp_text set_shadow_dirty_bit(u32 vmid, u32 vcpuid, u64 value) {
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	int offset = VCPU_IDX(vmid, vcpuid);
	if (value)
		el2_data->shadow_vcpu_ctxt[offset].dirty |= value;
	else
		el2_data->shadow_vcpu_ctxt[offset].dirty = 0;
}

bool __hyp_text get_int_writable(u32 vmid, u32 vcpuid) {
	struct shared_data *shared_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	struct kvm_vcpu *vcpu;
	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	vcpu = &shared_data->vcpu_pool[offset];
	return vcpu->arch.walk_result.writable;
}

u64 __hyp_text get_int_new_pte(u32 vmid, u32 vcpuid) {
	struct shared_data *shared_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	struct kvm_vcpu *vcpu;
	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	vcpu = &shared_data->vcpu_pool[offset];
	return vcpu->arch.walk_result.output;
}

u32 __hyp_text get_int_new_level(u32 vmid, u32 vcpuid) {
	struct shared_data *shared_data;
	int offset = VCPU_IDX(vmid, vcpuid);
	struct kvm_vcpu *vcpu;
	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	vcpu = &shared_data->vcpu_pool[offset];
	return vcpu->arch.walk_result.level;
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

void __hyp_text clear_phys_page(unsigned long pfn)
{
	unsigned long addr = __el2_va(pfn << PAGE_SHIFT);
	el2_memset((void *)addr, 0, PAGE_SIZE);
}

u32 __hyp_text verify_image(u32 vmid, u32 load_idx, u64 addr) {
    uint8_t* signature;
    uint8_t* public_key;
    int result = 0;
    u64 size;
    uint8_t signature1[64], key[32];

    size = get_vm_load_size(vmid, load_idx);
    public_key = get_vm_public_key(vmid);
    signature = get_vm_load_signature(vmid, load_idx);
    print_string("\rverifying image:\n");
    //printhex_ul(size);
    result = Hacl_Ed25519_verify(public_key, size, (uint8_t *)addr, signature);
    //result = Hacl_Ed25519_verify(key, size, (char *)addr, signature1);
    print_string("\r[result]\n");
    printhex_ul(result);
    return 1;
}
#if 0
void    int_to_shadow_decrypt(u32 vmid, u32 vcpuid);
void    shadow_to_int_encrypt(u32 vmid, u32 vcpuid);
#endif
