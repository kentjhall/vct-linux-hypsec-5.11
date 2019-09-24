static int hypsec_register_kvm(void) {return 0;};
static int hypsec_register_vcpu(u32 vmid, int vcpu_id) {return 0;};
static struct kvm* __hyp_text hypsec_alloc_vm(u32 vmid) {return NULL;};

int __hyp_text hypsec_set_vcpu_active(u32 vmid, int vcpu_id) {return 0;}
struct kvm* __hyp_text hypsec_vmid_to_kvm(u32 vmid) {return NULL;};
struct kvm_vcpu* __hyp_text hypsec_vcpu_id_to_vcpu(u32 vmid, int vcpu_id) {return NULL;};
struct shadow_vcpu_context* __hyp_text hypsec_vcpu_id_to_shadow_ctxt(u32 vmid, int vcpu_id) {return NULL;};

void __restore_shadow_kvm_regs(struct kvm_vcpu *vcpu,
			       struct shadow_vcpu_context *shadow_ctxt) {};

void update_exception_gp_regs(struct shadow_vcpu_context *shadow_ctxt);
extern int sec_el2_handle_sys_reg(u32 esr);

u64 __hyp_text get_shadow_vttbr(u32 vmid)
{
	//struct el2_vm_info *vm_info = vmid_to_vm_info(vmid);
	//return vm_info->vttbr;
	return 0;
}

void __save_shadow_kvm_regs(struct kvm_vcpu *vcpu,
			    struct shadow_vcpu_context *shadow_ctxt, u64 ec) {};

void __hyp_text hypsec_set_vcpu_state(u32 vmid, int vcpu_id, int state) {};

void el2_memset(void *b, int c, int len);
void el2_memcpy(void *dest, void *src, size_t len);
