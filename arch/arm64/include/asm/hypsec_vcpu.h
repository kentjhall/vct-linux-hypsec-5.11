#ifndef __ARM_STAGE2_VCPU__
#define __ARM_STAGE2_VCPU__

struct s2_host_regs {
	u64 regs[32];
};

struct s2_cpu_arch {
	u64 host_hcr_el2;
	u64 host_vttbr_el2;
};

struct s2_sys_reg_params {
	u8	Op0;
	u8	Op1;
	u8	CRn;
	u8	CRm;
	u8	Op2;
	u64	regval;
	bool	is_write;
	bool	is_aarch32;
	bool	is_32bit;	/* Only valid if is_aarch32 is true */
};

struct s2_sys_reg_desc {
	/* MRS/MSR instruction which accesses it. */
	u8	Op0;
	u8	Op1;
	u8	CRn;
	u8	CRm;
	u8	Op2;

	/* Index into sys_reg[], or 0 if we don't need to save it. */
	int reg;
	u64 val;
};


void __save_shadow_kvm_regs(struct kvm_vcpu *vcpu, u64 ec);
void __restore_shadow_kvm_regs(struct kvm_vcpu *vcpu);

void update_exception_gp_regs(struct kvm_vcpu *vcpu);
extern int sec_el2_handle_sys_reg(struct kvm_vcpu *vcpu, u32 esr);

void __save_encrypted_vcpu(u32 vmid, int vcpu_id);
void __update_exception_shadow_flag(struct kvm_vcpu *vcpu, int exp);
#endif /* __ARM_STAGE2_H__ */
