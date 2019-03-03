#include <linux/types.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>
#include <linux/mman.h>
#include <linux/kvm_host.h>
#include <linux/io.h>
#include <trace/events/kvm.h>
#include <asm/pgalloc.h>
#include <asm/cacheflush.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_mmio.h>
#include <asm/kvm_emulate.h>
#include <asm/virt.h>
#include <asm/kernel-pgtable.h>
#include <asm/hypsec_host.h>
#include <uapi/linux/psci.h>

static void __hyp_text get_crypt_buf(__u64 *buf,
				     struct kvm_regs *kvm_regs)
{
	buf[0] = kvm_regs->regs.pc;
	buf[1] = kvm_regs->sp_el1;
	buf[2] = kvm_regs->elr_el1;
	buf[3] = kvm_regs->spsr[0];
	buf[4] = kvm_regs->spsr[1];
	buf[5] = kvm_regs->spsr[2];
	buf[6] = kvm_regs->spsr[3];
	buf[7] = kvm_regs->spsr[4];
}

static void __hyp_text put_crypt_buf(__u64 *buf,
				     struct kvm_regs *kvm_regs)
{
	 kvm_regs->regs.pc = buf[0];
	 kvm_regs->sp_el1  = buf[1];
	 kvm_regs->elr_el1 = buf[2];
	 kvm_regs->spsr[0] = buf[3];
	 kvm_regs->spsr[1] = buf[4];
	 kvm_regs->spsr[2] = buf[5];
	 kvm_regs->spsr[3] = buf[6];
	 kvm_regs->spsr[4] = buf[7];
}

static void __hyp_text encrypt_kvm_regs(u32 vmid,
					struct kvm_regs *kvm_regs)
{
	struct user_pt_regs *regs = &kvm_regs->regs;
	__u64 buf[8];

	encrypt_buf(vmid, regs, sizeof(__u64) * 32);

	get_crypt_buf(buf, kvm_regs);
	encrypt_buf(vmid, buf, sizeof(__u64) * 8);
	put_crypt_buf(buf, kvm_regs);

	encrypt_buf(vmid, &kvm_regs->fp_regs, sizeof(struct user_fpsimd_state));
}

static void __hyp_text decrypt_kvm_regs(u32 vmid, struct kvm_regs *kvm_regs)
{
	struct user_pt_regs *regs = &kvm_regs->regs;
	__u64 buf[8];

	// sizeof(regs[31] + sp + pc), all in __u64
	decrypt_buf(vmid, regs, sizeof(__u64) * 32);

	get_crypt_buf(buf, kvm_regs);
	decrypt_buf(vmid, buf, sizeof(__u64) * 8);
	put_crypt_buf(buf, kvm_regs);

	decrypt_buf(vmid, &kvm_regs->fp_regs, sizeof(struct user_fpsimd_state));
}

static void __hyp_text prep_hvc(struct kvm_vcpu *vcpu)
{
	/* We care only about hvc for psci now. */
	struct shadow_vcpu_context *shadow_ctxt =
		vcpu->arch.shadow_vcpu_ctxt;
	struct kvm_regs *gp_regs = &shadow_ctxt->gp_regs;
	unsigned long psci_fn = gp_regs->regs.regs[0] & ~((u32) 0);
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));

	/* PSCI updates x0 for return value */
	shadow_ctxt->dirty |= (1UL << 0);

	vcpu_set_reg(vcpu, 0, gp_regs->regs.regs[0]);

	switch (psci_fn) {
		case PSCI_0_2_FN64_CPU_ON:
			vcpu_set_reg(vcpu, 1, gp_regs->regs.regs[1]);
			vcpu_set_reg(vcpu, 2, gp_regs->regs.regs[2]);
			vcpu_set_reg(vcpu, 3, gp_regs->regs.regs[3]);
			break;
		case PSCI_0_2_FN_AFFINITY_INFO:
		case PSCI_0_2_FN64_AFFINITY_INFO:
			vcpu_set_reg(vcpu, 1, gp_regs->regs.regs[1]);
			vcpu_set_reg(vcpu, 2, gp_regs->regs.regs[2]);
			break;
		case PSCI_0_2_FN_SYSTEM_OFF:
			el2_data->vm_info[vcpu->arch.vmid].powered_on = false;
			break;
		default:
			break;
	}
}

static void __hyp_text prep_wfx(struct kvm_vcpu *vcpu)
{
	// We should make sure we skip the WFx instruction later
	struct shadow_vcpu_context *shadow_ctxt = vcpu->arch.shadow_vcpu_ctxt;
	shadow_ctxt->dirty |= DIRTY_PC_FLAG;
}

static void __hyp_text prep_sys_reg(struct kvm_vcpu *vcpu, u32 esr)
{
	struct shadow_vcpu_context *shadow_ctxt =
		vcpu->arch.shadow_vcpu_ctxt;
	struct kvm_regs *gp_regs = &shadow_ctxt->gp_regs;
	int Rt = (esr >> 5) & 0x1f, ret;
	bool is_write = !(esr & 1);

	vcpu_set_reg(vcpu, Rt, gp_regs->regs.regs[Rt]);

	ret = sec_el2_handle_sys_reg(vcpu, esr);

	shadow_ctxt->dirty = 0;
	smp_wmb();
	shadow_ctxt->dirty |= DIRTY_PC_FLAG;
	if (!is_write) {
		if (ret > 0)
			gp_regs->regs.regs[Rt] = shadow_ctxt->sys_regs[ret];
		/* The guest can trap on accessing id, debug, pmu registers */
		else
			shadow_ctxt->dirty |= (1UL << Rt);
	} else {
		if (ret > 0)
			shadow_ctxt->sys_regs[ret] = gp_regs->regs.regs[Rt];
	}
}

static void __hyp_text prep_abort(struct kvm_vcpu *vcpu)
{
	struct shadow_vcpu_context *shadow_ctxt =
		vcpu->arch.shadow_vcpu_ctxt;
	struct kvm_regs *gp_regs = &shadow_ctxt->gp_regs;
	int Rd = hypsec_vcpu_dabt_get_rd(vcpu);
	phys_addr_t fault_ipa = (read_sysreg(hpfar_el2) & HPFAR_MASK) << 8;

	/* We only have to care about regiters if it's MMIO */
	if (!is_mmio_gpa(fault_ipa))
		return;

	shadow_ctxt->dirty |= DIRTY_PC_FLAG;
	if (hypsec_vcpu_dabt_iswrite(vcpu))
		vcpu_set_reg(vcpu, Rd, gp_regs->regs.regs[Rd]);
	else
		shadow_ctxt->dirty |= (1UL << Rd);
}

static void __hyp_text sync_dirty_to_shadow(struct kvm_vcpu *vcpu)
{
	struct shadow_vcpu_context *shadow_ctxt =
		vcpu->arch.shadow_vcpu_ctxt;
	struct kvm_regs *gp_regs = &shadow_ctxt->gp_regs;
	int i;

	if (!shadow_ctxt->dirty)
		return;

	for (i = 0; i < 31; i++)
		if (shadow_ctxt->dirty & (1UL << i))
			gp_regs->regs.regs[i] = vcpu_get_reg(vcpu, i);
}

static void __hyp_text el2_prepare_exit_ctxt(struct kvm_vcpu *vcpu, u32 hsr)
{
	u8 hsr_ec = ESR_ELx_EC(hsr);

	switch (hsr_ec) {
		case ESR_ELx_EC_WFx:
			prep_wfx(vcpu);
			break;
		case ESR_ELx_EC_HVC32:
		case ESR_ELx_EC_HVC64:
			prep_hvc(vcpu);
			break;
		case ESR_ELx_EC_SYS64:
			prep_sys_reg(vcpu, hsr);
			break;
		case ESR_ELx_EC_IABT_LOW:
		case ESR_ELx_EC_DABT_LOW:
			prep_abort(vcpu);
			break;
		case ESR_ELx_EC_CP15_32:
		case ESR_ELx_EC_CP15_64:
		case ESR_ELx_EC_CP14_MR:
		case ESR_ELx_EC_CP14_LS:
		case ESR_ELx_EC_CP14_64:
		case ESR_ELx_EC_SMC32:
		case ESR_ELx_EC_SMC64:
		case ESR_ELx_EC_SOFTSTP_LOW:
		case ESR_ELx_EC_WATCHPT_LOW:
		case ESR_ELx_EC_BREAKPT_LOW:
		case ESR_ELx_EC_BKPT32:
		case ESR_ELx_EC_BRK64:
			hypsec_inject_undef(vcpu);
			break;
		default:
			print_string("\runknown exception\n");
			hypsec_inject_undef(vcpu);
	}
}

void __hyp_text el2_save_sys_regs_32(struct kvm_vcpu *vcpu,
				     struct shadow_vcpu_context *shadow_ctxt)
{
	/* save to shadow sysregs */
	shadow_ctxt->sys_regs[DACR32_EL2] = vcpu->arch.ctxt.sys_regs[DACR32_EL2];
	shadow_ctxt->sys_regs[IFSR32_EL2] = vcpu->arch.ctxt.sys_regs[IFSR32_EL2];
	shadow_ctxt->sys_regs[FPEXC32_EL2] = vcpu->arch.ctxt.sys_regs[FPEXC32_EL2];

	/* clear the vcpu entries */
	vcpu->arch.ctxt.sys_regs[DACR32_EL2] = 0;
	vcpu->arch.ctxt.sys_regs[IFSR32_EL2] = 0;
	vcpu->arch.ctxt.sys_regs[FPEXC32_EL2] = 0;
}

void __hyp_text el2_restore_sys_regs_32(struct kvm_vcpu *vcpu,
					struct shadow_vcpu_context *shadow_ctxt)
{
	/* restore to vcpu from shadow entries */
	vcpu->arch.ctxt.sys_regs[DACR32_EL2] = shadow_ctxt->sys_regs[DACR32_EL2];
	vcpu->arch.ctxt.sys_regs[IFSR32_EL2] = shadow_ctxt->sys_regs[IFSR32_EL2];
	vcpu->arch.ctxt.sys_regs[FPEXC32_EL2] = shadow_ctxt->sys_regs[FPEXC32_EL2];
}

static u64 __hyp_text el2_reset_mpidr(struct kvm_vcpu *vcpu)
{
	u64 mpidr;
	mpidr = (vcpu->vcpu_id & 0x0f) << MPIDR_LEVEL_SHIFT(0);
	mpidr |= ((vcpu->vcpu_id >> 4) & 0xff) << MPIDR_LEVEL_SHIFT(1);
	mpidr |= ((vcpu->vcpu_id >> 12) & 0xff) << MPIDR_LEVEL_SHIFT(2);
	return ((1ULL << 31) | mpidr);
}

static void __hyp_text el2_reset_sysregs(struct kvm_vcpu *vcpu,
					 struct shadow_vcpu_context *shadow_ctxt,
					 struct el2_data *el2_data)
{
	int i;
	u64 val;

	for (i = 1; i <= SHADOW_SYS_REGS_SIZE; i++) {
		if (i == MPIDR_EL1)
			val = el2_reset_mpidr(vcpu);
		else if (i == ACTLR_EL1)
			val = read_sysreg(actlr_el1);
		else
			val = el2_data->s2_sys_reg_descs[i].val;

		shadow_ctxt->sys_regs[i] = val;
	}
}

static void __hyp_text el2_reset_gp_regs(struct kvm_vcpu *vcpu,
					 struct shadow_vcpu_context *shadow_ctxt)
{
	struct kvm_regs *kvm_regs = &vcpu->arch.ctxt.gp_regs;
	__u64 pc = kvm_regs->regs.pc;
	struct el2_data *el2_data;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));

	el2_memset(&shadow_ctxt->gp_regs, 0, sizeof(struct kvm_regs));
	shadow_ctxt->gp_regs.regs.pstate = kvm_regs->regs.pstate;

	if (search_load_info(vcpu->arch.vmid, el2_data, pc))
		shadow_ctxt->gp_regs.regs.pc = pc;
	else
		__hyp_panic();

	el2_memcpy(&shadow_ctxt->gp_regs.fp_regs, &kvm_regs->fp_regs,
					sizeof(struct user_fpsimd_state));
}

void __hyp_text __save_shadow_kvm_regs(struct kvm_vcpu *vcpu, u64 ec)
{
	struct shadow_vcpu_context *shadow_ctxt = vcpu->arch.shadow_vcpu_ctxt;
	shadow_ctxt->ec = ec;

	switch (ec) {
		case ARM_EXCEPTION_TRAP:
			el2_prepare_exit_ctxt(vcpu, shadow_ctxt->esr);
			break;
		case ARM_EXCEPTION_IRQ:
		case ARM_EXCEPTION_EL1_SERROR:
		default:
			break;
	};
}

void __hyp_text __restore_shadow_kvm_regs(struct kvm_vcpu *vcpu)
{
	struct shadow_vcpu_context *shadow_ctxt = vcpu->arch.shadow_vcpu_ctxt;
	u64 ec;
	size_t shadow_sys_regs_len = sizeof(u64) * (SHADOW_SYS_REGS_SIZE + 1);
	struct el2_data *el2_data;

	/*
	 * We don't have anything to restore when entering the
	 * guest for the first time..
	 */
	if (shadow_ctxt->dirty == -1) {
		el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
		if (el2_use_inc_exe(vcpu->arch.vmid)) {
			decrypt_kvm_regs(vcpu->arch.vmid, &vcpu->arch.ctxt.gp_regs);
			decrypt_buf(vcpu->arch.vmid, &vcpu->arch.ctxt.sys_regs,
					shadow_sys_regs_len);
			el2_memcpy(&shadow_ctxt->sys_regs, &vcpu->arch.ctxt.sys_regs,
					shadow_sys_regs_len);
			el2_memset(&vcpu->arch.ctxt.sys_regs, 0, shadow_sys_regs_len);
			el2_memcpy(&shadow_ctxt->gp_regs, &vcpu->arch.ctxt.gp_regs,
					sizeof(struct kvm_regs));
			el2_memset(&vcpu->arch.ctxt.gp_regs, 0, sizeof(struct kvm_regs));
		} else {
			el2_reset_gp_regs(vcpu, shadow_ctxt);
			el2_reset_sysregs(vcpu, shadow_ctxt, el2_data);
		}

		el2_save_sys_regs_32(vcpu, shadow_ctxt);
		shadow_ctxt->dirty = 0;

		if (!el2_data->vm_info[vcpu->arch.vmid].powered_on)
			el2_data->vm_info[vcpu->arch.vmid].powered_on = true;

		return;
	}

	ec = shadow_ctxt->ec;
	switch (ec) {
		case ARM_EXCEPTION_TRAP:
			sync_dirty_to_shadow(vcpu);
			break;
		case ARM_EXCEPTION_IRQ:
		case ARM_EXCEPTION_EL1_SERROR:
		default:
			break;
	};

	if (shadow_ctxt->dirty & PENDING_EXCEPT_INJECT_FLAG)
		update_exception_gp_regs(vcpu);

	if (shadow_ctxt->dirty & DIRTY_PC_FLAG)
		*shadow_vcpu_pc(vcpu) += 4;

	shadow_ctxt->dirty = 0;
	shadow_ctxt->far_el2 = 0;

	if (shadow_ctxt->hpfar)
		post_handle_shadow_s2pt_fault(vcpu, shadow_ctxt->hpfar);
	shadow_ctxt->hpfar = 0;
}

void __hyp_text __save_encrypted_vcpu(u32 vmid, int vcpu_id)
{
	struct kvm_vcpu *vcpu = hypsec_vcpu_id_to_vcpu(vmid, vcpu_id);
	struct shadow_vcpu_context *shadow_ctxt;
	size_t shadow_sys_regs_len = sizeof(u64) * (SHADOW_SYS_REGS_SIZE + 1);
	struct kvm_regs gp_local;
	u64 sr_local[SHADOW_SYS_REGS_SIZE + 1];

	shadow_ctxt = vcpu->arch.shadow_vcpu_ctxt;

	el2_memcpy(&gp_local, &shadow_ctxt->gp_regs, sizeof(struct kvm_regs));
	el2_memcpy(sr_local, &shadow_ctxt->sys_regs, shadow_sys_regs_len);

	encrypt_kvm_regs(vmid, &gp_local);
	encrypt_buf(vmid, sr_local, shadow_sys_regs_len);
	gp_local.regs.pstate = *shadow_vcpu_cpsr(vcpu);

	el2_memcpy(&vcpu->arch.ctxt.gp_regs, &gp_local,
					sizeof(struct kvm_regs));
	el2_memcpy(&vcpu->arch.ctxt.sys_regs, sr_local,
					shadow_sys_regs_len);
}

void save_encrypted_vcpu(struct kvm_vcpu *vcpu)
{
	kvm_call_core((void *)HVC_SAVE_CRYPT_VCPU,
			vcpu->kvm->arch.vmid, vcpu->vcpu_id);
}
