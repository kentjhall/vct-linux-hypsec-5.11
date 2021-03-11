
/*
 * Copyright (C) 2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#include <hyp/adjust_pc.h>
#include <hyp/switch.h>
#include <hyp/sysreg-sr.h>

#include <linux/arm-smccc.h>
#include <linux/kvm_host.h>
#include <linux/types.h>
#include <linux/jump_label.h>
#include <uapi/linux/psci.h>

#include <kvm/arm_psci.h>

#include <asm/barrier.h>
#include <asm/cpufeature.h>
#include <asm/kprobes.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/fpsimd.h>
#include <asm/debug-monitors.h>
#include <asm/processor.h>
#include <asm/thread_info.h>
#include <asm/hypsec_host.h>
#include <asm/hypsec_constant.h>

#include "switch-simple.h"

/* Non-VHE specific context */
DEFINE_PER_CPU(struct kvm_host_data, kvm_host_data);
DEFINE_PER_CPU(struct kvm_cpu_context, kvm_hyp_ctxt);
DEFINE_PER_CPU(unsigned long, kvm_hyp_vector);
DEFINE_PER_CPU(struct kvm_cpu_context *, shadow_ctxt_ptr);

static void ___activate_traps_common(struct kvm_vcpu *vcpu)
{
	/*
	 * Make sure we trap PMU access from EL0 to EL2. Also sanitize
	 * PMSELR_EL0 to make sure it never contains the cycle
	 * counter, which could make a PMXEVCNTR_EL0 access UNDEF at
	 * EL1 instead of being trapped to EL2.
	 */
	set_pmselr_el0(0);
	set_pmuserenr_el0(ARMV8_PMU_USERENR_MASK);

	set_mdcr_el2(0);
}

static void ___deactivate_traps_common(void)
{
	set_pmuserenr_el0(0);
}

static void __activate_traps(struct kvm_vcpu *vcpu)
{
	u64 hcr = HCR_HYPSEC_VM_FLAGS;
	u64 val;

	if (vcpu->arch.hcr_el2 & HCR_VI)
		hcr |= HCR_VI;

	if (vcpu->arch.hcr_el2 & HCR_VF)
		hcr |= HCR_VF;

	set_hcr_el2(hcr);
	
	___activate_traps_common(vcpu);

	val = CPTR_EL2_DEFAULT;
	val |= CPTR_EL2_TTA | CPTR_EL2_TZ;

	set_cptr_el2(val);
	write_sysreg(__this_cpu_read(kvm_hyp_vector), vbar_el2);
}

static void __deactivate_traps(struct kvm_vcpu *vcpu)
{
	extern char __kvm_hyp_host_vector[];

	___deactivate_traps_common();
	/*
	 * Don't trap host access to debug related registers
	 * but clear all available counters.
	 */
	set_mdcr_el2(0);

	set_cptr_el2(CPTR_EL2_DEFAULT);
	write_sysreg(__kvm_hyp_host_vector, vbar_el2);
}

static void ___load_guest_stage2(u64 vmid)
{
	//u64 shadow_vttbr = get_shadow_vttbr((u32)vmid);
	u64 shadow_vttbr = get_pt_vttbr((u32)vmid);
	set_vttbr_el2(shadow_vttbr);	
}

static void __load_host_stage2(void)
{
}

/* Save VGICv3 state on non-VHE systems */
static void __hyp_vgic_save_state(struct kvm_vcpu *vcpu)
{
}

/* Restore VGICv3 state on non_VEH systems */
static void __hyp_vgic_restore_state(struct kvm_vcpu *vcpu)
{
}

static bool ___translate_far_to_hpfar(u64 far, u64 *hpfar)
{
	u64 par, tmp;

	/*
	 * Resolve the IPA the hard way using the guest VA.
	 *
	 * Stage-1 translation already validated the memory access
	 * rights. As such, we can use the EL1 translation regime, and
	 * don't have to distinguish between EL0 and EL1 access.
	 *
	 * We do need to save/restore PAR_EL1 though, as we haven't
	 * saved the guest context yet, and we may return early...
	 */
	par = read_sysreg(par_el1);
	asm volatile("at s1e1r, %0" : : "r" (far));
	isb();

	tmp = read_sysreg(par_el1);
	write_sysreg(par, par_el1);

	if (unlikely(tmp & 1))
		return false; /* Translation failed, back to guest */

	/* Convert PAR to HPFAR format */
	*hpfar = ((tmp >> 12) & ((1UL << 36) - 1)) << 4;
	return true;
}

static inline bool ___populate_fault_info(struct kvm_vcpu *vcpu, u64 esr,
		                         struct shadow_vcpu_context *shadow_ctxt)
{
	u64 hpfar, far = get_far_el2();

	/*
	 * The HPFAR can be invalid if the stage 2 fault did not
	 * happen during a stage 1 page table walk (the ESR_EL2.S1PTW
	 * bit is clear) and one of the two following cases are true:
	 *   1. The fault was due to a permission fault
	 *   2. The processor carries errata 834220
	 *
	 * Therefore, for all non S1PTW faults where we either have a
	 * permission fault or the errata workaround is enabled, we
	 * resolve the IPA using the AT instruction.
	 */
	if (!(esr & ESR_ELx_S1PTW) &&
	    (cpus_have_final_cap(ARM64_WORKAROUND_834220) ||
	     (esr & ESR_ELx_FSC_TYPE) == FSC_PERM)) {
		if (!___translate_far_to_hpfar(far, &hpfar))
			return false;
	} else {
		hpfar = get_hpfar_el2();
	}

	vcpu->arch.fault.far_el2 = far;
	vcpu->arch.fault.hpfar_el2 = hpfar;
	shadow_ctxt->far_el2 = far;
	shadow_ctxt->hpfar = hpfar;

	if ((esr & ESR_ELx_FSC_TYPE) == FSC_FAULT) {
		/*
		 * Here we'd like to avoid calling handle_shadow_s2pt_fault
		 * twice if it's GPA belongs to MMIO region. Since no mapping
		 * should be built anyway.
		 */
		if (!is_mmio_gpa((hpfar & HPFAR_MASK) << 8)) {
			el2_memset(&vcpu->arch.walk_result, 0, sizeof(struct s2_trans));
			shadow_ctxt->flags |= PENDING_FSC_FAULT;
		}
	}

	return true;
}

/*
 * Return true when we were able to fixup the guest exit and should return to
 * the guest, false when we should restore the host state and return to the
 * main run loop.
 */
static inline bool _fixup_guest_exit(struct kvm_vcpu *vcpu, u64 *exit_code,
						u32 vmid, u32 vcpuid)
{
	u32 esr_el2 = 0;
	u8 ec;
	struct shadow_vcpu_context *shadow_ctxt;

	shadow_ctxt = hypsec_vcpu_id_to_shadow_ctxt(vmid, vcpuid);
	if (ARM_EXCEPTION_CODE(*exit_code) != ARM_EXCEPTION_IRQ) {
		esr_el2 = get_esr_el2();
		vcpu->arch.fault.esr_el2 = esr_el2;
		shadow_ctxt->esr = esr_el2;
	}

	if (ARM_SERROR_PENDING(*exit_code)) {
		u8 esr_ec = kvm_vcpu_trap_get_class(vcpu);

		/*
		 * HVC already have an adjusted PC, which we need to
		 * correct in order to return to after having injected
		 * the SError.
		 *
		 * SMC, on the other hand, is *trapped*, meaning its
		 * preferred return address is the SMC itself.
		 */
		if (esr_ec == ESR_ELx_EC_HVC32 || esr_ec == ESR_ELx_EC_HVC64)
			write_sysreg_el2(read_sysreg_el2(SYS_ELR) - 4, SYS_ELR);
	}

	/*
	 * We're using the raw exception code in order to only process
	 * the trap if no SError is pending. We will come back to the
	 * same PC once the SError has been injected, and replay the
	 * trapping instruction.
	 */
	if (*exit_code != ARM_EXCEPTION_TRAP)
		goto exit;

	ec = ESR_ELx_EC(esr_el2);
	if (ec == ESR_ELx_EC_HVC64) {
		if (handle_pvops(vmid, vcpuid) > 0)
			goto guest;
		else
			goto exit;
	} else if (ec == ESR_ELx_EC_DABT_LOW || ec == ESR_ELx_EC_IABT_LOW) {
		if (!___populate_fault_info(vcpu, esr_el2, shadow_ctxt))
			goto guest;
	} else if (ec == ESR_ELx_EC_SYS64) {
		u64 elr = read_sysreg(elr_el2);
		write_sysreg(elr + 4, elr_el2);
		goto guest;
	}

exit:
	/* Return to the host kernel and handle the exit */
	return false;

guest:
	/* Re-enter the guest */
	return true;
}

static void __host_el2_restore_state(struct el2_data *el2_data)
{
	set_vttbr_el2(el2_data->host_vttbr);
	set_hcr_el2(HCR_HYPSEC_HOST_NVHE_FLAGS);
}

/* Switch to the guest for legacy non-VHE systems */
int __kvm_vcpu_run(u32 vmid, int vcpu_id)
{
	u64 exit_code;
	struct kvm_cpu_context *host_ctxt;
	struct el2_data *el2_data;
	struct kvm_vcpu *vcpu;
	struct shadow_vcpu_context *prot_ctxt;

	/* check if vm is verified and vcpu is already active. */
	hypsec_set_vcpu_active(vmid, vcpu_id);
	set_per_cpu_nvhe(vmid, vcpu_id);

	vcpu = hypsec_vcpu_id_to_vcpu(vmid, vcpu_id);
	prot_ctxt = hypsec_vcpu_id_to_shadow_ctxt(vmid, vcpu_id);

	el2_data = kern_hyp_va((void *)&el2_data_start);
	host_ctxt = &this_cpu_ptr(&kvm_host_data)->host_ctxt;
	host_ctxt->__hyp_running_vcpu = vcpu;
	__this_cpu_write(shadow_ctxt_ptr, (struct kvm_cpu_context *)prot_ctxt);

	__sysreg_save_state_nvhe(host_ctxt);

	restore_shadow_kvm_regs();

	__activate_traps(vcpu);
	___load_guest_stage2(vmid & 0xff);
	if (vcpu->arch.was_preempted) {
		hypsec_tlb_flush_local_vmid();
		vcpu->arch.was_preempted = false;
	}

	__hyp_vgic_restore_state(vcpu);
	__timer_enable_traps(vcpu);

	/*
	 * We must restore the 32-bit state before the sysregs, thanks
	 * to erratum #852523 (Cortex-A57) or #853709 (Cortex-A72).
	 *
	 * Also, and in order to be able to deal with erratum #1319537 (A57)
	 * and #1319367 (A72), we must ensure that all VM-related sysreg are
	 * restored before we enable S2 translation.
	 */
	__sysreg32_restore_state(vcpu);
	__vm_sysreg_restore_state_nvhe_opt(prot_ctxt);	

	__fpsimd_save_state(&host_ctxt->fp_regs);
	__fpsimd_restore_state(&prot_ctxt->fp_regs);

	do {
		/* Jump in the fire! */
		exit_code = __guest_enter(vcpu);

		/* And we're baaack! */
	} while (_fixup_guest_exit(vcpu, &exit_code, vmid, vcpu_id));

	__vm_sysreg_save_state_nvhe_opt(prot_ctxt);
	__sysreg32_save_state(vcpu);
	__timer_disable_traps(vcpu);
	__hyp_vgic_save_state(vcpu);

	__deactivate_traps(vcpu);
	__load_host_stage2();
	__host_el2_restore_state(el2_data);

	__sysreg_restore_state_nvhe(host_ctxt);

	__fpsimd_save_state(&prot_ctxt->fp_regs);
	__fpsimd_restore_state(&host_ctxt->fp_regs);

	set_shadow_ctxt(vmid, vcpu_id, V_EC, exit_code);
	save_shadow_kvm_regs();

	set_per_cpu_nvhe(0, read_cpuid_mpidr() & MPIDR_HWID_BITMASK);
	hypsec_set_vcpu_state(vmid, vcpu_id, READY);

	host_ctxt->__hyp_running_vcpu = NULL;
	return exit_code;
}

void __noreturn hyp_panic(void)
{
	u64 spsr = read_sysreg_el2(SYS_SPSR);
	u64 elr = read_sysreg_el2(SYS_ELR);
	u64 par = read_sysreg_par();
	bool restore_host = true;
	struct kvm_cpu_context *host_ctxt;
	struct kvm_vcpu *vcpu;

	host_ctxt = &this_cpu_ptr(&kvm_host_data)->host_ctxt;
	vcpu = host_ctxt->__hyp_running_vcpu;

	if (vcpu) {
		__timer_disable_traps(vcpu);
		__deactivate_traps(vcpu);
		__load_host_stage2();
		__sysreg_restore_state_nvhe(host_ctxt);
	}

	__hyp_do_panic(restore_host, spsr, elr, par);
	unreachable();
}

asmlinkage void kvm_unexpected_el2_exception(void)
{
	return __kvm_unexpected_el2_exception();
}
