/*
 * Copyright (C) 2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This file is a simplified version of switch.c for verfication.
 * We currently do not support 32-bit VM, debugging support, RAS extn,
 * PMU, VHE, and SVE.
 */

#include <linux/arm-smccc.h>
#include <linux/types.h>
#include <linux/jump_label.h>
#include <uapi/linux/psci.h>

#include <kvm/arm_psci.h>

#include <asm/cpufeature.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_host.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/fpsimd.h>
#include <asm/debug-monitors.h>
#include <asm/processor.h>
#include <asm/thread_info.h>
#include <asm/hypsec_host.h>

#include "switch-simple.h"

/* Check whether the FP regs were dirtied while in the host-side run loop: */
static bool __hyp_text update_fp_enabled(struct kvm_vcpu *vcpu)
{
	return !!(vcpu->arch.flags & KVM_ARM64_FP_ENABLED);
}

/* We don't support 32-bit VM so no need to save FPSIMD system register state */
static void __hyp_text __fpsimd_save_fpexc32(struct kvm_vcpu *vcpu)
{
}

/* We don't support 32-bit VM so no need to set FPEXC.EN here */
static void __hyp_text __activate_traps_fpsimd32(struct kvm_vcpu *vcpu)
{
	/*
	 * We are about to set CPTR_EL2.TFP to trap all floating point
	 * register accesses to EL2, however, the ARM ARM clearly states that
	 * traps are only taken to EL2 if the operation would not otherwise
	 * trap to EL1.  Therefore, always make sure that for 32-bit guests,
	 * we set FPEXC.EN to prevent traps to EL1, when setting the TFP bit.
	 * If FP/ASIMD is not implemented, FPEXC is UNDEFINED and any access to
	 * it will cause an exception.
	 */
}

static void __hyp_text __activate_traps_common(struct kvm_vcpu *vcpu)
{
	u64 mdcr_el2 = read_sysreg(mdcr_el2);
	/* Trap on AArch32 cp15 c15 (impdef sysregs) accesses (EL1 or EL0) */
	set_hstr_el2(1 << 15);

	/*
	 * Make sure we trap PMU access from EL0 to EL2. Also sanitize
	 * PMSELR_EL0 to make sure it never contains the cycle
	 * counter, which could make a PMXEVCNTR_EL0 access UNDEF at
	 * EL1 instead of being trapped to EL2.
	 */
	set_pmselr_el0(0);
	set_pmuserenr_el0(ARMV8_PMU_USERENR_MASK);

	mdcr_el2 &= MDCR_EL2_HPMN_MASK;
	mdcr_el2 |= (MDCR_EL2_TPM |
		     MDCR_EL2_TPMS |
		     MDCR_EL2_TPMCR |
		     MDCR_EL2_TDRA |
		     MDCR_EL2_TDOSA |
		     MDCR_EL2_TDA |
		     MDCR_EL2_TDE);
	write_sysreg(mdcr_el2, mdcr_el2);
}

static void __hyp_text __deactivate_traps_common(void)
{
	set_hstr_el2(0);
	set_pmuserenr_el0(0);
}

static void __hyp_text __activate_traps_nvhe(struct kvm_vcpu *vcpu)
{
	u64 val;

	__activate_traps_common(vcpu);

	val = CPTR_EL2_DEFAULT;
	val |= CPTR_EL2_TTA | CPTR_EL2_TZ;
	if (!update_fp_enabled(vcpu))
		val |= CPTR_EL2_TFP;

	set_cptr_el2(val);
}

static void __hyp_text __activate_traps(struct kvm_vcpu *vcpu)
{
	u64 hcr = vcpu->arch.hcr_el2;

	hcr |= HCR_HYPSEC_VM_FLAGS;
	hcr &= ~HCR_TGE;

	set_hcr_el2(hcr);

	/* We don't support RAS_EXTN for now in HypSec */

	__activate_traps_fpsimd32(vcpu);
	__activate_traps_nvhe(vcpu);
}

static void __hyp_text __deactivate_traps_nvhe(void)
{
	u64 mdcr_el2 = get_mdcr_el2();

	__deactivate_traps_common();

	mdcr_el2 &= MDCR_EL2_HPMN_MASK;
	mdcr_el2 |= MDCR_EL2_E2PB_MASK << MDCR_EL2_E2PB_SHIFT;

	set_mdcr_el2(mdcr_el2);

	set_cptr_el2(CPTR_EL2_DEFAULT);
}

static void __hyp_text __deactivate_traps(struct kvm_vcpu *vcpu)
{
	__deactivate_traps_nvhe();
}

void activate_traps_vhe_load(struct kvm_vcpu *vcpu)
{
}

void deactivate_traps_vhe_put(void)
{
}

static void __hyp_text __activate_vm(u64 vmid)
{
	u64 shadow_vttbr = get_shadow_vttbr((u32)vmid);
	set_vttbr_el2(shadow_vttbr);
}

static void __hyp_text __deactivate_vm(struct kvm_vcpu *vcpu)
{
}

/* Save VGICv3 state on non-VHE systems */
static void __hyp_text __hyp_vgic_save_state(struct kvm_vcpu *vcpu)
{
}

/* Restore VGICv3 state on non_VEH systems */
static void __hyp_text __hyp_vgic_restore_state(struct kvm_vcpu *vcpu)
{
}

static bool __hyp_text __check_arm_834220(void)
{
	/*
	 * We return true here since AMD Seattle uses Cortex-A57 CPUs.
	 * This needs to be updated if the hardware has different type
	 * of CPUs.
	 */
	return true;
}

static bool __hyp_text __translate_far_to_hpfar(u64 far, u64 *hpfar)
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

static bool __hyp_text __populate_fault_info(struct kvm_vcpu *vcpu, u64 esr)
{
	u64 hpfar, far;

	far = get_far_el2();

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
	    (__check_arm_834220() || (esr & ESR_ELx_FSC_TYPE) == FSC_PERM)) {
		if (!__translate_far_to_hpfar(far, &hpfar))
			return false;
	} else {
		hpfar = get_hpfar_el2();
	}

	vcpu->arch.fault.far_el2 = far;
	vcpu->arch.fault.hpfar_el2 = hpfar;
	vcpu->arch.shadow_vcpu_ctxt->far_el2 = far;

	if ((esr & ESR_ELx_FSC_TYPE) == FSC_FAULT) {
		if (pre_handle_shadow_s2pt_fault(vcpu, hpfar) > 0)
			return false;
		/*
		 * Here we'd like to avoid calling handle_shadow_s2pt_fault
		 * twice if it's GPA belongs to MMIO region. Since no mapping
		 * should be built anyway.
		 */
		else if (!is_mmio_gpa((hpfar & HPFAR_MASK) << 8)) {
			vcpu->arch.shadow_vcpu_ctxt->hpfar = hpfar;
			el2_memset(&vcpu->arch.walk_result, 0, sizeof(struct s2_trans));
		}
	}

	return true;
}

static bool __hyp_text __hyp_switch_fpsimd(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *host_ctxt = kern_hyp_va(vcpu->arch.host_cpu_context);
	struct user_fpsimd_state *host_fpsimd = &host_ctxt->gp_regs.fp_regs;

	set_cptr_el2(get_cptr_el2() & ~(u64)CPTR_EL2_TFP);

	isb();

	if (vcpu->arch.flags & KVM_ARM64_FP_HOST) {
		__fpsimd_save_state(host_fpsimd);

		vcpu->arch.flags &= ~KVM_ARM64_FP_HOST;
	}
	__fpsimd_restore_state(&vcpu->arch.shadow_vcpu_ctxt->gp_regs.fp_regs);

	/* No need to restore fpexc32 since we don't support AArch64 guests */

	vcpu->arch.flags |= KVM_ARM64_FP_ENABLED;

	return true;
}

/*
 * Return true when we were able to fixup the guest exit and should return to
 * the guest, false when we should restore the host state and return to the
 * main run loop. We try to handle VM exit early here.
 */
static bool __hyp_text fixup_guest_exit(struct kvm_vcpu *vcpu, u64 *exit_code)
{
	u32 esr_el2 = 0;
	u8 ec;

	if (ARM_EXCEPTION_CODE(*exit_code) != ARM_EXCEPTION_IRQ) {
		esr_el2 = get_esr_el2();
		vcpu->arch.fault.esr_el2 = esr_el2;
		vcpu->arch.shadow_vcpu_ctxt->esr = esr_el2;
	}

	/*
	 * We're using the raw exception code in order to only process
	 * the trap if no SError is pending. We will come back to the
	 * same PC once the SError has been injected, and replay the
	 * trapping instruction.
	 */
	if (*exit_code != ARM_EXCEPTION_TRAP)
		goto exit;

	ec = hypsec_vcpu_trap_get_class(vcpu);
	if (ec == ESR_ELx_EC_HVC64) {
		if (handle_pvops(vcpu) > 0)
			return true;
		else
			return false;
	} else if (ec == ESR_ELx_EC_FP_ASIMD) {
		/*
		 * We trap the first access to the FP/SIMD to save the host context
		 * and restore the guest context lazily.
		 * If FP/SIMD is not implemented, handle the trap and inject an
		 * undefined instruction exception to the guest.
		 */
		if (hypsec_supports_fpsimd())
			return __hyp_switch_fpsimd(vcpu);
	} else if (ec == ESR_ELx_EC_DABT_LOW || ec == ESR_ELx_EC_IABT_LOW) {
		if (!__populate_fault_info(vcpu, esr_el2))
			return true;
	}

exit:
	/* Return to the host kernel and handle the exit */
	return false;
}

static void __hyp_text __host_el2_restore_state(struct el2_data *el2_data)
{
	set_vttbr_el2(el2_data->host_vttbr);
	set_hcr_el2(HCR_HOST_NVHE_FLAGS);
	set_tpidr_el2(0);
}

int kvm_vcpu_run_vhe(struct kvm_vcpu *vcpu)
{
	return 0;
}

/* Switch to the guest for legacy non-VHE systems */
int __hyp_text __kvm_vcpu_run_nvhe(struct kvm_vcpu *vcpu,
				   struct shadow_vcpu_context *prot_ctxt)
{
	u64 exit_code;
	struct kvm_cpu_context *host_ctxt;
	struct kvm_cpu_context *guest_ctxt;
	struct kvm_cpu_context *shadow_ctxt;
	struct el2_data *el2_data;
	u32 vmid = vcpu->arch.vmid;
	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));

	host_ctxt = kern_hyp_va(vcpu->arch.host_cpu_context);
	host_ctxt->__hyp_running_vcpu = vcpu;
	guest_ctxt = &vcpu->arch.ctxt;
	shadow_ctxt =
		(struct kvm_cpu_context *)prot_ctxt;

	__sysreg_save_state_nvhe(host_ctxt);

	set_tpidr_el2(vcpu->arch.tpidr_el2);
	__restore_shadow_kvm_regs(vcpu);

	__activate_traps(vcpu);
	__activate_vm(vmid & 0xff);

	__hyp_vgic_restore_state(vcpu);
	__timer_enable_traps(vcpu);

	/*
	 * We must restore the 32-bit state before the sysregs, thanks
	 * to erratum #852523 (Cortex-A57) or #853709 (Cortex-A72).
	 */
	__sysreg32_restore_state(vcpu);
	__sysreg_restore_state_nvhe(shadow_ctxt);

	do {
		/* Jump in the fire! */
		exit_code = __guest_enter(vcpu, host_ctxt);

		/* And we're baaack! */
	} while (fixup_guest_exit(vcpu, &exit_code));


	__sysreg_save_state_nvhe(shadow_ctxt);
	__sysreg32_save_state(vcpu);
	__timer_disable_traps(vcpu);
	__hyp_vgic_save_state(vcpu);

	__deactivate_traps(vcpu);
	__deactivate_vm(vcpu);
	__host_el2_restore_state(el2_data);

	__sysreg_restore_state_nvhe(host_ctxt);

	if (vcpu->arch.flags & KVM_ARM64_FP_ENABLED) {
		__fpsimd_save_fpexc32(vcpu);
		__fpsimd_save_state(&shadow_ctxt->gp_regs.fp_regs);
		__fpsimd_restore_state(&host_ctxt->gp_regs.fp_regs);
		vcpu->arch.flags &= ~KVM_ARM64_FP_ENABLED;
		vcpu->arch.flags |= KVM_ARM64_FP_HOST;
	}

	__save_shadow_kvm_regs(vcpu, exit_code);

	return exit_code;
}

void __hyp_text __noreturn hyp_panic(struct kvm_cpu_context *host_ctxt)
{
	/* For simplicity, we just hang in here. */
	unreachable();
}
