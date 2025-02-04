// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 - Google Inc
 * Author: Andrew Scull <ascull@google.com>
 */

#include <hyp/switch.h>

#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_host.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#ifdef CONFIG_VERIFIED_KVM
#include <asm/hypsec_host.h>
#endif

#include <nvhe/trap_handler.h>

DEFINE_PER_CPU(struct kvm_nvhe_init_params, kvm_init_params);

void __kvm_hyp_host_forward_smc(struct kvm_cpu_context *host_ctxt);

#ifndef CONFIG_VERIFIED_KVM
static void handle___kvm_vcpu_run(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct kvm_vcpu *, vcpu, host_ctxt, 1);

	cpu_reg(host_ctxt, 1) =  __kvm_vcpu_run(kern_hyp_va(vcpu));
}

static void handle___kvm_flush_vm_context(struct kvm_cpu_context *host_ctxt)
{
	__kvm_flush_vm_context();
}

static void handle___kvm_tlb_flush_vmid_ipa(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct kvm_s2_mmu *, mmu, host_ctxt, 1);
	DECLARE_REG(phys_addr_t, ipa, host_ctxt, 2);
	DECLARE_REG(int, level, host_ctxt, 3);

	__kvm_tlb_flush_vmid_ipa(kern_hyp_va(mmu), ipa, level);
}

static void handle___kvm_tlb_flush_vmid(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct kvm_s2_mmu *, mmu, host_ctxt, 1);

	__kvm_tlb_flush_vmid(kern_hyp_va(mmu));
}

static void handle___kvm_tlb_flush_local_vmid(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct kvm_s2_mmu *, mmu, host_ctxt, 1);

	__kvm_tlb_flush_local_vmid(kern_hyp_va(mmu));
}

static void handle___kvm_timer_set_cntvoff(struct kvm_cpu_context *host_ctxt)
{
	__kvm_timer_set_cntvoff(cpu_reg(host_ctxt, 1));
}

static void handle___kvm_enable_ssbs(struct kvm_cpu_context *host_ctxt)
{
	u64 tmp;

	tmp = read_sysreg_el2(SYS_SCTLR);
	tmp |= SCTLR_ELx_DSSBS;
	write_sysreg_el2(tmp, SYS_SCTLR);
}

static void handle___vgic_v3_get_ich_vtr_el2(struct kvm_cpu_context *host_ctxt)
{
	cpu_reg(host_ctxt, 1) = __vgic_v3_get_ich_vtr_el2();
}

static void handle___vgic_v3_read_vmcr(struct kvm_cpu_context *host_ctxt)
{
	cpu_reg(host_ctxt, 1) = __vgic_v3_read_vmcr();
}

static void handle___vgic_v3_write_vmcr(struct kvm_cpu_context *host_ctxt)
{
	__vgic_v3_write_vmcr(cpu_reg(host_ctxt, 1));
}

static void handle___vgic_v3_init_lrs(struct kvm_cpu_context *host_ctxt)
{
	__vgic_v3_init_lrs();
}

static void handle___kvm_get_mdcr_el2(struct kvm_cpu_context *host_ctxt)
{
	cpu_reg(host_ctxt, 1) = __kvm_get_mdcr_el2();
}

static void handle___vgic_v3_save_aprs(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct vgic_v3_cpu_if *, cpu_if, host_ctxt, 1);

	__vgic_v3_save_aprs(kern_hyp_va(cpu_if));
}

static void handle___vgic_v3_restore_aprs(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct vgic_v3_cpu_if *, cpu_if, host_ctxt, 1);

	__vgic_v3_restore_aprs(kern_hyp_va(cpu_if));
}

typedef void (*hcall_t)(struct kvm_cpu_context *);

#define HANDLE_FUNC(x)	[__KVM_HOST_SMCCC_FUNC_##x] = kimg_fn_ptr(handle_##x)

static const hcall_t *host_hcall[] = {
	HANDLE_FUNC(__kvm_vcpu_run),
	HANDLE_FUNC(__kvm_flush_vm_context),
	HANDLE_FUNC(__kvm_tlb_flush_vmid_ipa),
	HANDLE_FUNC(__kvm_tlb_flush_vmid),
	HANDLE_FUNC(__kvm_tlb_flush_local_vmid),
	HANDLE_FUNC(__kvm_timer_set_cntvoff),
	HANDLE_FUNC(__kvm_enable_ssbs),
	HANDLE_FUNC(__vgic_v3_get_ich_vtr_el2),
	HANDLE_FUNC(__vgic_v3_read_vmcr),
	HANDLE_FUNC(__vgic_v3_write_vmcr),
	HANDLE_FUNC(__vgic_v3_init_lrs),
	HANDLE_FUNC(__kvm_get_mdcr_el2),
	HANDLE_FUNC(__vgic_v3_save_aprs),
	HANDLE_FUNC(__vgic_v3_restore_aprs),
};
#endif

static void handle_host_hcall(struct kvm_cpu_context *host_ctxt)
{
#ifndef CONFIG_VERIFIED_KVM
	DECLARE_REG(unsigned long, id, host_ctxt, 0);
	const hcall_t *kfn;
	hcall_t hfn;
#else
	struct s2_host_regs hr;
	int i;
	for (i = 0; i < ARRAY_SIZE(host_ctxt->regs.regs); ++i)
		hr.regs[i] = (unsigned long)cpu_reg(host_ctxt, i);
#endif

#ifndef CONFIG_VERIFIED_KVM
	id -= KVM_HOST_SMCCC_ID(0);

	if (unlikely(id >= ARRAY_SIZE(host_hcall)))
		goto inval;

	kfn = host_hcall[id];
	if (unlikely(!kfn))
		goto inval;
#endif

	cpu_reg(host_ctxt, 0) = SMCCC_RET_SUCCESS;

#ifndef CONFIG_VERIFIED_KVM
	hfn = kimg_fn_hyp_va(kfn);
	hfn(host_ctxt);
#else
	handle_host_hvc(&hr);
	cpu_reg(host_ctxt, 1) = hr.regs[0];
#endif
	return;
#ifndef CONFIG_VERIFIED_KVM
inval:
	cpu_reg(host_ctxt, 0) = SMCCC_RET_NOT_SUPPORTED;
#endif
}

static void default_host_smc_handler(struct kvm_cpu_context *host_ctxt)
{
	__kvm_hyp_host_forward_smc(host_ctxt);
}

static void handle_host_smc(struct kvm_cpu_context *host_ctxt)
{
	bool handled;

	handled = kvm_host_psci_handler(host_ctxt);
	if (!handled)
		default_host_smc_handler(host_ctxt);

	/* SMC was trapped, move ELR past the current PC. */
	kvm_skip_host_instr();
}

void handle_trap(struct kvm_cpu_context *host_ctxt)
{
	u64 esr = read_sysreg_el2(SYS_ESR);
#ifdef CONFIG_VERIFIED_KVM
	struct s2_host_regs hr;
	int i;
	for (i = 0; i < ARRAY_SIZE(host_ctxt->regs.regs); ++i)
		hr.regs[i] = (unsigned long)cpu_reg(host_ctxt, i);
#endif

	switch (ESR_ELx_EC(esr)) {
	case ESR_ELx_EC_HVC64:
		handle_host_hcall(host_ctxt);
		break;
	case ESR_ELx_EC_SMC64:
		handle_host_smc(host_ctxt);
		break;
#ifdef CONFIG_VERIFIED_KVM
	case ESR_ELx_EC_DABT_LOW:
	case ESR_ELx_EC_IABT_LOW:
		handle_host_stage2_fault(0, &hr);
		for (i = 0; i < ARRAY_SIZE(host_ctxt->regs.regs); ++i)
			cpu_reg(host_ctxt, i) = hr.regs[i];
		break;
#endif
	default:
		hyp_panic();
	}
}
