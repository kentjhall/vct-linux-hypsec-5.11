#include <linux/compiler.h>
#include <linux/kvm_host.h>

#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>

#include <asm/hypsec_host.h>
#include <asm/hypsec_constant.h>

#define OFF SYSREGS_START 
static void __vm_sysreg_save_common_state(struct shadow_vcpu_context *ctxt)
{
	ctxt->sys_regs[MDSCR_EL1] = read_sysreg(mdscr_el1);
}

static void __vm_sysreg_save_user_state(struct shadow_vcpu_context *ctxt)
{
	ctxt->sys_regs[TPIDR_EL0] = read_sysreg(tpidr_el0);
	ctxt->sys_regs[TPIDRRO_EL0] = read_sysreg(tpidrro_el0);
}

static void __vm_sysreg_save_el1_state(struct shadow_vcpu_context *ctxt)
{	
	ctxt->sys_regs[MPIDR_EL1] = read_sysreg(vmpidr_el2);
	ctxt->sys_regs[CSSELR_EL1] = read_sysreg(csselr_el1);
	ctxt->sys_regs[SCTLR_EL1] = read_sysreg_el1(SYS_SCTLR);
	ctxt->sys_regs[ACTLR_EL1] = read_sysreg(actlr_el1);
	ctxt->sys_regs[CPACR_EL1] = read_sysreg_el1(SYS_CPACR);
	ctxt->sys_regs[TTBR0_EL1] = read_sysreg_el1(SYS_TTBR0);
	ctxt->sys_regs[TTBR1_EL1] = read_sysreg_el1(SYS_TTBR1);
	ctxt->sys_regs[TCR_EL1] = read_sysreg_el1(SYS_TCR);
	ctxt->sys_regs[ESR_EL1] = read_sysreg_el1(SYS_ESR);
	ctxt->sys_regs[AFSR0_EL1] = read_sysreg_el1(SYS_AFSR0);
	ctxt->sys_regs[AFSR1_EL1] = read_sysreg_el1(SYS_AFSR1);
	ctxt->sys_regs[FAR_EL1] = read_sysreg_el1(SYS_FAR);
	ctxt->sys_regs[MAIR_EL1] = read_sysreg_el1(SYS_MAIR);
	ctxt->sys_regs[VBAR_EL1] = read_sysreg_el1(SYS_VBAR);
	ctxt->sys_regs[CONTEXTIDR_EL1] = read_sysreg_el1(SYS_CONTEXTIDR);
	ctxt->sys_regs[AMAIR_EL1] = read_sysreg_el1(SYS_AMAIR);
	ctxt->sys_regs[CNTKCTL_EL1] = read_sysreg_el1(SYS_CNTKCTL);
	ctxt->sys_regs[PAR_EL1] = read_sysreg(par_el1);
	ctxt->sys_regs[TPIDR_EL1] = read_sysreg(tpidr_el1);

	ctxt->gp_regs.sp_el1 = read_sysreg(sp_el1);
	ctxt->gp_regs.elr_el1 = read_sysreg_el1(SYS_ELR);
	ctxt->gp_regs.spsr[0] = read_sysreg_el1(SYS_SPSR);
}

static void __vm_sysreg_save_el2_return_state(struct shadow_vcpu_context *ctxt)
{
	ctxt->gp_regs.regs.pc = read_sysreg_el2(SYS_ELR);
	ctxt->gp_regs.regs.pstate = read_sysreg_el2(SYS_SPSR);
}

static void __vm_sysreg_restore_el1_state(struct shadow_vcpu_context *ctxt)
{
	write_sysreg(ctxt->sys_regs[MPIDR_EL1],	vmpidr_el2);
	write_sysreg(ctxt->sys_regs[CSSELR_EL1], csselr_el1);

	write_sysreg_el1(ctxt->sys_regs[SCTLR_EL1],	SYS_SCTLR);
	write_sysreg_el1(ctxt->sys_regs[TCR_EL1],	SYS_TCR);

	write_sysreg(ctxt->sys_regs[ACTLR_EL1],	actlr_el1);
	write_sysreg_el1(ctxt->sys_regs[CPACR_EL1], SYS_CPACR);
	write_sysreg_el1(ctxt->sys_regs[TTBR0_EL1], SYS_TTBR0);
	write_sysreg_el1(ctxt->sys_regs[TTBR1_EL1], SYS_TTBR1);
	write_sysreg_el1(ctxt->sys_regs[ESR_EL1], SYS_ESR);
	write_sysreg_el1(ctxt->sys_regs[AFSR0_EL1], SYS_AFSR0);
	write_sysreg_el1(ctxt->sys_regs[AFSR1_EL1], SYS_AFSR1);
	write_sysreg_el1(ctxt->sys_regs[FAR_EL1], SYS_FAR);
	write_sysreg_el1(ctxt->sys_regs[MAIR_EL1], SYS_MAIR);
	write_sysreg_el1(ctxt->sys_regs[VBAR_EL1], SYS_VBAR);
	write_sysreg_el1(ctxt->sys_regs[CONTEXTIDR_EL1], SYS_CONTEXTIDR);
	write_sysreg_el1(ctxt->sys_regs[AMAIR_EL1], SYS_AMAIR);
	write_sysreg_el1(ctxt->sys_regs[CNTKCTL_EL1], SYS_CNTKCTL);
	write_sysreg(ctxt->sys_regs[PAR_EL1], par_el1);
	write_sysreg(ctxt->sys_regs[TPIDR_EL1],	tpidr_el1);

	write_sysreg(ctxt->gp_regs.sp_el1, sp_el1);
	write_sysreg_el1(ctxt->gp_regs.elr_el1, SYS_ELR);
	write_sysreg_el1(ctxt->gp_regs.spsr[0], SYS_SPSR);
}

static void __vm_sysreg_restore_common_state(struct shadow_vcpu_context *ctxt)
{
	write_sysreg(ctxt->sys_regs[MDSCR_EL1], mdscr_el1);
}

static void
__vm_sysreg_restore_el2_return_state(struct shadow_vcpu_context *ctxt)
{
	write_sysreg_el2(ctxt->gp_regs.regs.pc, SYS_ELR);
	write_sysreg_el2(ctxt->gp_regs.regs.pstate, SYS_SPSR);
}

static void
__vm_sysreg_restore_user_state(struct shadow_vcpu_context *ctxt)
{
	write_sysreg(ctxt->sys_regs[TPIDR_EL0], tpidr_el0);
	write_sysreg(ctxt->sys_regs[TPIDRRO_EL0], tpidrro_el0);
}

void __vm_sysreg_restore_state_nvhe_opt(struct shadow_vcpu_context *ctxt)
{
	__vm_sysreg_restore_el1_state(ctxt);
	__vm_sysreg_restore_common_state(ctxt);
	__vm_sysreg_restore_user_state(ctxt);
	__vm_sysreg_restore_el2_return_state(ctxt);
}

void __vm_sysreg_save_state_nvhe_opt(struct shadow_vcpu_context *ctxt)
{
	__vm_sysreg_save_el1_state(ctxt);
	__vm_sysreg_save_common_state(ctxt);
	__vm_sysreg_save_user_state(ctxt);
	__vm_sysreg_save_el2_return_state(ctxt);
}
