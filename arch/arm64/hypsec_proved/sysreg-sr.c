#include <linux/compiler.h>
#include <linux/kvm_host.h>

#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>

#include <asm/hypsec_host.h>
#include <asm/hypsec_constant.h>

#define OFF KVM_REGS_SIZE

static void __hyp_text __vm_sysreg_save_common_state(u32 vmid, u32 vcpuid)
{
	set_shadow_ctxt(vmid, vcpuid, OFF+MDSCR_EL1, read_sysreg(mdscr_el1));

	/*
	 * The host arm64 Linux uses sp_el0 to point to 'current' and it must
	 * therefore be saved/restored on every entry/exit to/from the guest.
	 */
	set_shadow_ctxt(vmid, vcpuid, V_SP, read_sysreg(sp_el0));
}

static void __hyp_text __vm_sysreg_save_user_state(u32 vmid, u32 vcpuid)
{
	set_shadow_ctxt(vmid, vcpuid, OFF+TPIDR_EL0, read_sysreg(tpidr_el0));
	set_shadow_ctxt(vmid, vcpuid, OFF+TPIDRRO_EL0, read_sysreg(tpidrro_el0));
}

static void __hyp_text __vm_sysreg_save_el1_state(u32 vmid, u32 vcpuid)
{
	set_shadow_ctxt(vmid, vcpuid, OFF+MPIDR_EL1, read_sysreg(vmpidr_el2));
	set_shadow_ctxt(vmid, vcpuid, OFF+CSSELR_EL1, read_sysreg(csselr_el1));
	set_shadow_ctxt(vmid, vcpuid, OFF+SCTLR_EL1, read_sysreg_el1(sctlr));
	set_shadow_ctxt(vmid, vcpuid, OFF+ACTLR_EL1, read_sysreg(actlr_el1));
	set_shadow_ctxt(vmid, vcpuid, OFF+CPACR_EL1, read_sysreg_el1(cpacr));
	set_shadow_ctxt(vmid, vcpuid, OFF+TTBR0_EL1, read_sysreg_el1(ttbr0));
	set_shadow_ctxt(vmid, vcpuid, OFF+TTBR1_EL1, read_sysreg_el1(ttbr1));
	set_shadow_ctxt(vmid, vcpuid, OFF+TCR_EL1, read_sysreg_el1(tcr));
	set_shadow_ctxt(vmid, vcpuid, OFF+ESR_EL1, read_sysreg_el1(esr));
	set_shadow_ctxt(vmid, vcpuid, OFF+AFSR0_EL1, read_sysreg_el1(afsr0));
	set_shadow_ctxt(vmid, vcpuid, OFF+AFSR1_EL1, read_sysreg_el1(afsr1));
	set_shadow_ctxt(vmid, vcpuid, OFF+FAR_EL1, read_sysreg_el1(far));
	set_shadow_ctxt(vmid, vcpuid, OFF+MAIR_EL1, read_sysreg_el1(mair));
	set_shadow_ctxt(vmid, vcpuid, OFF+VBAR_EL1, read_sysreg_el1(vbar));
	set_shadow_ctxt(vmid, vcpuid, OFF+CONTEXTIDR_EL1, read_sysreg_el1(contextidr));
	set_shadow_ctxt(vmid, vcpuid, OFF+AMAIR_EL1, read_sysreg_el1(amair));
	set_shadow_ctxt(vmid, vcpuid, OFF+CNTKCTL_EL1, read_sysreg_el1(cntkctl));
	set_shadow_ctxt(vmid, vcpuid, OFF+PAR_EL1, read_sysreg(par_el1));
	set_shadow_ctxt(vmid, vcpuid, OFF+TPIDR_EL1, read_sysreg(tpidr_el1));

	set_shadow_ctxt(vmid, vcpuid, V_SP_EL1, read_sysreg(sp_el1));
	set_shadow_ctxt(vmid, vcpuid, V_ELR_EL1, read_sysreg_el1(elr));
	set_shadow_ctxt(vmid, vcpuid, V_SPSR_EL1, read_sysreg_el1(spsr));
}

static void __hyp_text __vm_sysreg_save_el2_return_state(u32 vmid, u32 vcpuid)
{
	set_shadow_ctxt(vmid, vcpuid, V_PC, read_sysreg_el2(elr));
	set_shadow_ctxt(vmid, vcpuid, V_PSTATE, read_sysreg_el2(spsr));
}

void __hyp_text __vm_sysreg_save_state_nvhe(u32 vmid, u32 vcpuid)
{
	__vm_sysreg_save_el1_state(vmid, vcpuid);
	__vm_sysreg_save_common_state(vmid, vcpuid);
	__vm_sysreg_save_user_state(vmid, vcpuid);
	__vm_sysreg_save_el2_return_state(vmid, vcpuid);
}


static void __hyp_text __vm_sysreg_restore_el1_state(u32 vmid, u32 vcpu_id)
{
	write_sysreg(get_shadow_ctxt(vmid, vcpu_id, OFF+MPIDR_EL1),	vmpidr_el2);
	write_sysreg(get_shadow_ctxt(vmid, vcpu_id, OFF+CSSELR_EL1),	csselr_el1);
	write_sysreg_el1(get_shadow_ctxt(vmid, vcpu_id, OFF+SCTLR_EL1),	sctlr);
	write_sysreg(get_shadow_ctxt(vmid, vcpu_id, OFF+ACTLR_EL1),	actlr_el1);
	write_sysreg_el1(get_shadow_ctxt(vmid, vcpu_id, OFF+CPACR_EL1),	cpacr);
	write_sysreg_el1(get_shadow_ctxt(vmid, vcpu_id, OFF+TTBR0_EL1),	ttbr0);
	write_sysreg_el1(get_shadow_ctxt(vmid, vcpu_id, OFF+TTBR1_EL1),	ttbr1);
	write_sysreg_el1(get_shadow_ctxt(vmid, vcpu_id, OFF+TCR_EL1),	tcr);
	write_sysreg_el1(get_shadow_ctxt(vmid, vcpu_id, OFF+ESR_EL1),	esr);
	write_sysreg_el1(get_shadow_ctxt(vmid, vcpu_id, OFF+AFSR0_EL1),	afsr0);
	write_sysreg_el1(get_shadow_ctxt(vmid, vcpu_id, OFF+AFSR1_EL1),	afsr1);
	write_sysreg_el1(get_shadow_ctxt(vmid, vcpu_id, OFF+FAR_EL1),	far);
	write_sysreg_el1(get_shadow_ctxt(vmid, vcpu_id, OFF+MAIR_EL1),	mair);
	write_sysreg_el1(get_shadow_ctxt(vmid, vcpu_id, OFF+VBAR_EL1),	vbar);
	write_sysreg_el1(get_shadow_ctxt(vmid, vcpu_id, OFF+CONTEXTIDR_EL1),contextidr);
	write_sysreg_el1(get_shadow_ctxt(vmid, vcpu_id, OFF+AMAIR_EL1),	amair);
	write_sysreg_el1(get_shadow_ctxt(vmid, vcpu_id, OFF+CNTKCTL_EL1),cntkctl);
	write_sysreg(get_shadow_ctxt(vmid, vcpu_id, OFF+PAR_EL1),	par_el1);
	write_sysreg(get_shadow_ctxt(vmid, vcpu_id, OFF+TPIDR_EL1),	tpidr_el1);

	write_sysreg(get_shadow_ctxt(vmid, vcpu_id, V_SP_EL1),		sp_el1);
	write_sysreg_el1(get_shadow_ctxt(vmid, vcpu_id, V_ELR_EL1),	elr);
	write_sysreg_el1(get_shadow_ctxt(vmid, vcpu_id, V_SPSR_EL1),	spsr);
}

static void __hyp_text __vm_sysreg_restore_common_state(u32 vmid, u32 vcpuid)
{
	write_sysreg(get_shadow_ctxt(vmid, vcpuid, OFF+MDSCR_EL1), mdscr_el1);

	/*
	 * The host arm64 Linux uses sp_el0 to point to 'current' and it must
	 * therefore be saved/restored on every entry/exit to/from the guest.
	 */
	write_sysreg(get_shadow_ctxt(vmid, vcpuid, V_SP), sp_el0);
}

static void __hyp_text
__vm_sysreg_restore_el2_return_state(u32 vmid, u32 vcpuid)
{
	write_sysreg_el2(get_shadow_ctxt(vmid, vcpuid, V_PC), elr);
	write_sysreg_el2(get_shadow_ctxt(vmid, vcpuid, V_PSTATE), spsr);
}

static void __hyp_text
__vm_sysreg_restore_user_state(u32 vmid, u32 vcpuid)
{
	write_sysreg(get_shadow_ctxt(vmid, vcpuid, OFF+TPIDR_EL0), tpidr_el0);
	write_sysreg(get_shadow_ctxt(vmid, vcpuid, OFF+TPIDRRO_EL0), tpidrro_el0);
}

void __hyp_text __vm_sysreg_restore_state_nvhe(u32 vmid, u32 vcpuid)
{
	__vm_sysreg_restore_el1_state(vmid, vcpuid);
	__vm_sysreg_restore_common_state(vmid, vcpuid);
	__vm_sysreg_restore_user_state(vmid, vcpuid);
	__vm_sysreg_restore_el2_return_state(vmid, vcpuid);
}
