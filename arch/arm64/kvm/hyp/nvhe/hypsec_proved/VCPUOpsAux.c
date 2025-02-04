#include "hypsec.h"
#include <uapi/linux/psci.h>

/*
 * VCPUOpsAux
 */

void reset_gp_regs(u32 vmid, u32 vcpuid)
{
	u64 pc, pstate, load_addr;

	pc = get_int_pc(vmid, vcpuid);
	load_addr = search_load_info(vmid, pc);

	if (load_addr == 0UL)
	{
		print_string("\reset gp reg\n");
		v_panic();
	}
	else
	{
		clear_shadow_gp_regs(vmid, vcpuid);
		pstate = get_int_pstate(vmid, vcpuid);
		set_shadow_ctxt(vmid, vcpuid, V_PSTATE, pstate);
		set_shadow_ctxt(vmid, vcpuid, V_PC, pc);
		reset_fp_regs(vmid, vcpuid);
    	}
}

//TODO: Embed this function in reset_sys_regs
static inline u64 el2_reset_mpidr(u32 vcpu_id)
{
	u64 mpidr;
	mpidr = (vcpu_id & 0x0f) << MPIDR_LEVEL_SHIFT(0);
	mpidr |= ((vcpu_id >> 4) & 0xff) << MPIDR_LEVEL_SHIFT(1);
	mpidr |= ((vcpu_id >> 12) & 0xff) << MPIDR_LEVEL_SHIFT(2);
	return ((1ULL << 31) | mpidr);
}

void reset_sys_regs(u32 vmid, u32 vcpuid)
{
	u64 val;
	u32 i = 1U;
	while (i <= SHADOW_SYS_REGS_SIZE)
	{
		if (i == MPIDR_EL1)
		{
			//TODO: Confirm with LXP
			//u64 mpidr = (vcpuid % 16U) + ((vcpuid / 16U) % 256U) * 256U +
			//                      ((vcpuid / 4096U) % 256U) * 65536U;
			//val = mpidr + 2147483648UL;
			val = el2_reset_mpidr(vcpuid);
		}
		else if (i == ACTLR_EL1)
		{
			val = read_sysreg(actlr_el1);
		}
		else
		{
			//TODO:this will not work, we need to pass vmid and vcpuid
			val = get_sys_reg_desc_val(i);
		}
		set_shadow_ctxt(vmid, vcpuid, i + SYSREGS_START, val);
		i += 1U;
	}
}

void sync_dirty_to_shadow(u32 vmid, u32 vcpuid)
{
	u32 i = 0U;
	u64 dirty = get_shadow_dirty_bit(vmid, vcpuid);
	while (i < 31U)
	{
		if (dirty & (1U << i))
		{
			u64 reg = get_int_gpr(vmid, vcpuid, i);
			set_shadow_ctxt(vmid, vcpuid, i, reg);
		}
		i += 1U;
	}
}

void prep_wfx(u32 vmid, u32 vcpuid)
{
	set_shadow_dirty_bit(vmid, vcpuid, DIRTY_PC_FLAG);
}

void prep_hvc(u32 vmid, u32 vcpuid)
{
	u64 psci_fn;

	psci_fn = get_shadow_ctxt(vmid, vcpuid, 0UL) & ~((u32) 0);
	set_shadow_dirty_bit(vmid, vcpuid, 1 << 0U);
	set_int_gpr(vmid, vcpuid, 0U, get_shadow_ctxt(vmid, vcpuid, 0UL));

	if (psci_fn == PSCI_0_2_FN64_CPU_ON)
	{
		set_int_gpr(vmid, vcpuid, 1U, get_shadow_ctxt(vmid, vcpuid, 1U));
		set_int_gpr(vmid, vcpuid, 2U, get_shadow_ctxt(vmid, vcpuid, 2U));
		set_int_gpr(vmid, vcpuid, 3U, get_shadow_ctxt(vmid, vcpuid, 3U));
	}
	else if (psci_fn == PSCI_0_2_FN_AFFINITY_INFO || 
		 psci_fn == PSCI_0_2_FN64_AFFINITY_INFO)
	{
		set_int_gpr(vmid, vcpuid, 1U, get_shadow_ctxt(vmid, vcpuid, 1U));
		set_int_gpr(vmid, vcpuid, 2U, get_shadow_ctxt(vmid, vcpuid, 2U));
	}
	else if (psci_fn == PSCI_0_2_FN_SYSTEM_OFF)
	{
		set_vm_poweroff(vmid);
	}
}

//synchronized
void prep_abort(u32 vmid, u32 vcpuid)
{
	u64 esr, fault_ipa, reg;
	u32 Rd;
	//bool is_write;

	esr = get_int_esr(vmid, vcpuid);
	Rd = (u32)((esr / 65536UL) % 32UL);
	fault_ipa = (get_shadow_ctxt(vmid, vcpuid, V_HPFAR_EL2) / 16UL) * 4096UL;

	//TODO: sync with verified code to support QEMU 3.0
	if (fault_ipa < MAX_MMIO_ADDR || fault_ipa >= 0x4000000000)
	{
		/*if (fault_ipa > 0xc000000 && fault_ipa < 0xe000000) {
		  u64 flags = get_shadow_ctxt(vmid, vcpuid, V_FLAGS);
		  flags |= PENDING_FSC_FAULT;
		  set_shadow_ctxt(vmid, vcpuid, V_FLAGS, flags);
		  printhex_ul(fault_ipa);
		  return;
		  }*/
		set_shadow_dirty_bit(vmid, vcpuid, DIRTY_PC_FLAG);

		//if ((esr / 64UL) % 4UL == 0UL) {
		//is_write = !!(esr & ESR_ELx_WNR) || !!(esr & ESR_ELx_S1PTW);
		//if (!is_write) {
		//MMIO_READ
		if (((esr & ESR_ELx_WNR) == 0) && ((esr & ESR_ELx_S1PTW) == 0))
		{
			set_shadow_dirty_bit(vmid, vcpuid, 1 << Rd);
		}
		else
		{
			reg = get_shadow_ctxt(vmid, vcpuid, Rd);
			set_int_gpr(vmid, vcpuid, Rd, reg);
		}
	}
}

void v_update_exception_gp_regs(u32 vmid, u32 vcpuid)
{
	u64 esr, pstate, pc, new_pc;
	esr = ESR_ELx_EC_UNKNOWN;
	pstate = get_shadow_ctxt(vmid, vcpuid, V_PSTATE);
	pc = get_shadow_ctxt(vmid, vcpuid, V_PC);
	new_pc = get_exception_vector(pstate);
	set_shadow_ctxt(vmid, vcpuid, V_ELR_EL1, pc);
	set_shadow_ctxt(vmid, vcpuid, V_PC, new_pc);
	set_shadow_ctxt(vmid, vcpuid, V_PSTATE, PSTATE_FAULT_BITS_64);
	set_shadow_ctxt(vmid, vcpuid, V_SPSR_0, pstate);
	set_shadow_ctxt(vmid, vcpuid, V_ESR_EL1, esr);
}

//TODO: API is a bit different, why is level not 32 bit?
void post_handle_shadow_s2pt_fault(u32 vmid, u32 vcpuid, u64 addr)
{
	u64 pte;
	u32 level;
	pte = get_int_new_pte(vmid, vcpuid);
	level = get_int_new_level(vmid, vcpuid);
	prot_and_map_vm_s2pt(vmid, addr, pte, level);
}

//TODO: where is this in the proof?
void v_hypsec_inject_undef(u32 vmid, u32 vcpuid)
{
	set_shadow_dirty_bit(vmid, vcpuid, PENDING_UNDEF_INJECT);
}


