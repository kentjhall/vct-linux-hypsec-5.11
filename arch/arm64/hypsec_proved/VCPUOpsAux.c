#include "hypsec.h"
#include <uapi/linux/psci.h>

/*
 * VCPUOpsAux
 */

extern void reset_fp_regs(u32 vmid, int vcpu_id);
void __hyp_text reset_gp_regs(u32 vmid, u32 vcpuid)
{
    u64 pc = get_int_pc(vmid, vcpuid), pstate;
    //if (v_search_load_info(vmid, pc))
    if (1)
    {
        clear_shadow_gp_regs(vmid, vcpuid);
        pstate = get_int_pstate(vmid, vcpuid);
        set_shadow_ctxt(vmid, vcpuid, V_PSTATE, pstate);
        set_shadow_ctxt(vmid, vcpuid, V_PC, pc);
        //int_to_shadow_fp_regs(vmid, vcpuid);
	reset_fp_regs(vmid, vcpuid);
    }
    else {
        v_panic();
    }
}

void __hyp_text reset_sys_regs(u32 vmid, u32 vcpuid)
{
    u64 val;
    u32 i = 1U;
    while (i <= SHADOW_SYS_REGS_SIZE)
    {
        if (i == V_MPIDR_EL1)
        {
            u64 mpidr = (vcpuid % 16U) + ((vcpuid / 16U) % 256U) * 256U +
                                  ((vcpuid / 4096U) % 256U) * 65536U;
            val = mpidr + 2147483648UL;
        }
        else
        {
	    //TODO:this will not work, we need to pass vmid and vcpuid
            val = get_sys_reg_desc_val(i);
        }
        set_shadow_ctxt(vmid, vcpuid, i + KVM_REGS_SIZE, val);
        i += 1U;
    }
}

/*void save_sys_regs(u32 vmid, u32 vcpuid)
{
    set_shadow_ctxt(vmid, vcpuid, V_DACR32_EL2, get_int_ctxt(vmid, vcpuid, V_DACR32_EL2));
    set_shadow_ctxt(vmid, vcpuid, V_IFSR32_EL2, get_int_ctxt(vmid, vcpuid, V_IFSR32_EL2));
    set_shadow_ctxt(vmid, vcpuid, V_FPEXC32_EL2, get_int_ctxt(vmid, vcpuid, V_FPEXC32_EL2));

    set_int_ctxt(vmid, vcpuid, V_DACR32_EL2, 0UL);
    set_int_ctxt(vmid, vcpuid, V_IFSR32_EL2, 0UL);
    set_int_ctxt(vmid, vcpuid, V_FPEXC32_EL2, 0UL);
}

void restore_sys_regs(u32 vmid, u32 vcpuid)
{
    set_int_ctxt(vmid, vcpuid, V_DACR32_EL2, get_shadow_ctxt(vmid, vcpuid, V_DACR32_EL2));
    set_int_ctxt(vmid, vcpuid, V_IFSR32_EL2, get_shadow_ctxt(vmid, vcpuid, V_IFSR32_EL2));
    set_int_ctxt(vmid, vcpuid, V_FPEXC32_EL2, get_shadow_ctxt(vmid, vcpuid, V_FPEXC32_EL2));
}*/

// could have some problems here
void __hyp_text sync_dirty_to_shadow(u32 vmid, u32 vcpuid)
{
    u32 i = 0U;
    u64 dirty = get_shadow_dirty_bit(vmid, vcpuid);
    while (i < 31U)
    {
        if (dirty & (1U << i)) {
            u64 reg = get_int_gpr(vmid, vcpuid, i);
            set_shadow_ctxt(vmid, vcpuid, i, reg);
        }
        i += 1U;
    }
}

void __hyp_text prep_wfx(u32 vmid, u32 vcpuid)
{
    set_shadow_dirty_bit(vmid, vcpuid, DIRTY_PC_FLAG);
}

void __hyp_text prep_hvc(u32 vmid, u32 vcpuid)
{
    u64 psci_fn = get_shadow_ctxt(vmid, vcpuid, 0UL);
    set_shadow_dirty_bit(vmid, vcpuid, 0U);
    set_int_gpr(vmid, vcpuid, 0U, psci_fn);
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
    else if (psci_fn == PSCI_0_2_FN_SYSTEM_OFF) {
        set_vm_poweroff(vmid);
    }
}

void __hyp_text prep_abort(u32 vmid, u32 vcpuid)
{
    u64 esr = get_int_esr(vmid, vcpuid);
    u32 Rd = (u32)((esr / 65536UL) % 32UL);
    u64 fault_ipa = (get_shadow_ctxt(vmid, vcpuid, V_HPFAR_EL2) / 16UL) * 4096UL;

    if (fault_ipa < MAX_MMIO_ADDR)
    {
        set_shadow_dirty_bit(vmid, vcpuid, DIRTY_PC_FLAG);

        if ((esr / 64UL) % 4UL == 0UL) {
            set_shadow_dirty_bit(vmid, vcpuid, 1 << Rd);
        }
        else {
            u64 reg = get_shadow_ctxt(vmid, vcpuid, Rd);
            set_int_gpr(vmid, vcpuid, Rd, reg);
        }
    }
}

void __hyp_text v_hypsec_inject_undef(u32 vmid, u32 vcpuid)
{
    //set_shadow_dirty_bit(vmid, vcpuid, PENDING_UNDEF_INJECT, 1U);
}

void __hyp_text v_update_exception_gp_regs(u32 vmid, u32 vcpuid)
{
    u64 esr = ESR_ELx_EC_UNKNOWN;
    u64 pstate = get_shadow_ctxt(vmid, vcpuid, V_PSTATE);
    u64 pc = get_shadow_ctxt(vmid, vcpuid, V_PC);
    u64 new_pc = get_exception_vector(pstate);
    set_shadow_ctxt(vmid, vcpuid, V_ELR_EL1, pc);
    set_shadow_ctxt(vmid, vcpuid, V_PC, new_pc);
    set_shadow_ctxt(vmid, vcpuid, V_PSTATE, PSTATE_FAULT_BITS_64);
    set_shadow_ctxt(vmid, vcpuid, V_SPSR_0, pstate);
    set_shadow_ctxt(vmid, vcpuid, V_ESR_EL1, esr);
}

void __hyp_text v_post_handle_shadow_s2pt_fault(u32 vmid, u32 vcpuid)
{
    u64 hpfar = get_shadow_ctxt(vmid, vcpuid, V_HPFAR_EL2);
    u64 addr = (hpfar & HPFAR_MASK) * 256UL;
    u64 pte = get_int_new_pte(vmid, vcpuid);
    u32 level = get_int_new_level(vmid, vcpuid);

    u64 esr = get_shadow_esr(vmid, vcpuid);
    u64 esr_ec = (esr / ESR_ELx_EC_SHIFT) % ESR_ELx_EC_MASK;
    u32 is_iabt = 0U;
    if (esr_ec == ESR_ELx_EC_IABT_LOW) is_iabt = 1U;
    prot_and_map_vm_s2pt(vmid, addr, pte, level, is_iabt);
}
