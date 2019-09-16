#include "hypsec.h"

/*
 * VCPUOpsAux
 */

void reset_gp_regs(u32 ctxtid)
{
    u64 pc = get_int_ctxt(ctxtid, PC);
    u32 vmid = get_ctxt_vmid(ctxtid);

    if (search_load_info(vmid, pc))
    {
        clear_shadow_gp_regs(ctxtid);
        u64 pstate = get_int_ctxt(ctxtid, PSTATE);
        set_shadow_ctxt(ctxtid, PSTATE, pstate);
        set_shadow_ctxt(ctxtid, PC, pc);
        int_to_shadow_fp_regs(ctxtid);
    }
    else {
        panic();
    }
}

void reset_sys_regs(u32 ctxtid)
{
    u64 val;
    u32 i = 1U;
    u32 vcpu_id = get_ctxt_vcpuid(ctxtid);
    while (i <= SHADOW_SYS_REGS_SIZE)
    {
        if (i == MPIDR_EL1)
        {
            u64 mpidr = (vcpu_id % 16U) + ((vcpu_id / 16U) % 256U) * 256U +
                                  ((vcpu_id / 4096U) % 256U) * 65536U;
            val = mpidr + 2147483648UL;
        }
        else
        {
            val = get_sys_reg_desc_val(i);
        }
        set_shadow_ctxt(ctxtid, i, val);
        i += 1U;
    }
}

void save_sys_regs(u32 ctxtid)
{
    set_shadow_ctxt(ctxtid, DACR32_EL2, get_int_ctxt(ctxtid, DACR32_EL2));
    set_shadow_ctxt(ctxtid, IFSR32_EL2, get_int_ctxt(ctxtid, IFSR32_EL2));
    set_shadow_ctxt(ctxtid, FPEXC32_EL2, get_int_ctxt(ctxtid, FPEXC32_EL2));

    set_int_ctxt(ctxtid, DACR32_EL2, 0UL);
    set_int_ctxt(ctxtid, IFSR32_EL2, 0UL);
    set_int_ctxt(ctxtid, FPEXC32_EL2, 0UL);
}

void restore_sys_regs(u32 ctxtid)
{
    set_int_ctxt(ctxtid, DACR32_EL2, get_shadow_ctxt(ctxtid, DACR32_EL2));
    set_int_ctxt(ctxtid, IFSR32_EL2, get_shadow_ctxt(ctxtid, IFSR32_EL2));
    set_int_ctxt(ctxtid, FPEXC32_EL2, get_shadow_ctxt(ctxtid, FPEXC32_EL2));
}

void sync_dirty_to_shadow(u32 ctxtid)
{
    u32 i = 0U;
    while (i < 31U)
    {
        if (get_shadow_dirty_bit(ctxtid, i) == 1U) {
            u64 reg = get_int_ctxt(ctxtid, i);
            set_shadow_ctxt(ctxtid, i, reg);
        }
        i += 1U;
    }
}

void prep_wfx(u32 ctxtid)
{
    set_shadow_dirty_bit(ctxtid, DIRTY_PC_FLAG, 1U);
}

void prep_hvc(u32 ctxtid)
{
    u32 vmid = get_ctxt_vmid(ctxtid);
    u64 psci_fn = get_shadow_ctxt(ctxtid, 0UL);
    set_shadow_dirty_bit(ctxtid, 0U, 1U);
    set_int_ctxt(ctxtid, 0U, psci_fn);
    if (psci_fn == PSCI_0_2_FN64_CPU_ON)
    {
        set_int_ctxt(ctxtid, 1U, get_shadow_ctxt(ctxtid, 1U));
        set_int_ctxt(ctxtid, 2U, get_shadow_ctxt(ctxtid, 2U));
        set_int_ctxt(ctxtid, 3U, get_shadow_ctxt(ctxtid, 3U));
    }
    else if (psci_fn == PSCI_0_2_FN_AFFINITY_INFO ||
             psci_fn == PSCI_0_2_FN64_AFFINITY_INFO)
    {
        set_int_ctxt(ctxtid, 1U, get_shadow_ctxt(ctxtid, 1U));
        set_int_ctxt(ctxtid, 2U, get_shadow_ctxt(ctxtid, 2U));

    }
    else if (psci_fn == PSCI_0_2_FN_SYSTEM_OFF) {
        set_vm_poweroff(vmid);
    }
}

void prep_abort(u32 ctxtid)
{
    u64 esr = get_int_ctxt(ctxtid, ESR_EL2);
    u32 Rd = (u32)((esr / 65536UL) % 32UL);
    u64 fault_ipa = (get_shadow_ctxt(ctxtid, HPFAR_EL2) / 16UL) * 4096UL;

    if (fault_ipa < MAX_MMIO_ADDR)
    {
        set_shadow_dirty_bit(ctxtid, DIRTY_PC_FLAG, 1UL);

        if ((esr / 64UL) % 4UL == 0UL) {
            set_shadow_dirty_bit(ctxtid, Rd, 1U);
        }
        else {
            u64 reg = get_shadow_ctxt(ctxtid, Rd);
            set_int_ctxt(ctxtid, Rd, reg);
        }
    }
}

void hypsec_inject_undef(u32 ctxtid)
{
    set_shadow_dirty_bit(ctxtid, PENDING_UNDEF_INJECT, 1U);
}

void update_exception_gp_regs(u32 ctxtid)
{
    u64 esr = ESR_ELx_EC_UNKNOWN;
    u64 pstate = get_shadow_ctxt(ctxtid, PSTATE);
    u64 pc = get_shadow_ctxt(ctxtid, PC);
    set_shadow_ctxt(ctxtid, ELR_EL1, pc);
    u64 new_pc = get_exception_vector(pstate);
    set_shadow_ctxt(ctxtid, PC, new_pc);
    set_shadow_ctxt(ctxtid, PSTATE, PSTATE_FAULT_BITS_64);
    set_shadow_ctxt(ctxtid, SPSR_0, pstate);
    set_shadow_ctxt(ctxtid, ESR_EL1, esr);
}

void post_handle_shadow_s2pt_fault(u32 ctxtid)
{
    u32 vmid = get_ctxt_vmid(ctxtid);
    u64 hpfar = get_shadow_ctxt(ctxtid, HPFAR_EL2);
    u64 addr = (hpfar & HPFAR_MASK) * 256UL;
    u64 pte = get_int_new_pte(ctxtid);
    u32 level = get_int_new_level(ctxtid);
    u64 esr = get_shadow_ctxt(ctxtid, ESR_EL2);
    u64 esr_ec = (esr / ESR_ELx_EC_SHIFT) % ESR_ELx_EC_MASK;
    u32 is_iabt = 0U;
    if (esr_ec == ESR_ELx_EC_IABT_LOW) is_iabt = 1U;
    prot_and_map_vm_s2pt(vmid, addr, pte, level, is_iabt);
}

