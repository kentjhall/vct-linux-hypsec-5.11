#include "hypsec.h"

/*
 * VCPUOps
 */

void save_shadow_kvm_regs(u32 ctxtid, u64 ec)
{
    set_shadow_ctxt(ctxtid, V_EC, ec);
    if (ec == ARM_EXCEPTION_TRAP)
    {
        u64 hsr = get_shadow_ctxt(ctxtid, V_ESR_EL2);
        u64 hsr_ec = (hsr / ESR_ELx_EC_SHIFT) % ESR_ELx_EC_MASK;
        if (hsr_ec == ESR_ELx_EC_WFx)
            prep_wfx(ctxtid);
        else if (hsr_ec == ESR_ELx_EC_HVC32)
            prep_hvc(ctxtid);
        else if (hsr_ec == ESR_ELx_EC_HVC64)
            prep_hvc(ctxtid);
        else if (hsr_ec == ESR_ELx_EC_IABT_LOW)
            prep_abort(ctxtid);
        else if (hsr_ec == ESR_ELx_EC_DABT_LOW)
            prep_abort(ctxtid);
        else
            v_panic();
            //hypsec_inject_undef(ctxtid);
    }
}

void restore_shadow_kvm_regs(u32 ctxtid)
{
    u32 vmid = get_ctxt_vmid(ctxtid);
    u64 dirty = get_shadow_ctxt(ctxtid, DIRTY);

    if (dirty == INVALID64)
    {
        /*if (vm_is_inc_exe(vmid) == 1U)
        {
            int_to_shadow_decrypt(ctxtid);
        }
        else*/
        {
            reset_gp_regs(ctxtid);
            reset_sys_regs(ctxtid);
        }
        save_sys_regs(ctxtid);
        set_shadow_ctxt(ctxtid, DIRTY, 0UL);
    }
    else
    {
        u64 ec = get_shadow_ctxt(ctxtid, V_EC);
        if (ec == ARM_EXCEPTION_TRAP)
            sync_dirty_to_shadow(ctxtid);
        //if (dirty & PENDING_EXCEPT_INJECT_FLAG)
            //update_exception_gp_regs(ctxtid);
        if (dirty & DIRTY_PC_FLAG) {
            u64 pc = get_shadow_ctxt(ctxtid, V_PC);
            set_shadow_ctxt(ctxtid, V_PC, pc + 4UL);
        }
        set_shadow_ctxt(ctxtid, DIRTY, 0UL);
        set_shadow_ctxt(ctxtid, V_FAR_EL2, 0UL);

        if (get_shadow_ctxt(ctxtid, V_FLAGS) & PENDING_FSC_FAULT)
        {
            //post_handle_shadow_s2pt_fault(ctxtid);
        }

        set_shadow_ctxt(ctxtid, V_FLAGS, 0UL);
    }
}

/*
void save_encrypted_vcpu(u32 ctxtid)
{
    shadow_to_int_encrypt(ctxtid);
    u64 pstate = get_shadow_ctxt(ctxtid, PSTATE);
    set_int_ctxt(ctxtid, PSTATE, pstate);
}
*/
