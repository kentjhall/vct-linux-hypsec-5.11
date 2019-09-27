#include "hypsec.h"

/*
 * VCPUOps
 */

void save_shadow_kvm_regs()
{
    u32 vmid = get_cur_vmid();
    u32 vcpuid = get_cur_vcpuid();
    u64 ec = get_shadow_ctxt(vmid, vcpuid, V_EC);
    if (ec == ARM_EXCEPTION_TRAP)
    {
        u64 hsr = get_shadow_ctxt(vmid, vcpuid, V_ESR_EL2);
        u64 hsr_ec = (hsr / ESR_ELx_EC_SHIFT) % ESR_ELx_EC_MASK;
        if (hsr_ec == ESR_ELx_EC_WFx)
            prep_wfx(vmid, vcpuid);
        else if (hsr_ec == ESR_ELx_EC_HVC32)
            prep_hvc(vmid, vcpuid);
        else if (hsr_ec == ESR_ELx_EC_HVC64)
            prep_hvc(vmid, vcpuid);
        else if (hsr_ec == ESR_ELx_EC_IABT_LOW)
            prep_abort(vmid, vcpuid);
        else if (hsr_ec == ESR_ELx_EC_DABT_LOW)
            prep_abort(vmid, vcpuid);
        else
			v_panic();
    }
}

void restore_shadow_kvm_regs()
{
    u32 vmid = get_cur_vmid();
    u32 vcpuid = get_cur_vcpuid();
    u64 dirty = get_shadow_ctxt(vmid, vcpuid, DIRTY);

    if (dirty == INVALID64)
    {
        /*if (vm_is_inc_exe(vmid) == 1U)
        {
            int_to_shadow_decrypt(vmid, vcpuid);
        }
        else*/
        {
            reset_gp_regs(vmid, vcpuid);
            reset_sys_regs(vmid, vcpuid);
        }
        save_sys_regs(vmid, vcpuid);
        set_shadow_ctxt(vmid, vcpuid, DIRTY, 0UL);
    }
    else
    {
        u64 ec = get_shadow_ctxt(vmid, vcpuid, V_EC);
        if (ec == ARM_EXCEPTION_TRAP)
            sync_dirty_to_shadow(vmid, vcpuid);
        if (dirty & PENDING_EXCEPT_INJECT_FLAG)
            v_update_exception_gp_regs(vmid, vcpuid);
        if (dirty & DIRTY_PC_FLAG) {
            u64 pc = get_shadow_ctxt(vmid, vcpuid, V_PC);
            set_shadow_ctxt(vmid, vcpuid, V_PC, pc + 4UL);
        }
        set_shadow_ctxt(vmid, vcpuid, DIRTY, 0UL);
        set_shadow_ctxt(vmid, vcpuid, V_FAR_EL2, 0UL);

        if (get_shadow_ctxt(vmid, vcpuid, V_FLAGS) & PENDING_FSC_FAULT)
        {
            v_post_handle_shadow_s2pt_fault(vmid, vcpuid);
        }

        set_shadow_ctxt(vmid, vcpuid, V_FLAGS, 0UL);
    }
}

/*
void save_encrypted_vcpu(u32 vmid, u32 vcpuid)
{
    shadow_to_int_encrypt(vmid, vcpuid);
    u64 pstate = get_shadow_ctxt(vmid, vcpuid, V_PSTATE);
    set_int_ctxt(vmid, vcpuid, V_PSTATE, pstate);
}
*/
