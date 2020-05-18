#include <linux/kvm.h>
#include <linux/kvm_host.h>

#include <asm/esr.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_coproc.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_hyp.h>
#include <asm/hypsec_host.h>

#include <kvm/pvops.h>

int __hyp_text handle_pvops(u32 vmid, u32 vcpuid)
{
	struct el2_data *el2_data = kern_hyp_va((void*)&el2_data_start);
	u32 index = VCPU_IDX(vmid, vcpuid);

	//u64 call_num = get_shadow_ctxt(vmid, vcpu_id, 0);
	u64 call_num = el2_data->shadow_vcpu_ctxt[index].regs[0];
	//u64 addr = get_shadow_ctxt(vmid, vcpu_id, 1);
	u64 addr = el2_data->shadow_vcpu_ctxt[index].regs[1];
	//u64 size = get_shadow_ctxt(vmid, vcpu_id, 2);
	u64 size = el2_data->shadow_vcpu_ctxt[index].regs[2];

	switch (call_num) {
		case KVM_SET_DESC_PFN:
			v_grant_stage2_sg_gpa(vmid, addr, size);
			break;
		case KVM_UNSET_DESC_PFN:
			v_revoke_stage2_sg_gpa(vmid, addr, size);
			break;
		//case KVM_SET_BALLOON_PFN:
		//	set_balloon_pfn(shadow_ctxt);
		//	break;
		default:
			return -EINVAL;
	}

	return 1;
	//return -EINVAL;
}
