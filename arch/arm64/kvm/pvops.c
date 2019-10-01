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

int __hyp_text handle_pvops(void)
{
	u32 vmid = get_cur_vmid();
	u32 vcpu_id = get_cur_vcpu_id();
	unsigned long call_num = get_shadow_ctxt(vmid, vcpu_id, 0);

#if 0
	switch (call_num) {
		case KVM_SET_DESC_PFN:
			grant_stage2_sg_gpa(shadow_ctxt);
			break;
		case KVM_UNSET_DESC_PFN:
			revoke_stage2_sg_gpa(shadow_ctxt);
			break;
		case KVM_SET_BALLOON_PFN:
			set_balloon_pfn(shadow_ctxt);
			break;
		default:
			return -EINVAL;
	}
#endif
	return 1;
}
