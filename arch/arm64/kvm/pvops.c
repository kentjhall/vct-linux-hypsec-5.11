#include <linux/kvm.h>
#include <linux/kvm_host.h>

#include <asm/esr.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_coproc.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_hyp.h>
#include <asm/stage2_host.h>

#include <kvm/pvops.h>

int __hyp_text handle_pvops(struct kvm_vcpu *vcpu)
{
	/* TODO: We should get call num from shadow regs later */
	unsigned long call_num = shadow_vcpu_get_reg(vcpu, 0);

	switch (call_num) {
		case KVM_SET_VRING_PFN:
			set_stage2_vring_gpa(vcpu);
			break;
		case KVM_SET_DESC_PFN:
			grant_stage2_sg_gpa(vcpu);
			break;
		case KVM_UNSET_DESC_PFN:
			revoke_stage2_sg_gpa(vcpu);
			break;
		case KVM_SET_BALLOON_PFN:
			set_balloon_pfn(vcpu);
			break;
		default:
			return -EINVAL;
	}
	return 1;
}
