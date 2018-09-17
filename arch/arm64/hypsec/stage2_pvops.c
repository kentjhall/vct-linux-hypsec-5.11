#include <linux/types.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>
#include <linux/mman.h>
#include <linux/kvm_host.h>
#include <linux/io.h>
#include <trace/events/kvm.h>
#include <asm/pgalloc.h>
#include <asm/cacheflush.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_mmio.h>
#include <asm/kvm_emulate.h>
#include <asm/virt.h>
#include <asm/kernel-pgtable.h>
#include <asm/stage2_host.h>
#include <asm/spinlock_types.h>

extern void set_pfn_owner(struct stage2_data *stage2_data, phys_addr_t addr,
				size_t len, u32 vmid);

void __hyp_text set_stage2_vring_gpa(struct kvm_vcpu *vcpu)
{
}

void __hyp_text set_balloon_pfn(struct kvm_vcpu *vcpu)
{
}

void __hyp_text set_stage2_sg_gpa(struct kvm_vcpu *vcpu)
{
}

void __hyp_text unset_stage2_sg_gpa(struct kvm_vcpu *vcpu)
{
}
