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
#include <asm/hypsec_host.h>
#include <asm/spinlock_types.h>


void __hyp_text set_balloon_pfn(struct kvm_vcpu *vcpu)
{
	struct s2_trans result;
	struct el2_data *el2_data;
	unsigned long gpa = shadow_vcpu_get_reg(vcpu, 1);
	kvm_pfn_t pfn;

	el2_data = (void *)kern_hyp_va(kvm_ksym_ref(el2_data_start));

	result = walk_stage2_pgd(vcpu->arch.vmid, gpa);
	if (!result.level)
		return;

	pfn = result.pfn;
	if (pfn) {
		/* FIXME: Do we really need to flush the entire thing? */
		clear_shadow_stage2_range(vcpu->arch.vmid, 0, KVM_PHYS_SIZE);
		el2_memset((void *)__el2_va(pfn << PAGE_SHIFT), 0, PAGE_SIZE);
		set_pfn_owner(el2_data, pfn << PAGE_SHIFT, 1, 0);
		__set_pfn_host(pfn << PAGE_SHIFT, PAGE_SIZE,
			pfn, PAGE_S2_KERNEL);
	}

	return;
}

static void __hyp_text __grant_stage2_sg_gpa(struct el2_data *el2_data,
				      	     unsigned long addr,
				      	     pgprot_t mem_type,
				      	     u32 vmid)
{
	struct s2_trans result;
	struct s2_page *s2_pages;
	unsigned long index;
	int count = -EINVAL;
	kvm_pfn_t pfn;

	s2_pages = el2_data->s2_pages;

	result = walk_stage2_pgd(vmid, addr);
	stage2_spin_lock(&el2_data->s2pages_lock);
	pfn = result.pfn;
	if (!pfn) {
		print_string("\rset: failed to find hpa for gpa\n");
		printhex_ul(addr);
		goto out;
	}

	index = get_s2_page_index(el2_data, pfn << PAGE_SHIFT);

	count = s2_pages[index].count++;

	if (pfn && !count) {
		s2_pages[index].vmid = 0;
		__set_pfn_host(pfn << PAGE_SHIFT, PAGE_SIZE, pfn, mem_type);
	}
out:
	stage2_spin_unlock(&el2_data->s2pages_lock);

	return;
}

void __hyp_text grant_stage2_sg_gpa(struct kvm_vcpu *vcpu)
{
	struct el2_data *el2_data;
	unsigned long addr;
	int writable;
	int len = 0;
	u64 arg2;
	pgprot_t mem_type = PAGE_S2;

	el2_data = (void *)kern_hyp_va(kvm_ksym_ref(el2_data_start));

	addr = shadow_vcpu_get_reg(vcpu, 1);
	arg2 = shadow_vcpu_get_reg(vcpu, 2);
	len += (arg2 & (PAGE_SIZE - 1) ? 1 : 0);
	if (arg2 >> PAGE_SHIFT)
		len += arg2 >> PAGE_SHIFT;

	writable = shadow_vcpu_get_reg(vcpu, 3);
	if (writable == 1)
		mem_type = PAGE_S2_KERNEL;

	while (len > 0) {
		__grant_stage2_sg_gpa(el2_data, addr, mem_type, vcpu->arch.vmid);
		addr += PAGE_SIZE;
		len--;
	};
}

static void __hyp_text __revoke_stage2_sg_gpa(struct el2_data *el2_data,
				      	      unsigned long addr,
				      	      u32 vmid)
{
	struct s2_trans result;
	struct s2_page *s2_pages;
	unsigned long index;
	int count = -EINVAL;
	kvm_pfn_t pfn;

	s2_pages = el2_data->s2_pages;

	result = walk_stage2_pgd(vmid, addr);
	stage2_spin_lock(&el2_data->s2pages_lock);
	pfn = result.pfn;
	if (!pfn) {
		print_string("\runset: failed to find hpa for gpa\n");
		printhex_ul(addr);
		goto out;
	}

	index = get_s2_page_index(el2_data, pfn << PAGE_SHIFT);

	count = --s2_pages[index].count;

	if (pfn && !count) {
		s2_pages[index].vmid = vmid;
		__set_pfn_host(pfn << PAGE_SHIFT, PAGE_SIZE, 0, PAGE_GUEST);
	}
out:
	stage2_spin_unlock(&el2_data->s2pages_lock);
}

void __hyp_text revoke_stage2_sg_gpa(struct kvm_vcpu *vcpu)
{
	struct el2_data *el2_data;
	unsigned long addr;
	int len = 0;
	u64 arg2;

	el2_data = (void *)kern_hyp_va(kvm_ksym_ref(el2_data_start));

	addr = shadow_vcpu_get_reg(vcpu, 1);
	arg2 = shadow_vcpu_get_reg(vcpu, 2);
	len += (arg2 & (PAGE_SIZE - 1) ? 1 : 0);
	if (arg2 >> PAGE_SHIFT)
		len += arg2 >> PAGE_SHIFT;

	while (len > 0) {
		__revoke_stage2_sg_gpa(el2_data, addr, vcpu->arch.vmid);
		addr += PAGE_SIZE;
		len--;
	};
}
