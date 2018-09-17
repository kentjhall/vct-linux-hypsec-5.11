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
	struct stage2_data *stage2_data;
	unsigned long addr, npages, index;
	size_t size_in_bytes;
	int i;
	struct kvm *kvm = (void *)kern_hyp_va(vcpu->kvm);
	struct s2_trans result;

	stage2_data = (void *)kern_hyp_va(kvm_ksym_ref(stage2_data_start));

	addr = vcpu_get_reg(vcpu, 1) & PAGE_MASK;
	size_in_bytes = vcpu_get_reg(vcpu, 2);
	npages = (size_in_bytes >> PAGE_SHIFT) + 1;

	for (i = 0; i < npages; i++) {
		result = walk_stage2_pgd(kvm, addr, true);
		if (!result.level)
			return;

		index = get_s2_page_index(stage2_data, result.pfn << PAGE_SHIFT);
		set_pfn_owner(stage2_data, result.pfn << PAGE_SHIFT, PAGE_SIZE, 0);
		stage2_data->s2_pages[index].count++;
		addr += PAGE_SIZE;
	}

	return;
}

void __hyp_text set_balloon_pfn(struct kvm_vcpu *vcpu)
{
}

static void __hyp_text __grant_stage2_sg_gpa(struct kvm *kvm,
				      struct stage2_data *stage2_data,
				      unsigned long addr,
				      pgprot_t mem_type)
{
	struct s2_trans result;
	struct s2_page *s2_pages;
	unsigned long index;
	int count = -EINVAL;
	kvm_pfn_t pfn;

	s2_pages = stage2_data->s2_pages;

	result = walk_stage2_pgd(kvm, addr, true);
	stage2_spin_lock(&stage2_data->s2pages_lock);
	pfn = result.pfn;
	if (!pfn) {
		print_string("\rset: failed to find hpa for gpa\n");
		printhex_ul(addr);
		goto out;
	}

	index = get_s2_page_index(stage2_data, pfn << PAGE_SHIFT);

	count = s2_pages[index].count++;

out:
	stage2_spin_unlock(&stage2_data->s2pages_lock);
	if (pfn && !count) {
		__set_pfn_host(pfn << PAGE_SHIFT, PAGE_SIZE, pfn, mem_type);
		set_pfn_owner(stage2_data, pfn << PAGE_SHIFT, PAGE_SIZE, 0);
	}

	return;
}

void __hyp_text grant_stage2_sg_gpa(struct kvm_vcpu *vcpu)
{
	struct stage2_data *stage2_data;
	unsigned long addr;
	int len;
	struct kvm *kvm = (void *)kern_hyp_va(vcpu->kvm);
	int writable;
	pgprot_t mem_type = PAGE_S2;

	stage2_data = (void *)kern_hyp_va(kvm_ksym_ref(stage2_data_start));

	addr = vcpu_get_reg(vcpu, 1);
	len = vcpu_get_reg(vcpu, 2) >> PAGE_SHIFT;

	writable = vcpu_get_reg(vcpu, 3);
	if (writable == 1)
		mem_type = PAGE_S2_KERNEL;

	do {
		__grant_stage2_sg_gpa(kvm, stage2_data, addr, mem_type);
		addr += PAGE_SIZE;
		len--;
	} while (len > 0);
}

static void __hyp_text __revoke_stage2_sg_gpa(struct kvm *kvm,
				      struct stage2_data *stage2_data,
				      unsigned long addr)
{
	struct s2_trans result;
	struct s2_page *s2_pages;
	unsigned long index;
	int count = -EINVAL;
	u32 vmid;
	kvm_pfn_t pfn;

	s2_pages = stage2_data->s2_pages;

	result = walk_stage2_pgd(kvm, addr, true);
	stage2_spin_lock(&stage2_data->s2pages_lock);
	pfn = result.pfn;
	if (!pfn) {
		print_string("\runset: failed to find hpa for gpa\n");
		printhex_ul(addr);
		goto out;
	}

	index = get_s2_page_index(stage2_data, pfn << PAGE_SHIFT);

	count = --s2_pages[index].count;

out:
	stage2_spin_unlock(&stage2_data->s2pages_lock);

	if (pfn && !count) {
		__set_pfn_host(pfn << PAGE_SHIFT, PAGE_SIZE, 0, PAGE_GUEST);
		vmid = el2_get_vmid(stage2_data, kvm);
		set_pfn_owner(stage2_data, pfn << PAGE_SHIFT, PAGE_SIZE, vmid);
	}
}

void __hyp_text revoke_stage2_sg_gpa(struct kvm_vcpu *vcpu)
{
	struct stage2_data *stage2_data;
	unsigned long addr;
	int len;
	struct kvm *kvm = (void *)kern_hyp_va(vcpu->kvm);

	stage2_data = (void *)kern_hyp_va(kvm_ksym_ref(stage2_data_start));

	addr = vcpu_get_reg(vcpu, 1);
	len = vcpu_get_reg(vcpu, 2) >> PAGE_SHIFT;

	do {
		__revoke_stage2_sg_gpa(kvm, stage2_data, addr);
		addr += PAGE_SIZE;
		len--;
	} while (len > 0);
}
