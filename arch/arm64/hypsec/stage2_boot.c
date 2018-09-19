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

static int __hyp_text hypsec_gen_vmid(struct stage2_data *stage2_data)
{
	int vmid;
	stage2_spin_lock(&stage2_data->vmid_lock);
	vmid = stage2_data->next_vmid++;
	stage2_spin_unlock(&stage2_data->vmid_lock);
	return vmid;
}

static int __hyp_text __alloc_vm_info(struct kvm* kvm)
{
	struct stage2_data *stage2_data;
	int count;

	kvm = kern_hyp_va(kvm);
	stage2_data = kern_hyp_va(kvm_ksym_ref(stage2_data_start));
	count = stage2_data->used_vm_info++;

	stage2_data->used_vm_info %= EL2_VM_INFO_SIZE;
	stage2_data->vm_info[count].is_valid_vm = false;
	stage2_data->vm_info[count].inc_exe = false;
	stage2_data->vm_info[count].vmid = hypsec_gen_vmid(stage2_data);
	stage2_data->vm_info[count].shadow_pt_lock =
		(arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	kvm->arch.vm_info = &stage2_data->vm_info[count];
	return stage2_data->vm_info[count].vmid;
}

static unsigned long __hyp_text alloc_remap_addr(unsigned long size)
{
	struct stage2_data *stage2_data;
	unsigned long ret, page_count;

	stage2_data = kern_hyp_va(kvm_ksym_ref(stage2_data_start));
	ret = EL2_REMAP_START + stage2_data->last_remap_ptr;
	page_count = (size >> PAGE_SHIFT) + ((size & (PAGE_SIZE - 1)) ? 1 : 0);

	stage2_data->last_remap_ptr += (page_count * PAGE_SIZE);

	return ret;
}

static inline struct el2_vm_info* get_vm_info(struct stage2_data *stage2_data,
					      struct kvm *kvm)
{
	u64 pool_start, len;
	void *ret;

	if (!kvm)
		goto out_panic;

	ret = kvm->arch.vm_info;
	pool_start = (u64)&stage2_data->vm_info;
	len = sizeof(struct el2_vm_info) * EL2_VM_INFO_SIZE;
	/* Check if vm_info was allocated from the pool */
	if ((u64)ret < pool_start && (u64)ret >= (pool_start + len))
		goto out_panic;

	return ret;

out_panic:
	__hyp_panic();
}

arch_spinlock_t* __hyp_text get_shadow_pt_lock(struct kvm *kvm)
{
	struct el2_vm_info *vm_info;
	struct stage2_data *stage2_data;
	stage2_data = kern_hyp_va(kvm_ksym_ref(stage2_data_start));
	vm_info = get_vm_info(stage2_data, kvm);
	return &vm_info->shadow_pt_lock;
}

int __hyp_text el2_get_vmid(struct stage2_data *stage2_data,
			     struct kvm *kvm)
{
	struct el2_vm_info *vm_info = get_vm_info(stage2_data, kvm);
	return vm_info->vmid;
}

int __hyp_text __el2_set_boot_info(struct kvm *kvm, unsigned long load_addr,
				unsigned long size, int image_type)
{
	struct stage2_data *stage2_data;
	struct el2_vm_info *vm_info;
	int load_count;

	kvm = kern_hyp_va(kvm);
	stage2_data = kern_hyp_va(kvm_ksym_ref(stage2_data_start));
	vm_info = get_vm_info(stage2_data, kvm);

	load_count = vm_info->load_info_cnt;
	vm_info->load_info[load_count].load_addr = load_addr;
	vm_info->load_info[load_count].size = size;
	vm_info->load_info[load_count].el2_remap_addr = alloc_remap_addr(size);
	vm_info->load_info[load_count].el2_mapped_pages = 0;

	return 0;
}

void __hyp_text __el2_remap_vm_image(struct kvm *kvm, unsigned long pfn)
{
	struct stage2_data *stage2_data;
	struct el2_vm_info *vm_info;
	struct el2_load_info *load_info;
	int count;
	unsigned long target;

	stage2_data = kern_hyp_va(kvm_ksym_ref(stage2_data_start));
	kvm = kern_hyp_va(kvm);

	vm_info = get_vm_info(stage2_data, kvm);
	count = vm_info->load_info_cnt;
	load_info = &vm_info->load_info[count];

	target = load_info->el2_remap_addr + (load_info->el2_mapped_pages * PAGE_SIZE);
	map_el2_mem(target, target + PAGE_SIZE, pfn, PAGE_HYP);

	if ((stage2_data->last_remap_ptr + EL2_REMAP_START) == (target + PAGE_SIZE))
		vm_info->load_info_cnt++;

	load_info->el2_mapped_pages++; 
}

int el2_alloc_vm_info(struct kvm *kvm)
{
	return kvm_call_hyp(__alloc_vm_info, kvm);
}

int el2_set_boot_info(struct kvm *kvm, unsigned long load_addr,
			unsigned long size, int type)
{
	return kvm_call_hyp(__el2_set_boot_info, kvm, load_addr,
						 size, type);
}

int el2_remap_vm_image(struct kvm *kvm, unsigned long pfn)
{
	return kvm_call_hyp(__el2_remap_vm_image, kvm, pfn);
}
