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

#include "ed25519/ed25519.h"

static int __hyp_text hypsec_gen_vmid(struct el2_data *el2_data)
{
	int vmid;
	stage2_spin_lock(&el2_data->vmid_lock);
	vmid = el2_data->next_vmid++;
	stage2_spin_unlock(&el2_data->vmid_lock);
	return vmid;
}

static int __hyp_text __alloc_vm_info(struct kvm* kvm)
{
	struct el2_data *el2_data;
	int count;

	kvm = kern_hyp_va(kvm);
	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	count = el2_data->used_vm_info++;

	el2_data->used_vm_info %= EL2_VM_INFO_SIZE;
	el2_data->vm_info[count].is_valid_vm = false;
	el2_data->vm_info[count].inc_exe = false;
	el2_data->vm_info[count].vmid = hypsec_gen_vmid(el2_data);
	el2_data->vm_info[count].shadow_pt_lock =
		(arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	el2_data->vm_info[count].boot_lock =
		(arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	kvm->arch.vm_info = &el2_data->vm_info[count];
	return el2_data->vm_info[count].vmid;
}

static unsigned long __hyp_text alloc_remap_addr(unsigned long size)
{
	struct el2_data *el2_data;
	unsigned long ret, page_count;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	ret = EL2_REMAP_START + el2_data->last_remap_ptr;
	page_count = (size >> PAGE_SHIFT) + ((size & (PAGE_SIZE - 1)) ? 1 : 0);

	el2_data->last_remap_ptr += (page_count * PAGE_SIZE);

	return ret;
}

static inline struct el2_vm_info* get_vm_info(struct el2_data *el2_data,
					      struct kvm *kvm)
{
	u64 pool_start, len;
	void *ret;

	if (!kvm)
		goto out_panic;

	ret = kvm->arch.vm_info;
	pool_start = (u64)&el2_data->vm_info;
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
	struct el2_data *el2_data;
	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	vm_info = get_vm_info(el2_data, kvm);
	return &vm_info->shadow_pt_lock;
}

int __hyp_text el2_get_vmid(struct el2_data *el2_data,
			     struct kvm *kvm)
{
	struct el2_vm_info *vm_info = get_vm_info(el2_data, kvm);
	return vm_info->vmid;
}

int __hyp_text __el2_set_boot_info(struct kvm *kvm, unsigned long load_addr,
				unsigned long size, int image_type)
{
	struct el2_data *el2_data;
	struct el2_vm_info *vm_info;
	int load_count;

	kvm = kern_hyp_va(kvm);
	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	vm_info = get_vm_info(el2_data, kvm);

	load_count = vm_info->load_info_cnt;
	vm_info->load_info[load_count].load_addr = load_addr;
	vm_info->load_info[load_count].size = size;
	vm_info->load_info[load_count].el2_remap_addr = alloc_remap_addr(size);
	vm_info->load_info[load_count].el2_mapped_pages = 0;

	return 0;
}

void __hyp_text __el2_remap_vm_image(struct kvm *kvm, unsigned long pfn)
{
	struct el2_data *el2_data;
	struct el2_vm_info *vm_info;
	struct el2_load_info *load_info;
	int count;
	unsigned long target;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	kvm = kern_hyp_va(kvm);

	vm_info = get_vm_info(el2_data, kvm);
	count = vm_info->load_info_cnt;
	load_info = &vm_info->load_info[count];

	target = load_info->el2_remap_addr + (load_info->el2_mapped_pages * PAGE_SIZE);
	map_el2_mem(target, target + PAGE_SIZE, pfn, PAGE_HYP);

	if ((el2_data->last_remap_ptr + EL2_REMAP_START) == (target + PAGE_SIZE))
		vm_info->load_info_cnt++;

	load_info->el2_mapped_pages++; 
}

bool __hyp_text __el2_verify_and_load_images(struct kvm *kvm)
{
	struct el2_data *el2_data;
	struct el2_vm_info *vm_info;
	struct el2_load_info load_info;
	int i;
	bool res = true;
	unsigned char signature[64];
	unsigned char public_key[32];
	unsigned char *signature_hex = "3f8e027d94055d36a8a12de3472970e7072897a0700d09e8fd03ff78dcbeb939723ff81f098db82a1562dfd3cf1794aa61a210c733d849bcdfdf55f69014780a";
	unsigned char *public_key_hex = "25f2d889403a586265eeff77d54687971301c280a02a4b5e7a416449be2ab239";
	arch_spinlock_t *lock;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	kvm = kern_hyp_va(kvm);
	vm_info = get_vm_info(el2_data, kvm);

	lock = &vm_info->boot_lock;
	stage2_spin_lock(lock);

	if (vm_info->is_valid_vm)
		goto out;
	/* Traverse through the load info list and check the integrity of images. */
	for (i = 0; i < vm_info->load_info_cnt; i++) {
		//Call to the crypto authentication function here.
		unsigned char *kern_img;
		int verify_res = 0;

		load_info = vm_info->load_info[i];
		unmap_image_from_host_s2pt(kvm, load_info.el2_remap_addr,
			load_info.el2_mapped_pages);

		el2_hex2bin(signature, signature_hex, 64);
		el2_hex2bin(public_key, public_key_hex, 32);

		load_info = vm_info->load_info[i];
		kern_img = (char *) load_info.el2_remap_addr;
		verify_res = ed25519_verify(signature, kern_img, load_info.size, public_key);
		/*
		 * Desirably, we'd like to map verified images only, but
		 * now we map all images to VM memory anyway.
		 */
		load_image_to_shadow_s2pt(kvm, el2_data, load_info.load_addr,
			load_info.el2_remap_addr, load_info.el2_mapped_pages);
	}

	vm_info->is_valid_vm = true;

out:
	stage2_spin_unlock(lock);
	return res;
}

unsigned long __hyp_text search_load_info(struct kvm *kvm,
					  struct el2_data *el2_data,
					  unsigned long addr)
{
	struct el2_load_info li;
	int i;
	struct el2_vm_info *vm_info = get_vm_info(el2_data, kvm);
	unsigned long el2_va = 0;

	for (i = 0; i < vm_info->load_info_cnt; i++) {
		li = vm_info->load_info[i];
		if (addr >= li.load_addr && (li.load_addr + li.size) >= addr) {
			el2_va = (addr - li.load_addr) + li.el2_remap_addr;
			break;
		}
	}
	return el2_va;
}

unsigned long __hyp_text get_el2_image_va(struct kvm *kvm, unsigned long addr)
{
	struct el2_data *el2_data;
	unsigned long ret = 0;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	ret = search_load_info(kvm, el2_data, addr);
	return ret;
}

bool __hyp_text el2_use_inc_exe(struct kvm *kvm,
			        struct el2_data *el2_data)
{
	struct el2_vm_info *vm_info;

	vm_info = get_vm_info(el2_data, kvm);
	return vm_info->inc_exe;
}

void __hyp_text __el2_boot_from_inc_exe(struct kvm *kvm)
{
	struct el2_data *el2_data;
	struct el2_vm_info *vm_info;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	kvm = kern_hyp_va(kvm);
	vm_info = get_vm_info(el2_data, kvm);
	vm_info->inc_exe = true;
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

int el2_verify_and_load_images(struct kvm *kvm)
{
	return kvm_call_hyp(__el2_verify_and_load_images, kvm);
}

void el2_boot_from_inc_exe(struct kvm *kvm)
{
	kvm_call_hyp(__el2_boot_from_inc_exe, kvm);
}
