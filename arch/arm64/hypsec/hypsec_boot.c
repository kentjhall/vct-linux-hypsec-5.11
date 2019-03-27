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
#include "tiny-AES-c/aes.h"

static u32 __hyp_text hypsec_gen_vmid(struct el2_data *el2_data)
{
	u32 vmid;
	stage2_spin_lock(&el2_data->vmid_lock);
	vmid = el2_data->next_vmid++;
	stage2_spin_unlock(&el2_data->vmid_lock);

	if (vmid < EL2_MAX_VMID)
		return vmid;
	else
		return -1;
}

static unsigned long __hyp_text alloc_remap_addr(unsigned long size)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	unsigned long ret, page_count;


	stage2_spin_lock(&el2_data->remap_lock);
	ret = EL2_REMAP_START + el2_data->last_remap_ptr;
	page_count = (size >> PAGE_SHIFT) + ((size & (PAGE_SIZE - 1)) ? 1 : 0);
	el2_data->last_remap_ptr += (page_count * PAGE_SIZE);
	stage2_spin_unlock(&el2_data->remap_lock);

	return ret;
}

struct el2_vm_info* __hyp_text vmid_to_vm_info(u32 vmid)
{
	struct el2_data *el2_data;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	if (vmid < EL2_MAX_VMID)
		return &el2_data->vm_info[vmid];
	else
		__hyp_panic();
}

struct int_vcpu* __hyp_text vcpu_id_to_int_vcpu(
			struct el2_vm_info *vm_info, int vcpu_id)
{
	if (vcpu_id < 0 || vcpu_id >= HYPSEC_MAX_VCPUS)
		return NULL;
	else
		return &vm_info->int_vcpus[vcpu_id];
}

arch_spinlock_t* __hyp_text get_shadow_pt_lock(u32 vmid)
{
	struct el2_vm_info *vm_info = vmid_to_vm_info(vmid);
	return &vm_info->shadow_pt_lock;
}

u64 __hyp_text get_shadow_vttbr(u32 vmid)
{
	struct el2_vm_info *vm_info = vmid_to_vm_info(vmid);
	return vm_info->vttbr;
}

void __hyp_text __el2_set_boot_info(u32 vmid, unsigned long load_addr,
				unsigned long size, int image_type)
{
	struct el2_vm_info *vm_info;
	int load_count;
	unsigned char *signature_hex = "3f8e027d94055d36a8a12de3472970e7072897a0700d09e8fd03ff78dcbeb939723ff81f098db82a1562dfd3cf1794aa61a210c733d849bcdfdf55f69014780a";

	vm_info = vmid_to_vm_info(vmid);
	stage2_spin_lock(&vm_info->boot_lock);
	/*
	 * If we have validated the images then the host is not
	 * allowed to add stuff to boot_info.
	 */
	if (vm_info->state != READY)
		goto out;

	load_count = vm_info->load_info_cnt;
	vm_info->load_info[load_count].load_addr = load_addr;
	vm_info->load_info[load_count].size = size;
	vm_info->load_info[load_count].el2_remap_addr = alloc_remap_addr(size);
	vm_info->load_info[load_count].el2_mapped_pages = 0;
	el2_hex2bin(vm_info->load_info[load_count].signature, signature_hex, 64);
out:
	stage2_spin_unlock(&vm_info->boot_lock);
}

void __hyp_text __el2_remap_vm_image(u32 vmid, unsigned long pfn)
{
	struct el2_vm_info *vm_info;
	struct el2_load_info *load_info;
	struct el2_data *el2_data;
	int count;
	unsigned long target;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	vm_info = vmid_to_vm_info(vmid);
	count = vm_info->load_info_cnt;
	load_info = &vm_info->load_info[count];

	target = load_info->el2_remap_addr + (load_info->el2_mapped_pages * PAGE_SIZE);
	map_el2_mem(target, target + PAGE_SIZE, pfn, PAGE_HYP);

	if ((el2_data->last_remap_ptr + EL2_REMAP_START) == (target + PAGE_SIZE))
		vm_info->load_info_cnt++;

	load_info->el2_mapped_pages++; 
}

bool __hyp_text __el2_verify_and_load_images(u32 vmid)
{
	struct el2_data *el2_data;
	struct el2_vm_info *vm_info = vmid_to_vm_info(vmid);
	struct el2_load_info load_info;
	int i;
	bool res = true;
	arch_spinlock_t *lock;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));

	lock = &vm_info->boot_lock;
	stage2_spin_lock(lock);

	if (vm_info->state != READY)
		goto out;
	/* Traverse through the load info list and check the integrity of images. */
	for (i = 0; i < vm_info->load_info_cnt; i++) {
		/* Call to the crypto authentication function here. */
		unsigned char *kern_img;
		int verify_res = 0;

		load_info = vm_info->load_info[i];
		unmap_image_from_host_s2pt(vmid, load_info.el2_remap_addr,
			load_info.el2_mapped_pages);
		kern_img = (char *) load_info.el2_remap_addr;
		verify_res = ed25519_verify(load_info.signature, kern_img,
					    load_info.size, vm_info->public_key);
		/*
		 * Desirably, we'd like to map verified images only, but
		 * now we map all images to VM memory anyway.
		 */
		load_image_to_shadow_s2pt(vmid, el2_data, load_info.load_addr,
			load_info.el2_remap_addr, load_info.el2_mapped_pages);
	}

	vm_info->state = VERIFIED;

out:
	stage2_spin_unlock(lock);
	return res;
}

unsigned long __hyp_text search_load_info(u32 vmid,
					  struct el2_data *el2_data,
					  unsigned long addr)
{
	struct el2_load_info li;
	int i;
	struct el2_vm_info *vm_info = vmid_to_vm_info(vmid);
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

unsigned long __hyp_text get_el2_image_va(u32 vmid, unsigned long addr)
{
	struct el2_data *el2_data;
	unsigned long ret = 0;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	ret = search_load_info(vmid, el2_data, addr);
	return ret;
}

bool __hyp_text el2_use_inc_exe(u32 vmid)
{
	struct el2_vm_info *vm_info = vmid_to_vm_info(vmid);
	return vm_info->inc_exe;
}

void __hyp_text __el2_boot_from_inc_exe(u32 vmid)
{
	struct el2_vm_info *vm_info = vmid_to_vm_info(vmid);
	vm_info->inc_exe = true;
}

#define KVM_SIZE	sizeof(struct kvm)
#define VCPU_SIZE	sizeof(struct kvm_vcpu)
#define N_KVM_PAGES	(KVM_SIZE >> PAGE_SHIFT) + ((KVM_SIZE % PAGE_SIZE) ? 1 : 0)
#define N_VCPU_PAGES	(VCPU_SIZE >> PAGE_SHIFT) + ((VCPU_SIZE % PAGE_SIZE) ? 1 : 0)
#define EL2_REMAP_KVM_BASE	0x10000000
#define EL2_REMAP_VCPU_BASE	0x40000000
static void* __hyp_text get_el2_kvm_addr(struct el2_data *el2_data)
{
	unsigned long npages = N_KVM_PAGES, offset;

	stage2_spin_lock(&el2_data->remap_lock);
	offset = (PAGE_SIZE * npages) * el2_data->kvm_cnt++;
	stage2_spin_unlock(&el2_data->remap_lock);
	return (void*)((unsigned long)EL2_REMAP_KVM_BASE | offset);
}

static void* __hyp_text get_el2_vcpu_addr(struct el2_data *el2_data)
{
	unsigned long npages = N_VCPU_PAGES, offset;

	stage2_spin_lock(&el2_data->remap_lock);
	offset = (PAGE_SIZE * npages) * el2_data->vcpu_cnt++;
	stage2_spin_unlock(&el2_data->remap_lock);
	return (void*)((unsigned long)EL2_REMAP_VCPU_BASE | offset);
}

int __hyp_text __hypsec_register_vcpu(u32 vmid, int vcpu_id)
{
	struct el2_data *el2_data;
	struct int_vcpu *int_vcpu;
	struct el2_vm_info *vm_info;
	int ret = 1;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));

	/*
	 * We can only register a vcpu if its vm_info has been allocated and
	 * kvm is remapped.
	 */
	vm_info = vmid_to_vm_info(vmid);
	if (vm_info->state != READY)
		return -EINVAL;

	stage2_spin_lock(&vm_info->vm_lock);
	int_vcpu = vcpu_id_to_int_vcpu(vm_info, vcpu_id);
	if (!int_vcpu || int_vcpu->state != INVALID) {
		ret = -EINVAL;
		goto out;
	}

	int_vcpu->vcpu = get_el2_vcpu_addr(el2_data);
	int_vcpu->state = USED;

out:
	stage2_spin_unlock(&vm_info->vm_lock);
	return ret;
}

u32 __hyp_text __hypsec_register_kvm(void)
{
	u32 vmid;
	struct el2_data *el2_data;

	if (!system_supports_fpsimd())
		return 0;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	/*
	 * We guarantee vmid is always unique so we don't need
	 * to check the state here.
	 */
	vmid = hypsec_gen_vmid(el2_data);
	if (vmid < 0)
		return 0;

	el2_data->vm_info[vmid].vm_lock =
		(arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	el2_data->vm_info[vmid].state = USED;
	el2_data->vm_info[vmid].kvm = get_el2_kvm_addr(el2_data);
	el2_data->vm_info[vmid].vmid = vmid;
	return vmid;
}

int __hyp_text __hypsec_map_one_vcpu_page(u32 vmid, int vcpu_id, unsigned long pfn)
{
	struct el2_data *el2_data;
	struct el2_vm_info *vm_info;
	struct int_vcpu *int_vcpu;
	unsigned long target;
	int ret = 1;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));

	vm_info = vmid_to_vm_info(vmid);
	/* Return if vm_info has not been allocated OR kvm is remapped */
	if (vm_info->state != READY)
		return -EINVAL;

	stage2_spin_lock(&vm_info->vm_lock);
	int_vcpu = vcpu_id_to_int_vcpu(vm_info, vcpu_id);
	if (!int_vcpu || int_vcpu->state != USED) {
		ret = -EINVAL;
		goto out;
	}

	target = (unsigned long)int_vcpu->vcpu + (int_vcpu->vcpu_pg_cnt * PAGE_SIZE);
	map_el2_mem(target, target + PAGE_SIZE, pfn, PAGE_HYP);
	int_vcpu->vcpu_pg_cnt++;
	if (int_vcpu->vcpu_pg_cnt == N_VCPU_PAGES)
		int_vcpu->state = MAPPED;

out:
	stage2_spin_unlock(&vm_info->vm_lock);
	return ret;
}

int __hyp_text __hypsec_map_one_kvm_page(u32 vmid, unsigned long pfn)
{
	struct el2_data *el2_data;
	struct el2_vm_info *vm_info;
	unsigned long target;
	int ret = 1;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	vm_info = vmid_to_vm_info(vmid);
	stage2_spin_lock(&vm_info->vm_lock);

	/* Return if vm_info has not been allocated OR kvm is remapped */
	if (vm_info->state != USED) {
		ret = -EINVAL;
		goto out;
	}

	target = (unsigned long)vm_info->kvm + (vm_info->kvm_pg_cnt * PAGE_SIZE);
	map_el2_mem(target, target + PAGE_SIZE, pfn, PAGE_HYP);
	vm_info->kvm_pg_cnt++;
	if (vm_info->kvm_pg_cnt == N_KVM_PAGES)
		vm_info->state = MAPPED;

out:
	stage2_spin_unlock(&vm_info->vm_lock);
	return ret;
}

int __hyp_text __hypsec_init_vm(u32 vmid)
{
	struct el2_data *el2_data;
	u64 vttbr, vmid64;
	uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	uint8_t iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	unsigned char *public_key_hex = "25f2d889403a586265eeff77d54687971301c280a02a4b5e7a416449be2ab239";
	struct el2_vm_info *vm_info;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	vm_info = vmid_to_vm_info(vmid);

	stage2_spin_lock(&vm_info->vm_lock);
	if (vm_info->state != MAPPED)
		goto out_unlock;

	vm_info->inc_exe = false;
	vm_info->shadow_pt_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	vm_info->boot_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;

	/* Hardcoded VM's keys for now. */
	el2_memcpy(vm_info->key, key, 16);
	el2_memcpy(vm_info->iv, iv, 16);
	el2_hex2bin(vm_info->public_key, public_key_hex, 32);

	/* Allocates a 8KB page for stage 2 pgd */
	vttbr = (u64)alloc_stage2_page(S2_PGD_PAGES_NUM);

	/* Supports 8-bit VMID */
	vmid64 = ((u64)(vmid) << VTTBR_VMID_SHIFT) & VTTBR_VMID_MASK(8);
	vm_info->vttbr = vttbr | vmid64;

	map_vgic_cpu_to_shadow_s2pt(vmid, el2_data);

	vm_info->state = READY;

out_unlock:
	stage2_spin_unlock(&vm_info->vm_lock);
	return 0;
}

struct kvm* __hyp_text hypsec_vmid_to_kvm(u32 vmid)
{
	struct kvm *kvm = NULL;
	struct el2_vm_info *vm_info;

	// Check vmid bound here
	vm_info = vmid_to_vm_info(vmid);
	kvm = vm_info->kvm;
	if (!kvm)
		__hyp_panic();
	else
		return kvm;
}

struct kvm_vcpu* __hyp_text hypsec_vcpu_id_to_vcpu(u32 vmid, int vcpu_id)
{
	struct kvm_vcpu *vcpu = NULL;
	struct el2_vm_info *vm_info;

	if (vcpu_id >= HYPSEC_MAX_VCPUS)
		__hyp_panic();

	vm_info = vmid_to_vm_info(vmid);
	vcpu = vm_info->int_vcpus[vcpu_id].vcpu;
	if (!vcpu)
		__hyp_panic();
	else
		return vcpu;
}

struct shadow_vcpu_context* __hyp_text hypsec_vcpu_id_to_shadow_ctxt(
	u32 vmid, int vcpu_id)
{
	struct shadow_vcpu_context *shadow_ctxt = NULL;
	struct el2_vm_info *vm_info;

	if (vcpu_id >= HYPSEC_MAX_VCPUS)
		__hyp_panic();

	vm_info = vmid_to_vm_info(vmid);
	shadow_ctxt = vm_info->shadow_ctxt[vcpu_id];
	if (!shadow_ctxt)
		__hyp_panic();
	else
		return shadow_ctxt;
}

void __hyp_text encrypt_buf(u32 vmid, void *buf, uint32_t len)
{
	struct AES_ctx ctx;
	struct el2_vm_info *vm_info;
	vm_info = vmid_to_vm_info(vmid);
	AES_init_ctx_iv(&ctx, vm_info->key, vm_info->iv);
	AES_CBC_encrypt_buffer(&ctx, (uint8_t *)buf, len);
}

void __hyp_text decrypt_buf(u32 vmid, void *buf, uint32_t len)
{
	struct AES_ctx ctx;
	struct el2_vm_info *vm_info;
	vm_info = vmid_to_vm_info(vmid);
	AES_init_ctx_iv(&ctx, vm_info->key, vm_info->iv);
	AES_CBC_decrypt_buffer(&ctx, (uint8_t *)buf, len);
}

void el2_set_boot_info(u32 vmid, unsigned long load_addr,
			unsigned long size, int type)
{
	kvm_call_core(HVC_SET_BOOT_INFO, vmid, load_addr, size, type);
}

int el2_remap_vm_image(u32 vmid, unsigned long pfn)
{
	return kvm_call_core(HVC_REMAP_VM_IMAGE, vmid, pfn);
}

int el2_verify_and_load_images(u32 vmid)
{
	return kvm_call_core(HVC_VERIFY_VM_IMAGES, vmid);
}

void el2_boot_from_inc_exe(u32 vmid)
{
	kvm_call_core(HVC_BOOT_FROM_SAVED_VM, vmid);
}
