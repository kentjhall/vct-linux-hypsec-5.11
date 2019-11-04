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
#include <linux/serial_reg.h>

#include "hypsec.h"

static void __hyp_text self_test(void)
{
	int vmid, i = 0;

	print_string("\rregister kvm\n");
	vmid = register_kvm();
	do {
		print_string("\rregister vcpu\n");
		printhex_ul((unsigned long)i);
		register_vcpu(vmid, i++);
	} while (i < 4);
}

extern int __hypsec_register_vm(struct kvm *kvm);
void __hyp_text handle_host_stage2_fault(unsigned long host_lr,
					struct s2_host_regs *host_regs)
{
	phys_addr_t addr = (read_sysreg(hpfar_el2) & HPFAR_MASK) << 8;
	map_page_host(addr);
	return;
}

//TODO: Did we prove the following?
static void __hyp_text hvc_enable_s2_trans(void)
{
	struct el2_data *el2_data;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));

	if (!el2_data->installed) {
		protect_el2_mem();
		el2_data->installed = true;
	}

	__init_stage2_translation();

	write_sysreg(el2_data->host_vttbr, vttbr_el2);
	write_sysreg(HCR_HOST_NVHE_FLAGS, hcr_el2);
	__kvm_flush_vm_context();

	//self_test();
}

void __hyp_text handle_host_hvc(struct s2_host_regs *hr)
{
	u64 ret = 0, callno = hr->regs[0];

	/* FIXME: we write return val to reg[31] as this will be restored to x0 */
	switch (callno) {
	case HVC_ENABLE_S2_TRANS:
		hvc_enable_s2_trans();
		break;
	case HVC_VCPU_RUN:
		ret = (u64)__kvm_vcpu_run_nvhe((u32)hr->regs[1], (int)hr->regs[2]);
		hr->regs[31] = ret;
		break;
	case HVC_TIMER_SET_CNTVOFF:
		__kvm_timer_set_cntvoff((u32)hr->regs[1], (u32)hr->regs[2]);
		break;
	// The following can only be called when VM terminates.
	case HVC_CLEAR_VM_S2_RANGE:
		__clear_vm_stage2_range((u32)hr->regs[1],
					(phys_addr_t)hr->regs[2], (u64)hr->regs[3]);
		break;
	case HVC_SET_BOOT_INFO:
		//ret = __el2_set_boot_info((u32)hr->regs[1], (unsigned long)hr->regs[2],
		//		    (unsigned long)hr->regs[3], (int)hr->regs[4]);
		//hr->regs[31] = (int)ret;
		hr->regs[31] = 1;
		break;
	case HVC_REMAP_VM_IMAGE:
		//__el2_remap_vm_image((u32)hr->regs[1], (unsigned long)hr->regs[2],
		//		     (int)hr->regs[3]);
		break;
	case HVC_VERIFY_VM_IMAGES:
		//ret = (u64)__el2_verify_and_load_images((u32)hr->regs[1]);
		//hr->regs[31] = (u64)ret;
		verify_and_load_images((u32)hr->regs[1]);
		hr->regs[31] = 1;
		break;
	/*case HVC_FREE_SMMU_PGD:
		__el2_free_smmu_pgd((unsigned long)hr->regs[1]);
		break;
	case HVC_ALLOC_SMMU_PGD:
		__el2_alloc_smmu_pgd((unsigned long)hr->regs[1], (u8)hr->regs[2],
					(u32)hr->regs[3], (u64)hr->regs[4]);
		break;
	case HVC_SMMU_LPAE_MAP:
		__el2_arm_lpae_map((unsigned long)hr->regs[1], hr->regs[2],
					hr->regs[3], hr->regs[4], hr->regs[5]);
		break;
	case HVC_SMMU_LPAE_IOVA_TO_PHYS:
		ret = (u64)el2_arm_lpae_iova_to_phys((unsigned long)hr->regs[1],
							(u64)hr->regs[2]);
		hr->regs[31] = (u64)ret;
		break;
	case HVC_BOOT_FROM_SAVED_VM:
		__el2_boot_from_inc_exe((u32)hr->regs[1]);
		break;
	case HVC_ENCRYPT_BUF:
		__el2_encrypt_buf((u32)hr->regs[1], (void*)hr->regs[2], (uint32_t)hr->regs[3]);
		break;
	case HVC_DECRYPT_BUF:
		__el2_decrypt_buf((u32)hr->regs[1], (void*)hr->regs[2], (uint32_t)hr->regs[3]);
		break;
	case HVC_SAVE_CRYPT_VCPU:
		__save_encrypted_vcpu((u32)hr->regs[1], (int)hr->regs[2]);
		break;*/
	case HVC_REGISTER_KVM:
		ret = (int)register_kvm();
		hr->regs[31] = (u64)ret;
		break;
	case HVC_REGISTER_VCPU:
		ret = (int)register_vcpu((u32)hr->regs[1], (int)hr->regs[2]);
		hr->regs[31] = (u64)ret;
		break;
	default:
		print_string("\rno support hvc:\n");
		printhex_ul(callno);
		break;
		//__hyp_panic();
	};
}

//added by shih-wei
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
int __hyp_text hypsec_set_vcpu_active(u32 vmid, int vcpu_id)
{
	struct el2_vm_info *vm_info = vmid_to_vm_info(vmid);
	struct int_vcpu *int_vcpu;
	int ret = 1;

	stage2_spin_lock(&vm_info->vm_lock);
	if (vm_info->state != VERIFIED) {
		ret = 0;
		goto out;
	}

	int_vcpu = vcpu_id_to_int_vcpu(vm_info, vcpu_id);
	if (int_vcpu->state == READY)
		int_vcpu->state = ACTIVE;
	else
		ret = 0;
out:
	stage2_spin_unlock(&vm_info->vm_lock);
	return ret;
}

struct kvm_vcpu* __hyp_text hypsec_vcpu_id_to_vcpu(u32 vmid, int vcpu_id)
{
	struct kvm_vcpu *vcpu = NULL;
	int offset;
	struct shared_data *shared_data;

	if (vcpu_id >= HYPSEC_MAX_VCPUS)
		__hyp_panic();

	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	offset = VCPU_IDX(vmid, vcpu_id);
	vcpu = &shared_data->vcpu_pool[offset];
	if (!vcpu)
		__hyp_panic();
	else
		return vcpu;
}

struct kvm* __hyp_text hypsec_vmid_to_kvm(u32 vmid)
{
	struct kvm *kvm = NULL;
	struct shared_data *shared_data;

	shared_data = kern_hyp_va(kvm_ksym_ref(shared_data_start));
	kvm = &shared_data->kvm_pool[vmid];
	if (!kvm)
		__hyp_panic();
	else
		return kvm;
}

struct shadow_vcpu_context* __hyp_text hypsec_vcpu_id_to_shadow_ctxt(
	u32 vmid, int vcpu_id)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	struct shadow_vcpu_context *shadow_ctxt = NULL;
	int index;

	if (vcpu_id >= HYPSEC_MAX_VCPUS)
		__hyp_panic();

	index = VCPU_IDX(vmid, vcpu_id);
	shadow_ctxt = &el2_data->shadow_vcpu_ctxt[index];
	if (!shadow_ctxt)
		__hyp_panic();
	else
		return shadow_ctxt;
}

void __hyp_text hypsec_set_vcpu_state(u32 vmid, int vcpu_id, int state)
{
	struct el2_vm_info *vm_info = vmid_to_vm_info(vmid);
	struct int_vcpu *int_vcpu;

	stage2_spin_lock(&vm_info->vm_lock);
	int_vcpu = vcpu_id_to_int_vcpu(vm_info, vcpu_id);
	int_vcpu->state = state;
	stage2_spin_unlock(&vm_info->vm_lock);
}

void __hyp_text reset_fp_regs(u32 vmid, int vcpu_id)
{
	struct shadow_vcpu_context *shadow_ctxt = NULL;
	struct kvm_vcpu *vcpu = vcpu;
	struct kvm_regs *kvm_regs;

	shadow_ctxt = hypsec_vcpu_id_to_shadow_ctxt(vmid, vcpu_id);
	vcpu = hypsec_vcpu_id_to_vcpu(vmid, vcpu_id);
	kvm_regs = &vcpu->arch.ctxt.gp_regs;
	el2_memcpy(&shadow_ctxt->fp_regs, &kvm_regs->fp_regs,
					sizeof(struct user_fpsimd_state));
}

void __hyp_text map_vgic_to_vm(u32 vmid)
{
	struct el2_data *el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	unsigned long vgic_cpu_gpa = 0x08010000;
	u64 pte = el2_data->vgic_cpu_base + (pgprot_val(PAGE_S2_DEVICE) | S2_RDWR);
	mmap_s2pt(vmid, vgic_cpu_gpa, 3U, pte);
	mmap_s2pt(vmid, vgic_cpu_gpa + PAGE_SIZE, 3U, pte + PAGE_SIZE);
}
