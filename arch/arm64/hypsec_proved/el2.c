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
}

void __hyp_text handle_host_hvc(struct s2_host_regs *hr)
{
	u64 ret = 0, callno = hr->regs[0];

	/* FIXME: we write return val to reg[31] as this will be restored to x0 */
	switch (callno) {
	case HVC_ENABLE_S2_TRANS:
		hvc_enable_s2_trans();
		break;
	/*case HVC_VCPU_RUN:
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
		ret = __el2_set_boot_info((u32)hr->regs[1], (unsigned long)hr->regs[2],
				    (unsigned long)hr->regs[3], (int)hr->regs[4]);
		hr->regs[31] = (int)ret;
		break;
	case HVC_REMAP_VM_IMAGE:
		__el2_remap_vm_image((u32)hr->regs[1], (unsigned long)hr->regs[2],
				     (int)hr->regs[3]);
		break;
	case HVC_VERIFY_VM_IMAGES:
		ret = (u64)__el2_verify_and_load_images((u32)hr->regs[1]);
		hr->regs[31] = (u64)ret;
		break;
	case HVC_FREE_SMMU_PGD:
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
		break;
	case HVC_REGISTER_KVM:
		ret = (int)__hypsec_register_kvm();
		hr->regs[31] = (u64)ret;
		break;
	case HVC_REGISTER_VCPU:
		ret = (int)__hypsec_register_vcpu((u32)hr->regs[1], (int)hr->regs[2]);
		hr->regs[31] = (u64)ret;
		break;*/
	default:
		__hyp_panic();
	};
}
