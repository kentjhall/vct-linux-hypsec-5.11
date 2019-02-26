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

#define Op0(_x) 	.Op0 = _x
#define Op1(_x) 	.Op1 = _x
#define CRn(_x)		.CRn = _x
#define CRm(_x) 	.CRm = _x
#define Op2(_x) 	.Op2 = _x

static struct s2_sys_reg_desc host_sys_reg_descs[] = {
	/* TTBR0_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0010), CRm(0b0000), Op2(0b000),
	  TTBR0_EL1, 0x1de7ec7edbadc0deULL },
	/* TTBR1_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0010), CRm(0b0000), Op2(0b001),
	  TTBR1_EL1, 0x1de7ec7edbadc0deULL },
	/* VBAR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b1100), CRm(0b0000), Op2(0b000),
	  VBAR_EL1, 0 },
	/* SCTLR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0001), CRm(0b0000), Op2(0b000),
	  SCTLR_EL1, 0x00C50078 },
	/* ESR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0101), CRm(0b0010), Op2(0b000),
	  ESR_EL1, 0x1de7ec7edbadc0deULL },
	/* FAR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0110), CRm(0b0000), Op2(0b000),
	  FAR_EL1, 0x1de7ec7edbadc0deULL },
	/* TPIDR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b1101), CRm(0b0000), Op2(0b100),
	  TPIDR_EL1, 0x1de7ec7edbadc0deULL },
	/* TPIDRRO_EL0 */
	{ Op0(0b11), Op1(0b011), CRn(0b1101), CRm(0b0000), Op2(0b011),
	  TPIDRRO_EL0, 0x1de7ec7edbadc0deULL },
	/* TPIDR_EL0 */
	{ Op0(0b11), Op1(0b011), CRn(0b1101), CRm(0b0000), Op2(0b010),
	  TPIDR_EL0, 0x1de7ec7edbadc0deULL },
	/* CONTEXTIDR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b1101), CRm(0b0000), Op2(0b001),
	  CONTEXTIDR_EL1, 0 },
	/* PAR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0111), CRm(0b0100), Op2(0b000),
	  PAR_EL1, 0x1de7ec7edbadc0deULL },
	/* MPIDR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0000), CRm(0b0000), Op2(0b101),
	  MPIDR_EL1, 0 },
	/* CSSELR_EL1 */
	{ Op0(0b11), Op1(0b010), CRn(0b0000), CRm(0b0000), Op2(0b000),
	  CSSELR_EL1, 0x1de7ec7edbadc0deULL },
	/* ACTLR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0001), CRm(0b0000), Op2(0b001),
	  ACTLR_EL1, 0 },
	/* CPACR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0001), CRm(0b0000), Op2(0b010),
	  CPACR_EL1, 0x1de7ec7edbadc0deULL },
	/* TCR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0010), CRm(0b0000), Op2(0b010),
	  TCR_EL1, 0 },
	/* AFSR0_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0101), CRm(0b0001), Op2(0b000),
	  AFSR0_EL1, 0x1de7ec7edbadc0deULL },
	/* AFSR1_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b0101), CRm(0b0001), Op2(0b001),
	  AFSR1_EL1, 0x1de7ec7edbadc0deULL },
	/* MAIR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b1010), CRm(0b0010), Op2(0b000),
	  MAIR_EL1, 0x1de7ec7edbadc0deULL },
	/* AMAIR_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b1010), CRm(0b0011), Op2(0b000),
	  AMAIR_EL1, 0x1de7ec7edbadc0deULL },
	/* CNTKCTL_EL1 */
	{ Op0(0b11), Op1(0b000), CRn(0b1110), CRm(0b0001), Op2(0b000),
	  CNTKCTL_EL1, 0 },
	/* DACR32_EL2 */
	{ Op0(0b11), Op1(0b100), CRn(0b0011), CRm(0b0000), Op2(0b000),
	  DACR32_EL2, 0x1de7ec7edbadc0deULL },
	/* IFSR32_EL2 */
	{ Op0(0b11), Op1(0b100), CRn(0b0101), CRm(0b0000), Op2(0b001),
	  IFSR32_EL2, 0x1de7ec7edbadc0deULL },
	/* FPEXC32_EL2 */
	{ Op0(0b11), Op1(0b100), CRn(0b0101), CRm(0b0011), Op2(0b000),
	  FPEXC32_EL2, 0x70 }
};

void init_el2_data_page(void)
{
	int i = 0, index = 0, err;
	struct el2_data *el2_data;
	struct memblock_region *r;
	struct el2_arm_smmu_device *smmu;

	memset((void *)kvm_ksym_ref(stage2_pgs_start), 0, STAGE2_PAGES_SIZE);
	__flush_dcache_area((void *)kvm_ksym_ref(stage2_pgs_start), STAGE2_PAGES_SIZE);

	el2_data = (void *)kvm_ksym_ref(el2_data_start);
	el2_data->installed = false;

	/* We copied memblock_regions to the EL2 data structure*/
	for_each_memblock(memory, r) {
		el2_data->regions[i] = *r;
		if (!(r->flags & MEMBLOCK_NOMAP)) {
			el2_data->s2_memblock_info[i].index = index;
			index += (r->size >> PAGE_SHIFT);
		} else
			el2_data->s2_memblock_info[i].index = S2_PFN_SIZE;
		i++;
	}
	el2_data->regions_cnt = i;

	el2_data->used_pages = 0;
	el2_data->used_pgd_pages = 2;
	el2_data->used_tmp_pages = 0;
	el2_data->page_pool_start = (u64)__pa(stage2_pgs_start);

	el2_data->fault_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	el2_data->s2pages_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	el2_data->page_pool_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	el2_data->tmp_page_pool_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	el2_data->shadow_vcpu_ctxt_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	el2_data->vmid_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;

	err = create_hypsec_io_mappings((phys_addr_t)el2_data->pl011_base,
					 PAGE_SIZE,
					 &el2_data->pl011_base);
	if (err) {
		kvm_err("Cannot map pl011\n");
		goto out_err;
	}

	memset(&el2_data->arch, 0, sizeof(struct s2_cpu_arch));

	memset(el2_data->s2_pages, 0, sizeof(struct s2_page) * S2_PFN_SIZE);
	el2_data->ram_start_pfn = el2_data->regions[0].base >> PAGE_SHIFT;

	el2_data->host_vttbr = __pa(stage2_pgs_start);

	memset(el2_data->shadow_vcpu_ctxt, 0,
	       sizeof(struct shadow_vcpu_context) * NUM_SHADOW_VCPU_CTXT);
	el2_data->used_shadow_vcpu_ctxt = 0;

	memset(el2_data->vm_info, 0,
	       sizeof(struct el2_vm_info) * EL2_VM_INFO_SIZE);
	el2_data->used_vm_info = 0;
	el2_data->last_remap_ptr = 0;

	memset(el2_data->smmu_cfg, 0,
		sizeof(struct el2_smmu_cfg) * EL2_SMMU_CFG_SIZE);
	for (i = 0; i < el2_data->el2_smmu_num; i++) {
		smmu = &el2_data->smmus[i];
		err = create_hypsec_io_mappings(smmu->phys_base, smmu->size,
						&smmu->hyp_base);
		if (err) {
			kvm_err("Cannot map smmu %d from %llx\n", i, smmu->phys_base);
			goto out_err;
		}
	}

	for (i = 0; i < SHADOW_SYS_REGS_DESC_SIZE; i++)
		el2_data->s2_sys_reg_descs[i] = host_sys_reg_descs[i];

	el2_data->next_vmid = 1;

out_err:
	return;
}

unsigned long __hyp_text get_s2_page_index(struct el2_data *el2_data,
                                           phys_addr_t addr)
{
	int i;
	unsigned long ret = 0;

	i = stage2_mem_regions_search(addr, el2_data->regions,
			el2_data->regions_cnt);
	if (i == -1)
		goto out;

	/* The requested memblock is unused! */
	if (el2_data->s2_memblock_info[i].index == S2_PFN_SIZE)
		print_string("memblock unused\n");

	ret = el2_data->s2_memblock_info[i].index +
		((addr - el2_data->regions[i].base) >> PAGE_SHIFT);

out:
	return ret;
}

static int __hyp_text __hypsec_init_vcpu(u32 vmid, int vcpu_id)
{
	struct el2_data *el2_data;
	struct shadow_vcpu_context *new_ctxt = NULL;
	struct el2_vm_info *vm_info;
	int index, ret = 0;
	struct kvm_vcpu *vcpu = hypsec_vcpu_id_to_vcpu(vmid, vcpu_id);

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	/*
	 * We cannot protect shadow ctxt if vcpu isn't aligned
	 * to PAGE_SIZE so we just bailed if it's the case.
	 */
	if ((u64)vcpu & (PAGE_SIZE -1))
		return ret;

	if (vmid >= EL2_VM_INFO_SIZE)
		return ret;

	vm_info = &el2_data->vm_info[vmid];
	vcpu->arch.vmid = vmid;

	stage2_spin_lock(&el2_data->shadow_vcpu_ctxt_lock);

	index = el2_data->used_shadow_vcpu_ctxt++;
	if (index > NUM_SHADOW_VCPU_CTXT)
		goto err_unlock;

	ret = 1;
	el2_data->shadow_vcpu_ctxt[index].dirty = -1;
	new_ctxt = &el2_data->shadow_vcpu_ctxt[index];
	vm_info->shadow_ctxt[vcpu_id] = new_ctxt;

err_unlock:
	stage2_spin_unlock(&el2_data->shadow_vcpu_ctxt_lock);

	/*
	 *Make the shadow structures in VCPU RO, We now move vcpu_arch
	 * as we moved it to the start of the vcpu structure.
	 */
	//__set_pfn_host(addr, PAGE_SIZE, addr >> PAGE_SHIFT, PAGE_S2);
	/*
	 * Make the page that contains shadow structure a guest page,
	 * so it can be cleaned up later on when VM terminates.
	 */
	//set_pfn_owner(el2_data, addr, PAGE_SIZE, vmid);

	/* TODO: Needs to go back to fully protect shadow_ctxt. */
	vcpu->arch.shadow_vcpu_ctxt = new_ctxt;

	return ret;
}

static void __hyp_text hvc_enable_s2_trans(unsigned long stack_addr)
{
	struct el2_data *el2_data;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));

	__init_stage2_translation();

	write_sysreg(el2_data->host_vttbr, vttbr_el2);
	write_sysreg(HCR_HOST_NVHE_FLAGS, hcr_el2);
	__kvm_flush_vm_context();

	if (!el2_data->installed) {
		protect_el2_mem();
		el2_data->installed = true;
	}

	protect_el2_stack_page(stack_addr);
}

extern int __hypsec_register_vm(struct kvm *kvm);
void __hyp_text handle_host_hvc(struct s2_host_regs *hr)
{
	u64 ret = 0, callno = hr->regs[0];
	struct kvm_vcpu *vcpu;
	struct shadow_vcpu_context *shadow_ctxt;

	/* FIXME: we write return val to reg[31] as this will be restored to x0 */
	switch (callno) {
	case HVC_ENABLE_S2_TRANS:
		hvc_enable_s2_trans((unsigned long)hr->regs[1]);
		break;
	case HVC_VCPU_RUN:
		vcpu = hypsec_vcpu_id_to_vcpu((u32)hr->regs[1], (int)hr->regs[2]);
		shadow_ctxt = hypsec_vcpu_id_to_shadow_ctxt((u32)hr->regs[1], (int)hr->regs[2]);
		ret = (u64)__kvm_vcpu_run_nvhe(vcpu, shadow_ctxt);
		hr->regs[31] = ret;
		break;
	case HVC_TIMER_SET_CNTVOFF:
		__kvm_timer_set_cntvoff((u32)hr->regs[1], (u32)hr->regs[2]);
		break;
	/*case HVC_FLUSH_DCACHE_AREA:
		__flush_dcache_area((void*)hr->regs[1], hr->regs[2]);
		break;
	case HVC_FLUSH_ICACHE_RANGE:
		flush_icache_range(hr->regs[1], hr->regs[2]);
		break;*/
	case HVC_TLB_FLUSH_VMID:
		hypsec_tlb_flush_helper((u32)hr->regs[1], 0);
		break;
	case HVC_TLB_FLUSH_LOCAL_VMID:
		hypsec_tlb_flush_helper((u32)hr->regs[1], 1);
		break;
	case HVC_UPDATE_EXPT_FLAG:
		vcpu = hypsec_vcpu_id_to_vcpu((u32)hr->regs[1], (int)hr->regs[2]);
		__update_exception_shadow_flag(vcpu, (int)hr->regs[3]);
		break;
	case HVC_FLUSH_VM_CTXT:
		__kvm_flush_vm_context();
		break;
	case HVC_CLEAR_VM_S2_RANGE:
		__clear_vm_stage2_range((u32)hr->regs[1],
					(phys_addr_t)hr->regs[2], (u64)hr->regs[3]);
		break;
	case HVC_SET_BOOT_INFO:
		__el2_set_boot_info((u32)hr->regs[1], (unsigned long)hr->regs[2],
				    (unsigned long)hr->regs[3], (int)hr->regs[4]);
		break;
	case HVC_REMAP_VM_IMAGE:
		__el2_remap_vm_image((u32)hr->regs[1], (unsigned long)hr->regs[2]);
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
					(u32)hr->regs[3]);
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
	case HVC_GET_MDCR_EL2:
		ret = (u64)__kvm_get_mdcr_el2();
		hr->regs[31] = (u64)ret;
		break;
	case HVC_REGISTER_KVM:
		ret = (int)__hypsec_register_kvm();
		hr->regs[31] = (u64)ret;
		break;
	case HVC_REGISTER_VCPU:
		ret = (int)__hypsec_register_vcpu((u32)hr->regs[1], (int)hr->regs[2]);
		hr->regs[31] = (u64)ret;
		break;
	case HVC_MAP_ONE_KVM_PAGE:
		ret = (int)__hypsec_map_one_kvm_page((u32)hr->regs[1], (unsigned long)hr->regs[2]);
		hr->regs[31] = (int)ret;
		break;
	case HVC_MAP_ONE_VCPU_PAGE:
		ret = (int)__hypsec_map_one_vcpu_page((u32)hr->regs[1], (int)hr->regs[2], (unsigned long)hr->regs[3]);
		hr->regs[31] = (int)ret;
		break;
	case HVC_INIT_VM:
		ret = (int)__hypsec_init_vm((u32)hr->regs[1]);
		hr->regs[31] = (int)ret;
		break;
	case HVC_INIT_VCPU:
		ret = (int)__hypsec_init_vcpu((u32)hr->regs[1], (int)hr->regs[2]);
		hr->regs[31] = (int)ret;
		break;
	default:
		__hyp_panic();
	};
}

int hypsec_register_kvm(void)
{
	return kvm_call_core(HVC_REGISTER_KVM);
}

int hypsec_register_vcpu(u32 vmid, int vcpu_id)
{
	return kvm_call_core((void *)HVC_REGISTER_VCPU, vmid, vcpu_id);
}

int hypsec_map_one_kvm_page(u32 vmid, unsigned long pfn)
{
	return kvm_call_core(HVC_MAP_ONE_KVM_PAGE, vmid, pfn);
}

int hypsec_map_one_vcpu_page(u32 vmid, int vcpu_id, unsigned long pfn)
{
	return kvm_call_core(HVC_MAP_ONE_VCPU_PAGE, vmid, vcpu_id, pfn);
}

int hypsec_init_vm(u32 vmid)
{
	return kvm_call_core(HVC_INIT_VM, vmid);
}

int hypsec_init_vcpu(u32 vmid, int vcpu_id)
{
	return kvm_call_core(HVC_INIT_VCPU, vmid, vcpu_id);
}
