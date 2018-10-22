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

static void stage2_init_aes(struct el2_data *el2_data)
{
	uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	uint8_t iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

	el2_memcpy(el2_data->key, key, 16);
	el2_memcpy(el2_data->iv, iv, 16);
}

void init_el2_data_page(void)
{
	int i = 0, index = 0, err;
	struct el2_data *el2_data;
	struct memblock_region *r;

	memset((void *)kvm_ksym_ref(stage2_pgs_start), 0, STAGE2_PAGES_SIZE);
	__flush_dcache_area((void *)kvm_ksym_ref(stage2_pgs_start), STAGE2_PAGES_SIZE);

	el2_data = (void *)kvm_ksym_ref(el2_data_start);

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

	for (i = 0; i < SHADOW_SYS_REGS_DESC_SIZE; i++)
		el2_data->s2_sys_reg_descs[i] = host_sys_reg_descs[i];

	el2_data->next_vmid = 1;

	stage2_init_aes(el2_data);

	memset(el2_data->va_regions, 0,
		sizeof(struct hyp_va_region) * NUM_HYP_VA_REGIONS);
out_err:
	return;
}

int add_hyp_va_region(unsigned long from, unsigned long to)
{
	struct el2_data *el2_data;
	int i, ret = 0;

	el2_data = (void *)kvm_ksym_ref(el2_data_start);
	for (i = 0; i < NUM_HYP_VA_REGIONS; i++) {
		if (el2_data->va_regions[i].from &&
		    el2_data->va_regions[i].to)
			continue;
		else {
			el2_data->va_regions[i].from = from;
			el2_data->va_regions[i].to = to;
			break;
		}
	}

	if (unlikely(i == NUM_HYP_VA_REGIONS))
		ret = -EINVAL;

	return ret;
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

int __hyp_text alloc_shadow_vcpu_ctxt(struct kvm_vcpu *vcpu)
{
	struct el2_data *el2_data;
	struct shadow_vcpu_context *new_ctxt = NULL;
	int index, ret = 0, vmid;
	unsigned long addr = __pa(vcpu);
	arch_spinlock_t *lock;
	struct kvm *kvm;

	vcpu = kern_hyp_va(vcpu);
	kvm = kern_hyp_va(vcpu->kvm);
	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	lock = &el2_data->shadow_vcpu_ctxt_lock;
	stage2_spin_lock(lock);

	index = el2_data->used_shadow_vcpu_ctxt++;
	if (index > NUM_SHADOW_VCPU_CTXT)
		goto err_unlock;

	ret = 1;
	el2_data->shadow_vcpu_ctxt[index].dirty = -1;
	new_ctxt = &el2_data->shadow_vcpu_ctxt[index];

err_unlock:
	stage2_spin_unlock(lock);

	/*
	 *Make the shadow structures in VCPU RO, We now move vcpu_arch
	 * as we moved it to the start of the vcpu structure.
	 */
	__set_pfn_host(addr, PAGE_SIZE, addr >> PAGE_SHIFT, PAGE_S2);
	vmid = el2_get_vmid(el2_data, kvm);
	/*
	 * Make the page that contains shadow structure a guest page,
	 * so it can be cleaned up later on when VM terminates.
	,*/
	set_pfn_owner(el2_data, addr, PAGE_SIZE, vmid);
	vcpu->arch.shadow_vcpu_ctxt = new_ctxt;

	return ret;
}

void __hyp_text hvc_enable_s2_trans(void)
{
	struct el2_data *el2_data;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));

	__init_stage2_translation();

	write_sysreg(el2_data->host_vttbr, vttbr_el2);
	write_sysreg(HCR_HOST_NVHE_FLAGS, hcr_el2);
	__kvm_flush_vm_context();

	protect_el2_mem();
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
		ret = (u64)__kvm_vcpu_run_nvhe((struct kvm_vcpu*)hr->regs[1]);
		hr->regs[31] = ret;
		break;
	case HVC_TIMER_SET_CNTVOFF:
		__kvm_timer_set_cntvoff((u32)hr->regs[1], (u32)hr->regs[2]);
		break;
	case HVC_FLUSH_DCACHE_AREA:
		__flush_dcache_area((void*)hr->regs[1], hr->regs[2]);
		break;
	case HVC_FLUSH_ICACHE_RANGE:
		flush_icache_range(hr->regs[1], hr->regs[2]);
		break;
	case HVC_TLB_FLUSH_VMID:
		__kvm_tlb_flush_vmid((struct kvm*)hr->regs[1]);
		break;
	case HVC_TLB_FLUSH_VMID_IPA:
		__kvm_tlb_flush_vmid_ipa((struct kvm*)hr->regs[1],
					 (phys_addr_t)hr->regs[2]);
		break;
	case HVC_TLB_FLUSH_LOCAL_VMID:
		__kvm_tlb_flush_local_vmid((struct kvm_vcpu*)hr->regs[1]);
		break;
	case HVC_ALLOC_SHADOW_VTTBR:
		__alloc_shadow_vttbr((struct kvm*)hr->regs[1]);
		break;
	case HVC_ALLOC_SHADOW_VCPU_CTXT:
		ret = (u64)alloc_shadow_vcpu_ctxt((struct kvm_vcpu*)hr->regs[1]);
		hr->regs[31] = (u64)ret;
		break;
	case HVC_ALLOC_VMINFO:
		ret = (u64)__alloc_vm_info((struct kvm*)hr->regs[1]);
		hr->regs[31] = (u64)ret;
		break;
	case HVC_UPDATE_EXPT_FLAG:
		__update_exception_shadow_flag((struct kvm_vcpu*)hr->regs[1],
						(int)hr->regs[2]);
		break;
	case HVC_FLUSH_VM_CTXT:
		__kvm_flush_vm_context();
		break;
	case HVC_PROT_EL2_STACK:
		__el2_protect_stack_page((phys_addr_t)hr->regs[1]);
		break;
	case HVC_MAP_TO_EL2:
		ret = (int)check_and_map_el2_mem((unsigned long)hr->regs[1],
						 (unsigned long)hr->regs[2],
						 (unsigned long)hr->regs[3]);
		hr->regs[31] = (u64)ret;
		break;
	case HVC_CLEAR_VM_S2_RANGE:
		__clear_vm_stage2_range((struct kvm*)hr->regs[1],
					(phys_addr_t)hr->regs[2], (u64)hr->regs[3]);
		break;
	case HVC_SET_BOOT_INFO:
		ret = (u64)__el2_set_boot_info(
				(struct kvm *)hr->regs[1], (unsigned long)hr->regs[2],
				(unsigned long)hr->regs[3], (int)hr->regs[4]);
		hr->regs[31] = (u64)ret;
		break;
	case HVC_REMAP_VM_IMAGE:
		__el2_remap_vm_image((struct kvm*)hr->regs[1], (unsigned long)hr->regs[2]);
		break;
	case HVC_VERIFY_VM_IMAGES:
		ret = (u64)__el2_verify_and_load_images((struct kvm*)hr->regs[1]);
		hr->regs[31] = (u64)ret;
		break;
	case HVC_REGISTER_SMMU:
		__el2_register_smmu();
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
		__el2_boot_from_inc_exe((struct kvm*)hr->regs[1]);
		break;
	case HVC_ENCRYPT_BUF:
		__el2_encrypt_buf((void*)hr->regs[1], (uint32_t)hr->regs[2]);
		break;
	case HVC_DECRYPT_BUF:
		__el2_decrypt_buf((void*)hr->regs[1], (uint32_t)hr->regs[2]);
		break;
	case HVC_SAVE_CRYPT_VCPU:
		__save_encrypted_vcpu((struct kvm_vcpu*)hr->regs[1]);
		break;
	case HVC_GET_MDCR_EL2:
		ret = (u64)__kvm_get_mdcr_el2();
		hr->regs[31] = (u64)ret;
		break;
	default:
		__hyp_panic();
	};
}

int el2_alloc_shadow_ctxt(struct kvm_vcpu *vcpu)
{
	return kvm_call_core((void *)HVC_ALLOC_SHADOW_VCPU_CTXT, vcpu);
}
