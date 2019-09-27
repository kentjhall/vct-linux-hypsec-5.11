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

#define SYS_DESC(reg)					\
	Op0(sys_reg_Op0(reg)), Op1(sys_reg_Op1(reg)),	\
	CRn(sys_reg_CRn(reg)), CRm(sys_reg_CRm(reg)),	\
	Op2(sys_reg_Op2(reg))

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
	{ SYS_DESC(SYS_MDSCR_EL1), MDSCR_EL1, 0 },
	{ SYS_DESC(SYS_MDCCINT_EL1), MDCCINT_EL1, 0 },
	{ SYS_DESC(SYS_DISR_EL1), DISR_EL1, 0 },
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

void el2_shared_data_init(void)
{
	struct el2_shared_data *shared_data;

	shared_data = (void *)kvm_ksym_ref(shared_data_start);
	memset(shared_data, 0, sizeof(struct shared_data));
	printk("EL2: cleared %lx byte data size %lx\n",
		sizeof(struct shared_data), PAGE_SIZE * (PAGE_SIZE * 64));
}

void init_el2_data_page(void)
{
	int i = 0, index = 0;
	struct el2_data *el2_data;
	struct memblock_region *r;
	u64 pool_start;

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
	el2_data->used_tmp_pages = 0;
	el2_data->page_pool_start = (u64)__pa(stage2_pgs_start);

	el2_data->s2pages_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	el2_data->abs_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	el2_data->el2_pt_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;

	memset(&el2_data->arch, 0, sizeof(struct s2_cpu_arch));

	memset(el2_data->s2_pages, 0, sizeof(struct s2_page) * S2_PFN_SIZE);
	el2_data->ram_start_pfn = el2_data->regions[0].base >> PAGE_SHIFT;

	memset(el2_data->shadow_vcpu_ctxt, 0,
	       sizeof(struct shadow_vcpu_context) * NUM_SHADOW_VCPU_CTXT);
	el2_data->used_shadow_vcpu_ctxt = 0;

	/* This guarantees all locks are initially zero. */
	memset(el2_data->vm_info, 0,
	       sizeof(struct el2_vm_info) * EL2_VM_INFO_SIZE);
	el2_data->used_vm_info = 0;
	el2_data->last_remap_ptr = 0;

	el2_data->vm_info[0].shadow_pt_lock =
		(arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;

	pool_start = el2_data->page_pool_start + STAGE2_CORE_PAGES_SIZE;
	for (i = 0; i < EL2_VM_INFO_SIZE; i++) {
		el2_data->vm_info[i].page_pool_start =
			pool_start + (STAGE2_VM_POOL_SIZE * i);
		memset(__va(el2_data->vm_info[i].page_pool_start), 0, STAGE2_VM_POOL_SIZE);
	}

	el2_data->host_vttbr = el2_data->vm_info[0].page_pool_start;
	el2_data->vm_info[0].used_pages = 2;
	el2_data->vm_info[0].vttbr = el2_data->host_vttbr;
	printk("%s %llx\n", __func__, el2_data->host_vttbr);

	memset(el2_data->smmu_cfg, 0,
		sizeof(struct el2_smmu_cfg) * EL2_SMMU_CFG_SIZE);

	for (i = 0; i < SHADOW_SYS_REGS_DESC_SIZE; i++)
		el2_data->s2_sys_reg_descs[i] = host_sys_reg_descs[i];

	el2_data->next_vmid = 1;

	/* We init intermediate data structure here. */
	el2_shared_data_init();

	BUG_ON(num_online_cpus() > HYPSEC_MAX_CPUS);
	for (i = 0; i < num_online_cpus(); i++) {
		el2_data->per_cpu_data[i].vmid = 0;
		el2_data->per_cpu_data[i].vcpu_id = i;
	}

	return;
}

void init_hypsec_io(void)
{
	int i = 0, err;
	struct el2_data *el2_data;
	struct el2_arm_smmu_device *smmu;

	el2_data = (void *)kvm_ksym_ref(el2_data_start);
	err = create_hypsec_io_mappings((phys_addr_t)el2_data->pl011_base,
					 PAGE_SIZE,
					 &el2_data->pl011_base);
	if (err) {
		kvm_err("Cannot map pl011\n");
		goto out_err;
	}


	for (i = 0; i < el2_data->el2_smmu_num; i++) {
		smmu = &el2_data->smmus[i];
		err = create_hypsec_io_mappings(smmu->phys_base, smmu->size,
						&smmu->hyp_base);
		if (err) {
			kvm_err("Cannot map smmu %d from %llx\n", i, smmu->phys_base);
			goto out_err;
		}
	}

out_err:
	return;
}

unsigned long __hyp_text get_s2_page_index(struct el2_data *el2_data,
                                           phys_addr_t addr)
{
	int i;
	unsigned long ret = S2_PFN_SIZE;

	i = stage2_mem_regions_search(addr, el2_data->regions,
			el2_data->regions_cnt);
	if (i == -1)
		goto out;

	/* The requested memblock is unused! */
	if (el2_data->s2_memblock_info[i].index == S2_PFN_SIZE) {
		printhex_ul(addr);
		print_string("\rmemblock unused\n");
		goto out;
	}

	ret = el2_data->s2_memblock_info[i].index +
		((addr - el2_data->regions[i].base) >> PAGE_SHIFT);

out:
	return ret;
}

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

extern int __hypsec_register_vm(struct kvm *kvm);
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
	/* The following can only be called when VM terminates. */
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
