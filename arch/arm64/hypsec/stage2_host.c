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
#include <linux/serial_reg.h>

void init_stage2_data_page(void)
{
	int i = 0, index = 0, err;
	struct stage2_data *stage2_data;
	struct memblock_region *r;

	memset((void *)kvm_ksym_ref(stage2_pgs_start), 0, STAGE2_PAGES_SIZE);
	__flush_dcache_area((void *)kvm_ksym_ref(stage2_pgs_start), STAGE2_PAGES_SIZE);

	stage2_data = (void *)kvm_ksym_ref(stage2_data_start);

	/* We copied memblock_regions to the EL2 data structure*/
	for_each_memblock(memory, r) {
		stage2_data->regions[i] = *r;
		if (!(r->flags & MEMBLOCK_NOMAP)) {
			stage2_data->s2_memblock_info[i].index = index;
			index += (r->size >> PAGE_SHIFT);
		} else
			stage2_data->s2_memblock_info[i].index = S2_PFN_SIZE;
		i++;
	}
	stage2_data->regions_cnt = i;

	stage2_data->used_pages = 0;
	stage2_data->used_pgd_pages = 2;
	stage2_data->used_tmp_pages = 0;
	stage2_data->page_pool_start = (u64)__pa(stage2_pgs_start);

	stage2_data->fault_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	stage2_data->s2pages_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	stage2_data->page_pool_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	stage2_data->tmp_page_pool_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	stage2_data->shadow_vm_ctxt_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;
	stage2_data->vmid_lock = (arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;

	err = create_hypsec_io_mappings((phys_addr_t)stage2_data->pl011_base,
					 PAGE_SIZE,
					 &stage2_data->pl011_base);
	if (err) {
		kvm_err("Cannot map pl011\n");
		goto out_err;
	}

	memset(&stage2_data->arch, 0, sizeof(struct s2_cpu_arch));

	memset(stage2_data->s2_pages, 0, sizeof(struct s2_page) * S2_PFN_SIZE);
	stage2_data->ram_start_pfn = stage2_data->regions[0].base >> PAGE_SHIFT;

	stage2_data->host_vttbr = __pa(stage2_pgs_start);

	hash_init(stage2_data->softtlb);
	memset(stage2_data->ipa_hash, 0, sizeof(struct ipa_hash) * IPA_HASH_SIZE);
	stage2_data->ipa_hash_cnt = 0;

	memset(stage2_data->vm_info, 0, sizeof(struct el2_vm_info) * EL2_VM_INFO_SIZE);
	stage2_data->used_vm_info = 0;
	stage2_data->last_remap_ptr = 0;

	memset(stage2_data->smmu_cfg, 0,
		sizeof(struct el2_smmu_cfg) * EL2_SMMU_CFG_SIZE);

	stage2_data->next_vmid = 1;

out_err:
	return;
}

