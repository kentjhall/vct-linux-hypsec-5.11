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
#include <asm/stage2_mmio.h>

int __hyp_text stage2_mem_regions_search(phys_addr_t addr,
		struct memblock_region *regions, unsigned long cnt)
{
	unsigned long left = 0, right = cnt;

	do {
		unsigned long mid = (right + left) / 2;

		if (addr < regions[mid].base)
			right = mid;
		else if (addr >= regions[mid].base + regions[mid].size)
			left = mid + 1;
		else
			return mid;
	} while (left < right);
	return -1;
}

bool __hyp_text stage2_is_map_memory(phys_addr_t addr)
{
	struct stage2_data *stage2_data;
	int i;

	stage2_data = kern_hyp_va(kvm_ksym_ref(stage2_data_start));
	i = stage2_mem_regions_search(addr, stage2_data->regions,
		stage2_data->regions_cnt);

	if (i == -1)
		return false;

	return true;
}

void* __hyp_text alloc_stage2_page(unsigned int num)
{
	u64 p_addr, start;
	struct stage2_data *stage2_data;

	if (!num)
		return NULL;

	stage2_data = kern_hyp_va(kvm_ksym_ref(stage2_data_start));
	stage2_spin_lock(&stage2_data->page_pool_lock);

	/* Check if we're out of memory in the reserved area */
	if (stage2_data->used_pages >= STAGE2_NUM_NORM_PAGES) {
		print_string("stage2: out of pages\r\n");
		__hyp_panic();
	}

	/* Start allocating memory from the normal page pool */
	start = stage2_data->page_pool_start + STAGE2_PGD_PAGES_SIZE;
	p_addr = (u64)start + (PAGE_SIZE * stage2_data->used_pages);
	stage2_data->used_pages += num;

	stage2_spin_unlock(&stage2_data->page_pool_lock);
	return (void *)p_addr;
}

#if CONFIG_PGTABLE_LEVELS > 3
static pud_t __hyp_text *pud_offset_el2(pgd_t *pgd, u64 addr)
{
	pud_t *pud;
	u64 pgd_pa;

	pgd_pa = pgd_val(*pgd) & PHYS_MASK & (s32)PAGE_MASK;
	pud = (pud_t *)((u64)pgd_pa + (pud_index(addr) * sizeof(pud_t)));
	return __el2_va(pud);
}
#else
static pud_t __hyp_text *pud_offset_el2(pgd_t *pgd, u64 addr)
{
	return (pud_t *)pgd;
}
#endif

pmd_t __hyp_text *pmd_offset_el2(pud_t *pud, u64 addr)
{
	pmd_t *pmd;
	u64 pud_pa;

	pud_pa = pud_val(*pud) & PHYS_MASK & (s32)PAGE_MASK;
	pmd = (pmd_t *)((u64)pud_pa + (pmd_index(addr) * sizeof(pmd_t)));
	return __el2_va(pmd);
}

pte_t __hyp_text *pte_offset_el2(pmd_t *pmd, u64 addr)
{
	pte_t *pte;
	u64 pmd_pa;

	pmd_pa = pmd_val(*pmd) & PHYS_MASK & (s32)PAGE_MASK;
	pte = (pte_t *)((u64)pmd_pa + (pte_index(addr) * sizeof(pte_t)));
	return __el2_va(pte);
}

static void __hyp_text handle_host_stage2_trans_fault(unsigned host_lr,
					phys_addr_t addr,
					struct stage2_data *stage2_data,
					pte_t new_pte)
{
	pgd_t *pgd;
	pgd_t *vttbr;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	/* We assume paging is enabled in EL2 at the point we call this
	 * function.
	 */
	vttbr = (pgd_t *)stage2_data->host_vttbr;
	BUG_ON(addr >= KVM_PHYS_SIZE);

	stage2_spin_lock(&stage2_data->fault_lock);

	vttbr = __el2_va(vttbr);
	pgd = vttbr + stage2_pgd_index(addr);
	if (stage2_pgd_none(*pgd)) {
		pud = alloc_stage2_page(1);
		__pgd_populate(pgd, (phys_addr_t)pud, PUD_TYPE_TABLE);
	}

	pud = stage2_pud_offset(pgd, addr);
	if (stage2_pud_none(*pud)) {
		pmd = alloc_stage2_page(1);
		__pud_populate(pud, (phys_addr_t)pmd, PMD_TYPE_TABLE);
	}

	pmd = pmd_offset_el2(pud, addr);
	if (pmd_none(*pmd)) {
		pte = alloc_stage2_page(1);
		__pmd_populate(pmd, (phys_addr_t)pte, PMD_TYPE_TABLE);
	}
	
	pte = pte_offset_el2(pmd, addr);
	kvm_set_pte(pte, new_pte);

	stage2_spin_unlock(&stage2_data->fault_lock);
}

static int __hyp_text stage2_emul_mmio(phys_addr_t addr,
					struct s2_host_regs *host_regs)
{
	/* Fill in the stuff for SMMU later */
	return false;
}

void __hyp_text handle_host_stage2_fault(unsigned long host_lr,
					struct s2_host_regs *host_regs)
{
	u32 vmid;
	phys_addr_t addr;
	kvm_pfn_t pfn;
	pte_t new_pte;
	struct stage2_data *stage2_data;

	addr = (read_sysreg(hpfar_el2) & HPFAR_MASK) << 8;

	stage2_data = kern_hyp_va(kvm_ksym_ref(stage2_data_start));

	pfn = addr >> PAGE_SHIFT;
	if (stage2_is_map_memory(addr)) {
		new_pte = pfn_pte(pfn, PAGE_S2_KERNEL);
	} else if (!stage2_emul_mmio(addr, host_regs)) {
		new_pte = pfn_pte(pfn, PAGE_S2_DEVICE);
		new_pte = kvm_s2pte_mkwrite(new_pte);
	} else
		goto out;

	handle_host_stage2_trans_fault(host_lr, addr, stage2_data, new_pte);

out:
	return;
}

static void __hyp_text protect_el2_pmd_mem(pud_t *pud, unsigned long start,
				   unsigned long end,
				   struct stage2_data *stage2_data)
{
	pmd_t *pmd;
	u64 pte;
	unsigned long addr, next, index;

	addr = start;
	pmd = pmd_offset_el2(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_val(*pmd) & PMD_TYPE_TABLE) {
			pte = pmd_val(*pmd);
			index = get_s2_page_index(stage2_data, pte & PAGE_MASK);
			stage2_data->s2_pages[index].vmid = HYPSEC_VMID;
		}
	} while (pmd++, addr = next, addr != end);
}

static void __hyp_text protect_el2_pud_mem(pgd_t *pgd, unsigned long start,
				   unsigned long end,
				   struct stage2_data *stage2_data)
{
	pud_t *pud;
	u64 pmd;
	unsigned long addr, next, index;

	addr = start;
	pud = pud_offset_el2(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_val(*pud) & PUD_TYPE_TABLE) {
			protect_el2_pmd_mem(pud, addr, next, stage2_data);
			pmd = pud_val(*pud);
			index = get_s2_page_index(stage2_data, pmd & PAGE_MASK);
			stage2_data->s2_pages[index].vmid = HYPSEC_VMID;
		}
	} while (pud++, addr = next, addr != end);
}

/*
 * Since EL2 page tables were allocated in EL2, here we need to protect
 * them by setting the ownership of the pages to HYPSEC_VMID. This allows
 * the core to reject any following accesses from the host.
 */
void __hyp_text protect_el2_pgtable_mem(void)
{
	pgd_t *pgd, *pgdp;
	unsigned long addr, next, end, index;
	struct stage2_data *stage2_data;

	addr = 0;
	end = TASK_SIZE_64 - PGDIR_SIZE;

	stage2_data = (void *)kern_hyp_va(kvm_ksym_ref(stage2_data_start));
	pgdp = (pgd_t *)read_sysreg(ttbr0_el2);
	pgd = __el2_va(pgdp) + pgd_index(addr);
	do {
		next = pgd_addr_end(addr, end);
		if (!pgd_none(*pgd))
			protect_el2_pud_mem(pgd, addr, next, stage2_data);
	} while (pgd++, addr = next, addr != end);

	index = get_s2_page_index(stage2_data, read_sysreg(ttbr0_el2) & PAGE_MASK);
	stage2_data->s2_pages[index].vmid = HYPSEC_VMID;

	/* Protect stage2 data */
	addr = __pa(kvm_ksym_ref(stage2_pgs_start));
	end = __pa(kvm_ksym_ref(stage2_data_end));
	do {
		index = get_s2_page_index(stage2_data, addr);
		stage2_data->s2_pages[index].vmid = HYPSEC_VMID;
		addr += PAGE_SIZE;
	} while (addr < end);
}

void el2_protect_stack_page(phys_addr_t addr)
{
	/* TODO: Have to protect the stack page from the host */
}

void el2_flush_dcache_to_poc(void *addr, size_t size)
{
	kvm_call_hyp(__flush_dcache_area, kern_hyp_va(addr), size);
}

void el2_flush_icache_range(unsigned long start, unsigned long end)
{
	kvm_call_hyp(flush_icache_range, kern_hyp_va(start), kern_hyp_va(end));
}
