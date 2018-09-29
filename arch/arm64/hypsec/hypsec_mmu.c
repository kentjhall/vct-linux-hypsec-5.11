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
#include <asm/hypsec_mmio.h>

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
	struct el2_data *el2_data;
	int i;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	i = stage2_mem_regions_search(addr, el2_data->regions,
		el2_data->regions_cnt);

	if (i == -1)
		return false;

	return true;
}

void __hyp_text set_pfn_owner(struct el2_data *el2_data, phys_addr_t addr,
				size_t len, u32 vmid)
{
	kvm_pfn_t pfn;
	struct s2_page *s2_pages = el2_data->s2_pages;
	unsigned long index, end;

	pfn = addr >> PAGE_SHIFT;
	end = addr + len;

	stage2_spin_lock(&el2_data->s2pages_lock);
	do {
		index = get_s2_page_index(el2_data, addr);

		/*
		 * If count > 0, it means the host may still own the page.
		 * So when we are called by handle_shadow fault, we should
		 * not set the owner to VM this time.
		*/
		if (!vmid || !s2_pages[index].count)
			s2_pages[index].vmid = vmid;
	} while (addr += PAGE_SIZE, addr < end);
	stage2_spin_unlock(&el2_data->s2pages_lock);
}

static void __hyp_text free_s2pages_vmid(struct el2_data *el2_data,
				unsigned long addr, u32 vmid)
{
	struct s2_page *s2_pages = el2_data->s2_pages;
	unsigned long index;
	bool is_vm_page = false;

	index = get_s2_page_index(el2_data, addr);

	stage2_spin_lock(&el2_data->s2pages_lock);
	if (vmid == s2_pages[index].vmid) {
		s2_pages[index].vmid = 0;
		s2_pages[index].count = 0;
		el2_memset((void *)__el2_va(addr), 0, PAGE_SIZE);
		is_vm_page = true;
	}
	stage2_spin_unlock(&el2_data->s2pages_lock);
	if (is_vm_page)
		__set_pfn_host(addr, PAGE_SIZE, 0, PAGE_NONE);
}

static void __hyp_text clear_vm_pfn_owner(struct el2_data *el2_data, u32 vmid)
{
	struct memblock_region *r;
	unsigned long addr;
	int i;

	for (i = 0; i < el2_data->regions_cnt; i++) {
		r = &el2_data->regions[i];
		if (r->flags & MEMBLOCK_NOMAP)
			continue;

		addr = r->base;
		do {
			free_s2pages_vmid(el2_data, addr, vmid);
		} while (addr += PAGE_SIZE, addr < (r->base + r->size));
	}
}

void* __hyp_text alloc_stage2_page(unsigned int num)
{
	u64 p_addr, start;
	struct el2_data *el2_data;

	if (!num)
		return NULL;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	stage2_spin_lock(&el2_data->page_pool_lock);

	/* Check if we're out of memory in the reserved area */
	if (el2_data->used_pages >= STAGE2_NUM_NORM_PAGES) {
		print_string("stage2: out of pages\r\n");
		__hyp_panic();
	}

	/* Start allocating memory from the normal page pool */
	start = el2_data->page_pool_start + STAGE2_PGD_PAGES_SIZE;
	p_addr = (u64)start + (PAGE_SIZE * el2_data->used_pages);
	el2_data->used_pages += num;

	stage2_spin_unlock(&el2_data->page_pool_lock);
	return (void *)p_addr;
}

void * __hyp_text alloc_tmp_page(void)
{
	u64 p_addr, start;
	struct el2_data *el2_data;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	stage2_spin_lock(&el2_data->tmp_page_pool_lock);

	/* Check if we're out of memory in the reserved area */
	if (el2_data->used_tmp_pages >= STAGE2_NUM_TMP_PAGES) {
		print_string("stage2: out of tmp pages\r\n");
		el2_data->used_tmp_pages = 0;
	}

	start = el2_data->page_pool_start + STAGE2_NORM_PAGES_SIZE;
	p_addr = (u64)start + (PAGE_SIZE * el2_data->used_tmp_pages);
	el2_data->used_tmp_pages++;

	stage2_spin_unlock(&el2_data->tmp_page_pool_lock);
	return (void *)p_addr;
}

/* Allocate a 4k page from the reserved 2M area  */
void* __hyp_text alloc_shadow_s2_pgd(unsigned int num)
{
	u64 p_addr, start;
	struct el2_data *el2_data;

	if (!num)
		return NULL;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	stage2_spin_lock(&el2_data->page_pool_lock);

	/* Check if we're out of memory in the reserved area */
	if (el2_data->used_pgd_pages >= STAGE2_NUM_PGD_PAGES)
		print_string("stage2: out of pages\r\n");

	start = el2_data->page_pool_start;
	p_addr = (u64)start + (PAGE_SIZE * el2_data->used_pgd_pages);
	el2_data->used_pgd_pages += num;

	stage2_spin_unlock(&el2_data->page_pool_lock);
	return (void *)p_addr;
}

u64 __hyp_text get_shadow_vttbr(struct kvm *kvm)
{
	u64 pool_start, ret = kvm->arch.shadow_vttbr;
	struct el2_data *el2_data =
			kern_hyp_va(kvm_ksym_ref(el2_data_start));

	pool_start = el2_data->page_pool_start;
	if (ret >= pool_start &&
	    ret < (pool_start + (STAGE2_NUM_PGD_PAGES << PAGE_SHIFT)))
		return ret;
	else
		__hyp_panic();
}

static u32 __hyp_text get_hpa_owner(phys_addr_t addr)
{
	u32 ret;
	unsigned long index;
	struct el2_data *el2_data;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	index = get_s2_page_index(el2_data, addr & PAGE_MASK);

	stage2_spin_lock(&el2_data->s2pages_lock);
	ret = el2_data->s2_pages[index].vmid;
	stage2_spin_unlock(&el2_data->s2pages_lock);

	return ret;
}

static int __hyp_text stage2_pmd_huge(pmd_t pmd)
{
	return pmd_val(pmd) && !(pmd_val(pmd) & PMD_TABLE_BIT);
}

#define stage2_pmd_thp_or_huge(pmd)	(stage2_pmd_huge(pmd) || pmd_trans_huge(pmd))

static void __hyp_text walk_stage2_pte(pmd_t *pmd, phys_addr_t addr,
				struct s2_trans *result )
{
	u64 desc;
	pte_t *pte;

	pte = pte_offset_el2(pmd, addr);
	if (pte_none(*pte))
		return;

	result->pfn = pte_pfn(*pte);
	result->output = result->pfn << PAGE_SHIFT;
	desc = pte_val(*pte);
	result->level = 3;
	result->readable = desc & (0b01 << 6);
        result->writable = desc & (0b10 << 6);
	result->desc = desc;
}

static void __hyp_text walk_stage2_pmd(pud_t *pud, phys_addr_t addr,
				struct s2_trans *result)
{
	pmd_t *pmd;
	u64 addr_off;
	kvm_pfn_t pfn;

	pmd = pmd_offset_el2(pud, addr);
	if (!pmd_none(*pmd)) {
		if (stage2_pmd_thp_or_huge(*pmd)) {
			pfn = pmd_pfn(*pmd);
			result->output = pfn << PAGE_SHIFT;
			result->desc = pmd_val(*pmd);

			addr_off = (addr & (PMD_SIZE - 1)) >> PAGE_SHIFT;
			pfn += addr_off;
			result->pfn = pfn;
			result->level = 2;
			result->readable = pmd_val(*pmd) & (0b01 << 6);
			result->writable = pmd_val(*pmd) & (0b10 << 6);
		} else
			walk_stage2_pte(pmd, addr, result);
	}
}

static void __hyp_text walk_stage2_pud(pgd_t *pgd, phys_addr_t addr,
				struct s2_trans *result)
{
	pud_t *pud;

	pud = stage2_pud_offset(pgd, addr);
	if (!stage2_pud_none(*pud))
		walk_stage2_pmd(pud, addr, result);
}

struct s2_trans __hyp_text walk_stage2_pgd(struct kvm *kvm,
					   phys_addr_t addr,
					   bool walk_shadow_s2)
{
	pgd_t *vttbr;
	pgd_t *pgd;
	arch_spinlock_t *lock;
	struct s2_trans result;

	/* Just in case we cannot find the pfn.. */
	el2_memset(&result, 0, sizeof(struct s2_trans));
	if (walk_shadow_s2) {
		vttbr = (pgd_t *)get_shadow_vttbr(kvm);
		lock = get_shadow_pt_lock(kvm);
	} else {
		vttbr = (void *)kvm->arch.vttbr;
		vttbr = (void *)((unsigned long)vttbr & VTTBR_BADDR_MASK);
		lock = &kvm->mmu_lock.rlock.raw_lock;
	}
	vttbr = __el2_va(vttbr);

	stage2_spin_lock(lock);
	pgd = vttbr + stage2_pgd_index(addr);
	if (stage2_pgd_present(*pgd))
		walk_stage2_pud(pgd, addr, &result);
	stage2_spin_unlock(lock);

	return result;
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

void __hyp_text walk_el2_pte(pmd_t *pmd, unsigned long addr, struct s2_trans *result)
{
	pte_t *pte;
	u64 desc;

	pte = pte_offset_el2(pmd, addr);
	if (pte_none(*pte))
		return;

	result->pfn = pte_pfn(*pte);
	result->output = result->pfn << PAGE_SHIFT;
	desc = pte_val(*pte);
	result->level = 3;
	result->readable = desc & (0b01 << 6);
	result->writable = desc & (0b10 << 6);
	result->desc = desc;
}

void __hyp_text walk_el2_pmd(pud_t *pud, unsigned long addr, struct s2_trans *result)
{
	pmd_t *pmd;
	pmd = pmd_offset_el2(pud, addr);
	if (pmd_none(*pmd))
		return;
	walk_el2_pte(pmd, addr, result);
}

void __hyp_text walk_el2_pud(pgd_t *pgd, unsigned long addr, struct s2_trans *result)
{
	pud_t *pud;
	pud = pud_offset_el2(pgd, addr);
	if (pud_none(*pud))
		return;
	walk_el2_pmd(pud, addr, result);
}

void __hyp_text walk_el2_pgd(unsigned long addr, struct s2_trans *result)
{
	pgd_t *ttbr_el2 = (pgd_t *)read_sysreg(ttbr0_el2);
	pgd_t *pgd;

	ttbr_el2 = __el2_va(ttbr_el2);
	el2_memset(result, 0, sizeof(struct s2_trans));
	pgd = ttbr_el2 + pgd_index(addr);
	if (stage2_pgd_present(*pgd))
		walk_el2_pud(pgd, addr, result);

	return;
}

void __hyp_text unmap_image_from_host_s2pt(struct kvm* kvm,
					   unsigned long el2_remap_addr,
					   unsigned long pgnum)
{
	struct s2_trans result;
	struct el2_data *el2_data;
	int i = 0;
	unsigned long addr;
	u32 vmid;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	kvm = kern_hyp_va(kvm);
	vmid = el2_get_vmid(el2_data, kvm);

	while (i < pgnum) {
		addr = el2_remap_addr + (i * PAGE_SIZE);
		walk_el2_pgd(addr, &result);
		if (!result.level)
			__hyp_panic();
		__set_pfn_host(result.output, PAGE_SIZE, 0, PAGE_GUEST);
		set_pfn_owner(el2_data, result.output, PAGE_SIZE, vmid);
		__kvm_flush_vm_context();

		i++;
	}
}

void __hyp_text set_pfn_host_ptes(pmd_t *pmd, phys_addr_t addr,
				phys_addr_t end, kvm_pfn_t pfn, pgprot_t prot)
{
	pte_t *pte, *start_pte;
	pte_t new_pte;

	start_pte = pte = pte_offset_el2(pmd, addr);
	do {
		new_pte = pfn_pte(pfn, prot);
		kvm_set_pte(pte, new_pte);
		__kvm_tlb_flush_vmid_ipa_shadow(addr);

		if (stage2_is_map_memory(addr))
			__flush_dcache_area(__el2_va(addr), PAGE_SIZE);

		/* Why am I doing this? */
		if (pte_none(*pte))
			el2_memset(__el2_va(addr), 0, PAGE_SIZE);

		if (pfn)
			pfn++;
	} while (pte++, addr += PAGE_SIZE, addr != end);
}

static void __hyp_text set_pfn_host_pmds(pud_t *pud, phys_addr_t addr,
				phys_addr_t end, kvm_pfn_t pfn, pgprot_t prot)
{
	phys_addr_t next;
	pmd_t *pmd, *start_pmd;

	start_pmd = pmd = pmd_offset_el2(pud, addr);
	do {
		next = stage2_pmd_addr_end(addr, end);
		if (!pmd_none(*pmd))
			set_pfn_host_ptes(pmd, addr, next, pfn, prot);
	} while (pmd++, addr = next, addr != end);
}

static void __hyp_text set_pfn_host_puds(pgd_t *pgd, phys_addr_t addr,
				phys_addr_t end, kvm_pfn_t pfn, pgprot_t prot)
{
	phys_addr_t next;
	pud_t *pud, *start_pud;

	start_pud = pud = stage2_pud_offset(pgd, addr);
	do {
		next = stage2_pud_addr_end(addr, end);
		if (!stage2_pud_none(*pud))
			set_pfn_host_pmds(pud, addr, next, pfn, prot);
	} while (pud++, addr = next, addr != end);
}

void __hyp_text __set_pfn_host(phys_addr_t start, u64 size,
			kvm_pfn_t pfn, pgprot_t prot)
{
	pgd_t *pgd;
	pgd_t *vttbr;
	phys_addr_t addr = start, end = start + size;
	phys_addr_t next;
	struct el2_data *el2_data;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	stage2_spin_lock(&el2_data->fault_lock);

	vttbr = (pgd_t *)el2_data->host_vttbr;
	vttbr = __el2_va(vttbr);
	pgd = vttbr + stage2_pgd_index(addr);

	do {
		next = stage2_pgd_addr_end(addr, end);
		if (!stage2_pgd_none(*pgd))
			set_pfn_host_puds(pgd, addr, next, pfn, prot);
	} while (pgd++, addr = next, addr != end);

	stage2_spin_unlock(&el2_data->fault_lock);
}

static void __hyp_text handle_host_stage2_trans_fault(unsigned host_lr,
					phys_addr_t addr,
					struct el2_data *el2_data,
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
	vttbr = (pgd_t *)el2_data->host_vttbr;
	BUG_ON(addr >= KVM_PHYS_SIZE);

	stage2_spin_lock(&el2_data->fault_lock);

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

	stage2_spin_unlock(&el2_data->fault_lock);
}

static int __hyp_text stage2_emul_mmio(struct el2_data *el2_data,
				       phys_addr_t addr,
				       struct s2_host_regs *host_regs)
{
	if (el2_data->smmu.exists && is_smmu_range(el2_data->smmu, addr)) {
		handle_host_mmio(addr, host_regs);
		return 1;
	}
	return 0;
}

static void __hyp_text reject_invalid_mem_access(phys_addr_t addr,
						unsigned long host_lr)
{
	print_string("\rinvalid access of guest memory\n\r");
	print_string("\rpc: \n");
	printhex_ul(read_sysreg(elr_el2));
	print_string("\rpa: \n");
	printhex_ul(addr);
	print_string("\rlr: \n");
	printhex_ul(host_lr);

	stage2_inject_el1_fault(addr);
}

static pte_t __hyp_text gen_encrypted_pte(struct el2_data *el2_data,
                                         phys_addr_t addr)
{
	pte_t new_pte;
	phys_addr_t pa = (phys_addr_t)alloc_tmp_page();

	el2_memcpy(__el2_va(pa), __el2_va(addr), PAGE_SIZE);
	encrypt_buf(el2_data, __el2_va(pa), PAGE_SIZE);
	new_pte = pfn_pte(pa >> PAGE_SHIFT, PAGE_S2_KERNEL);
	__kvm_tlb_flush_vmid_el2();
	return new_pte;
}

void __hyp_text handle_host_stage2_fault(unsigned long host_lr,
					struct s2_host_regs *host_regs)
{
	u32 vmid;
	phys_addr_t addr;
	kvm_pfn_t pfn;
	pte_t new_pte;
	struct el2_data *el2_data;

	addr = (read_sysreg(hpfar_el2) & HPFAR_MASK) << 8;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));

	pfn = addr >> PAGE_SHIFT;
	if (stage2_is_map_memory(addr)) {
		vmid = get_hpa_owner(addr);
		if (vmid == HYPSEC_VMID) {
			reject_invalid_mem_access(addr, host_lr);
			goto out;
		} else if (vmid) {
			new_pte = gen_encrypted_pte(el2_data, addr);
		} else if (!vmid)
			new_pte = pfn_pte(pfn, PAGE_S2_KERNEL);
	} else if (!stage2_emul_mmio(el2_data, addr, host_regs)) {
		new_pte = pfn_pte(pfn, PAGE_S2_DEVICE);
		new_pte = kvm_s2pte_mkwrite(new_pte);
	} else
		goto out;

	handle_host_stage2_trans_fault(host_lr, addr, el2_data, new_pte);

out:
	return;
}

static int __hyp_text map_shadow_s2pt_mem(struct kvm *kvm,
					  struct el2_data *el2_data,
					  phys_addr_t addr,
					  struct s2_trans result,
					  bool exec_fault)
{
	pgd_t *pgd;
	pgd_t *vttbr;
	pud_t *pud;
	pmd_t *pmd, *old_pmd;
	pte_t *pte;
	pte_t new_pte;
	kvm_pfn_t pfn;
	arch_spinlock_t *lock;
	int ret = -ENOMEM;

	lock = get_shadow_pt_lock(kvm);

	vttbr = (pgd_t *)get_shadow_vttbr(kvm);
	vttbr = __el2_va(vttbr);

	stage2_spin_lock(lock);

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
	if (result.level == 2) {
		pmd_t new_pmd = pfn_pmd(result.output >> PAGE_SHIFT, PAGE_S2);
		new_pmd = pmd_mkhuge(new_pmd);
		if (result.writable)
			new_pmd = kvm_s2pmd_mkwrite(new_pmd);
		if (exec_fault)
			new_pmd = kvm_s2pmd_mkexec(new_pmd);
		old_pmd = pmd;
		if (pmd_present(*old_pmd)) {
			ret = 1;
			goto out;
		}
		//new_pmd.pmd = result.desc;
		kvm_set_pmd(pmd, new_pmd);
		__kvm_tlb_flush_vmid_ipa_shadow(addr);

		ret = 1;
		goto out;
	}

	/* Now we know the host uses pte mapping */
	if (pmd_none(*pmd)) {
		pte = alloc_stage2_page(1);
		__pmd_populate(pmd, (phys_addr_t)pte, PMD_TYPE_TABLE);
	}

	pte = pte_offset_el2(pmd, addr);
	if (!pte_none(*pte)) {
		ret = 1;
		goto out;
	}

	pfn = result.pfn;
	if (stage2_is_map_memory(result.output)) {
		new_pte = pfn_pte(pfn, PAGE_S2);
		if (result.writable)
			new_pte = kvm_s2pte_mkwrite(new_pte);
	} else {
		new_pte = pfn_pte(pfn, PAGE_S2_DEVICE);
		new_pte = kvm_s2pte_mkwrite(new_pte);
	}

	kvm_set_pte(pte, new_pte);
	__kvm_tlb_flush_vmid_ipa_shadow(addr);

	ret = 1;

out:
	stage2_spin_unlock(lock);

	return ret;
}

static __hyp_text bool is_within_range(u64 ss, u64 se,
				       u64 ts, u64 te)
{
	if (se > te) {
		if (ss > ts)
			return true;
	} else {
		if (se > te || ss >= te)
			return true;
	}
	return false;
}

static __hyp_text bool is_hypsec_pa_range(unsigned long hpa, size_t len)
{
	u64 s = hpa, e = hpa + len;
	if (is_within_range(s, e, (u64)__pa(kvm_ksym_ref(stage2_pgs_start)),
	    (u64)__pa(kvm_ksym_ref(stage2_pgs_start))))
		return true;
	return false;
}

static __hyp_text bool is_hypsec_va_range(unsigned long s, unsigned long e)
{
	/* Check if VA is valid */
	return false;
}

int __hyp_text handle_shadow_s2pt_fault(struct kvm_vcpu *vcpu, u64 hpfar)
{
	phys_addr_t addr;
	struct el2_data *el2_data;
	struct kvm *kvm = kern_hyp_va(vcpu->kvm);
	struct s2_trans result;
	int ret = -ENOMEM;
	u32 vmid, target_vmid;
	unsigned long remapped_va;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	addr = (hpfar & HPFAR_MASK) << 8;
	vmid = el2_get_vmid(el2_data, kvm);

	remapped_va = get_el2_image_va(kvm, addr);
	if (remapped_va)
		result = handle_from_vm_info(kvm, el2_data,
					remapped_va, addr);
	else
		result = walk_stage2_pgd(kvm, addr, false);

	if (!result.level)
		return ret;

	if (stage2_is_map_memory(result.output)) {
		if (is_hypsec_pa_range(result.output, PAGE_SIZE))
			return ret;

		/* Check if a page is owned by EL2 or already belongs to a VM */
		target_vmid = get_hpa_owner(result.output);
		if (target_vmid == HYPSEC_VMID || (target_vmid && target_vmid != vmid))
			return ret;
	}

	ret = map_shadow_s2pt_mem(kvm, el2_data, addr, result,
				  kvm_vcpu_trap_is_iabt(vcpu));

	if (result.pfn && (ret > 0) && !is_mmio_gpa(addr)) {
		if (result.level == 2) {
			set_pfn_owner(el2_data, result.output, PMD_SIZE, vmid);
			__set_pfn_host(result.output, PMD_SIZE, 0, PAGE_GUEST);
		} else if (result.level == 3) {
			set_pfn_owner(el2_data, result.output, PAGE_SIZE, vmid);
			__set_pfn_host(result.output, PAGE_SIZE, 0, PAGE_GUEST);
		}
	}

	__kvm_flush_vm_context();

	return ret;
}

void __hyp_text clear_vm_stage2_ptes(pmd_t *pmd, phys_addr_t addr,
				phys_addr_t end)
{
	pte_t *pte, *start_pte;

	start_pte = pte = pte_offset_el2(pmd, addr);
	do {
		if (!pte_none(*pte)) {
			kvm_set_pte(pte, __pte(0));
			__kvm_tlb_flush_vmid_ipa_shadow(addr);

			if (stage2_is_map_memory(addr))
				__flush_dcache_area(__el2_va(addr),
					PAGE_SIZE);
		}
	} while (pte++, addr += PAGE_SIZE, addr != end);
}

static void __hyp_text clear_vm_stage2_pmds(pud_t *pud, phys_addr_t addr,
				phys_addr_t end)
{
	phys_addr_t next;
	pmd_t *pmd, *start_pmd;

	start_pmd = pmd = pmd_offset_el2(pud, addr);
	do {
		next = stage2_pmd_addr_end(addr, end);
		if (!pmd_none(*pmd)) {
			if (stage2_pmd_thp_or_huge(*pmd)) {
				pmd_clear(pmd);
				__kvm_tlb_flush_vmid_ipa_shadow(addr);

				if (stage2_is_map_memory(addr))
					__flush_dcache_area(__el2_va(addr),
						PMD_SIZE);
			} else
				clear_vm_stage2_ptes(pmd, addr, next);
		}
	} while (pmd++, addr = next, addr != end);
}

static void __hyp_text clear_vm_stage2_puds(pgd_t *pgd, phys_addr_t addr,
				phys_addr_t end)
{
	phys_addr_t next;
	pud_t *pud, *start_pud;

	start_pud = pud = stage2_pud_offset(pgd, addr);
	do {
		next = stage2_pud_addr_end(addr, end);
		if (!stage2_pud_none(*pud))
			clear_vm_stage2_pmds(pud, addr, next);
	} while (pud++, addr = next, addr != end);
}

void __hyp_text clear_shadow_stage2_range(struct kvm *kvm, phys_addr_t start, u64 size)
{
	pgd_t *pgd;
	pgd_t *vttbr;
	phys_addr_t addr = start, end = start + size;
	phys_addr_t next;
	struct el2_data *el2_data;
	arch_spinlock_t *lock;

	vttbr = (pgd_t *)get_shadow_vttbr(kvm);
	if (!vttbr)
		return;
	vttbr = __el2_va(vttbr);

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	lock = get_shadow_pt_lock(kvm);
	stage2_spin_lock(lock);

	pgd = vttbr + stage2_pgd_index(addr);

	do {
		next = stage2_pgd_addr_end(addr, end);
		if (!stage2_pgd_none(*pgd))
			clear_vm_stage2_puds(pgd, addr, next);
	} while (pgd++, addr = next, addr != end);

	stage2_spin_unlock(lock);
}

void __hyp_text __clear_vm_stage2_range(struct kvm *kvm,
			phys_addr_t start, u64 size)
{
	struct el2_data *el2_data;
	u32 vmid;
	kvm = kern_hyp_va(kvm);

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	clear_shadow_stage2_range(kvm, start, size);

	if (size != KVM_PHYS_SIZE)
		return;
	vmid = el2_get_vmid(el2_data, kvm);
	clear_vm_pfn_owner(el2_data, vmid);
}

static void __hyp_text protect_el2_pmd_mem(pud_t *pud, unsigned long start,
				   unsigned long end,
				   struct el2_data *el2_data)
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
			index = get_s2_page_index(el2_data, pte & PAGE_MASK);
			el2_data->s2_pages[index].vmid = HYPSEC_VMID;
		}
	} while (pmd++, addr = next, addr != end);
}

static void __hyp_text protect_el2_pud_mem(pgd_t *pgd, unsigned long start,
				   unsigned long end,
				   struct el2_data *el2_data)
{
	pud_t *pud;
	u64 pmd;
	unsigned long addr, next, index;

	addr = start;
	pud = pud_offset_el2(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_val(*pud) & PUD_TYPE_TABLE) {
			protect_el2_pmd_mem(pud, addr, next, el2_data);
			pmd = pud_val(*pud);
			index = get_s2_page_index(el2_data, pmd & PAGE_MASK);
			el2_data->s2_pages[index].vmid = HYPSEC_VMID;
		}
	} while (pud++, addr = next, addr != end);
}

/*
 * Since EL2 page tables were allocated in EL2, here we need to protect
 * them by setting the ownership of the pages to HYPSEC_VMID. This allows
 * the core to reject any following accesses from the host.
 */
void __hyp_text protect_el2_mem(void)
{
	pgd_t *pgd, *pgdp;
	unsigned long addr, next, end, index;
	struct el2_data *el2_data;

	addr = 0;
	end = TASK_SIZE_64 - PGDIR_SIZE;

	el2_data = (void *)kern_hyp_va(kvm_ksym_ref(el2_data_start));
	pgdp = (pgd_t *)read_sysreg(ttbr0_el2);
	pgd = __el2_va(pgdp) + pgd_index(addr);
	do {
		next = pgd_addr_end(addr, end);
		if (!pgd_none(*pgd))
			protect_el2_pud_mem(pgd, addr, next, el2_data);
	} while (pgd++, addr = next, addr != end);

	index = get_s2_page_index(el2_data, read_sysreg(ttbr0_el2) & PAGE_MASK);
	el2_data->s2_pages[index].vmid = HYPSEC_VMID;

	/* Protect stage2 data */
	addr = __pa(kvm_ksym_ref(stage2_pgs_start));
	end = __pa(kvm_ksym_ref(el2_data_end));
	do {
		index = get_s2_page_index(el2_data, addr);
		el2_data->s2_pages[index].vmid = HYPSEC_VMID;
		addr += PAGE_SIZE;
	} while (addr < end);
}

void __hyp_text __el2_protect_stack_page(phys_addr_t addr)
{
	unsigned long index;
	struct el2_data *el2_data;

	el2_data = (void *)kern_hyp_va(kvm_ksym_ref(el2_data_start));
	index = get_s2_page_index(el2_data, addr & PAGE_MASK);
	el2_data->s2_pages[index].vmid = HYPSEC_VMID;
}

static void __hyp_text map_el2_pte_mem(pmd_t *pmd, unsigned long start,
				    unsigned long end, unsigned long pfn, pgprot_t prot)
{
	pte_t *pte;
	unsigned long addr;
	pte_t hi;

	addr = start;
	do {
		pte = pte_offset_el2(pmd, addr);
		hi = pfn_pte(pfn, prot);
		kvm_set_pte(pte, pfn_pte(pfn, prot));
		__flush_dcache_area(pte, sizeof(*pte));

		pfn++;
	} while (addr += PAGE_SIZE, addr != end);
}

static int __hyp_text map_el2_pmd_mem(pud_t *pud, unsigned long start,
				    unsigned long end, unsigned long pfn, pgprot_t prot)
{
	pmd_t *pmd;
	pte_t *pte;
	unsigned long addr, next;

	addr = start;
	do {
		pmd = pmd_offset_el2(pud, addr);

		if (pmd_none(*pmd)) {
			pte = alloc_stage2_page(1);
			__pmd_populate(pmd, (phys_addr_t)pte, PMD_TYPE_TABLE);
			__flush_dcache_area(pmd, sizeof(*pmd));
		}

		next = pmd_addr_end(addr, end);

		map_el2_pte_mem(pmd, addr, next, pfn, prot);
		pfn += (next - addr) >> PAGE_SHIFT;
	} while (addr = next, addr != end);

	return 0;
}


static int __hyp_text map_el2_pud_mem(pgd_t *pgd, unsigned long start,
				    unsigned long end, unsigned long pfn, pgprot_t prot)
{
	pud_t *pud;
	pmd_t *pmd;
	unsigned long addr, next;
	int ret;

	addr = start;
	do {
		pud = pud_offset_el2(pgd, addr);

		if (pud_none_or_clear_bad(pud)) {
			pmd = alloc_stage2_page(1);
			__pud_populate(pud, (phys_addr_t)pmd, PMD_TYPE_TABLE);
			__flush_dcache_area(pud, sizeof(*pud));
		}

		next = pud_addr_end(addr, end);

		ret = map_el2_pmd_mem(pud, addr, next, pfn, prot);
		if (ret)
			return ret;
		pfn += (next - addr) >> PAGE_SHIFT;
	} while (addr = next, addr != end);

	return 0;
}

int __hyp_text map_el2_mem(unsigned long start, unsigned long end,
			    unsigned long pfn, pgprot_t prot)
{
	pgd_t *pgd, *pgdp;
	pud_t *pud;
	unsigned long addr, next;
	int err = 0;

	pgdp = (pgd_t *)read_sysreg(ttbr0_el2);
	pgdp =__el2_va(pgdp);

	addr = start & PAGE_MASK;
	end = PAGE_ALIGN(end);

	do {
		pgd =  pgdp + pgd_index(addr);
		if (pgd_none(*pgd)) {
			pud = alloc_stage2_page(1);
			__pgd_populate(pgd, (phys_addr_t)pud, PUD_TYPE_TABLE);
			__flush_dcache_area(pgd, sizeof(*pgd));
		}

		next = pgd_addr_end(addr, end);

		err = map_el2_pud_mem(pgd, addr, next, pfn, prot);
		if (err)
			goto out;
		pfn += (next - addr) >> PAGE_SHIFT;
	} while (addr = next, addr != end);

out:
	return err;
}

int __hyp_text check_and_map_el2_mem(unsigned long start,
				      unsigned long end, unsigned long pfn)
{
	unsigned hpa = pfn << PAGE_SHIFT;
	int i = 0, pgnum = (end - start) >> PAGE_SHIFT;

	if (is_hypsec_va_range(start, end))
		return -EINVAL;

	do {
		if (is_hypsec_pa_range(hpa, PAGE_SIZE)) {
			print_string("Attempted to overwrite data in EL2\n");
			return -EINVAL;
		}
		hpa += PAGE_SIZE;
		i++;
	} while (i < pgnum);

	return map_el2_mem(start, end, pfn, PAGE_HYP);
}

void __hyp_text load_image_to_shadow_s2pt(struct kvm *kvm, struct el2_data *el2_data,
				unsigned long target_addr, unsigned long el2_remap_addr,
				unsigned long pgnum)
{
	struct s2_trans result;
	int i = 0;
	unsigned long addr, ipa;

	while (i < pgnum) {
		addr = el2_remap_addr + (i * PAGE_SIZE);
		ipa = target_addr + (i * PAGE_SIZE);

		walk_el2_pgd(addr, &result);
		if (!result.level) {
			print_string("\rWe cannot retrieve the PTE\n");
			return;
		}

		result.output &= PMD_MASK;
		result.pfn = result.output >> PAGE_SHIFT;
		result.writable = true;
		result.level = 2;
		map_shadow_s2pt_mem(kvm, el2_data, ipa, result, true);

		i += (PMD_SIZE >> PAGE_SHIFT);
	}
}

struct s2_trans __hyp_text handle_from_vm_info(struct kvm *kvm, struct el2_data *el2_data,
				unsigned long el2_va, unsigned long addr)
{
	struct s2_trans result;

	walk_el2_pgd(el2_va, &result);
	if (!result.level) {
		print_string("\rWe cannot retrieve the PTE for vm_info\n");
		goto out;
	}

	/* Aligned to 2MB size */
	result.output &= PMD_MASK;
	result.pfn = result.output >> PAGE_SHIFT;
	result.level = 2;
	result.readable = true;
	result.writable = true;
out:
	return result;
}

void __hyp_text __el2_register_smmu(void)
{
	struct el2_data *el2_data;
	struct el2_arm_smmu_device el2_smmu;
	u64 start, end;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	el2_smmu = el2_data->smmu;
	start = el2_smmu.phys_base;
	end = start + el2_smmu.size;
	map_el2_mem(start, end, start >> PAGE_SHIFT, PAGE_HYP_DEVICE);

	__set_pfn_host(start, end - start, 0, PAGE_NONE);
}

#define S2_PGD_PAGES_NUM	(PTRS_PER_S2_PGD * sizeof(pgd_t)) / PAGE_SIZE
void __hyp_text __alloc_shadow_vttbr(struct kvm *kvm)
{
	struct kvm *kvm_el2 = kern_hyp_va(kvm);

	/* Allocates a 8KB page for stage 2 pgd */
	kvm_el2->arch.shadow_vttbr = (u64)alloc_shadow_s2_pgd(S2_PGD_PAGES_NUM);
}

void __hyp_text __el2_encrypt_buf(void *buf, uint32_t len)
{
	struct el2_data *el2_data;
	phys_addr_t pa, addr = (phys_addr_t)buf;
	pte_t new_pte;

	el2_data = (void *)kern_hyp_va(kvm_ksym_ref(el2_data_start));

	pa = (phys_addr_t)alloc_tmp_page();
	el2_memcpy(__el2_va(pa), __el2_va(addr), len);

	encrypt_buf(el2_data, __el2_va(pa), len);
	new_pte = pfn_pte(pa >> PAGE_SHIFT, PAGE_S2_KERNEL);

	handle_host_stage2_trans_fault(0, addr, el2_data, new_pte);
	__kvm_tlb_flush_vmid_el2();
}

void __hyp_text __el2_decrypt_buf(void *buf, uint32_t len)
{
	struct el2_data *el2_data;
	el2_data = (void *)kern_hyp_va(kvm_ksym_ref(el2_data_start));

	/* Unmap the decrypted page now so the host can not get access to it. */
	__set_pfn_host((phys_addr_t)buf, PAGE_SIZE, 0, PAGE_NONE);
	decrypt_buf(el2_data, __el2_va(buf), len);
}

void el2_protect_stack_page(phys_addr_t addr)
{
	kvm_call_core(HVC_PROT_EL2_STACK, addr);
}

void el2_flush_dcache_to_poc(void *addr, size_t size)
{
	kvm_call_core(HVC_FLUSH_DCACHE_AREA, __el2_va(__pa(addr)), size);
}

void el2_flush_icache_range(unsigned long start, unsigned long end)
{
	kvm_call_core(HVC_FLUSH_ICACHE_RANGE, __el2_va(__pa(start)), __el2_va(__pa(end)));
}

int el2_create_hyp_mapping(unsigned long start, unsigned long end,
			    unsigned long pfn)
{
	return kvm_call_core(HVC_MAP_TO_EL2, start, end, pfn);
}

void alloc_shadow_vttbr(struct kvm *kvm)
{
	kvm_call_core(HVC_ALLOC_SHADOW_VTTBR, kvm);
}

void clear_vm_stage2_range(struct kvm *kvm, phys_addr_t start, u64 size)
{
	kvm_call_core(HVC_CLEAR_VM_S2_RANGE, kvm, start, size);
}

void el2_register_smmu(void)
{
	kvm_call_core(HVC_REGISTER_SMMU);
}

void el2_encrypt_buf(void *buf, uint32_t len)
{
	kvm_call_core(HVC_ENCRYPT_BUF, buf, len);
}

void el2_decrypt_buf(void *buf, uint32_t len)
{
	kvm_call_core(HVC_DECRYPT_BUF, buf, len);
}
