#include "hypsec.h"

void* __hyp_text alloc_stage2_page_split(u32 vmid, unsigned int num)
{
	u64 p_addr, start, unaligned, append;
	struct el2_vm_info *vm_info;
	struct el2_data *el2_data;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	if (!num)
		return NULL;
	vm_info = &el2_data->vm_info[vmid];

	/* Check if we're out of memory in the reserved area */
	if (vm_info->used_pages >= (STAGE2_VM_POOL_SIZE / PAGE_SIZE)) {
		print_string("stage2: out of vm pages\r\n");
		__hyp_panic();
	}

	/* Start allocating memory from the normal page pool */
	start = vm_info->page_pool_start;
	p_addr = (u64)start + (PAGE_SIZE * vm_info->used_pages);

	unaligned = p_addr % (PAGE_SIZE * num);
	/* Append to make p_addr aligned with (PAGE_SIZE * num) */
	if (unaligned) {
		append = num - (unaligned >> PAGE_SHIFT);
		p_addr += append * PAGE_SIZE;
		num += append;
	}
	vm_info->used_pages += num;

	return (void *)p_addr;
}

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

void __hyp_text t_mmap_s2pt(phys_addr_t addr,
                                 u64 desc,
                                 int level,
                                 u32 vmid)
{
        pgd_t *pgd;
        pgd_t *vttbr;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *pte;
        arch_spinlock_t *lock;

        BUG_ON(addr >= KVM_PHYS_SIZE);

        if (!level)
                return;

        /* We assume paging is enabled in EL2 at the point we call this
         * function.
         */
        //lock = get_shadow_pt_lock(vmid);
        //vttbr = (pgd_t *)get_shadow_vttbr(vmid);
	vttbr = (pgd_t *)get_pt_vttbr(vmid);

        //stage2_spin_lock(lock);
	acquire_lock_pt(vmid);

        vttbr = __el2_va(vttbr);
        pgd = vttbr + stage2_pgd_index(addr);
        if (stage2_pgd_none(*pgd)) {
                pud = alloc_stage2_page_split(vmid, 1);
		//pud = alloc_s2pt_page(vmid);
                __pgd_populate(pgd, (phys_addr_t)pud, PUD_TYPE_TABLE);
        }

        pud = stage2_pud_offset(pgd, addr);
        if (stage2_pud_none(*pud)) {
                pmd = alloc_stage2_page_split(vmid, 1);
		//pmd = alloc_s2pt_page(vmid);
                __pud_populate(pud, (phys_addr_t)pmd, PMD_TYPE_TABLE);
        }

        pmd = pmd_offset_el2(pud, addr);
        if (level == 2) {
                kvm_set_pmd(pmd, __pmd(desc));
                goto out;
        }

        if (pmd_none(*pmd)) {
                pte = alloc_stage2_page_split(vmid, 1);
		//pte = alloc_s2pt_page(vmid);
                __pmd_populate(pmd, (phys_addr_t)pte, PMD_TYPE_TABLE);
        }

        pte = pte_offset_el2(pmd, addr);
        kvm_set_pte(pte, __pte(desc));

out:
	
	//printhex_ul(read_sysreg(elr_el2));
        //stage2_spin_unlock(lock);
	release_lock_pt(vmid);
}
