#include <linux/types.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>
#include <linux/mman.h>
#include <linux/kvm_host.h>
#include <linux/io.h>
#include <linux/dma-direction.h>
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

typedef u64 arm_lpae_iopte;

/* Configuration registers */
#define ARM_SMMU_GR0_sCR0		0x0
#define ARM_SMMU_GR0_sCR2		0x8

/* Stream mapping registers */
#define ARM_SMMU_GR0_SMR(n)		(0x800 + ((n) << 2))

/* Stream to Context registers */
#define ARM_SMMU_GR0_S2CR(n)		(0xc00 + ((n) << 2))

/* Context bank attribute registers */
#define ARM_SMMU_GR1_CBAR(n)		(0x0 + ((n) << 2))

/* Translation context bank */
#define ARM_SMMU_CB_BASE(smmu)		(SMMU_BASE(smmu) + (SMMU_SIZE(smmu) >> 1))
#define ARM_SMMU_CB(pgshift, n)		((n) * (1 << pgshift))

#define ARM_SMMU_CB_TTBR0		0x20
#define ARM_SMMU_CB_TTBR1		0x28
#define ARM_SMMU_CB_CONTEXTIDR		0x34

#define for_each_smmu_cfg(i) \
	for ((i) = 0; i < EL2_SMMU_CFG_SIZE; (i)++)

/* Page table bits */
#define ARM_LPAE_PTE_TYPE_SHIFT		0
#define ARM_LPAE_PTE_TYPE_MASK		0x3

#define ARM_LPAE_MAX_ADDR_BITS		48
#define ARM_LPAE_PGD_S2_SHIFT		30
#define ARM_LPAE_PUD_S2_SHIFT		0
#define ARM_LPAE_PMD_S2_SHIFT		21
#define ARM_LPAE_PTE_S2_SHIFT		12

#define ARM_LPAE_PTE_TYPE_BLOCK		1
#define ARM_LPAE_PTE_TYPE_TABLE		3
#define ARM_LPAE_PTE_TYPE_PAGE		3

#define ARM_LPAE_PTE_NSTABLE		(((arm_lpae_iopte)1) << 63)
#define ARM_LPAE_PTE_XN			(((arm_lpae_iopte)3) << 53)
#define ARM_LPAE_PTE_AF			(((arm_lpae_iopte)1) << 10)
#define ARM_LPAE_PTE_SH_NS		(((arm_lpae_iopte)0) << 8)
#define ARM_LPAE_PTE_SH_OS		(((arm_lpae_iopte)2) << 8)
#define ARM_LPAE_PTE_SH_IS		(((arm_lpae_iopte)3) << 8)
#define ARM_LPAE_PTE_NS			(((arm_lpae_iopte)1) << 5)
#define ARM_LPAE_PTE_VALID		(((arm_lpae_iopte)1) << 0)

#define ARM_LPAE_START_LVL	1
#define ARM_LPAE_MAX_LEVELS	4
#define ARM_LPAE_GRANULE	12

#define iopte_deref(pte)					\
	(__el2_va((pte) & ((1ULL << ARM_LPAE_MAX_ADDR_BITS) - 1)	\
	& ~(ARM_LPAE_GRANULE - 1ULL)))

#define iopte_type(pte)					\
	(((pte) >> ARM_LPAE_PTE_TYPE_SHIFT) & ARM_LPAE_PTE_TYPE_MASK)

#define ARM_LPAE_PTE_S2_IDX(iova) \
	((iova >> ARM_LPAE_PTE_S2_SHIFT) & 0x1ff)

#define ARM_LPAE_PMD_S2_IDX(iova) \
	((iova >> ARM_LPAE_PMD_S2_SHIFT) & 0x1ff)

#define ARM_LPAE_PUD_S2_IDX(iova) \
	(iova >> ARM_LPAE_PUD_S2_SHIFT)

#define ARM_LPAE_PGD_S2_IDX(iova) \
	((iova >> ARM_LPAE_PGD_S2_SHIFT) & 0x3ff)

#define ARM_LPAE_MAX_ADDR_BITS		48
#define iopte_to_pfn(pte) \
	(((pte) & ((1ULL << ARM_LPAE_MAX_ADDR_BITS) - 1)) >> 12)

#define pfn_to_iopte(pfn)					\
	(((pfn) << 12) & ((1ULL << ARM_LPAE_MAX_ADDR_BITS) - 1))

#define CBAR_VMID_SHIFT			0
#define CBAR_VMID_MASK			0xff
#define CBAR_TYPE_SHIFT			16
#define CBAR_TYPE_MASK			0x3
#define CBAR_TYPE_S2_TRANS		(0 << CBAR_TYPE_SHIFT)

#define CBA2R_VMID_SHIFT		16
#define CBA2R_VMID_MASK			0xffff

#define sCR0_SMCFCFG_SHIFT		21

#define	get_cbndx(offset, base)		(offset - base) >> 2

static struct el2_smmu_cfg* __hyp_text get_smmu_cfg_ttbr(
				struct el2_data *el2_data,
				unsigned long addr)
{
	int i;
	for_each_smmu_cfg(i) {
		if (el2_data->smmu_cfg[i].ttbr == addr)
			return &el2_data->smmu_cfg[i];
	};
	return NULL;
}

static inline struct el2_smmu_cfg* __hyp_text get_smmu_cfg_cbndx(int cbndx,
					struct el2_data *el2_data)
{
	if (cbndx > EL2_SMMU_CFG_SIZE)
		__hyp_panic();
	return &el2_data->smmu_cfg[cbndx];
}

u32 __hyp_text stage2_get_cb_offset(struct el2_arm_smmu_device smmu,
				    u32 offset, u8 *cbndx)
{
	offset -= (SMMU_SIZE(smmu) >> 1);
	*cbndx = offset >> smmu.pgshift;
	offset &= ((1 << smmu.pgshift) - 1);
	return offset;
}

static inline void __hyp_text host_skip_instr(void)
{
	u64 val = read_sysreg(elr_el2);
	write_sysreg(val + 4, elr_el2);
}

static inline int __hyp_text host_dabt_get_rd(u32 hsr)
{
	return (hsr & ESR_ELx_SRT_MASK) >> ESR_ELx_SRT_SHIFT;
}

static inline int __hyp_text host_dabt_get_as(u32 hsr)
{
	return 1 << ((hsr & ESR_ELx_SAS) >> ESR_ELx_SAS_SHIFT);
}

static inline bool __hyp_text host_dabt_is_write(u32 hsr)
{
	return !!(hsr & ESR_ELx_WNR);
}

u32 __hyp_text host_get_mmio_data(u32 hsr, struct s2_host_regs *host_regs)
{
	int rt;

	rt = host_dabt_get_rd(hsr);
	return (u32)host_regs->regs[rt];
}

bool __hyp_text handle_smmu_global_access(u32 hsr, u64 fault_ipa,
					 struct s2_host_regs *host_regs,
					 u32 offset, bool is_write,
					 struct el2_arm_smmu_device smmu)
{
	int n;
	u32 gr1_base, data;
	struct el2_data *el2_data;
	struct el2_smmu_cfg *smmu_cfg;

	el2_data = (void *)kern_hyp_va(kvm_ksym_ref(el2_data_start));

	/* We don't care if it's read accesses */
	if (!is_write)
		return true;

	gr1_base = 1 << smmu.pgshift;
	data = host_get_mmio_data(hsr, host_regs);
	/* GR0 */
	switch (offset) {
		case ARM_SMMU_GR0_sCR0:
			/* Check if the host tries to bypass SMMU */
			if (is_write && !((data >> sCR0_SMCFCFG_SHIFT) & 1))
				return false;
			break;
		case ARM_SMMU_GR0_sCR2:
			/*
			 * Check if the host tries to bypass VMID by
			 * writing the BPVMID[0:7] bits.
			 */
			if (data & 0xff)
				return false;
		/* We don't care abt GR0_ID0-7, cuz they're RO. */
		default:
			break;
	}

#if 0
	if (offset >= 0x800 && offset < 0xc00) { /* GR0 SMR */
		n = get_cbndx(offset, 0x800);
	} else if (offset >= 0xc00 && offset < gr1_base) { /* GR0 S2CR */
		n = get_cbndx(offset, 0xc00);
	} else if (offset >= gr1_base + 0x800) { /* GR1 CBA2R */
		n = get_cbndx(offset, 0x1800);
	}

#endif
	 /* GR1 CBAR for the specific Context Bank Index */
	if (offset >= gr1_base && offset < gr1_base + 0x800) {
		n = get_cbndx(offset, 0x1000);
		if (n >= smmu.num_context_banks) {
			print_string("\rhandle_smmu_global_access: invalid cbndx\n");
			return false;
		}

		if ((data >> CBAR_TYPE_SHIFT) != CBAR_TYPE_S2_TRANS) {
			print_string("\rhandle_smmu_global_access: invalid data\n");
			return false;
		}

		/* Hostvisor is only allowed to set the context bank using data in its smmu_cfg */
		smmu_cfg = get_smmu_cfg_cbndx(n, el2_data);
		if (!smmu_cfg->vmid)
			smmu_cfg->vmid = (data & CBAR_VMID_MASK);
		else {
			if (smmu_cfg->vmid != (data & CBAR_VMID_MASK))
				return false;
		}
	}

	return true;
}

bool __hyp_text handle_smmu_cb_access(u32 hsr, u64 fault_ipa,
				     struct s2_host_regs *host_regs,
				     u32 offset, u64 *val, bool is_write,
				     struct el2_arm_smmu_device smmu)
{
	struct el2_data *el2_data;
	struct el2_smmu_cfg *smmu_cfg;
	u32 cb_offset;
	u8 cbndx;

	if (!is_write)
		goto out;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	cb_offset = stage2_get_cb_offset(smmu, offset, &cbndx);
	if (cbndx >= smmu.num_context_banks) {
		print_string("\rhandle_smmu_cb_access: invalid cbndx\n");
		return false;
	}

	switch (cb_offset) {
		case ARM_SMMU_CB_TTBR0:
			smmu_cfg = get_smmu_cfg_cbndx((int)cbndx, el2_data);
			/* We write hw_ttbr to CB_TTBR0 */
			*val = smmu_cfg->hw_ttbr;
			break;
		case ARM_SMMU_CB_TTBR1:
			/* It's not used since we have single stage SMMU. */
			break;
		case ARM_SMMU_CB_CONTEXTIDR:
			return false;
			break;
		default:
		/* let accesses to other registers and TLB flushes just
		 * happen since they don't affect our guarantees.
		 */
			break;
	}

out:
	return true;
}

void __hyp_text __handle_smmu_write(u32 hsr, u64 fault_ipa, int len,
					struct s2_host_regs *host_regs, u64 val)
{
	int rt = host_dabt_get_rd(hsr);
	u32 data = host_get_mmio_data(hsr, host_regs);

	switch (len) {
		case 8:
			if (!val)
				val = host_regs->regs[rt];
			writeq_relaxed(val, (void *)fault_ipa);
			break;
		case 4:
			writel_relaxed(data, (void *)fault_ipa);
			break;
		/* We don't handle cases which len is smaller than 4 bytes */
		default:
			print_string("\runsupport length in smmu_write\n");
	}
}

void __hyp_text __handle_smmu_read(u32 hsr, u64 fault_ipa, int len,
						struct s2_host_regs *host_regs)
{
	int rt = host_dabt_get_rd(hsr);
	u32 data_32;
	u64 data_64;

	switch (len) {
		case 8:
			data_64 = readq_relaxed((void *)fault_ipa);
			el2_memcpy(&host_regs->regs[rt], &data_64, 8);
			break;
		case 4:
			data_32 = readl_relaxed((void *)fault_ipa);
			el2_memcpy(&host_regs->regs[rt], &data_32, 4);
			break;
		/* We don't handle cases which len is smaller than 4 bytes */
		default:
			print_string("\runsupport length in smmu_read\n");
	}
}

void __hyp_text handle_smmu_write(u32 hsr, u64 fault_ipa, int len,
				  struct s2_host_regs *host_regs,
				 struct el2_arm_smmu_device smmu)
{
	unsigned long size = SMMU_SIZE(smmu);
	u32 offset = fault_ipa & (size - 1);
	u64 val = 0;
	bool ret;

	if (offset < (size >> 1)) {
		ret = handle_smmu_global_access(hsr, fault_ipa, host_regs,
						offset, true, smmu);
	} else {
		ret = handle_smmu_cb_access(hsr, fault_ipa, host_regs,
					    offset, &val, true, smmu);
	}

	if (ret)
		__handle_smmu_write(hsr, fault_ipa, len, host_regs, val);
}

void __hyp_text handle_smmu_read(u32 hsr, u64 fault_ipa, int len,
				 struct s2_host_regs *host_regs,
				 struct el2_arm_smmu_device smmu)
{
	unsigned long size = SMMU_SIZE(smmu);
	u32 offset = fault_ipa & (size - 1);
	u64 val = 0;
	bool ret;

	if (offset < (size >> 1)) {
		ret = handle_smmu_global_access(hsr, fault_ipa, host_regs,
						offset, true, smmu);
	} else {
		ret = handle_smmu_cb_access(hsr, fault_ipa, host_regs,
					    offset, &val, true, smmu);
	}

	if (ret)
		__handle_smmu_read(hsr, fault_ipa, len, host_regs);
}

void __hyp_text handle_host_mmio(phys_addr_t addr,
				 struct s2_host_regs *host_regs,
				 int index)
{
	u64 fault_ipa = addr | (read_sysreg_el2(far) & ((1 << 12) - 1));
	u32 hsr = read_sysreg(esr_el2);
	bool is_write = host_dabt_is_write(hsr);
	int len = host_dabt_get_as(hsr);
	struct el2_data *el2_data;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));

	if (is_write) {
		handle_smmu_write(hsr, fault_ipa, len, host_regs, el2_data->smmus[index]);
	} else {
		handle_smmu_read(hsr, fault_ipa, len, host_regs, el2_data->smmus[index]);
	}
	host_skip_instr();

	return;
}

/* TODO: how do we make sure it's ok to free now? */
void __hyp_text  __el2_free_smmu_pgd(unsigned long addr)
{
	struct el2_data *el2_data;
	struct el2_smmu_cfg *smmu_cfg;

	el2_data = (void *)kern_hyp_va(kvm_ksym_ref(el2_data_start));
	smmu_cfg = get_smmu_cfg_ttbr(el2_data, addr);
	if (!smmu_cfg) {
		print_string("\rcannot find smmu_cfg for ttbr\n");
		printhex_ul(addr);
		return;
	}
	memset(smmu_cfg, 0, sizeof(struct el2_smmu_cfg));
}

/* Allocate a hw_ttbr to map to a hostvisor allocated ttbr. */
void __hyp_text  __el2_alloc_smmu_pgd(unsigned long addr, u8 cbndx, u32 vmid)
{
	struct el2_data *el2_data;
	struct el2_smmu_cfg *smmu_cfg;

	el2_data = (void *)kern_hyp_va(kvm_ksym_ref(el2_data_start));
	if (cbndx >= el2_data->smmu.num_context_banks) {
		print_string("\r__el2_alloc_smmu_pgd: invalid cbndx\n");
		return;
	}

	smmu_cfg = get_smmu_cfg_cbndx((int)cbndx, el2_data);
	if (!smmu_cfg->vmid) {
		smmu_cfg->vmid = vmid;
	}

	smmu_cfg->ttbr = addr;
	/* Allocate a new hw ttbr */
	smmu_cfg->hw_ttbr = (u64)alloc_stage2_page(2);
}

u64 __hyp_text smmu_init_pte(u64 prot, phys_addr_t paddr)
{
	kvm_pfn_t pfn = paddr >> PAGE_SHIFT;
	u64 val;

	val = prot;
	val |= ARM_LPAE_PTE_AF | ARM_LPAE_PTE_SH_IS;
	val |= pfn_to_iopte(pfn);

	return val;
}

void __hyp_text smmu_alloc_init_pte(pmd_t *pmd, unsigned long iova,
				    phys_addr_t paddr, size_t size, u64 prot)
{
	u64 val = 0;
	pte_t *pte;

	pte = pte_offset_el2(pmd, iova);
	if (paddr) {
		val = smmu_init_pte(prot, paddr);
		val |= ARM_LPAE_PTE_TYPE_PAGE;
	}
	*pte = __pte(val);
	__dma_map_area(pte, sizeof(val), DMA_TO_DEVICE);
}

void __hyp_text smmu_alloc_init_pmd(pud_t *pud, unsigned long iova,
				    phys_addr_t paddr, size_t size, u64 prot)
{
	arm_lpae_iopte val = 0;
	pmd_t *pmd;
	pte_t *pte;

	pmd = pmd_offset_el2(pud, iova);
	if (size == SZ_2M) {
		if (paddr) {
			val = smmu_init_pte(prot, paddr);
			val |= ARM_LPAE_PTE_TYPE_BLOCK;
		}
		*pmd = __pmd(val);
		__dma_map_area(pmd, sizeof(val), DMA_TO_DEVICE);
		return;
	}

	if (pmd_none(*pmd)) {
		pte = alloc_stage2_page(1);
		__pmd_populate(pmd, (phys_addr_t)pte, PMD_TYPE_TABLE);
		__dma_map_area(pmd, sizeof(val), DMA_TO_DEVICE);
	}

	smmu_alloc_init_pte(pmd, iova, paddr, size, prot);
}

void __hyp_text smmu_alloc_init_pud(pgd_t *pgd, unsigned long iova,
				    phys_addr_t paddr, size_t size, u64 prot)
{
	pud_t *pud;

	pud = (pud_t *)(pgd);
	smmu_alloc_init_pmd(pud, iova, paddr, size, prot);
}

void __hyp_text __el2_arm_lpae_map(unsigned long iova, phys_addr_t paddr,
				   size_t size, u64 prot, u64 ttbr)
{
	struct el2_smmu_cfg *smmu_cfg;
	struct el2_data *el2_data;
	struct s2_page *s2_pages;
	pgd_t *pgd, *pgdp;
	pud_t *pud;
	unsigned long index, s = 0;
	int vmid;

	if (paddr == 0)
		goto skip_check;

	el2_data = kern_hyp_va(kvm_ksym_ref(el2_data_start));
	smmu_cfg = get_smmu_cfg_ttbr(el2_data, ttbr);
	if (!smmu_cfg) {
		print_string("\rinvalid vttbr in smmu\n");
		return;
	}

	vmid = smmu_cfg->vmid;
	ttbr = smmu_cfg->hw_ttbr;

	index = get_s2_page_index(el2_data, paddr);
	s2_pages = el2_data->s2_pages;

	while (s < size) {
		if (!stage2_is_map_memory(paddr + s)) {
			s += PAGE_SIZE;
			continue;
		}

		index = get_s2_page_index(el2_data, paddr + s);

		if (s2_pages[index].vmid != vmid &&
		    s2_pages[index].vmid != 0) {
			/* Inject exception here */
			print_string("\rsmmu map else\n");
			printhex_ul(paddr);
			stage2_inject_el1_fault(read_sysreg(elr_el2));
			return;
		}
		s += PAGE_SIZE;
	}

skip_check:
	/* FIXME: get the proper ttbr for the context*/
	pgdp = __el2_va(ttbr);

	pgd =  pgdp + ARM_LPAE_PGD_S2_IDX(iova);
	if (pgd_none(*pgd)) {
		pud = alloc_stage2_page(1);
		__pgd_populate(pgd, (phys_addr_t)pud, PUD_TYPE_TABLE);
		__dma_map_area(pgd, sizeof(u64), DMA_TO_DEVICE);
	}

	smmu_alloc_init_pud(pgd, iova, paddr, size, prot);
}

phys_addr_t __hyp_text __el2_arm_lpae_iova_to_phys(unsigned long iova, u64 ttbr)
{
	struct el2_smmu_cfg *smmu_cfg;
	struct el2_data *el2_data;
	arm_lpae_iopte pte, *ptep;

	el2_data = (void *)kern_hyp_va(kvm_ksym_ref(el2_data_start));
	smmu_cfg = get_smmu_cfg_ttbr(el2_data, ttbr);
	if (!smmu_cfg) {
		print_string("\rinvalid vttbr in smmu\n");
		return 0;
	}
	ptep = __el2_va(smmu_cfg->hw_ttbr);

	/* Valid IOPTE pointer? */
	if (!ptep)
		return 0;

	/* Grab the IOPTE we're interested in */
	pte = *(ptep + ARM_LPAE_PGD_S2_IDX(iova));
	if (!pte)
		return 0;

	ptep = iopte_deref(pte);
	if (!ptep)
		return 0;

	pte = *(ptep + ARM_LPAE_PMD_S2_IDX(iova));
	if (!pte)
		return 0;
	else if (iopte_type(pte) == ARM_LPAE_PTE_TYPE_BLOCK) {
		iova &= (SZ_2M - 1);
		goto found_translation;
	}

	ptep = iopte_deref(pte);
	if (!ptep)
		return 0;

	pte = *(ptep + ARM_LPAE_PTE_S2_IDX(iova));
	if (!pte)
		return 0;
	else
		iova &= (SZ_4K - 1);

found_translation:
	return ((phys_addr_t)iopte_to_pfn(pte) << 12) | iova;
}

/* DMA Protection */
void el2_free_smmu_pgd(unsigned long addr)
{
	kvm_call_core(HVC_FREE_SMMU_PGD, addr);
}

void el2_alloc_smmu_pgd(unsigned long addr, u8 cbndx, u32 vmid)
{
	kvm_call_core(HVC_ALLOC_SMMU_PGD, addr, cbndx, vmid);
}

/* TODO: we need to verify if the map is legit */
void el2_arm_lpae_map(unsigned long iova, phys_addr_t paddr,
		      size_t size, u64 prot, u64 ttbr)
{
	kvm_call_core(HVC_SMMU_LPAE_MAP, iova, paddr, size, prot, ttbr);
}

phys_addr_t el2_arm_lpae_iova_to_phys(unsigned long iova, u64 ttbr)
{
	return kvm_call_core(HVC_SMMU_LPAE_IOVA_TO_PHYS, iova, ttbr);
}
