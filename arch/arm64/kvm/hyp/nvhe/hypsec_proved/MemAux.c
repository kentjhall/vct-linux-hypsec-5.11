#include "hypsec.h"

// quick hax
bool arm64_use_ng_mappings = false;

#define __ARM64_FTR_BITS(SIGNED, VISIBLE, STRICT, TYPE, SHIFT, WIDTH, SAFE_VAL) \
	{						\
		.sign = SIGNED,				\
		.visible = VISIBLE,			\
		.strict = STRICT,			\
		.type = TYPE,				\
		.shift = SHIFT,				\
		.width = WIDTH,				\
		.safe_val = SAFE_VAL,			\
	}

/* Define a feature with unsigned values */
#define ARM64_FTR_BITS(VISIBLE, STRICT, TYPE, SHIFT, WIDTH, SAFE_VAL) \
	__ARM64_FTR_BITS(FTR_UNSIGNED, VISIBLE, STRICT, TYPE, SHIFT, WIDTH, SAFE_VAL)

/* Define a feature with a signed value */
#define S_ARM64_FTR_BITS(VISIBLE, STRICT, TYPE, SHIFT, WIDTH, SAFE_VAL) \
	__ARM64_FTR_BITS(FTR_SIGNED, VISIBLE, STRICT, TYPE, SHIFT, WIDTH, SAFE_VAL)

#define ARM64_FTR_END					\
	{						\
		.width = 0,				\
	}

static const struct arm64_ftr_bits ftr_ctr[] = {
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_EXACT, 31, 1, 1), /* RES1 */
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, CTR_DIC_SHIFT, 1, 1),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, CTR_IDC_SHIFT, 1, 1),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_HIGHER_OR_ZERO_SAFE, CTR_CWG_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_HIGHER_OR_ZERO_SAFE, CTR_ERG_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, CTR_DMINLINE_SHIFT, 4, 1),
	/*
	 * Linux can handle differing I-cache policies. Userspace JITs will
	 * make use of *minLine.
	 * If we have differing I-cache policies, report it as the weakest - VIPT.
	 */
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_NONSTRICT, FTR_EXACT, CTR_L1IP_SHIFT, 2, ICACHE_POLICY_VIPT),	/* L1Ip */
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, CTR_IMINLINE_SHIFT, 4, 0),
	ARM64_FTR_END,
};

struct arm64_ftr_reg arm64_ftr_reg_ctrel0 = {
	.name		= "SYS_CTR_EL0",
	.ftr_bits	= ftr_ctr
};

/*
 * MemManager
 */

void map_page_host(u64 addr)
{
	u64 pfn, new_pte, perm;
	u32 owner, count;

	pfn = addr / PAGE_SIZE;
	new_pte = 0UL;

	acquire_lock_s2page();
	owner = get_pfn_owner(pfn);
	count = get_pfn_count(pfn);
	//uncomment the following for m400
	//if (!(addr >= 0x4000000000 && addr < 0x5000000000)) {
	if (owner == INVALID_MEM)
	{
		perm = pgprot_val(PAGE_S2_DEVICE);
		perm |= S2_RDWR;
		new_pte = (pfn * PAGE_SIZE) | perm;
		mmap_s2pt(HOSTVISOR, addr, 3U, new_pte);
	}
	else
	{
		if (owner == HOSTVISOR || count > 0U)
		{
			perm = pgprot_val(PAGE_S2_KERNEL);
			new_pte = (pfn * PAGE_SIZE) | perm;
			mmap_s2pt(HOSTVISOR, addr, 3U, new_pte);
		}
		else
		{
			print_string("\rfaults on host\n");
			v_panic();
		}
	}
	release_lock_s2page();
}

void clear_vm_page(u32 vmid, u64 pfn)
{
	u32 owner;

	acquire_lock_s2page();
	owner = get_pfn_owner(pfn);
	if (owner == vmid)
	{
		clear_pfn_host(pfn);
		set_pfn_owner(pfn, HOSTVISOR);
		set_pfn_count(pfn, 0U);
		set_pfn_map(pfn, 0UL);
		clear_phys_page(pfn);
		__flush_dcache_area(__el2_va(pfn << PAGE_SHIFT), PAGE_SIZE);
	}
	release_lock_s2page();
}

void assign_pfn_to_vm(u32 vmid, u64 gfn, u64 pfn)
{
	u64 map;
	u32 owner, count;

	acquire_lock_s2page();

	owner = get_pfn_owner(pfn);
	count = get_pfn_count(pfn);
	if (owner == HOSTVISOR)
	{
		if (count == 0U)
		{
			set_pfn_owner(pfn, vmid);
			clear_pfn_host(pfn);
			set_pfn_map(pfn, gfn);
			fetch_from_doracle(vmid, pfn, 1UL);
		}
		else
		{
			//pfn is mapped to a hostvisor SMMU table
			print_string("\rassign pfn used by host smmu device\n");
			v_panic();
		}
	} 
	else if (owner == vmid)
	{
		map = get_pfn_map(pfn);
		/* the page was mapped to another gfn already! */
		// if gfn == map, it means someone in my VM has mapped it
		if (gfn == map || map == INVALID64)
		{
 			if (count == INVALID_MEM)
			{
				set_pfn_count(pfn, 0U);
			}

			if (map == INVALID64)
			{
				set_pfn_map(pfn, gfn);
			}
		}
		else
		{
			print_string("\rmap != gfn || count != INVALID_MEM\n");
			v_panic();
		}
	}
	else
	{
		v_panic();
	}
	__flush_dcache_area(__el2_va(pfn << PAGE_SHIFT), PAGE_SIZE);
	release_lock_s2page();
}

void map_pfn_vm(u32 vmid, u64 addr, u64 pte, u32 level)
{
	u64 paddr, perm;

	paddr = phys_page(pte);
	/* We give the VM RWX permission now. */
	perm = pgprot_val(PAGE_S2_KERNEL);

	if (level == 2U)
	{
		pte = paddr | perm;
		pte &= ~PMD_TABLE_BIT;
		mmap_s2pt(vmid, addr, 2U, pte);
	}
	else if (level == 3U)
	{
		pte = paddr | perm;
		mmap_s2pt(vmid, addr, 3U, pte);
	}
}

void map_vm_io(u32 vmid, u64 gpa, u64 pa)
{
	u64 pte, pfn;
	u32 owner;

	pfn = pa / PAGE_SIZE;
	pte = pa + (pgprot_val(PAGE_S2_DEVICE) | S2_RDWR);

	acquire_lock_s2page();
	owner = get_pfn_owner(pfn);
	// check if pfn is truly within an I/O area
	if (owner == INVALID_MEM)
	{ 
		mmap_s2pt(vmid, gpa, 3U, pte);
	}
	release_lock_s2page();
}

void grant_vm_page(u32 vmid, u64 pfn)
{
	u32 owner, count;
	acquire_lock_s2page();
	owner = get_pfn_owner(pfn);
	count = get_pfn_count(pfn);
	if (owner == vmid && count < MAX_SHARE_COUNT)
	{
		set_pfn_count(pfn, count + 1U);
	}
	release_lock_s2page();
}

void revoke_vm_page(u32 vmid, u64 pfn)
{
	u32 owner, count;
	acquire_lock_s2page();
	owner = get_pfn_owner(pfn);
	count = get_pfn_count(pfn);
	if (owner == vmid && count > 0U)
	{
		set_pfn_count(pfn, count - 1U);
		if (count == 1U)
		{
			clear_pfn_host(pfn);
			fetch_from_doracle(vmid, pfn, 1UL);
		}
	}
	release_lock_s2page();
}

void assign_pfn_to_smmu(u32 vmid, u64 gfn, u64 pfn)
{
	u64 map;
	u32 owner, count;

	acquire_lock_s2page();
	owner = get_pfn_owner(pfn);
	count = get_pfn_count(pfn);
	map = get_pfn_map(pfn);

	if (owner == HOSTVISOR)
	{
		if (count == 0)
		{
			clear_pfn_host(pfn);
			set_pfn_owner(pfn, vmid);
			set_pfn_map(pfn, gfn);
			set_pfn_count(pfn, INVALID_MEM);
		}
		else {
			print_string("\r\assign_to_smmu: host pfn count\n");
			v_panic();
		}
	}
	//TODO: LXP checks owner != vmid, why? this does not work 
	else if (owner != INVALID_MEM)
	{
		print_string("\rvmid\n");
		printhex_ul(vmid);
		print_string("\rowner\n");
		printhex_ul(owner);
		print_string("\rpfn\n");
		printhex_ul(pfn);
		print_string("\rassign_to_smmu: owner unknown\n");
		v_panic();
	}
	release_lock_s2page();
}

void update_smmu_page(u32 vmid, u32 cbndx, u32 index, u64 iova, u64 pte)
{
	u64 pfn, gfn;
	u32 owner, count, map;

	acquire_lock_s2page();
	pfn = phys_page(pte) / PAGE_SIZE;
	gfn = iova / PAGE_SIZE;
	owner = get_pfn_owner(pfn);
	map = get_pfn_map(pfn);
	//TODO: sync with LXP, we map the page in two cases
	//1. if the pfn is a device IO (owner is INVALID) or 
	//2. vmid == owner && gfn == map
	if ((owner == INVALID_MEM) || (vmid == owner && gfn == map))
	{
		map_spt(cbndx, index, iova, pte);
		if (owner == HOSTVISOR)
		{
			count = get_pfn_count(pfn);
			if (count < EL2_SMMU_CFG_SIZE)
			{
				set_pfn_count(pfn, count + 1U);
			}
		}
	}
	else
	{
		v_panic();
		print_string("\rbug in update_smmu_page\n");
		print_string("\rvmid\n");
		printhex_ul(vmid);
		print_string("\rowner\n");
		printhex_ul(owner);
		print_string("\rgfn\n");
		printhex_ul(gfn);
		print_string("\rmap\n");
		printhex_ul(map);
	}
	release_lock_s2page();
}

void unmap_smmu_page(u32 cbndx, u32 index, u64 iova)
{
	u64 pte, pfn; 
	u32 owner, count;

	acquire_lock_s2page();
	pte = unmap_spt(cbndx, index, iova);
	pfn = phys_page(pte) / PAGE_SIZE;
	owner = get_pfn_owner(pfn);
	if (owner == HOSTVISOR)
	{
		count = get_pfn_count(pfn);
		if (count > 0U)
		{
			set_pfn_count(pfn, count - 1U);
		}
	}
	release_lock_s2page();
}
