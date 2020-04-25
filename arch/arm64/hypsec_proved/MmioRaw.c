#include "hypsec.h"
#include "MmioOps.h"

u32 __hyp_text host_get_mmio_data(u32 hsr)
{
	int rt;

	rt = host_dabt_get_rd(hsr);
	return (u32)get_host_regs(rt);
}

u64 smmu_init_pte(u64 prot, u64 paddr)
{
	u64 pfn = paddr >> PAGE_SHIFT;
	u64 val;

	val = prot;
	val |= ARM_LPAE_PTE_AF | ARM_LPAE_PTE_SH_IS;
	//val |= pfn_to_iopte(pfn);
	val |= (((pfn) << 12) & ((1ULL << ARM_LPAE_MAX_ADDR_BITS) - 1));

	return val;
}

u32 __hyp_text smmu_get_cbndx(u32 smmu_index, u32 offset)
{
	u32 cbndx;
	u32 pgshift = get_smmu_pgshift(smmu_index);
	offset -= (get_smmu_size(smmu_index) >> 1);
	cbndx = offset >> pgshift;
	return cbndx;
}


