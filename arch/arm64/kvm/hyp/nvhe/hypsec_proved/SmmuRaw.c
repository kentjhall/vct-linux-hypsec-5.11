#include "hypsec.h"
#include "MmioOps.h"

u64 host_get_mmio_data(u32 hsr)
{
	int rt;

	rt = host_dabt_get_rd(hsr);
	return get_host_regs(rt);
}

//TODO: Xupeng why is this so simplified?
u64 smmu_init_pte(u64 prot, u64 paddr)
{
	u64 val;

	val = prot;
	val |= ARM_LPAE_PTE_AF | ARM_LPAE_PTE_SH_IS;
	//val |= (((pfn) << 12) & ((1ULL << ARM_LPAE_MAX_ADDR_BITS) - 1));
	//val |= paddr;
	val |= pfn_to_iopte(paddr >> 12);
	val |= ARM_LPAE_PTE_TYPE_PAGE;

	return val;
}

//TODO: FIXME: return u32..
u64 smmu_get_cbndx(u64 offset)
{
	u64 cbndx = 0;
	offset -= ARM_SMMU_GLOBAL_BASE;
	cbndx = offset >> ARM_SMMU_PGSHIFT;
	return cbndx;
}
