#include "hypsec.h"
#include "MmioOps.h"

u64 __hyp_text host_get_mmio_data(u32 hsr)
{
	int rt;

	rt = host_dabt_get_rd(hsr);
	return get_host_regs(rt);
}

u64 __hyp_text smmu_init_pte(u64 prot, u64 paddr)
{
	u64 val;

	val = prot;
	val |= ARM_LPAE_PTE_AF | ARM_LPAE_PTE_SH_IS;
	//val |= (((pfn) << 12) & ((1ULL << ARM_LPAE_MAX_ADDR_BITS) - 1));
	val |= paddr;

	return val;
}

u64 __hyp_text smmu_get_cbndx(u64 offset)
{
	u64 cbndx;
	offset -= ARM_SMMU_GLOBAL_BASE;
	cbndx = offset >> ARM_SMMU_PGSHIFT;
	return cbndx;
}
