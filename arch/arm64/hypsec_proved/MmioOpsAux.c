#include "hypsec.h"
#include "MmioOps.h"

u32 __hyp_text is_smmu_range(u64 addr)
{
	u32 i = 0;
	u32 total_smmu = get_smmu_num();

	while (i < total_smmu) {
		u64 base = get_smmu_base(i);
		u64 size = get_smmu_size(i);
		if ((base <= addr) && (addr < base + size)) {
			return i;
		}
		i = i + 1U;
	}
	return INVALID_MEM;
}

void __hyp_text handle_host_mmio(u64 addr, u32 index, u32 hsr)
{
	u64 fault_ipa;
	u32 is_write;
	u32 len;

	/* Following three lines are maco */
	fault_ipa = host_get_fault_ipa(addr); 
	len = host_dabt_get_as(hsr);
	is_write = host_dabt_is_write(hsr);

	if (is_write) {
		handle_smmu_write(hsr, fault_ipa, len, index);
	} else {
		handle_smmu_read(hsr, fault_ipa, len, index);
	}
	host_skip_instr();

	return;
}
