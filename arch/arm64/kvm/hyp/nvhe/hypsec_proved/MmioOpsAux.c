#include "hypsec.h"
#include "MmioOps.h"

u64 is_smmu_range(u64 addr)
{
	u32 total_smmu = get_smmu_num();
	u32 i = 0U;
	u64 res = INVALID64;

	while (i < total_smmu) {
		u64 base = get_smmu_base(i);
		u64 size = get_smmu_size(i);
		if ((base <= addr) && (addr < base + size)) {
			res = i;
		}
		i = i + 1U;
	}
	return res;
}

void handle_host_mmio(u64 index, u32 hsr)
{
	u64 base_addr;
	u64 fault_ipa;
	u64 val;
	u32 is_write;
	u32 len;

	/* Following three lines are maco */
	base_addr = get_smmu_hyp_base(index); 
	fault_ipa = (base_addr | (read_sysreg_el2(SYS_FAR) & ARM_SMMU_OFFSET_MASK));
	len = host_dabt_get_as(hsr);
	is_write = host_dabt_is_write(hsr);

	if (is_write) {
		//print_string("\rhandle_host_mmuio write\n");
		//printhex_ul(fault_ipa);
		handle_smmu_write(hsr, fault_ipa, len, index);
		//print_string("\rafter handle_host_mmuio write\n");
	} else {
		//print_string("\rhandle_host_mmuio read\n");
		//printhex_ul(fault_ipa);
		handle_smmu_read(hsr, fault_ipa, len, index);
		//print_string("\rafter handle_host_mmuio read\n");
	}

	//pc+4
	val = read_sysreg(elr_el2);
	wmb();
	write_sysreg(val + 4, elr_el2);
}
