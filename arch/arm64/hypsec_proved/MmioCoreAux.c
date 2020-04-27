#include "hypsec.h"
#include "MmioOps.h"


u32 handle_smmu_global_access(u32 hsr, u64 fault_ipa, u64 offset, u32 smmu_index)
{
	/* We don't care if it's read accesses */

	u32 ret;
	u64 data = host_get_mmio_data(hsr);
	/* GR0 */
	if (offset >= 0 && offset <= ARM_SMMU_GR1_BASE) {
		if (offset == ARM_SMMU_GR0_sCR0) {
			/* Check if the host tries to bypass SMMU */
			u64 smmu_enable = (data >> sCR0_SMCFCFG_SHIFT) & 1U;
			if (smmu_enable == 0) {
				ret = 0;
			} else {
				ret = 1;
			}
		} else if (offset == ARM_SMMU_GR0_sCR2) {
			/*
			 * Check if the host tries to bypass VMID by
			 * writing the BPVMID[0:7] bits.
			 */
			if ((data & 0xff) == 0) {
				ret = 1;
			} else {
				ret = 0;
			}
		} else
			ret = 1;	
		/* GR1 */
	} else if (offset >= ARM_SMMU_GR1_BASE && offset < ARM_SMMU_GR1_END) {
		/* GR1 CBAR for the specific Context Bank Index */
		u64 n = (offset - ARM_SMMU_GR1_BASE) / 4U;
		u64 vmid = get_smmu_cfg_vmid(n, smmu_index);
		u64 type = data >> CBAR_TYPE_SHIFT;
		u64 t_vmid = data & CBAR_VMID_MASK;
		if (vmid == 0) {
			ret = 1;
		} else {
			if (type == CBAR_TYPE_S2_TRANS && (vmid == (t_vmid))) {
				ret = 1;
			} else {
				ret = 0;
			}
		}
	} else {
		ret = 1;
	}
	return ret;
}

/* FIXME: we have a pointer here */
u32 handle_smmu_cb_access(u32 hsr, u64 fault_ipa, u64 offset, u32 smmu_index)
{
	u64 cb_offset;
	u32 ret;

	offset -= ARM_SMMU_GLOBAL_BASE;
	cb_offset = offset & ARM_SMMU_PGSHIFT_MASK;
	if (cb_offset == ARM_SMMU_CB_TTBR0) {
		/* We write hw_ttbr to CB_TTBR0 */
		ret = 2U;
	} else if (cb_offset == ARM_SMMU_CB_CONTEXTIDR) {
		ret = 0U;
	} else {
		/* let accesses to other registers and TLB flushes just
		 * happen since they don't affect our guarantees.
		 */
		ret = 1U;
	}

	return ret;
}


void __handle_smmu_write(u32 hsr, u64 fault_ipa, u32 len, u64 val, u32 write_val)
{
	u64 data = host_get_mmio_data(hsr);
	if (len == 8) {
		if (write_val == 0)
			writeq_relaxed(data, (void *)fault_ipa);
		else
			writeq_relaxed(val, (void *)fault_ipa);
	} else if(len == 4)
		writel_relaxed(data, (void *)fault_ipa);
	else {
		print_string("\rhandle smmu write panic\n");
		printhex_ul(len);
		v_panic();
	}
}

void __hyp_text __handle_smmu_read(u32 hsr, u64 fault_ipa, u32 len)
{
	//the following is a macro
	u32 rt = host_dabt_get_rd(hsr);
	u32 data_32;
	u64 data_64;

	if (len == 8) {
		data_64 = readq_relaxed((void *)fault_ipa);
		set_host_regs(rt, data_64);
	} else if (len == 4) {
		data_32 = readl_relaxed((void *)fault_ipa);
		set_host_regs(rt, data_32);
	} else {
		/* We don't handle cases which len is smaller than 4 bytes */
		print_string("\rhandle smmu read panic\n");
		printhex_ul(len);
		v_panic();
	}
}
