#include "hypsec.h"
#include "MmioOps.h"


u32 __hyp_text handle_smmu_global_access(u32 hsr, u64 offset, u32 smmu_index)
{
	u32 ret;
	u64 data, smmu_enable, n, vmid, type, t_vmid;

	/* We don't care if it's read accesses */
	data = host_get_mmio_data(hsr);

	/* GR0 */
	if (offset >= 0 && offset < ARM_SMMU_GR1_BASE)
	{
		if (offset == ARM_SMMU_GR0_sCR0)
		{
			/* Check if the host tries to bypass SMMU */
			smmu_enable = (data >> sCR0_SMCFCFG_SHIFT) & 1U;
			if (smmu_enable == 0UL)
			{
				ret = 0U;
			} else {
				ret = 1U;
			}
		}
		else if (offset == ARM_SMMU_GR0_sCR2)
		{
			/*
			 * Check if the host tries to bypass VMID by
			 * writing the BPVMID[0:7] bits.
			 */
			if ((data & 0xff) == 0)
			{
				ret = 1U;
			}
			else
			{
				ret = 0U;
			}
		}
		else
			ret = 1U;
		/* GR1 */
	}
	else if (offset >= ARM_SMMU_GR1_BASE && offset < ARM_SMMU_GR1_END)
	{
		/* GR1 CBAR for the specific Context Bank Index */
		n = (offset - ARM_SMMU_GR1_BASE) / 4U;
		vmid = get_smmu_cfg_vmid(n, smmu_index);
		type = data >> CBAR_TYPE_SHIFT;
		t_vmid = data & CBAR_VMID_MASK;
		if (vmid == 0U)
		{
			ret = 1U;
		}
		else
		{
			if (type == CBAR_TYPE_S2_TRANS && (vmid == (t_vmid)))
			{
				ret = 1U;
			}
			else
			{
				ret = 0U;
			}
		}
	}
	else {
		ret = 1U;
	}
	return check(ret);
}

/* FIXME: we have a pointer here */
u32 __hyp_text handle_smmu_cb_access(u64 offset)
{
	u64 cb_offset;
	u32 ret;

	offset -= ARM_SMMU_GLOBAL_BASE;
	cb_offset = offset & ARM_SMMU_PGSHIFT_MASK;

	if (cb_offset == ARM_SMMU_CB_TTBR0)
	{
		/* We write hw_ttbr to CB_TTBR0 */
		ret = 2U;
	}
	else if (cb_offset == ARM_SMMU_CB_CONTEXTIDR) {
		ret = 0U;
	}
	else if (cb_offset == ARM_SMMU_CB_TTBCR) {
		//TODO: this case is not implemented in the verified code, can we remove it?
		ret = 3U;
	}
	else {
		/* let accesses to other registers and TLB flushes just
		 * happen since they don't affect our guarantees.
		 */
		ret = 1U;
	}
	
	return check(ret);
}

//FIXME: do we need to use MMIO in the following?
void __hyp_text __handle_smmu_write(u32 hsr, u64 fault_ipa, u32 len, u64 val, u32 write_val)
{
	void __iomem *base = (void*)fault_ipa;
	u64 data = host_get_mmio_data(hsr);

	if (len == 8) {
		if (write_val == 0) {
			writeq_relaxed(data, base);
		} else {
			writeq_relaxed(val, base);
		}
	} else if(len == 4) {
		u32 val;
		el2_memcpy(&val, &data, sizeof(u32));
		writel_relaxed(val, base);
	} else {
		print_string("\rhandle smmu write panic\n");
		printhex_ul(len);
		v_panic();
	}
}

void __hyp_text __handle_smmu_read(u32 hsr, u64 fault_ipa, u32 len)
{
	//the following is a macro
	u32 rt = host_dabt_get_rd(hsr);
	u64 data_64, val;
	u32 data_32;

	if (len == 8) {
		data_64 = readq_relaxed((void *)fault_ipa);
		set_host_regs(rt, data_64);
	} else if (len == 4) {
		data_32 = readl_relaxed((void *)fault_ipa);
		val = get_host_regs(rt);
		el2_memcpy(&val, &data_32, sizeof(u32));
		set_host_regs(rt, val);
	} else {
		/* We don't handle cases which len is smaller than 4 bytes */
		print_string("\rhandle smmu read panic\n");
		printhex_ul(len);
		v_panic();
	}
}
