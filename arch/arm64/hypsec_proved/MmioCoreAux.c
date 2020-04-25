#include "hypsec.h"
#include "MmioOps.h"

u32 __hyp_text handle_smmu_global_access(u32 hsr, u64 fault_ipa,
					 u32 offset, u32 is_write, u32 smmu_index)
{
	u32 gr1_base, data, vmid, pgshift, num_context_banks, n;

	num_context_banks = get_smmu_num_context_banks(smmu_index);
	/* We don't care if it's read accesses */
	if (!is_write)
		return 1;

	pgshift = get_smmu_pgshift(smmu_index);
	gr1_base = 1 << pgshift;
	data = host_get_mmio_data(hsr);
	/* GR0 */
	switch (offset) {
		case ARM_SMMU_GR0_sCR0:
			/* Check if the host tries to bypass SMMU */
			if (is_write && !((data >> sCR0_SMCFCFG_SHIFT) & 1))
				return 0;
			break;
		case ARM_SMMU_GR0_sCR2:
			/*
			 * Check if the host tries to bypass VMID by
			 * writing the BPVMID[0:7] bits.
			 */
			if (data & 0xff)
				return 0;
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
		//n = get_cbndx(offset, 0x1000);
		n = (offset - gr1_base) >> 2;
		if (n >= num_context_banks) {
			print_string("\rhandle_smmu_global_access: invalid cbndx\n");
			return 0;
		}

		if ((data >> CBAR_TYPE_SHIFT) != CBAR_TYPE_S2_TRANS) {
			print_string("\rhandle_smmu_global_access: invalid data\n");
			return 0;
		}

		/* Hostvisor is only allowed to set the context bank using data in its smmu_cfg */
		vmid = get_smmu_cfg_vmid(n, smmu_index);
		if (!vmid)
			set_smmu_cfg_vmid(n, smmu_index, data & CBAR_VMID_MASK);
		else {
			if (vmid != (data & CBAR_VMID_MASK))
				return 0;
		}
	}

	return 1;
}

/* FIXME: we have a pointer here */
u32 __hyp_text handle_smmu_cb_access(u32 hsr, u64 fault_ipa, u32 cbndx,
				     u32 offset, u32 is_write, u32 smmu_index)
{
	u32 cb_offset, pgshift;
	u32 num_context_banks = get_smmu_num_context_banks(smmu_index);

	if (!is_write)
		return 1;

	if (cbndx >= num_context_banks)
		v_panic();

	pgshift = get_smmu_pgshift(smmu_index);
	offset -= (get_smmu_size(smmu_index) >> 1);
	cb_offset = offset & ((1 << pgshift) - 1);

	switch (cb_offset) {
		case ARM_SMMU_CB_TTBR0:
			/* We write hw_ttbr to CB_TTBR0 */
			return 2;
			break;
		case ARM_SMMU_CB_TTBR1:
			/* It's not used since we have single stage SMMU. */
			break;
		case ARM_SMMU_CB_CONTEXTIDR:
			return 0;
			break;
		default:
		/* let accesses to other registers and TLB flushes just
		 * happen since they don't affect our guarantees.
		 */
			break;
	}

	return 1;
}

void __hyp_text __handle_smmu_write(u32 hsr, u64 fault_ipa, u32 len, u64 val)
{
	//the following is a macro
	u32 rt = host_dabt_get_rd(hsr);
	u32 data = host_get_mmio_data(hsr);

	if (len == 8) {
		/* TODO: figure out why */
		if (!val)
			val = get_host_regs(rt);
		writeq_relaxed(val, (void *)fault_ipa);
	} else if(len == 4)
		writel_relaxed(data, (void *)fault_ipa);
	else
		v_panic();
}

void __hyp_text __handle_smmu_read(u32 hsr, u64 fault_ipa, u32 len)
{
	//the following is a macro
	u32 rt = host_dabt_get_rd(hsr);
	u32 data_32;
	u64 data_64;

	if (len == 8) {
		data_64 = readq_relaxed((void *)fault_ipa);
		//el2_memcpy(&host_regs->regs[rt], &data_64, 8);
		set_host_regs(rt, data_64);
	} else if (len == 4) {
		data_32 = readl_relaxed((void *)fault_ipa);
		set_host_regs(rt, data_32);
		//el2_memcpy(&host_regs->regs[rt], &data_32, 4);
	} else
		/* We don't handle cases which len is smaller than 4 bytes */
		v_panic();
}
