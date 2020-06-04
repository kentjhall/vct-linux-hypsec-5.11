void __hyp_text __el2_encrypt_buf(u32 vmid, u64 buf, u64 pa)
{
	u64 owner1, owner2;

	owner1 = get_pfn_owner(buf >> PAGE_SHIFT);
	owner2 = get_pfn_owner(pa >> PAGE_SHIFT);

	if (owner1 == HOSTVISOR && owner2 == vmid) {
		encrypt_buf(vmid, __el2_va(buf), __el2_va(pa), PAGE_SIZE);
		__kvm_tlb_flush_vmid_el2();
	} else {
		v_panic();
	}
}

void __hyp_text __el2_decrypt_buf(u32 vmid, u64 buf, u64 pa)
{
	u64 owner1, owner2;

	owner1 = get_pfn_owner(buf >> PAGE_SHIFT);
	owner2 = get_pfn_owner(pa >> PAGE_SHIFT);

	if (owner1 == HOSTVISOR && owner2 == vmid) {
		decrypt_buf(vmid, __el2_va(pa), __el2_va(buf), PAGE_SIZE);
		__kvm_tlb_flush_vmid_el2();
	} else {
		v_panic();
	}	
}

void __hyp_text __el2_encrypt_vcpu(u32 vmid, u32 vcpu_id)
{
	//we assume a func that concatenates unused entries in shadow_ctxt for us
	u64 ptr = get_shadow_vcpu_context_ptr_buf(vmid, vcpu_id);
	u64 buf[SHADOW_VCPU_CONTEXT_CONCAT_SIZE];
	encrypt_buf(vmid, buf, ptr, SHADOW_VCPU_CONTEXT_CONCAT_SIZE);

	set_int_reg(vmid, vcpu_id, REG_X0, buf[0]);
	set_int_reg(vmid, vcpu_id, REG_X1, buf[1]);
	set_int_reg(vmid, vcpu_id, REG_X2, buf[2]);
	set_int_reg(vmid, vcpu_id, REG_X3, buf[3]);
	set_int_reg(vmid, vcpu_id, REG_X4, buf[4]);
	set_int_reg(vmid, vcpu_id, REG_X5, buf[5]);
	set_int_reg(vmid, vcpu_id, REG_X6, buf[6]);
	set_int_reg(vmid, vcpu_id, REG_X7, buf[7]);
	set_int_reg(vmid, vcpu_id, REG_X8, buf[8]);
	set_int_reg(vmid, vcpu_id, REG_X9, buf[9]);
	set_int_reg(vmid, vcpu_id, REG_X10, buf[10]);
	set_int_reg(vmid, vcpu_id, REG_X11, buf[11]);
	set_int_reg(vmid, vcpu_id, REG_X12, buf[12]);
	set_int_reg(vmid, vcpu_id, REG_X13, buf[13]);
	set_int_reg(vmid, vcpu_id, REG_X14, buf[14]);
	set_int_reg(vmid, vcpu_id, REG_X15, buf[15]);
	set_int_reg(vmid, vcpu_id, REG_X16, buf[16]);
	set_int_reg(vmid, vcpu_id, REG_X17, buf[17]);
	set_int_reg(vmid, vcpu_id, REG_X18, buf[18]);
	set_int_reg(vmid, vcpu_id, REG_X19, buf[19]);
	set_int_reg(vmid, vcpu_id, REG_X20, buf[20]);
	set_int_reg(vmid, vcpu_id, REG_X21, buf[21]);
	set_int_reg(vmid, vcpu_id, REG_X22, buf[22]);
	set_int_reg(vmid, vcpu_id, REG_X23, buf[23]);
	set_int_reg(vmid, vcpu_id, REG_X24, buf[24]);
	set_int_reg(vmid, vcpu_id, REG_X25, buf[25]);
	set_int_reg(vmid, vcpu_id, REG_X26, buf[26]);
	set_int_reg(vmid, vcpu_id, REG_X27, buf[27]);
	set_int_reg(vmid, vcpu_id, REG_X28, buf[28]);
	set_int_reg(vmid, vcpu_id, REG_X29, buf[29]);
	set_int_reg(vmid, vcpu_id, REG_X30, buf[30]);
	set_int_reg(vmid, vcpu_id, REG_SP,  buf[31]);
	set_int_reg(vmid, vcpu_id, REG_PC,  buf[32]);
	set_int_reg(vmid, vcpu_id, REG_PSTATE, buf[33]);
	set_int_reg(vmid, vcpu_id, REG_SP_EL1, buf[34]);
	set_int_reg(vmid, vcpu_id, REG_ELR_EL1,buf[35]);
	set_int_reg(vmid, vcpu_id, REG_SPSR_0,buf[36]);
	set_int_reg(vmid, vcpu_id, REG_SPSR_1,buf[37]);
	set_int_reg(vmid, vcpu_id, REG_SPSR_2,buf[38]);
	set_int_reg(vmid, vcpu_id, REG_SPSR_3,buf[39]);
	set_int_reg(vmid, vcpu_id, REG_SPSR_4,buf[40]);
	//offset to sys_regs
	set_int_reg(vmid, vcpu_id, REG_MPIDR_EL1, buf[41]);
	set_int_reg(vmid, vcpu_id, REG_CSSELR_EL1,buf[42]);	
	set_int_reg(vmid, vcpu_id, REG_SCTLR_EL1, buf[43]);
	set_int_reg(vmid, vcpu_id, REG_ACTLR_EL1, buf[44]);
	set_int_reg(vmid, vcpu_id, REG_CPACR_EL1, buf[45]);	
	set_int_reg(vmid, vcpu_id, REG_TTBR0_EL1, buf[46]);	
	set_int_reg(vmid, vcpu_id, REG_TTBR1_EL1, buf[47]);	
	set_int_reg(vmid, vcpu_id, REG_TCR_EL1,	  buf[48]);
	set_int_reg(vmid, vcpu_id, REG_ESR_EL1,   buf[49]);	
	set_int_reg(vmid, vcpu_id, REG_AFSR0_EL1, buf[50]);      
	set_int_reg(vmid, vcpu_id, REG_AFSR1_EL1, buf[51]);      
	set_int_reg(vmid, vcpu_id, REG_FAR_EL1,	  buf[52]);
	set_int_reg(vmid, vcpu_id, REG_MAIR_EL1,  buf[53]);      
	set_int_reg(vmid, vcpu_id, REG_VBAR_EL1,  buf[54]);	
	set_int_reg(vmid, vcpu_id, REG_CONTEXTIDR_EL1, buf[55]);	
	set_int_reg(vmid, vcpu_id, REG_TPIDR_EL0, buf[56]);
	set_int_reg(vmid, vcpu_id, REG_TPIDRRO_EL0, buf[57]);	
	set_int_reg(vmid, vcpu_id, REG_TPIDR_EL1, buf[58]);
	set_int_reg(vmid, vcpu_id, REG_AMAIR_EL1, buf[59]);	
	set_int_reg(vmid, vcpu_id, REG_CNTKCTL_EL1, buf[60]);	
	set_int_reg(vmid, vcpu_id, REG_PAR_EL1,	  buf[61]);
	set_int_reg(vmid, vcpu_id, REG_MDSCR_EL1, buf[62]);
	set_int_reg(vmid, vcpu_id, REG_MDCCINT_EL1, buf[63]);
	set_int_reg(vmid, vcpu_id, REG_DISR_EL1,  buf[64]);
	//set fp_regs
	set_int_fpregs(vmid, vcpu_id, &buf[65]);
}

#define OFF SYSREGS_START 
void __hyp_text __el2_decrypt_vcpu(u32 vmid, u32 vcpu_id)
{
	u64 buf[SHADOW_VCPU_CONTEXT_CONCAT_SIZE]; 
	u64 out[SHADOW_VCPU_CONTEXT_CONCAT_SIZE]; 
	//we assume someone returns a point to us that pads zero to shadow_ctxt

	acquire_lock_vm(vmid);
	if (get_vm_state(vmid) != READY || get_vcpu_state(vmid, vcpu_id) != READY)
		v_panic();

	get_int_reg(vmid, vcpu_id, REG_X0, &buf[0]);
	get_int_reg(vmid, vcpu_id, REG_X1, &buf[1]);
	get_int_reg(vmid, vcpu_id, REG_X2, &buf[2]);
	get_int_reg(vmid, vcpu_id, REG_X3, &buf[3]);
	get_int_reg(vmid, vcpu_id, REG_X4, &buf[4]);
	get_int_reg(vmid, vcpu_id, REG_X5, &buf[5]);
	get_int_reg(vmid, vcpu_id, REG_X6, &buf[6]);
	get_int_reg(vmid, vcpu_id, REG_X7, &buf[7]);
	get_int_reg(vmid, vcpu_id, REG_X8, &buf[8]);
	get_int_reg(vmid, vcpu_id, REG_X9, &buf[9]);
	get_int_reg(vmid, vcpu_id, REG_X10, &buf[10]);
	get_int_reg(vmid, vcpu_id, REG_X11, &buf[11]);
	get_int_reg(vmid, vcpu_id, REG_X12, &buf[12]);
	get_int_reg(vmid, vcpu_id, REG_X13, &buf[13]);
	get_int_reg(vmid, vcpu_id, REG_X14, &buf[14]);
	get_int_reg(vmid, vcpu_id, REG_X15, &buf[15]);
	get_int_reg(vmid, vcpu_id, REG_X16, &buf[16]);
	get_int_reg(vmid, vcpu_id, REG_X17, &buf[17]);
	get_int_reg(vmid, vcpu_id, REG_X18, &buf[18]);
	get_int_reg(vmid, vcpu_id, REG_X19, &buf[19]);
	get_int_reg(vmid, vcpu_id, REG_X20, &buf[20]);
	get_int_reg(vmid, vcpu_id, REG_X21, &buf[21]);
	get_int_reg(vmid, vcpu_id, REG_X22, &buf[22]);
	get_int_reg(vmid, vcpu_id, REG_X23, &buf[23]);
	get_int_reg(vmid, vcpu_id, REG_X24, &buf[24]);
	get_int_reg(vmid, vcpu_id, REG_X25, &buf[25]);
	get_int_reg(vmid, vcpu_id, REG_X26, &buf[26]);
	get_int_reg(vmid, vcpu_id, REG_X27, &buf[27]);
	get_int_reg(vmid, vcpu_id, REG_X28, &buf[28]);
	get_int_reg(vmid, vcpu_id, REG_X29, &buf[29]);
	get_int_reg(vmid, vcpu_id, REG_X30, &buf[30]);
	get_int_reg(vmid, vcpu_id, REG_SP,  &buf[31]);
	get_int_reg(vmid, vcpu_id, REG_PC,  &buf[32]);
	get_int_reg(vmid, vcpu_id, REG_PSTATE, &buf[33]);
	get_int_reg(vmid, vcpu_id, REG_SP_EL1, &buf[34]);
	get_int_reg(vmid, vcpu_id, REG_ELR_EL1,&buf[35]);
	get_int_reg(vmid, vcpu_id, REG_SPSR_0, &buf[36]);
	get_int_reg(vmid, vcpu_id, REG_SPSR_1, &buf[37]);
	get_int_reg(vmid, vcpu_id, REG_SPSR_2, &buf[38]);
	get_int_reg(vmid, vcpu_id, REG_SPSR_3, &buf[39]);
	get_int_reg(vmid, vcpu_id, REG_SPSR_4, &uf[40]);
	//offset to sys_regs
	get_int_reg(vmid, vcpu_id, REG_MPIDR_EL1, &buf[41]);
	get_int_reg(vmid, vcpu_id, REG_CSSELR_EL1,&buf[42]);	
	get_int_reg(vmid, vcpu_id, REG_SCTLR_EL1, &buf[43]);
	get_int_reg(vmid, vcpu_id, REG_ACTLR_EL1, &buf[44]);
	get_int_reg(vmid, vcpu_id, REG_CPACR_EL1, &buf[45]);	
	get_int_reg(vmid, vcpu_id, REG_TTBR0_EL1, &buf[46]);	
	get_int_reg(vmid, vcpu_id, REG_TTBR1_EL1, &buf[47]);	
	get_int_reg(vmid, vcpu_id, REG_TCR_EL1,	  &buf[48]);
	get_int_reg(vmid, vcpu_id, REG_ESR_EL1,   &buf[49]);	
	get_int_reg(vmid, vcpu_id, REG_AFSR0_EL1, &buf[50]);      
	get_int_reg(vmid, vcpu_id, REG_AFSR1_EL1, &buf[51]);      
	get_int_reg(vmid, vcpu_id, REG_FAR_EL1,	  &buf[52]);
	get_int_reg(vmid, vcpu_id, REG_MAIR_EL1,  &buf[53]);      
	get_int_reg(vmid, vcpu_id, REG_VBAR_EL1,  &buf[54]);	
	get_int_reg(vmid, vcpu_id, REG_CONTEXTIDR_EL1, &buf[55]);	
	get_int_reg(vmid, vcpu_id, REG_TPIDR_EL0, &buf[56]);
	get_int_reg(vmid, vcpu_id, REG_TPIDRRO_EL0, &buf[57]);	
	get_int_reg(vmid, vcpu_id, REG_TPIDR_EL1, &buf[58]);
	get_int_reg(vmid, vcpu_id, REG_AMAIR_EL1, &buf[59]);	
	get_int_reg(vmid, vcpu_id, REG_CNTKCTL_EL1, &buf[60]);	
	get_int_reg(vmid, vcpu_id, REG_PAR_EL1,	  &buf[61]);
	get_int_reg(vmid, vcpu_id, REG_MDSCR_EL1, &buf[62]);
	get_int_reg(vmid, vcpu_id, REG_MDCCINT_EL1, &buf[63]);
	get_int_reg(vmid, vcpu_id, REG_DISR_EL1,  &buf[64]);
	//set fp_regs
	get_int_fpregs(vmid, vcpu_id, &buf[65]);

	decrypt_buf(vmid, out_buf, buf, SHADOW_VCPU_CONTEXT_CONCAT_SIZE);

	//V_SP_EL1 is prob missing...
	set_shadow_ctxt(vmid, vcpu_id, 0, out[0]);
	set_shadow_ctxt(vmid, vcpu_id, 1, out[1]);
	set_shadow_ctxt(vmid, vcpu_id, 2, out[2]);
	set_shadow_ctxt(vmid, vcpu_id, 3, out[3]);
	set_shadow_ctxt(vmid, vcpu_id, 4, out[4]);
	set_shadow_ctxt(vmid, vcpu_id, 5, out[5]);
	set_shadow_ctxt(vmid, vcpu_id, 6, out[6]);
	set_shadow_ctxt(vmid, vcpu_id, 7, out[7]);
	set_shadow_ctxt(vmid, vcpu_id, 8, out[8]);
	set_shadow_ctxt(vmid, vcpu_id, 9, out[9]);
	set_shadow_ctxt(vmid, vcpu_id, 10, out[10]);
	set_shadow_ctxt(vmid, vcpu_id, 11, out[11]);
	set_shadow_ctxt(vmid, vcpu_id, 12, out[12]);
	set_shadow_ctxt(vmid, vcpu_id, 13, out[13]);
	set_shadow_ctxt(vmid, vcpu_id, 14, out[14]);
	set_shadow_ctxt(vmid, vcpu_id, 15, out[15]);
	set_shadow_ctxt(vmid, vcpu_id, 16, out[16]);
	set_shadow_ctxt(vmid, vcpu_id, 17, out[17]);
	set_shadow_ctxt(vmid, vcpu_id, 18, out[18]);
	set_shadow_ctxt(vmid, vcpu_id, 19, out[19]);
	set_shadow_ctxt(vmid, vcpu_id, 20, out[20]);
	set_shadow_ctxt(vmid, vcpu_id, 21, out[21]);
	set_shadow_ctxt(vmid, vcpu_id, 22, out[22]);
	set_shadow_ctxt(vmid, vcpu_id, 23, out[23]);
	set_shadow_ctxt(vmid, vcpu_id, 24, out[24]);
	set_shadow_ctxt(vmid, vcpu_id, 25, out[25]);
	set_shadow_ctxt(vmid, vcpu_id, 26, out[26]);
	set_shadow_ctxt(vmid, vcpu_id, 27, out[27]);
	set_shadow_ctxt(vmid, vcpu_id, 28, out[28]);
	set_shadow_ctxt(vmid, vcpu_id, 29, out[29]);
	set_shadow_ctxt(vmid, vcpu_id, 30, out[30]);
	set_shadow_ctxt(vmid, vcpu_id, V_SP, out[31]);
	set_shadow_ctxt(vmid, vcpu_id, V_PC, out[33]);
	set_shadow_ctxt(vmid, vcpu_id, V_PSTATE, out[34]);
	set_shadow_ctxt(vmid, vcpu_id, V_ELR_EL1,out[35]);
	set_shadow_ctxt(vmid, vcpu_id, V_SPSR_EL1, out[36]);
	set_shadow_ctxt(vmid, vcpu_id, V_SPSR_ABT, out[37]);
	set_shadow_ctxt(vmid, vcpu_id, V_SPSR_UND, out[38]);
	set_shadow_ctxt(vmid, vcpu_id, V_SPSR_IRQ, out[39]);
	set_shadow_ctxt(vmid, vcpu_id, V_SPSR_FIQ, out[40]);
	set_shadow_ctxt(vmid, vcpu_id, OFF+MPIDR_EL1, out[41]);
	set_shadow_ctxt(vmid, vcpu_id, OFF+CSSELR_EL1,out[42]);	
	set_shadow_ctxt(vmid, vcpu_id, OFF+SCTLR_EL1, out[43]);
	set_shadow_ctxt(vmid, vcpu_id, OFF+ACTLR_EL1, out[44]);
	set_shadow_ctxt(vmid, vcpu_id, OFF+CPACR_EL1, out[45]);	
	set_shadow_ctxt(vmid, vcpu_id, OFF+TTBR0_EL1, out[46]);	
	set_shadow_ctxt(vmid, vcpu_id, OFF+TTBR1_EL1, out[47]);	
	set_shadow_ctxt(vmid, vcpu_id, OFF+TCR_EL1,   out[48]);
	set_shadow_ctxt(vmid, vcpu_id, OFF+ESR_EL1,   out[49]);	
	set_shadow_ctxt(vmid, vcpu_id, OFF+AFSR0_EL1, out[50]);      
	set_shadow_ctxt(vmid, vcpu_id, OFF+AFSR1_EL1, out[51]);      
	set_shadow_ctxt(vmid, vcpu_id, OFF+FAR_EL1,   out[52]);
	set_shadow_ctxt(vmid, vcpu_id, OFF+MAIR_EL1,  out[53]);      
	set_shadow_ctxt(vmid, vcpu_id, OFF+VBAR_EL1,  out[54]);	
	set_shadow_ctxt(vmid, vcpu_id, OFF+CONTEXTIDR_EL1, out[55]);	
	set_shadow_ctxt(vmid, vcpu_id, OFF+TPIDR_EL0, out[56]);
	set_shadow_ctxt(vmid, vcpu_id, OFF+TPIDRRO_EL0, out[57]);	
	set_shadow_ctxt(vmid, vcpu_id, OFF+TPIDR_EL1, out[58]);
	set_shadow_ctxt(vmid, vcpu_id, OFF+AMAIR_EL1, out[59]);	
	set_shadow_ctxt(vmid, vcpu_id, OFF+CNTKCTL_EL1, out[60]);	
	set_shadow_ctxt(vmid, vcpu_id, OFF+PAR_EL1,	out[61]);
	set_shadow_ctxt(vmid, vcpu_id, OFF+MDSCR_EL1, out[62]);
	set_shadow_ctxt(vmid, vcpu_id, OFF+MDCCINT_EL1, out[63]);
	set_shadow_ctxt(vmid, vcpu_id, OFF+DISR_EL1,  out[64]);

	set_shadow_fpregs(vmid, vcpu_id, &out[65]);

	release_lock_vm(vmid);
}
