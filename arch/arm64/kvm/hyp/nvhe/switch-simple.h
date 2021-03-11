static bool inline hypsec_supports_fpsimd(void)
{
	return true;
}
/*
static u64 get_pmuserenr_el0(void)
{
	return read_sysreg(pmuserenr_el0);
}
*/
static void set_pmuserenr_el0(u64 val)
{
	write_sysreg(val, pmuserenr_el0);
}
/*
static u64 get_pmselr_el0(void)
{
	return read_sysreg(pmselr_el0);
}
*/
static void set_pmselr_el0(u64 val)
{
	write_sysreg(val, pmselr_el0);
}
/*
static u64 get_hstr_el2(void)
{
	return read_sysreg(hstr_el2);
}

static void set_hstr_el2(u64 val)
{
	write_sysreg(val, hstr_el2);
}

static u64 get_cptr_el2(void)
{
	return read_sysreg(cptr_el2);
}
*/
static void set_cptr_el2(u64 val)
{
	write_sysreg(val, cptr_el2);
}
/*
static u64 get_mdcr_el2(void)
{
	return read_sysreg(mdcr_el2);
}
*/
static void set_mdcr_el2(u64 val)
{
	write_sysreg(val, mdcr_el2);
}
/*
static u64 get_hcr_el2(void)
{
	return read_sysreg(hcr_el2);
}
*/
static void set_hcr_el2(u64 val)
{
	write_sysreg(val, hcr_el2);
}

static u64 get_esr_el2(void)
{
	return read_sysreg(esr_el2);
}

/*
static void set_esr_el2(u64 val)
{
	write_sysreg(val, esr_el2);
}

static u64 get_vttbr_el2(void)
{
	return read_sysreg(vttbr_el2);
}
*/
static void set_vttbr_el2(u64 val)
{
	write_sysreg(val, vttbr_el2);
}

/*
static u64 get_tpidr_el2(void)
{
	return read_sysreg(tpidr_el2);
}

static void set_tpidr_el2(u64 val)
{
	write_sysreg(val, tpidr_el2);
}
*/

static u64 get_far_el2(void)
{
	return read_sysreg(far_el2);
}
/*
static void set_far_el2(u64 val)
{
	write_sysreg(val, far_el2);
}
*/
static u64 get_hpfar_el2(void)
{
	return read_sysreg(hpfar_el2);
}
/*
static void set_hpfar_el2(u64 val)
{
	write_sysreg(val, hpfar_el2);
}
*/
