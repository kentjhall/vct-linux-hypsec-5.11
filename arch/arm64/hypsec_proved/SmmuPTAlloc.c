#include "hypsec.h"

/*
 * MmioPTAlloc
 */

u64 __hyp_text alloc_smmu_pgd_page(void)
{
	u64 next, end;

	next = get_smmu_pgd_next();
	end = SMMU_PMD_START;
	if (next + PAGE_SIZE <= end)
	{
		set_smmu_pgd_next(next + PAGE_SIZE);
	}
	else
	{
		v_panic();
	}
	return next;
}

u64 __hyp_text alloc_smmu_pmd_page(void)
{
	u64 next, end;

	next = get_smmu_pmd_next();
	end = SMMU_POOL_END;
	if (next + PAGE_SIZE <= end)
	{
		set_smmu_pmd_next(next + PAGE_SIZE);
	}
	else
	{
		v_panic();
	}
	return next;
}
