#include "hypsec.h"

/*
 * MmioPTAlloc
 */

//TODO: To Xupeng, please sync the code to use end
u64 alloc_smmu_pgd_page(void)
{
	u64 next, end;

	next = get_smmu_pgd_next();
	end = smmu_pgd_end();
	if (next + PAGE_SIZE <= end)
	{
		set_smmu_pgd_next(next + PAGE_SIZE);
	}
	else
	{
	        print_string("\rwe used all smmu pgd pages\n");
		v_panic();
	}
	return next;
}

u64 alloc_smmu_pmd_page(void)
{
	u64 next, end;

	next = get_smmu_pmd_next();
	end = smmu_pmd_end();

	if (next + PAGE_SIZE <= end)
	{
		set_smmu_pmd_next(next + PAGE_SIZE);
	}
	else
	{
	        print_string("\rwe used all smmu pmd pages\n");
		v_panic();
	}
	return next;
}
