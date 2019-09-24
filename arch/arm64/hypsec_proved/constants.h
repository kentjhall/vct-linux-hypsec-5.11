#ifndef HYPSEC_CONSTANTS_H
#define HYPSEC_CONSTANTS_H

#define V_INVALID	0xFFFFFFFF
#define INVALID64	0xFFFFFFFFFFFFFFFF

#define PT_POOL_START 0x10000
#define PT_POOL_PER_VM 0x10000
#define MAX_VM_NUM 256
#define MAX_CTXT_NUM 1024
#define MAX_LOAD_INFO_NUM 1024
/*
#define KVM_PHYS_SIZE 4096UL
#define PAGE_SIZE 4096UL
#define PAGE_GUEST 0UL
#define PAGE_NONE 0UL
#define PAGE_S2_KERNEL 0UL
#define PAGE_S2_DEVICE 0UL
#define PAGE_HYP 0UL
#define PAGE_S2 0UL
#define PTE_S2_RDWR 0UL
#define PMD_S2_RDWR 0UL
#define PTE_S2_XN 0UL
#define PMD_S2_XN 0UL

#define PHYS_MASK 1UL
#define PAGE_MASK 1UL
#define S2_PGDIR_SHIFT 1UL
#define PTRS_PER_PGD 1UL
#define S2_PMD_SHIFT 1UL
#define PTRS_PER_PMD 1UL
#define PTRS_PER_PTE 1UL
#define PUD_TYPE_TABLE 1UL
#define PMD_TYPE_TABLE 1UL
#define VTTBR_VMID_SHIFT 1UL
#define S2_PGD_PAGES_NUM 1UL
#define MEMBLOCK_NOMAP 1UL
#define MAX_MMIO_ADDR 100000UL
*/
#define S2_RDWR PTE_S2_RDWR 
#define PMD_PAGE_MASK PMD_MASK 

#define S2_PTE_SHIFT PAGE_SHIFT
#define PMD_TABLE_SHIFT PMD_SHIFT 

#define COREVISOR 257
#define HOSTVISOR 0
#define MAX_SHARE_COUNT 100
//#define UNUSED 0
//#define READY 1
//#define VERIFIED 2
//#define ACTIVE 3

/*
#define SHADOW_SYS_REGS_SIZE 1
#define DIRTY 1
#define PC 2
#define PSTATE 3
#define FAR_EL2 0
#define ESR_EL2 1
#define MPIDR_EL1 2
#define DACR32_EL2 3
#define IFSR32_EL2 4
#define FPEXC32_EL2 5
#define HPFAR_EL2 6
#define ELR_EL1 7
#define SPSR_0 8
#define ESR_EL1 9
#define EC 100
#define FLAGS 102
#define HPFAR_MASK 65535UL

#define PENDING_FSC_FAULT 1UL //????????????
#define ARM_EXCEPTION_TRAP 0UL
#define PENDING_EXCEPT_INJECT_FLAG 2UL //????????
#define DIRTY_PC_FLAG 4UL //??????????????
#define ESR_ELx_EC_MASK 63UL
#define ESR_ELx_EC_SHIFT 67108864UL // (1 << 26)
#define PSCI_0_2_FN64_CPU_ON 4UL //?????????
#define PSCI_0_2_FN_AFFINITY_INFO 5UL //?????????
#define PSCI_0_2_FN64_AFFINITY_INFO 6UL //?????????
#define PSCI_0_2_FN_SYSTEM_OFF 7UL //?????????
#define ESR_ELx_EC_WFx 8UL //?????????????????
#define ESR_ELx_EC_HVC32 9UL
#define ESR_ELx_EC_HVC64 10UL
#define ESR_ELx_EC_IABT_LOW 11UL
#define ESR_ELx_EC_DABT_LOW 12UL
#define PENDING_UNDEF_INJECT 13UL
#define ESR_ELx_EC_UNKNOWN 67108864UL
#define PSTATE_FAULT_BITS_64 11UL
*/

// Micros

#define PT_POOL_SIZE (MAX_VM_NUM * PT_POOL_PER_VM)
#define pool_start(vm) (PT_POOL_PER_VM*(vm))
#define pool_end(vm) (PT_POOL_PER_VM * ((vm) + 1UL))
#define phys_page(addr) ((addr) & PHYS_MASK & PAGE_MASK)
#define pgd_idx(addr) (((addr) >> S2_PGDIR_SHIFT) & PTRS_PER_PGD)
#define pmd_idx(addr) (((addr) >> S2_PMD_SHIFT) & PTRS_PER_PMD)
#define pte_idx(addr) (((addr) >> S2_PTE_SHIFT) & PTRS_PER_PTE)
#define v_pmd_table(pmd) (((pmd) >> PMD_TABLE_SHIFT) & 1UL)
#define writable(pte) (((pte) >> 2UL) & 1UL)

#endif //HYPSEC_CONSTANTS_H
