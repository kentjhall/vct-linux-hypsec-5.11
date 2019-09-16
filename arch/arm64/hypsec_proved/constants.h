#ifndef HYPSEC_CONSTANTS_H
#define HYPSEC_CONSTANTS_H

#define INVALID 0xffffffffU
#define INVALID64 0xffffffffffffffffULL

#define PT_POOL_START 0x10000UL
#define PT_POOL_PER_VM 0x10000UL
#define MAX_VM_NUM 256U
#define MAX_CTXT_NUM 1024U
#define MAX_LOAD_INFO_NUM 1024U
#define KVM_PHYS_SIZE 4096UL
#define PAGE_SIZE 4096UL
#define PMD_PAGE_MASK 1UL
#define PAGE_GUEST 0UL
#define PAGE_NONE 0UL
#define PAGE_S2_KERNEL 0UL
#define PAGE_S2_DEVICE 0UL
#define PAGE_HYP 0UL
#define S2_RDWR 0UL
#define PAGE_S2 0UL
#define PTE_S2_RDWR 0UL
#define PMD_S2_RDWR 0UL
#define PTE_S2_XN 0UL
#define PMD_S2_XN 0UL
#define PMD_TABLE_SHIFT 1UL

#define PHYS_MASK 1UL
#define PAGE_MASK 1UL
#define S2_PGDIR_SHIFT 1UL
#define PTRS_PER_PGD 1UL
#define S2_PMD_SHIFT 1UL
#define PTRS_PER_PMD 1UL
#define S2_PTE_SHIFT 1UL
#define PTRS_PER_PTE 1UL
#define PUD_TYPE_TABLE 1UL
#define PMD_TYPE_TABLE 1UL
#define VTTBR_VMID_SHIFT 1UL
#define S2_PGD_PAGES_NUM 1UL
#define MEMBLOCK_NOMAP 1UL
#define MAX_MMIO_ADDR 100000UL

#define COREVISOR 257U
#define HOSTVISOR 0U
#define MAX_SHARE_COUNT 100U
#define UNUSED 0U
#define READY 1U
#define VERIFIED 2U
#define ACTIVE 3U

#define SHADOW_SYS_REGS_SIZE 1U
#define DIRTY 1U
#define PC 2U
#define PSTATE 3U
#define FAR_EL2 0U
#define ESR_EL2 1U
#define MPIDR_EL1 2U
#define DACR32_EL2 3U
#define IFSR32_EL2 4U
#define FPEXC32_EL2 5U
#define HPFAR_EL2 6U
#define ELR_EL1 7U
#define SPSR_0 8U
#define ESR_EL1 9U
#define EC 100U
#define FLAGS 102U
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

// Micros

#define PT_POOL_SIZE (MAX_VM_NUM * PT_POOL_PER_VM)
#define pool_start(vm) (PT_POOL_PER_VM*(vm))
#define pool_end(vm) (PT_POOL_PER_VM * ((vm) + 1UL))
#define phys_page(addr) ((addr) & PHYS_MASK & PAGE_MASK)
#define pgd_idx(addr) (((addr) >> S2_PGDIR_SHIFT) & PTRS_PER_PGD)
#define pmd_idx(addr) (((addr) >> S2_PMD_SHIFT) & PTRS_PER_PMD)
#define pte_idx(addr) (((addr) >> S2_PTE_SHIFT) & PTRS_PER_PTE)
#define pmd_table(pmd) (((pmd) >> PMD_TABLE_SHIFT) & 1UL)
#define writable(pte) (((pte) >> 2UL) & 1UL)

#endif //HYPSEC_CONSTANTS_H
