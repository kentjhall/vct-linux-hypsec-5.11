#ifndef HYPSEC_CONSTANTS_H
#define HYPSEC_CONSTANTS_H

#define V_INVALID	0xFFFFFFFF
#define INVALID64	0xFFFFFFFFFFFFFFFF
#define INVALID_MEM	-1

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
*/
#define MAX_MMIO_ADDR 0x40000000
#define S2_RDWR PTE_S2_RDWR 
#define PMD_PAGE_MASK PMD_MASK 

#define S2_PTE_SHIFT PAGE_SHIFT
#define PMD_TABLE_SHIFT PMD_SHIFT 

#define COREVISOR 257
#define HOSTVISOR 0
#define MAX_SHARE_COUNT 100
#define UNUSED 0
//#define READY 1
//#define VERIFIED 2
//#define ACTIVE 3

//Boot
#define SHARED_KVM_START 1
#define SHARED_VCPU_START 1
#define VCPU_PER_VM	8

//#define SHADOW_SYS_REGS_SIZE 1
#define V_SP		32
#define V_PC		33
#define V_PSTATE 	34
#define	V_SP_EL1	35
#define V_ELR_EL1	36
#define V_SPSR_EL1	37
#define V_SPSR_ABT	38
#define V_SPSR_UND	39
#define V_SPSR_IRQ	40
#define V_SPSR_FIQ	41
#define END_SYS_REGS	41 + NR_SYS_REGS
#define V_FAR_EL2	END_SYS_REGS + 1
#define V_HPFAR_EL2	END_SYS_REGS + 2
#define V_HCR_EL2	END_SYS_REGS + 3
#define V_EC		END_SYS_REGS + 4
#define V_DIRTY		END_SYS_REGS + 5
#define V_FLAGS		END_SYS_REGS + 6

// Do we need the 32 bit registers?
#define V_MPIDR_EL1 	41 + MPIDR_EL1
#define V_DACR32_EL2	41 + DACR32_EL2
#define V_IFSR32_EL2	41 + IFSR32_EL2
#define V_FPEXC32_EL2	41 + FPEXC32_EL2
#define V_ESR_EL1	41 + ESR_EL1
#define V_SPSR_0 8
#define V_HPFAR_MASK 65535UL

/*
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
*/
#define PSTATE_FAULT_BITS_64 11UL

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
