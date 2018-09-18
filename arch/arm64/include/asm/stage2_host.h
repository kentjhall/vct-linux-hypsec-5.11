#ifndef __ARM_STAGE2_H__
#define __ARM_STAGE2_H__
#include <linux/memblock.h>
#include <linux/kvm_host.h>
#include <linux/hashtable.h>
#include <asm/stage2_boot.h>
#include <asm/stage2_mmu.h>
#include <asm/stage2_vcpu.h>
#include <asm/stage2_mmio.h>

/* Handler for ACTLR_EL1 is not defined */
#define SHADOW_SYS_REGS_SIZE		(PAR_EL1)
#define SHADOW_32BIT_REGS_SIZE		3
#define SHADOW_SYS_REGS_DESC_SIZE	(SHADOW_SYS_REGS_SIZE + SHADOW_32BIT_REGS_SIZE)
#define NUM_SHADOW_VCPU_CTXT		128

struct stage2_data {
	struct memblock_region regions[32];
	struct s2_memblock_info s2_memblock_info[32];
	struct s2_cpu_arch arch;

	int regions_cnt;
	u64 page_pool_start;
	phys_addr_t host_vttbr;

	unsigned long used_pages;
	unsigned long used_tmp_pages;
	unsigned long used_pgd_pages;
	unsigned long pl011_base;

	arch_spinlock_t fault_lock;
	arch_spinlock_t s2pages_lock;
	arch_spinlock_t page_pool_lock;
	arch_spinlock_t tmp_page_pool_lock;
	arch_spinlock_t shadow_vcpu_ctxt_lock;
	arch_spinlock_t vmid_lock;

	kvm_pfn_t ram_start_pfn;
	struct s2_page s2_pages[S2_PFN_SIZE];

	struct shadow_vcpu_context shadow_vcpu_ctxt[NUM_SHADOW_VCPU_CTXT];
	int used_shadow_vcpu_ctxt;

	struct s2_sys_reg_desc s2_sys_reg_descs[SHADOW_SYS_REGS_DESC_SIZE];

	struct el2_vm_info vm_info[EL2_VM_INFO_SIZE];
	int used_vm_info;
	unsigned long last_remap_ptr;

	struct el2_smmu_cfg smmu_cfg[EL2_SMMU_CFG_SIZE];
	struct el2_arm_smmu_device smmu;

	uint8_t key[16];
	uint8_t iv[16];

	u32 next_vmid;
};

void init_stage2_data_page(void);

static inline void stage2_spin_lock(arch_spinlock_t *lock)
{	
	arch_spin_lock(lock);
}

static inline void stage2_spin_unlock(arch_spinlock_t *lock)
{
	arch_spin_unlock(lock);
}

extern void __noreturn __hyp_panic(void);

extern void printhex_ul(unsigned long input);
extern void print_string(char *input);

extern void stage2_inject_el1_fault(unsigned long addr);
void el2_memset(void *b, int c, int len);
void el2_memcpy(void *dest, void *src, size_t len);
int el2_memcmp(void *dest, void *src, size_t len);

int el2_hex_to_bin(char ch);
int el2_hex2bin(unsigned char *dst, const char *src, int count);

extern void el2_protect_stack_page(phys_addr_t addr);

extern void el2_alloc_smmu_pgd(unsigned long addr, u8 cbndx, u32 vmid);
extern void el2_free_smmu_pgd(unsigned long addr);
extern void el2_arm_lpae_map(unsigned long iova, phys_addr_t paddr,
		      size_t size, u64 prot, u64 ttbr);
extern phys_addr_t el2_arm_lpae_iova_to_phys(unsigned long iova, u64 ttbr);

void encrypt_buf(struct stage2_data *stage2_data, void *buf, uint32_t len);
void decrypt_buf(struct stage2_data *stage2_data, void *buf, uint32_t len);

extern void el2_boot_from_inc_exe(struct kvm *kvm);
extern bool el2_use_inc_exe(struct kvm *kvm, struct stage2_data *stage2_data);
extern bool search_load_info(struct kvm *kvm, struct stage2_data *stage2_data,
			     unsigned long addr, struct el2_load_info *input);

extern int el2_alloc_vm_info(struct kvm *kvm);
extern int el2_get_vmid(struct stage2_data *stage2_data, struct kvm *kvm);

int handle_pvops(struct kvm_vcpu *vcpu);
int el2_alloc_shadow_ctxt(struct kvm_vcpu *vcpu);
#endif /* __ARM_STAGE2_H__ */
