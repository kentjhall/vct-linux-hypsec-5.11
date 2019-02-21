#ifndef __ARM_STAGE2_H__
#define __ARM_STAGE2_H__
#include <linux/memblock.h>
#include <linux/kvm_host.h>
#include <linux/hashtable.h>
#include <asm/hypsec_boot.h>
#include <asm/hypsec_mmu.h>
#include <asm/hypsec_vcpu.h>
#include <asm/hypsec_mmio.h>

/* Handler for ACTLR_EL1 is not defined */
#define SHADOW_SYS_REGS_SIZE		(PAR_EL1)
#define SHADOW_32BIT_REGS_SIZE		3
#define SHADOW_SYS_REGS_DESC_SIZE	(SHADOW_SYS_REGS_SIZE + SHADOW_32BIT_REGS_SIZE)
#define NUM_SHADOW_VCPU_CTXT		128
#define NUM_HYP_VA_REGIONS		128

struct el2_data {
	struct memblock_region regions[32];
	struct s2_memblock_info s2_memblock_info[32];
	struct s2_cpu_arch arch;
	struct hyp_va_region va_regions[NUM_HYP_VA_REGIONS];

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
	struct el2_arm_smmu_device smmus[SMMU_NUM];
	int el2_smmu_num;

	u32 next_vmid;
	phys_addr_t vgic_cpu_base;
};

void init_el2_data_page(void);

static inline void stage2_spin_lock(arch_spinlock_t *lock)
{	
	arch_spin_lock(lock);
}

static inline void stage2_spin_unlock(arch_spinlock_t *lock)
{
	arch_spin_unlock(lock);
}

static inline void el2_init_vgic_cpu_base(phys_addr_t base)
{
	struct el2_data *el2_data = (void *)kvm_ksym_ref(el2_data_start);
	el2_data->vgic_cpu_base = base;
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

void encrypt_buf(u32 vmid, void *buf, uint32_t len);
void decrypt_buf(u32 vmid, void *buf, uint32_t len);

extern void el2_boot_from_inc_exe(u32 vmid);
extern bool el2_use_inc_exe(u32 vmid);
extern unsigned long search_load_info(u32 vmid, struct el2_data *el2_data,
				      unsigned long addr);

extern int el2_alloc_vm_info(struct kvm *kvm);

int handle_pvops(struct kvm_vcpu *vcpu);
void save_encrypted_vcpu(struct kvm_vcpu *vcpu);

extern void set_pfn_owner(struct el2_data *el2_data, phys_addr_t addr,
				size_t len, u32 vmid);
extern int hypsec_register_vm(struct kvm *kvm);
int hypsec_register_vcpu(u32 vmid, struct kvm_vcpu *vcpu);

struct el2_vm_info* vmid_to_vm_info(u32 vmid);

void hypsec_tlb_flush_helper(u32 vmid, int mode);
extern void map_vgic_cpu_to_shadow_s2pt(u32 vmid, struct el2_data *el2_data);

static inline int is_smmu_range(struct el2_data *el2_data, phys_addr_t addr)
{
	int ret = -EINVAL, i;
	struct el2_arm_smmu_device smmu;

	for (i = 0; i < el2_data->el2_smmu_num; i++) {
		smmu = el2_data->smmus[i];
		if ((addr >= smmu.phys_base) &&
		    (addr <= smmu.phys_base + smmu.size)) {
			ret = i;
			break;
		}
	}
	return ret;
}
#endif /* __ARM_STAGE2_H__ */
