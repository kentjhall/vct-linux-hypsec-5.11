#ifndef __ARM_STAGE2_MMU__
#define __ARM_STAGE2_MMU__

#include <linux/memblock.h>

/* S2 Pages can map up to 16GB of RAM */
#define S2_PFN_SIZE	4096 * 4096
#define IPA_HASH_SIZE	4096 * 32 

#define EL2_REMAP_START                 0xc0000000
#define EL2_PAGE_OFFSET			0x40000000000UL

#define PAGE_GUEST			__pgprot(PTE_S2_GUEST)

#define __el2_va(x)	(void *)(((unsigned long)(x) & \
					(EL2_PAGE_OFFSET - 1)) | EL2_PAGE_OFFSET)
#define	HYPSEC_VMID			0xffffffff

#define S2_PGD_PAGES_NUM	(PTRS_PER_S2_PGD * sizeof(pgd_t)) / PAGE_SIZE

struct el2_data;

struct vring_data {
	size_t queue_size_in_bytes;
	u64 host_pfn;
};

struct s2_page {
	int count;
	u32 vmid;
};

struct s2_memblock_info {
	unsigned long index;
};

struct s2_trans {
        kvm_pfn_t pfn;
        phys_addr_t output;
        bool writable;
        bool readable;
        int level;
	u64 desc;
};

struct ipa_hash {
	kvm_pfn_t ipa_pfn;
	kvm_pfn_t pfn;
	u64 vmid;
	struct hlist_node hlist;
};

struct s2_unmapped_ipa {
	phys_addr_t ipa;
	int count;
};

struct hyp_va_region {
	unsigned long from;
	unsigned long to;
};

extern u64 get_shadow_vttbr(struct kvm *kvm);
void __set_pfn_host(phys_addr_t start, u64 size, kvm_pfn_t pfn, pgprot_t prot);

void clear_vm_stage2_range(u32 vmid, phys_addr_t start, u64 size);
int el2_create_hyp_mapping(unsigned long start, unsigned long end,
			    unsigned long pfn);


extern void el2_flush_dcache_to_poc(void *addr, size_t size);
extern void el2_flush_icache_range(unsigned long start, unsigned long end);

void set_stage2_vring_gpa(struct kvm_vcpu *vcpu);
void grant_stage2_sg_gpa(struct kvm_vcpu *vcpu);
void revoke_stage2_sg_gpa(struct kvm_vcpu *vcpu);
void set_balloon_pfn(struct kvm_vcpu *vcpu);

void* alloc_stage2_page(unsigned int order);
void* alloc_shadow_s2_pgd(unsigned int num);

struct s2_trans walk_stage2_pgd(struct kvm *kvm, phys_addr_t addr,
				bool walk_shadow_s2);


int stage2_mem_regions_search(phys_addr_t addr, struct memblock_region *regions,
	unsigned long cnt);

unsigned long get_s2_page_index(struct el2_data *el2_data, phys_addr_t addr);
int handle_shadow_s2pt_fault(struct kvm_vcpu *vcpu, u64 hpfar);

extern void clear_shadow_stage2_range(struct kvm *kvm, phys_addr_t start, u64 size);
extern void __kvm_tlb_flush_vmid_el2(void);

extern int map_el2_mem(unsigned long start, unsigned long end,
			    unsigned long pfn, pgprot_t prot);

extern void unmap_image_from_host_s2pt(struct kvm *kvm, unsigned long el2_remap_addr, unsigned long pgnum);
extern void load_image_to_shadow_s2pt(struct kvm *kvm, struct el2_data *el2_data,
				unsigned long target_addr, unsigned long el2_remap_addr,
				unsigned long pgnum);

bool stage2_is_map_memory(phys_addr_t addr);
unsigned long get_el2_image_va(u32 vmid, unsigned long addr);
extern struct s2_trans handle_from_vm_info(struct el2_data *el2_data,
					   unsigned long el2_va, unsigned long addr);

static inline bool is_mmio_gpa(u64 addr)
{
	return (addr < 0x40000000) ? true : false;
}

pmd_t *pmd_offset_el2(pud_t *pud, u64 addr);
pte_t *pte_offset_el2(pmd_t *pmd, u64 addr);

extern void el2_encrypt_buf(void *buf, uint32_t len);
extern void el2_decrypt_buf(void *buf, uint32_t len);

extern void map_mem_el2(void);
extern void __kvm_tlb_flush_vmid_ipa_shadow(phys_addr_t ipa);
extern void el2_register_smmu(void);
extern void protect_el2_mem(void);

void __el2_protect_stack_page(phys_addr_t addr);
int map_el2_mem(unsigned long start, unsigned long end,
			    unsigned long pfn, pgprot_t prot);
void  __alloc_shadow_vttbr(struct kvm *kvm);
void  __clear_vm_stage2_range(struct kvm *kvm, phys_addr_t start, u64 size);
void  __el2_register_smmu(void);
void  __el2_encrypt_buf(void *buf, uint32_t len);
void  __el2_decrypt_buf(void *buf, uint32_t len);
int check_and_map_el2_mem(unsigned long start, unsigned long end,
			  unsigned long pfn);
int add_hyp_va_region(unsigned long from, unsigned long to);
#endif /* __ARM_STAGE2_MMU__ */

