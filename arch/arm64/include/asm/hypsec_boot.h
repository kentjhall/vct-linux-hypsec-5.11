#ifndef __ARM_STAGE2_BOOT__
#define __ARM_STAGE2_BOOT__

#define VM_LOADER_START		0x40000000
#define KERNEL64_LOAD_ADDR	0x00080000

#define EL2_MAX_VMID		16
#define EL2_VM_INFO_SIZE	EL2_MAX_VMID

#define HYPSEC_MAX_VCPUS	16	
#define HYPSEC_MAX_CPUS		32
#define HYPSEC_MAX_LOAD_IMG	5
/* Below is copied from QEMU  */
typedef enum {
	FIXUP_NONE = 0,   /* do nothing */
	FIXUP_TERMINATOR, /* end of insns */
	FIXUP_BOARDID,    /* overwrite with board ID number */
	FIXUP_ARGPTR,     /* overwrite with pointer to kernel args */
	FIXUP_ENTRYPOINT, /* overwrite with kernel entry point */
	FIXUP_GIC_CPU_IF, /* overwrite with GIC CPU interface address */
	FIXUP_BOOTREG,    /* overwrite with boot register address */
	FIXUP_DSB,        /* overwrite with correct DSB insn for cpu */
	FIXUP_MAX,
} FixupType;

enum hypsec_init_state {
	INVALID = 0,
	MAPPED,
	READY,
	VERIFIED,
	ACTIVE
};

typedef struct ARMInsnFixup {
	uint32_t insn;
	FixupType fixup;
} ARMInsnFixup;

struct el2_load_info {
	unsigned long load_addr;
	unsigned long size;
	unsigned long el2_remap_addr;
	int el2_mapped_pages;
	unsigned char signature[64];
};

struct int_vcpu {
	struct kvm_vcpu *vcpu;
	int vcpu_pg_cnt;
	enum hypsec_init_state state;
	u32 ctxtid;
};

struct el2_vm_info {
	u64 vttbr;
	int vmid;
	int load_info_cnt;
	int kvm_pg_cnt;
	bool inc_exe;
	enum hypsec_init_state state;
	struct el2_load_info load_info[HYPSEC_MAX_LOAD_IMG];
	arch_spinlock_t shadow_pt_lock;
	arch_spinlock_t vm_lock;
	struct kvm *kvm;
	struct int_vcpu int_vcpus[HYPSEC_MAX_VCPUS];
	struct shadow_vcpu_context *shadow_ctxt[HYPSEC_MAX_VCPUS];
	uint8_t key[16];
	uint8_t iv[16];
	unsigned char public_key[32];
	bool powered_on;
	/* For VM private pool */
	u64 page_pool_start;
	unsigned long used_pages;
};

extern int el2_set_boot_info(u32 vmid, unsigned long load_addr,
			unsigned long size, int image_type);
extern int el2_remap_vm_image(u32 vmid, unsigned long pfn, int id);
extern int el2_verify_and_load_images(u32 vmid);
extern int hypsec_get_vm_state(u32 vmid);
extern void hypsec_set_vcpu_state(u32 vmid, int vcpu_id, int state);
extern int hypsec_set_vcpu_active(u32 vmid, int vcpu_id);

extern bool is_valid_vm(struct kvm_vcpu *vcpu);
extern arch_spinlock_t* get_shadow_pt_lock(u32 vmid);

int __el2_set_boot_info(u32 vmid, unsigned long load_addr,
			 unsigned long size, int image_type);
void __el2_remap_vm_image(u32 vmid, unsigned long pfn, int id);
bool __el2_verify_and_load_images(u32 vmid);
void __el2_boot_from_inc_exe(u32 vmid);

struct kvm* hypsec_vmid_to_kvm(u32 vmid);
struct kvm_vcpu* hypsec_vcpu_id_to_vcpu(u32 vmid, int vcpu_id);
struct shadow_vcpu_context* hypsec_vcpu_id_to_shadow_ctxt( u32 vmid, int vcpu_id);
#endif /* __ARM_STAGE2_BOOT__ */
