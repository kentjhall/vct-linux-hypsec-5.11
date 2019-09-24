#ifndef HYPSEC_HYPSEC_H
#define HYPSEC_HYPSEC_H

#include <linux/types.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>
#include <linux/mman.h>
#include <linux/kvm_host.h>
#include <linux/io.h>
#include <trace/events/kvm.h>
#include <asm/pgalloc.h>
#include <asm/cacheflush.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_mmio.h>
#include <asm/kvm_emulate.h>
#include <asm/virt.h>
#include <asm/kernel-pgtable.h>
#include <asm/hypsec_host.h>
#include <asm/spinlock_types.h>
#include <linux/serial_reg.h>

#include "constants.h"

typedef unsigned long long u64;
typedef unsigned u32;
typedef u64 phys_addr_t;

/*
 * Data Structures
 */

/*
struct el2_data {
    struct memblock_region regions[32];
    struct s2_memblock_info s2_memblock_info[32];
    struct s2_cpu_arch arch;

    int regions_cnt;
    u64 page_pool_start;
    phys_addr_t host_vttbr;

    unsigned long used_pages;
    unsigned long used_tmp_pages;
    unsigned long pl011_base;

    arch_spinlock_t s2pages_lock;
    arch_spinlock_t abs_lock;
    arch_spinlock_t el2_pt_lock;

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
    bool installed;
};
*/

/*
 * AbstractMachine
 */

void    _panic(void);
void    clear_phys_mem(u64 pfn);
u64     get_shared_kvm(u32 vmid);
u64     get_shared_vcpu(u32 vmid, u32 vcpuid);
u32     verify_image(u32 vmid, u64 addr);
u64     get_sys_reg_desc_val(u32 index);
u64     get_exception_vector(u64 pstate);

void    acquire_lock_pt(u32 vmid);
void    release_lock_pt(u32 vmid);
u64     get_pt_next(u32 vmid);
void    set_pt_next(u32 vmid, u64 next);
u64     pt_load(u32 vmid, u64 addr);
void    pt_store(u32 vmid, u64 addr, u64 value);
u64     get_pt_vttbr(u32 vmid);
void    set_pt_vttbr(u32 vmid, u64 vttbr);

u32     get_mem_region_cnt(void);
u64     get_mem_region_base(u32 index);
u64     get_mem_region_size(u32 index);
u64     get_mem_region_index(u32 index);
u64     get_mem_region_flag(u32 index);

void    acquire_lock_s2page(void);
void    release_lock_s2page(void);
u32     get_s2_page_vmid(u64 index);
void    set_s2_page_vmid(u64 index, u32 vmid);
u32     get_s2_page_count(u64 index);
void    set_s2_page_count(u64 index, u32 count);

void    acquire_lock_vm(u32 vmid);
void    release_lock_vm(u32 vmid);
u32     get_vcpu_ctxtid(u32 vmid, u32 vcpuid, u32 ctxtid);
u32     get_ctxt_vmid(u32 ctxtid);
u32     get_ctxt_vcpuid(u32 ctxtid);
void    set_vcpu_ctxtid(u32 vmid, u32 vcpuid, u32 ctxtid);
u32     get_vm_state(u32 vmid);
void    set_vm_state(u32 vmid, u32 state);
u32     get_vcpu_state(u32 vmid, u32 vcpuid);
void    set_vcpu_state(u32 vmid, u32 vcpuid, u32 state);
u32     get_vm_power(u32 vmid);
void    set_vm_power(u32 vmid, u32 power);
u32     get_vm_inc_exe(u32 vmid);
void    set_vm_inc_exe(u32 vmid, u32 inc_exe);
u64     get_vm_kvm(u32 vmid);
void    set_vm_kvm(u32 vmid, u64 kvm);
u64     get_vm_vcpu(u32 vmid, u32 vcpuid);
void    set_vm_vcpu(u32 vmid, u32 vcpuid, u64 vcpu);
u32     get_vm_next_load_idx(u32 vmid);
void    set_vm_next_load_idx(u32 vmid, u32 load_idx);
u64     get_vm_load_addr(u32 vmid, u32 load_idx);
void    set_vm_load_addr(u32 vmid, u32 load_idx, u64 load_addr);
u64     get_vm_load_size(u32 vmid, u32 load_idx);
void    set_vm_load_size(u32 vmid, u32 load_idx, u64 size);
u64     get_vm_remap_addr(u32 vmid, u32 load_idx);
void    set_vm_remap_addr(u32 vmid, u32 load_idx, u64 remap_addr);
u64     get_vm_mapped_pages(u32 vmid, u32 load_idx);
void    set_vm_mapped_pages(u32 vmid, u32 load_idx, u64 mapped);

void    acquire_lock_core(void);
void    release_lock_core(void);
u32     get_next_vmid(void);
void    set_next_vmid(u32 vmid);
u32     get_next_ctxt(void);
void    set_next_ctxt(u32 ctxtid);
u64     get_next_remap_ptr(void);
void    set_next_remap_ptr(u64 remap);

u64     get_shadow_ctxt(u32 ctxtid, u32 index);
void    set_shadow_ctxt(u32 ctxtid, u32 index, u64 value);
u64     get_int_ctxt(u32 ctxtid, u32 index);
void    set_int_ctxt(u32 ctxtid, u32 index, u64 value);
void    clear_shadow_gp_regs(u32 ctxtid);
void    int_to_shadow_fp_regs(u32 ctxtid);
void    int_to_shadow_decrypt(u32 ctxtid);
void    shadow_to_int_encrypt(u32 ctxtid);
u32     get_shadow_dirty_bit(u32 ctxtid, u32 index);
void    set_shadow_dirty_bit(u32 ctxtid, u32 index, u32 value);
u64     get_int_new_pte(u32 ctxtid);
u32     get_int_new_level(u32 ctxtid);

/*
 * PTAlloc
 */

u64 alloc_s2pt_page(u32 vmid);

/*
 * PTWalk
 */

u64 walk_pgd(u32 vmid, u64 vttbr, u64 addr, u32 alloc);
u64 walk_pmd(u32 vmid, u64 pgd, u64 addr, u32 alloc);
u64 walk_pte(u32 vmid, u64 pmd, u64 addr);
void v_set_pmd(u32 vmid, u64 pgd, u64 addr, u64 pmd);
void v_set_pte(u32 vmid, u64 pmd, u64 addr, u64 pte);

/*
 * NPTWalk
 */

void init_npt(u32 vmid);
u32 get_npt_level(u32 vmid, u64 addr);
u64 walk_npt(u32 vmid, u64 addr);
void set_npt(u32 vmid, u64 addr, u32 level, u64 pte);

/*
 * NPTOps
 */

void init_s2pt(u32 vmid);
u64 get_vm_vttbr(u32 vmid);
u32 get_level_s2pt(u32 vmid, u64 addr);
u64 walk_s2pt(u32 vmid, u64 addr);
void mmap_s2pt(u32 vmid, u64 addr, u32 level, u64 pte);
void set_pfn_host(u64 gfn, u64 num, u64 pfn, u64 prot);

/*
 * MemRegion
 */

u32 mem_region_search(u64 addr);

/*
 * PageIndex
 */

u64 get_s2_page_index(u64 addr);

/*
 * PageManager
 */

u32 get_pfn_owner(u64 pfn);
void set_pfn_owner(u64 pfn, u64 num, u32 vmid);
u32 get_pfn_count(u64 pfn);
void set_pfn_count(u64 pfn, u32 count);

/*
 * VMPower
 */

void set_vm_poweroff(u32 vmid);
u32 get_vm_poweron(u32 vmid);

/*
 * MemManager
 */

void map_page_host(u64 addr);
void clear_vm_page(u32 vmid, u64 pfn);
void assign_pfn_to_vm(u32 vmid, u64 pfn);
void map_pfn_vm(u32 vmid, u64 addr, u64 new_pte, u32 level, u32 exec);
void grant_vm_page(u32 vmid, u64 pfn);
void revoke_vm_page(u32 vmid, u64 pfn);

/*
 * MemoryOps
 */

void clear_vm_stage2_range(u32 vmid, u64 start, u64 size);
void prot_and_map_vm_s2pt(u32 vmid, u64 fault_addr, u64 new_pte, u32 level, u32 iabt);
//void grant_stage2_sg_gpa(u32 vmid, u64 addr, u64 size);
//void revoke_stage2_sg_gpa(u32 vmid, u64 addr, u64 size);

/*
 * BootCore
 */

u32 gen_vmid(void);
u32 alloc_shadow_ctxt(void);
u64 alloc_remap_addr(u64 pgnum);

/*
 * BootAux
 */

//void unmap_image_from_host_s2pt(u32 vmid, u64 remap_addr, u64 num);
//void load_image_to_shadow_s2pt(u32 vmid, u64 target_addr, u64 remap_addr, u64 num);

/*
 * BootOps
 */

u32 vm_is_inc_exe(u32 vmid);
void boot_from_inc_exe(u32 vmid);
u32 set_vcpu_active(u32 vmid, u32 vcpuid);
u32 set_vcpu_inactive(u32 vmid, u32 vcpuid);
//u64 search_load_info(u32 vmid, u64 addr);
u32 register_vcpu(u32 vmid, u32 vcpuid);
u32 register_kvm(void);
void set_boot_info(u32 vmid, u64 load_addr, u64 size);
void remap_vm_image(u32 vmid, u32 load_idx, u64 pfn);
void verify_and_load_images(u32 vmid);

/*
 * VCPUOpsAux
 */

void reset_gp_regs(u32 ctxtid);
void reset_sys_regs(u32 ctxtid);
void save_sys_regs(u32 ctxtid);
void restore_sys_regs(u32 ctxtid);
void sync_dirty_to_shadow(u32 ctxtid);
void prep_wfx(u32 ctxtid);
void prep_hvc(u32 ctxtid);
void prep_abort(u32 ctxtid);
//void hypsec_inject_undef(u32 ctxtid);
//void update_exception_gp_regs(u32 ctxtid);
//void post_handle_shadow_s2pt_fault(u32 ctxtid);

/*
 * VCPUOps
 */

void save_shadow_kvm_regs(u32 ctxtid, u64 ec);
void restore_shadow_kvm_regs(u32 ctxtid);
//void save_encrypted_vcpu(u32 ctxtid);

#endif //HYPSEC_HYPSEC_H

