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
 * AbstractMachine
 */

void    v_panic(void);
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
u64     get_next_remap_ptr(void);
void    set_next_remap_ptr(u64 remap);

int     get_cur_vmid(void);
int     get_cur_vcpuid(void);
u64     get_int_ctxt(u32 vmid, u32 vcpuid, u32 index);
void    set_int_ctxt(u32 vmid, u32 vcpuid, u32 index, u64 value);
void    clear_shadow_gp_regs(u32 vmid, u32 vcpuid);
void    int_to_shadow_fp_regs(u32 vmid, u32 vcpuid);
void    int_to_shadow_decrypt(u32 vmid, u32 vcpuid);
void    shadow_to_int_encrypt(u32 vmid, u32 vcpuid);
u32     get_shadow_dirty_bit(u32 vmid, u32 vcpuid, u32 index);
void    set_shadow_dirty_bit(u32 vmid, u32 vcpuid, u32 index, u32 value);
u64     get_int_new_pte(u32 vmid, u32 vcpuid);
u32     get_int_new_level(u32 vmid, u32 vcpuid);


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

void __clear_vm_stage2_range(u32 vmid, u64 start, u64 size);
void prot_and_map_vm_s2pt(u32 vmid, u64 fault_addr, u64 new_pte, u32 level, u32 iabt);
//void grant_stage2_sg_gpa(u32 vmid, u64 addr, u64 size);
//void revoke_stage2_sg_gpa(u32 vmid, u64 addr, u64 size);

/*
 * BootCore
 */

u32 gen_vmid(void);
u64 alloc_remap_addr(u64 pgnum);

/*
 * BootAux
 */

void v_unmap_image_from_host_s2pt(u32 vmid, u64 remap_addr, u64 num);
void v_load_image_to_shadow_s2pt(u32 vmid, u64 target_addr, u64 remap_addr, u64 num);

/*
 * BootOps
 */

u32 vm_is_inc_exe(u32 vmid);
void boot_from_inc_exe(u32 vmid);
u64 v_search_load_info(u32 vmid, u64 addr);
void set_vcpu_active(u32 vmid, u32 vcpuid);
void set_vcpu_inactive(u32 vmid, u32 vcpuid);
u32 register_vcpu(u32 vmid, u32 vcpuid);
u32 register_kvm(void);
void set_boot_info(u32 vmid, u64 load_addr, u64 size);
void remap_vm_image(u32 vmid, u32 load_idx, u64 pfn);
void verify_and_load_images(u32 vmid);

/*
 * VCPUOpsAux
 */

void reset_gp_regs(u32 vmid, u32 vcpuid);
void reset_sys_regs(u32 vmid, u32 vcpuid);
void save_sys_regs(u32 vmid, u32 vcpuid);
void restore_sys_regs(u32 vmid, u32 vcpuid);
void sync_dirty_to_shadow(u32 vmid, u32 vcpuid);
void prep_wfx(u32 vmid, u32 vcpuid);
void prep_hvc(u32 vmid, u32 vcpuid);
void prep_abort(u32 vmid, u32 vcpuid);
void v_hypsec_inject_undef(u32 vmid, u32 vcpuid);
void v_update_exception_gp_regs(u32 vmid, u32 vcpuid);
void v_post_handle_shadow_s2pt_fault(u32 vmid, u32 vcpuid);


/*
 * VCPUOps
 */

void save_shadow_kvm_regs(void);
void restore_shadow_kvm_regs(void);
//void save_encrypted_vcpu(u32 vmid, u32 vcpuid);

#define VCPU_IDX(vmid, vcpu_id) \
	(vmid * HYPSEC_MAX_VCPUS) + vcpu_id

#endif //HYPSEC_HYPSEC_H

