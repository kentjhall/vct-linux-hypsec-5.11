/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2016 ARM Limited
 */
#ifndef __ASM_SECTIONS_H
#define __ASM_SECTIONS_H

#include <asm-generic/sections.h>

extern char __alt_instructions[], __alt_instructions_end[];
extern char __hibernate_exit_text_start[], __hibernate_exit_text_end[];
extern char __hyp_idmap_text_start[], __hyp_idmap_text_end[];
extern char __hyp_text_start[], __hyp_text_end[];
extern char __hyp_data_ro_after_init_start[], __hyp_data_ro_after_init_end[];
extern char __idmap_text_start[], __idmap_text_end[];
extern char __initdata_begin[], __initdata_end[];
extern char __inittext_begin[], __inittext_end[];
extern char __exittext_begin[], __exittext_end[];
extern char __irqentry_text_start[], __irqentry_text_end[];
extern char __mmuoff_data_start[], __mmuoff_data_end[];
extern char __entry_tramp_text_start[], __entry_tramp_text_end[];
#ifdef CONFIG_VERIFIED_KVM
extern char dtb_copy_start[];
extern char dtb_copy_end[];
extern char stage2_pgs_start[];
extern char stage2_pgs_end[];
extern char el2_data_start[];
extern char el2_data_end[];
extern char shared_data_start[];
extern char shared_data_end[];
extern char stage2_tmp_pgs_start[];
extern char stage2_tmp_pgs_end[];
extern char smmu_pgs_start[];
extern char smmu_pgs_end[];
#endif

#endif /* __ASM_SECTIONS_H */
