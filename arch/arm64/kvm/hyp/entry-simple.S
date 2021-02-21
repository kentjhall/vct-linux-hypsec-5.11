/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#include <linux/linkage.h>

#include <asm/alternative.h>
#include <asm/asm-offsets.h>
#include <asm/assembler.h>
#include <asm/fpsimdmacros.h>
#include <asm/kvm.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_ptrauth.h>

	.text
	.pushsection	.hyp.text, "ax"

.macro _save_callee_saved_regs ctxt
	stp	x19, x20, [\ctxt, #CPU_XREG_OFFSET(19)]
	stp	x21, x22, [\ctxt, #CPU_XREG_OFFSET(21)]
	stp	x23, x24, [\ctxt, #CPU_XREG_OFFSET(23)]
	stp	x25, x26, [\ctxt, #CPU_XREG_OFFSET(25)]
	stp	x27, x28, [\ctxt, #CPU_XREG_OFFSET(27)]
	stp	x29, lr,  [\ctxt, #CPU_XREG_OFFSET(29)]
.endm

.macro _restore_callee_saved_regs ctxt
	ldp	x19, x20, [\ctxt, #CPU_XREG_OFFSET(19)]
	ldp	x21, x22, [\ctxt, #CPU_XREG_OFFSET(21)]
	ldp	x23, x24, [\ctxt, #CPU_XREG_OFFSET(23)]
	ldp	x25, x26, [\ctxt, #CPU_XREG_OFFSET(25)]
	ldp	x27, x28, [\ctxt, #CPU_XREG_OFFSET(27)]
	ldp	x29, lr,  [\ctxt, #CPU_XREG_OFFSET(29)]
.endm

/*
 * u64 __guest_enter(struct kvm_vcpu *vcpu,
 *		     struct kvm_cpu_context *host_ctxt);
 */
SYM_FUNC_START(__guest_enter)
	// x0: vcpu, NO, it points to shadow vcpu context now
	// x1: host context
	// x2-x17: clobbered by macros
	// x18: guest context

	// Store the host regs
	_save_callee_saved_regs x1

	// Now the host state is stored if we have a pending RAS SError it must
	// affect the host. If any asynchronous exception is pending we defer
	// the guest entry. The DSB isn't necessary before v8.2 as any SError
	// would be fatal.
#alternative_if ARM64_HAS_RAS_EXTN
#	dsb	nshst
#	isb
#alternative_else_nop_endif
	#mrs	x1, isr_el1
	#cbz	x1,  1f
	#mov	x0, #ARM_EXCEPTION_IRQ
	#ret

1:
#ifndef CONFIG_VERIFIED_KVM
	add	x18, x0, #VCPU_CONTEXT
#else
	// Store the host_ctxt for use at exit time
	str     x1, [sp, #-16]!
	mov	x18, x0
#endif

	// Macro ptrauth_switch_to_guest format:
	// 	ptrauth_switch_to_guest(guest cxt, tmp1, tmp2, tmp3)
	// The below macro to restore guest keys is not implemented in C code
	// as it may cause Pointer Authentication key signing mismatch errors
	// when this feature is enabled for kernel code.
#ifndef CONFIG_VERIFIED_KVM
	ptrauth_switch_to_guest x18, x0, x1, x2
#endif

	// Restore guest regs x0-x17
	ldp	x0, x1,   [x18, #CPU_XREG_OFFSET(0)]
	ldp	x2, x3,   [x18, #CPU_XREG_OFFSET(2)]
	ldp	x4, x5,   [x18, #CPU_XREG_OFFSET(4)]
	ldp	x6, x7,   [x18, #CPU_XREG_OFFSET(6)]
	ldp	x8, x9,   [x18, #CPU_XREG_OFFSET(8)]
	ldp	x10, x11, [x18, #CPU_XREG_OFFSET(10)]
	ldp	x12, x13, [x18, #CPU_XREG_OFFSET(12)]
	ldp	x14, x15, [x18, #CPU_XREG_OFFSET(14)]
	ldp	x16, x17, [x18, #CPU_XREG_OFFSET(16)]

	// Restore guest regs x19-x29, lr
	_restore_callee_saved_regs x18

	// Restore guest reg x18
	ldr	x18,      [x18, #CPU_XREG_OFFSET(18)]

	// Do not touch any register after this!
	eret
	sb
SYM_FUNC_END(__guest_enter)

SYM_FUNC_START(__guest_exit)
	// x0: return code
	// x1: shadow_vcpu_context 
	// x2-x29,lr: vcpu regs
	// vcpu x0-x1 on the stack

#ifndef CONFIG_VERIFIED_KVM
	add	x1, x1, #VCPU_CONTEXT
#endif

	ALTERNATIVE(nop, SET_PSTATE_PAN(1), ARM64_HAS_PAN, CONFIG_ARM64_PAN)

	// Store the guest regs x2 and x3
	stp	x2, x3,   [x1, #CPU_XREG_OFFSET(2)]

	// Retrieve the guest regs x0-x1 from the stack
	ldp	x2, x3, [sp], #16	// x0, x1

	// Store the guest regs x0-x1 and x4-x18
	stp	x2, x3,   [x1, #CPU_XREG_OFFSET(0)]
	stp	x4, x5,   [x1, #CPU_XREG_OFFSET(4)]
	stp	x6, x7,   [x1, #CPU_XREG_OFFSET(6)]
	stp	x8, x9,   [x1, #CPU_XREG_OFFSET(8)]
	stp	x10, x11, [x1, #CPU_XREG_OFFSET(10)]
	stp	x12, x13, [x1, #CPU_XREG_OFFSET(12)]
	stp	x14, x15, [x1, #CPU_XREG_OFFSET(14)]
	stp	x16, x17, [x1, #CPU_XREG_OFFSET(16)]
	str	x18,      [x1, #CPU_XREG_OFFSET(18)]

	// Store the guest regs x19-x29, lr
	_save_callee_saved_regs x1

#ifndef CONFIG_VERIFIED_KVM
	get_host_ctxt	x2, x3
#else
	// Restore the host_ctxt from the stack
	ldr     x2, [sp], #16
#endif

	// Macro ptrauth_switch_to_guest format:
	// 	ptrauth_switch_to_host(guest cxt, host cxt, tmp1, tmp2, tmp3)
	// The below macro to save/restore keys is not implemented in C code
	// as it may cause Pointer Authentication key signing mismatch errors
	// when this feature is enabled for kernel code.
#ifndef CONFIG_VERIFIED_KVM
	ptrauth_switch_to_host x1, x2, x3, x4, x5
#endif

	// Now restore the host regs
	_restore_callee_saved_regs x2

#alternative_if ARM64_HAS_RAS_EXTN
	// If we have the RAS extensions we can consume a pending error
	// without an unmask-SError and isb. The ESB-instruction consumed any
	// pending guest error when we took the exception from the guest.
#	mrs_s	x2, SYS_DISR_EL1
#	str	x2, [x1, #(VCPU_FAULT_DISR - VCPU_CONTEXT)]
#	cbz	x2, 1f
#	msr_s	SYS_DISR_EL1, xzr
#	orr	x0, x0, #(1<<ARM_EXIT_WITH_SERROR_BIT)
#1:	ret
#alternative_else
#	dsb	sy		// Synchronize against in-flight ld/st
#	isb			// Prevent an early read of side-effect free ISR
	#mrs	x2, isr_el1
	#tbnz	x2, #8, 2f	// ISR_EL1.A
	#ret
#2:
#alternative_endif
	// We know we have a pending asynchronous abort, now is the
	// time to flush it out. From your VAXorcist book, page 666:
	// "Threaten me not, oh Evil one!  For I speak with
	// the power of DEC, and I command thee to show thyself!"
	mrs	x2, elr_el2
	mrs	x3, esr_el2
	mrs	x4, spsr_el2
	mov	x5, x0

	msr	daifclr, #4	// Unmask aborts

	// This is our single instruction exception window. A pending
	// SError is guaranteed to occur at the earliest when we unmask
	// it, and at the latest just after the ISB.
	.global	abort_guest_exit_start
abort_guest_exit_start:

	isb

	.global	abort_guest_exit_end
abort_guest_exit_end:

	msr	daifset, #4	// Mask aborts

	// If the exception took place, restore the EL1 exception
	// context so that we can report some information.
	// Merge the exception code with the SError pending bit.
	tbz	x0, #ARM_EXIT_WITH_SERROR_BIT, 1f
	msr	elr_el2, x2
	msr	esr_el2, x3
	msr	spsr_el2, x4
	orr	x0, x0, x5
1:	ret
SYM_FUNC_END(__guest_exit)

SYM_FUNC_START(__guest_exit_panic)
        // x2-x29,lr: vcpu regs
        // vcpu x0-x1 on the stack

        // If the hyp context is loaded, go straight to hyp_panic
        get_loaded_vcpu x0, x1
        cbz     x0, hyp_panic

        // The hyp context is saved so make sure it is restored to allow
        // hyp_panic to run at hyp and, subsequently, panic to run in the host.
        // This makes use of __guest_exit to avoid duplication but sets the
        // return address to tail call into hyp_panic. As a side effect, the
        // current state is saved to the guest context but it will only be
        // accurate if the guest had been completely restored.
        adr_this_cpu x0, kvm_hyp_ctxt, x1
        adr     x1, hyp_panic
        str     x1, [x0, #CPU_XREG_OFFSET(30)]

        get_vcpu_ptr    x1, x0
SYM_FUNC_END(__guest_exit_panic)
