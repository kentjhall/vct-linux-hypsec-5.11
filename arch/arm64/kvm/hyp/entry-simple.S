/*
 * Copyright (C) 2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/linkage.h>

#include <asm/asm-offsets.h>
#include <asm/assembler.h>
#include <asm/fpsimdmacros.h>
#include <asm/kvm.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_mmu.h>

	.text

/*
 * u64 __guest_enter(struct kvm_vcpu *vcpu,
 *		     struct kvm_cpu_context *host_ctxt);
 */
SYM_FUNC_START(__guest_enter)
	// x0: shadow vcpu context
	// x1: host context
	// x2-x17: clobbered by macros
	// x29: guest context
	bl	hyp_pr_something

	// Store the host regs
	save_callee_saved_regs x1

        // Save host's sp_el0
        save_sp_el0     x1, x2
	bl	hyp_pr_something

	// Now the host state is stored if we have a pending RAS SError it must
        // affect the host. If any asynchronous exception is pending we defer
        // the guest entry. The DSB isn't necessary before v8.2 as any SError
        // would be fatal.
#alternative_if ARM64_HAS_RAS_EXTN
#       dsb     nshst
#       isb
#alternative_else_nop_endif
        #mrs    x1, isr_el1
        #cbz    x1,  1f
        #mov    x0, #ARM_EXCEPTION_IRQ
        #ret

1:
	// Store the host_ctxt for use at exit time
	str	x1, [sp, #-16]!
	mov	x29, x0
	bl	hyp_pr_something

	// Restore the guest's sp_el0
	restore_sp_el0 x29, x0
	bl	hyp_pr_something

	// Restore guest regs x0-x17
	ldp	x0, x1,   [x29, #CPU_XREG_OFFSET(0)]
	ldp	x2, x3,   [x29, #CPU_XREG_OFFSET(2)]
	ldp	x4, x5,   [x29, #CPU_XREG_OFFSET(4)]
	ldp	x6, x7,   [x29, #CPU_XREG_OFFSET(6)]
	ldp	x8, x9,   [x29, #CPU_XREG_OFFSET(8)]
	ldp	x10, x11, [x29, #CPU_XREG_OFFSET(10)]
	ldp	x12, x13, [x29, #CPU_XREG_OFFSET(12)]
	ldp	x14, x15, [x29, #CPU_XREG_OFFSET(14)]
	ldp	x16, x17, [x29, #CPU_XREG_OFFSET(16)]
	bl	hyp_pr_something

	// Restore guest regs x18-x29, lr
	restore_callee_saved_regs x29
	bl	hyp_pr_something

	/* // Restore guest reg x18 */
	/* ldr	x18,      [x18, #CPU_XREG_OFFSET(18)] */
	/* bl	hyp_pr_something */

	// Do not touch any register after this!
	eret
	sb

SYM_INNER_LABEL(__guest_exit_panic, SYM_L_GLOBAL)
	// x2-x29,lr: vcpu regs
	// vcpu x0-x1 on the stack

	// If the hyp context is loaded, go straight to hyp_panic
	get_loaded_vcpu x0, x1
	cbz	x0, hyp_panic

	// The hyp context is saved so make sure it is restored to allow
	// hyp_panic to run at hyp and, subsequently, panic to run in the host.
	// This makes use of __guest_exit to avoid duplication but sets the
	// return address to tail call into hyp_panic. As a side effect, the
	// current state is saved to the guest context but it will only be
	// accurate if the guest had been completely restored.
	ldr	x1, [sp], #16
	adr	x1, hyp_panic
	str	x1, [x0, #CPU_XREG_OFFSET(30)]

	get_vcpu_ptr	x1, x0

SYM_INNER_LABEL(__guest_exit, SYM_L_GLOBAL)
	// x0: return code
	// x1: shadow vcpu context
	// x2-x29,lr: vcpu regs
	// vcpu x0-x1 on the stack

	ALTERNATIVE(nop, SET_PSTATE_PAN(1), ARM64_HAS_PAN, CONFIG_ARM64_PAN)

	bl	hyp_pr_something1
	// Store the guest regs x2 and x3
	stp	x2, x3,   [x1, #CPU_XREG_OFFSET(2)]

	bl	hyp_pr_something
	// Retrieve the guest regs x0-x1 from the stack
	ldp	x2, x3, [sp], #16	// x0, x1

	bl	hyp_pr_something
	// Store the guest regs x0-x1 and x4-x17
	stp	x2, x3,   [x1, #CPU_XREG_OFFSET(0)]
	stp	x4, x5,   [x1, #CPU_XREG_OFFSET(4)]
	stp	x6, x7,   [x1, #CPU_XREG_OFFSET(6)]
	stp	x8, x9,   [x1, #CPU_XREG_OFFSET(8)]
	stp	x10, x11, [x1, #CPU_XREG_OFFSET(10)]
	stp	x12, x13, [x1, #CPU_XREG_OFFSET(12)]
	stp	x14, x15, [x1, #CPU_XREG_OFFSET(14)]
	stp	x16, x17, [x1, #CPU_XREG_OFFSET(16)]

	bl	hyp_pr_something
	// Store the guest regs x18-x29, lr
	save_callee_saved_regs x1

	bl	hyp_pr_something
	// Store the guest's sp_el0
	save_sp_el0	x1, x2

	bl	hyp_pr_something
	// Restore the host_ctxt from the stack
	ldr	x2, [sp], #16

	bl	hyp_pr_something
	// Restore host's sp_el0
	restore_sp_el0 x2, x3

	bl	hyp_pr_something
	// Now restore the host regs
	restore_callee_saved_regs x2

#alternative_if ARM64_HAS_RAS_EXTN
#	// If we have the RAS extensions we can consume a pending error
#	// without an unmask-SError and isb. The ESB-instruction consumed any
#	// pending guest error when we took the exception from the guest.
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
	#nop
#2:
#alternative_endif
	bl	hyp_pr_something
	// We know we have a pending asynchronous abort, now is the
	// time to flush it out. From your VAXorcist book, page 666:
	// "Threaten me not, oh Evil one!  For I speak with
	// the power of DEC, and I command thee to show thyself!"
	mrs	x2, elr_el2
	mrs	x3, esr_el2
	mrs	x4, spsr_el2
	mov	x5, x0

	bl	hyp_pr_something
	msr	daifclr, #4	// Unmask aborts

	// This is our single instruction exception window. A pending
	// SError is guaranteed to occur at the earliest when we unmask
	// it, and at the latest just after the ISB.
abort_guest_exit_start:

	bl	hyp_pr_something4
	isb

abort_guest_exit_end:

	bl	hyp_pr_something5
	msr	daifset, #4	// Mask aborts
	ret

	bl	hyp_pr_something
	_kvm_extable	abort_guest_exit_start, 9997f
	_kvm_extable	abort_guest_exit_end, 9997f
9997:
	msr	daifset, #4	// Mask aborts
	mov	x0, #(1 << ARM_EXIT_WITH_SERROR_BIT)

	bl	hyp_pr_something
	// restore the EL1 exception context so that we can report some
	// information. Merge the exception code with the SError pending bit.
	msr	elr_el2, x2
	msr	esr_el2, x3
	msr	spsr_el2, x4
	orr	x0, x0, x5
	bl	hyp_pr_something3
1:	ret
SYM_FUNC_END(__guest_enter)
