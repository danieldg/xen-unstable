/*
 * vcpu.h: HVM per vcpu definitions
 *
 * Copyright (c) 2005, International Business Machines Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#ifndef __ASM_X86_HVM_VCPU_H__
#define __ASM_X86_HVM_VCPU_H__

#include <asm/hvm/io.h>
#include <asm/hvm/vlapic.h>
#include <asm/hvm/vmx/vmcs.h>
#include <asm/hvm/svm/vmcb.h>
#include <asm/mtrr.h>

#define HVM_VCPU_INIT_SIPI_SIPI_STATE_NORM          0
#define HVM_VCPU_INIT_SIPI_SIPI_STATE_WAIT_SIPI     1

enum hvm_io_state {
    HVMIO_none = 0,
    HVMIO_dispatched,
    HVMIO_awaiting_completion,
    HVMIO_handle_mmio_awaiting_completion,
    HVMIO_completed
};

struct hvm_vcpu {
    /* Guest control-register and EFER values, just as the guest sees them. */
    unsigned long       guest_cr[5];
    unsigned long       guest_efer;

    /*
     * Processor-visible control-register values, while guest executes.
     *  CR0, CR4: Used as a cache of VMCS contents by VMX only.
     *  CR1, CR2: Never used (guest_cr[2] is always processor-visible CR2).
     *  CR3:      Always used and kept up to date by paging subsystem.
     */
    unsigned long       hw_cr[5];

    struct vlapic       vlapic;
    s64                 cache_tsc_offset;
    u64                 guest_time;

    /* Lock and list for virtual platform timers. */
    spinlock_t          tm_lock;
    struct list_head    tm_list;

    /* For AP startup */
    unsigned long       init_sipi_sipi_state;

    int                 xen_port;

    bool_t              flag_dr_dirty;
    bool_t              debug_state_latch;

    union {
        struct arch_vmx_struct vmx;
        struct arch_svm_struct svm;
    } u;

    struct mtrr_state   mtrr;
    u64                 pat_cr;

    /* Which cache mode is this VCPU in (CR0:CD/NW)? */
    u8                  cache_mode;

    /* I/O request in flight to device model. */
    enum hvm_io_state   io_state;
    unsigned long       io_data;

    /*
     * HVM emulation:
     *  Virtual address @mmio_gva maps to MMIO physical frame @mmio_gpfn.
     *  The latter is known to be an MMIO frame (not RAM).
     *  This translation is only valid if @mmio_gva is non-zero.
     */
    unsigned long       mmio_gva;
    unsigned long       mmio_gpfn;
};

#endif /* __ASM_X86_HVM_VCPU_H__ */

