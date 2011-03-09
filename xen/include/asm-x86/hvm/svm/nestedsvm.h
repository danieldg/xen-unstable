/*
 * nestedsvm.h: Nested Virtualization
 * Copyright (c) 2011, Advanced Micro Devices, Inc
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
 *
 */
#ifndef __ASM_X86_HVM_SVM_NESTEDSVM_H__
#define __ASM_X86_HVM_SVM_NESTEDSVM_H__

#include <asm/config.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/svm/vmcb.h>

struct nestedsvm {
    uint64_t ns_msr_hsavepa; /* MSR HSAVE_PA value */

    /* l1 guest physical address of virtual vmcb used by prior VMRUN.
     * Needed for VMCB Cleanbit emulation.
     */
    uint64_t ns_ovvmcb_pa;

    /* Cached real intercepts of the l2 guest */
    uint32_t ns_cr_intercepts;
    uint32_t ns_dr_intercepts;
    uint32_t ns_exception_intercepts;
    uint32_t ns_general1_intercepts;
    uint32_t ns_general2_intercepts;

    /* Cached real lbr of the l2 guest */
    lbrctrl_t ns_lbr_control;

    /* Cached real MSR permission bitmaps of the l2 guest */
    unsigned long *ns_cached_msrpm;
    /* Merged MSR permission bitmap */
    unsigned long *ns_merged_msrpm;

    /* guest physical address of virtual io permission map */
    paddr_t ns_iomap_pa, ns_oiomap_pa;
    /* Shadow io permission map */
    unsigned long *ns_iomap;

    /* Cache guest cr3/host cr3 the guest sets up for the l2 guest.
     * Used by Shadow-on-Shadow and Nested-on-Nested.
     * ns_vmcb_guestcr3: in l2 guest physical address space and points to
     *     the l2 guest page table
     * ns_vmcb_hostcr3: in l1 guest physical address space and points to
     *     the l1 guest nested page table
     */
    uint64_t ns_vmcb_guestcr3, ns_vmcb_hostcr3;
    uint32_t ns_guest_asid;

    bool_t ns_hap_enabled;

    /* Only meaningful when vmexit_pending flag is set */
    struct {
        uint64_t exitcode;  /* native exitcode to inject into l1 guest */
        uint64_t exitinfo1; /* additional information to the exitcode */
        uint64_t exitinfo2; /* additional information to the exitcode */
    } ns_vmexit;
    union {
        uint32_t bytes;
        struct {
            uint32_t rflagsif: 1;
            uint32_t vintrmask: 1;
            uint32_t reserved: 30;
        } fields;
    } ns_hostflags;
};

#define vcpu_nestedsvm(v) (vcpu_nestedhvm(v).u.nsvm)

/* True when l1 guest enabled SVM in EFER */
#define hvm_svm_enabled(v) \
    (!!((v)->arch.hvm_vcpu.guest_efer & EFER_SVME))

int nestedsvm_vmcb_map(struct vcpu *v, uint64_t vmcbaddr);
void nestedsvm_vmexit_defer(struct vcpu *v,
    uint64_t exitcode, uint64_t exitinfo1, uint64_t exitinfo2);
enum nestedhvm_vmexits
nestedsvm_vmexit_n2n1(struct vcpu *v, struct cpu_user_regs *regs);
enum nestedhvm_vmexits
nestedsvm_check_intercepts(struct vcpu *v, struct cpu_user_regs *regs,
    uint64_t exitcode);

/* Interface methods */
int nsvm_vcpu_destroy(struct vcpu *v);
int nsvm_vcpu_initialise(struct vcpu *v);
int nsvm_vcpu_reset(struct vcpu *v);
int nsvm_vcpu_hostrestore(struct vcpu *v, struct cpu_user_regs *regs);
int nsvm_vcpu_vmrun(struct vcpu *v, struct cpu_user_regs *regs);
int nsvm_vcpu_vmexit_inject(struct vcpu *v, struct cpu_user_regs *regs,
    uint64_t exitcode);
int nsvm_vcpu_vmexit_trap(struct vcpu *v, unsigned int trapnr,
                      int errcode, unsigned long cr2);
uint64_t nsvm_vcpu_guestcr3(struct vcpu *v);
uint64_t nsvm_vcpu_hostcr3(struct vcpu *v);
uint32_t nsvm_vcpu_asid(struct vcpu *v);
int nsvm_vmcb_guest_intercepts_exitcode(struct vcpu *v,
    struct cpu_user_regs *regs, uint64_t exitcode);
int nsvm_vmcb_guest_intercepts_trap(struct vcpu *v, unsigned int trapnr);
bool_t nsvm_vmcb_hap_enabled(struct vcpu *v);

/* MSRs */
int nsvm_rdmsr(struct vcpu *v, unsigned int msr, uint64_t *msr_content);
int nsvm_wrmsr(struct vcpu *v, unsigned int msr, uint64_t msr_content);

#endif /* ASM_X86_HVM_SVM_NESTEDSVM_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
