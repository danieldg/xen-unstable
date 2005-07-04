/*
 * vmx.c: handling VMX architecture-related VM exits
 * Copyright (c) 2004, Intel Corporation.
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

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/trace.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <xen/softirq.h>
#include <xen/domain_page.h>
#include <asm/current.h>
#include <asm/io.h>
#include <asm/shadow.h>
#include <asm/regs.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/types.h>
#include <asm/msr.h>
#include <asm/spinlock.h>
#include <asm/vmx.h>
#include <asm/vmx_vmcs.h>
#include <asm/vmx_intercept.h>
#include <asm/shadow.h>
#include <public/io/ioreq.h>

#ifdef CONFIG_VMX

int vmcs_size;
unsigned int opt_vmx_debug_level = 0;
integer_param("vmx_debug", opt_vmx_debug_level);

#ifdef __x86_64__
static struct msr_state percpu_msr[NR_CPUS];

static u32 msr_data_index[VMX_MSR_COUNT] =
{
    MSR_LSTAR, MSR_STAR, MSR_CSTAR,
    MSR_SYSCALL_MASK, MSR_EFER,
};

/*
 * To avoid MSR save/restore at every VM exit/entry time, we restore
 * the x86_64 specific MSRs at domain switch time. Since those MSRs are
 * are not modified once set for generic domains, we don't save them, 
 * but simply reset them to the values set at percpu_traps_init().
 */
void vmx_load_msrs(struct vcpu *p, struct vcpu *n)
{
    struct msr_state *host_state;
    host_state = &percpu_msr[smp_processor_id()];

    while (host_state->flags){
        int i;

        i = find_first_set_bit(host_state->flags);
        wrmsrl(msr_data_index[i], host_state->msr_items[i]);
        clear_bit(i, &host_state->flags);
    }
}

static void vmx_save_init_msrs(void)
{
    struct msr_state *host_state;
    host_state = &percpu_msr[smp_processor_id()];
    int i;

    for (i = 0; i < VMX_MSR_COUNT; i++)
        rdmsrl(msr_data_index[i], host_state->msr_items[i]);
}

#define CASE_READ_MSR(address)              \
    case MSR_ ## address:                 \
    msr_content = msr->msr_items[VMX_INDEX_MSR_ ## address]; \
    break

#define CASE_WRITE_MSR(address)   \
    case MSR_ ## address:                   \
    msr->msr_items[VMX_INDEX_MSR_ ## address] = msr_content; \
    if (!test_bit(VMX_INDEX_MSR_ ## address, &msr->flags)){ \
    	set_bit(VMX_INDEX_MSR_ ## address, &msr->flags);   \
    }\
    break

#define IS_CANO_ADDRESS(add) 1
static inline int long_mode_do_msr_read(struct cpu_user_regs *regs)
{
    u64     msr_content = 0;
    struct vcpu *vc = current;
    struct msr_state * msr = &vc->arch.arch_vmx.msr_content;
    switch(regs->ecx){
        case MSR_EFER:
            msr_content = msr->msr_items[VMX_INDEX_MSR_EFER];
            VMX_DBG_LOG(DBG_LEVEL_2, "EFER msr_content %llx\n", (unsigned long long)msr_content);
            if (test_bit(VMX_CPU_STATE_LME_ENABLED,
                          &vc->arch.arch_vmx.cpu_state))
                msr_content |= 1 << _EFER_LME;

            if (VMX_LONG_GUEST(vc))
                msr_content |= 1 << _EFER_LMA;
            break;
        case MSR_FS_BASE:
            if (!(VMX_LONG_GUEST(vc)))
                /* XXX should it be GP fault */
                domain_crash();
            __vmread(GUEST_FS_BASE, &msr_content);
            break;
        case MSR_GS_BASE:
            if (!(VMX_LONG_GUEST(vc)))
                domain_crash();
            __vmread(GUEST_GS_BASE, &msr_content);
            break;
        case MSR_SHADOW_GS_BASE:
            msr_content = msr->shadow_gs;
            break;

        CASE_READ_MSR(STAR);
        CASE_READ_MSR(LSTAR);
        CASE_READ_MSR(CSTAR);
        CASE_READ_MSR(SYSCALL_MASK);
        default:
            return 0;
    }
    VMX_DBG_LOG(DBG_LEVEL_2, "mode_do_msr_read: msr_content: %lx\n", msr_content);
    regs->eax = msr_content & 0xffffffff;
    regs->edx = msr_content >> 32;
    return 1;
}

static inline int long_mode_do_msr_write(struct cpu_user_regs *regs)
{
    u64     msr_content = regs->eax | ((u64)regs->edx << 32); 
    struct vcpu *vc = current;
    struct msr_state * msr = &vc->arch.arch_vmx.msr_content;
    struct msr_state * host_state = 
		&percpu_msr[smp_processor_id()];

    VMX_DBG_LOG(DBG_LEVEL_1, " mode_do_msr_write msr %lx msr_content %lx\n", 
                regs->ecx, msr_content);

    switch (regs->ecx){
        case MSR_EFER:
            if ((msr_content & EFER_LME) ^
                  test_bit(VMX_CPU_STATE_LME_ENABLED,
                           &vc->arch.arch_vmx.cpu_state)){
                if (test_bit(VMX_CPU_STATE_PG_ENABLED,
                             &vc->arch.arch_vmx.cpu_state) ||
                    !test_bit(VMX_CPU_STATE_PAE_ENABLED,
                        &vc->arch.arch_vmx.cpu_state)){
                     vmx_inject_exception(vc, TRAP_gp_fault, 0);
                }
            }
            if (msr_content & EFER_LME)
                set_bit(VMX_CPU_STATE_LME_ENABLED,
                        &vc->arch.arch_vmx.cpu_state);
            /* No update for LME/LMA since it have no effect */
            msr->msr_items[VMX_INDEX_MSR_EFER] =
                  msr_content;
            if (msr_content & ~(EFER_LME | EFER_LMA)){
                msr->msr_items[VMX_INDEX_MSR_EFER] = msr_content;
                if (!test_bit(VMX_INDEX_MSR_EFER, &msr->flags)){ 
                    rdmsrl(MSR_EFER,
                            host_state->msr_items[VMX_INDEX_MSR_EFER]);
                      set_bit(VMX_INDEX_MSR_EFER, &host_state->flags);
                      set_bit(VMX_INDEX_MSR_EFER, &msr->flags);  
                      wrmsrl(MSR_EFER, msr_content);
                }
            }
            break;

        case MSR_FS_BASE:
        case MSR_GS_BASE:
           if (!(VMX_LONG_GUEST(vc)))
                domain_crash();
           if (!IS_CANO_ADDRESS(msr_content)){
               VMX_DBG_LOG(DBG_LEVEL_1, "Not cano address of msr write\n");
               vmx_inject_exception(vc, TRAP_gp_fault, 0);
           }
           if (regs->ecx == MSR_FS_BASE)
               __vmwrite(GUEST_FS_BASE, msr_content);
           else 
               __vmwrite(GUEST_GS_BASE, msr_content);
           break;

        case MSR_SHADOW_GS_BASE:
           if (!(VMX_LONG_GUEST(vc)))
               domain_crash();
           vc->arch.arch_vmx.msr_content.shadow_gs = msr_content;
           wrmsrl(MSR_SHADOW_GS_BASE, msr_content);
           break;

           CASE_WRITE_MSR(STAR);
           CASE_WRITE_MSR(LSTAR);
           CASE_WRITE_MSR(CSTAR);
           CASE_WRITE_MSR(SYSCALL_MASK);
        default:
            return 0;
    }
    return 1;
}

void
vmx_restore_msrs(struct vcpu *d)
{
    int i = 0;
    struct msr_state *guest_state;
    struct msr_state *host_state;
    unsigned long guest_flags ;

    guest_state = &d->arch.arch_vmx.msr_content;;
    host_state = &percpu_msr[smp_processor_id()];

    wrmsrl(MSR_SHADOW_GS_BASE, guest_state->shadow_gs);
    guest_flags = guest_state->flags;
    if (!guest_flags)
        return;

    while (guest_flags){
        i = find_first_set_bit(guest_flags);

        VMX_DBG_LOG(DBG_LEVEL_2,
          "restore guest's index %d msr %lx with %lx\n",
          i, (unsigned long) msr_data_index[i], (unsigned long) guest_state->msr_items[i]);
        set_bit(i, &host_state->flags);
        wrmsrl(msr_data_index[i], guest_state->msr_items[i]);
        clear_bit(i, &guest_flags);
    }
}

#else  /* __i386__ */
#define  vmx_save_init_msrs()   ((void)0)

static inline int  long_mode_do_msr_read(struct cpu_user_regs *regs){
    return 0;
}
static inline int  long_mode_do_msr_write(struct cpu_user_regs *regs){
    return 0;
}
#endif

extern long evtchn_send(int lport);
extern long do_block(void);
void do_nmi(struct cpu_user_regs *, unsigned long);

int start_vmx(void)
{
    struct vmcs_struct *vmcs;
    u32 ecx;
    u32 eax, edx;
    u64 phys_vmcs;      /* debugging */

    /*
     * Xen does not fill x86_capability words except 0.
     */
    ecx = cpuid_ecx(1);
    boot_cpu_data.x86_capability[4] = ecx;

    if (!(test_bit(X86_FEATURE_VMXE, &boot_cpu_data.x86_capability)))
        return 0;
 
    rdmsr(IA32_FEATURE_CONTROL_MSR, eax, edx);

    if (eax & IA32_FEATURE_CONTROL_MSR_LOCK) {
        if ((eax & IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON) == 0x0) {
                printk("VMX disabled by Feature Control MSR.\n");
                return 0;
        }
    }
    else {
        wrmsr(IA32_FEATURE_CONTROL_MSR, 
              IA32_FEATURE_CONTROL_MSR_LOCK |
              IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON, 0);
    }

    set_in_cr4(X86_CR4_VMXE);   /* Enable VMXE */

    if (!(vmcs = alloc_vmcs())) {
        printk("Failed to allocate VMCS\n");    
        return 0;
    }

    phys_vmcs = (u64) virt_to_phys(vmcs);

    if (!(__vmxon(phys_vmcs))) {
        printk("VMXON is done\n");
    }

    vmx_save_init_msrs();

    return 1;
}

void stop_vmx(void)
{
    if (read_cr4() & X86_CR4_VMXE)
        __vmxoff();
}

/*
 * Not all cases receive valid value in the VM-exit instruction length field.
 */
#define __get_instruction_length(len) \
    __vmread(INSTRUCTION_LEN, &(len)); \
     if ((len) < 1 || (len) > 15) \
        __vmx_bug(&regs);

static void inline __update_guest_eip(unsigned long inst_len) 
{
    unsigned long current_eip;

    __vmread(GUEST_RIP, &current_eip);
    __vmwrite(GUEST_RIP, current_eip + inst_len);
}


static int vmx_do_page_fault(unsigned long va, struct cpu_user_regs *regs) 
{
    unsigned long eip;
    unsigned long gpa; /* FIXME: PAE */
    int result;

#if VMX_DEBUG
    {
        __vmread(GUEST_RIP, &eip);
        VMX_DBG_LOG(DBG_LEVEL_VMMU, 
                "vmx_do_page_fault = 0x%lx, eip = %lx, error_code = %lx",
                va, eip, (unsigned long)regs->error_code);
    }
#endif

    if (!vmx_paging_enabled(current)){
        handle_mmio(va, va);
        return 1;
    }
    gpa = gva_to_gpa(va);

    /* Use 1:1 page table to identify MMIO address space */
    if ( mmio_space(gpa) ){
        if (gpa >= 0xFEE00000) { /* workaround for local APIC */
            u32 inst_len;
            __vmread(INSTRUCTION_LEN, &(inst_len));
            __update_guest_eip(inst_len);
            return 1;
        }
        handle_mmio(va, gpa);
        return 1;
    }

    result = shadow_fault(va, regs);

#if 0
    if ( !result )
    {
        __vmread(GUEST_RIP, &eip);
        printk("vmx pgfault to guest va=%p eip=%p\n", va, eip);
    }
#endif

    return result;
}

static void vmx_do_no_device_fault(void)
{
    unsigned long cr0;
        
    clts();
    setup_fpu(current);
    __vmread(CR0_READ_SHADOW, &cr0);
    if (!(cr0 & X86_CR0_TS)) {
        __vmread(GUEST_CR0, &cr0);
        cr0 &= ~X86_CR0_TS;
        __vmwrite(GUEST_CR0, cr0);
    }
    __vm_clear_bit(EXCEPTION_BITMAP, EXCEPTION_BITMAP_NM);
}


static void vmx_vmexit_do_cpuid(unsigned long input, struct cpu_user_regs *regs) 
{
    unsigned int eax, ebx, ecx, edx;
    unsigned long eip;

    __vmread(GUEST_RIP, &eip);

    VMX_DBG_LOG(DBG_LEVEL_1, 
                "do_cpuid: (eax) %lx, (ebx) %lx, (ecx) %lx, (edx) %lx,"
                " (esi) %lx, (edi) %lx",
                (unsigned long)regs->eax, (unsigned long)regs->ebx,
                (unsigned long)regs->ecx, (unsigned long)regs->edx,
                (unsigned long)regs->esi, (unsigned long)regs->edi);

    cpuid(input, &eax, &ebx, &ecx, &edx);

    if (input == 1) {
#ifdef __i386__
        clear_bit(X86_FEATURE_PSE, &edx);
        clear_bit(X86_FEATURE_PAE, &edx);
        clear_bit(X86_FEATURE_PSE36, &edx);
#endif
    }

    regs->eax = (unsigned long) eax;
    regs->ebx = (unsigned long) ebx;
    regs->ecx = (unsigned long) ecx;
    regs->edx = (unsigned long) edx;

    VMX_DBG_LOG(DBG_LEVEL_1, 
            "vmx_vmexit_do_cpuid: eip: %lx, input: %lx, out:eax=%x, ebx=%x, ecx=%x, edx=%x",
            eip, input, eax, ebx, ecx, edx);

}

#define CASE_GET_REG_P(REG, reg)    \
    case REG_ ## REG: reg_p = (unsigned long *)&(regs->reg); break

static void vmx_dr_access (unsigned long exit_qualification, struct cpu_user_regs *regs)
{
    unsigned int reg;
    unsigned long *reg_p = 0;
    struct vcpu *v = current;
    unsigned long eip;

    __vmread(GUEST_RIP, &eip);

    reg = exit_qualification & DEBUG_REG_ACCESS_NUM;

    VMX_DBG_LOG(DBG_LEVEL_1, 
                "vmx_dr_access : eip=%lx, reg=%d, exit_qualification = %lx",
                eip, reg, exit_qualification);

    switch(exit_qualification & DEBUG_REG_ACCESS_REG) {
        CASE_GET_REG_P(EAX, eax);
        CASE_GET_REG_P(ECX, ecx);
        CASE_GET_REG_P(EDX, edx);
        CASE_GET_REG_P(EBX, ebx);
        CASE_GET_REG_P(EBP, ebp);
        CASE_GET_REG_P(ESI, esi);
        CASE_GET_REG_P(EDI, edi);
    case REG_ESP:
        break;  
    default:
        __vmx_bug(regs);
    }
        
    switch (exit_qualification & DEBUG_REG_ACCESS_TYPE) {
    case TYPE_MOV_TO_DR: 
        /* don't need to check the range */
        if (reg != REG_ESP)
            v->arch.guest_context.debugreg[reg] = *reg_p; 
        else {
            unsigned long value;
            __vmread(GUEST_RSP, &value);
            v->arch.guest_context.debugreg[reg] = value;
        }
        break;
    case TYPE_MOV_FROM_DR:
        if (reg != REG_ESP)
            *reg_p = v->arch.guest_context.debugreg[reg];
        else {
            __vmwrite(GUEST_RSP, v->arch.guest_context.debugreg[reg]);
        }
        break;
    }
}

/*
 * Invalidate the TLB for va. Invalidate the shadow page corresponding
 * the address va.
 */
static void vmx_vmexit_do_invlpg(unsigned long va) 
{
    unsigned long eip;
    struct vcpu *v = current;

    __vmread(GUEST_RIP, &eip);

    VMX_DBG_LOG(DBG_LEVEL_VMMU, "vmx_vmexit_do_invlpg: eip=%lx, va=%lx",
                eip, va);

    /*
     * We do the safest things first, then try to update the shadow
     * copying from guest
     */
    shadow_invlpg(v, va);
}

static int check_for_null_selector(unsigned long eip)
{
    unsigned char inst[MAX_INST_LEN];
    unsigned long sel;
    int i, inst_len;
    int inst_copy_from_guest(unsigned char *, unsigned long, int);

    __vmread(INSTRUCTION_LEN, &inst_len);
    memset(inst, 0, MAX_INST_LEN);
    if (inst_copy_from_guest(inst, eip, inst_len) != inst_len) {
        printf("check_for_null_selector: get guest instruction failed\n");
        domain_crash_synchronous();
    }

    for (i = 0; i < inst_len; i++) {
        switch (inst[i]) {
        case 0xf3: /* REPZ */
        case 0xf2: /* REPNZ */
        case 0xf0: /* LOCK */
        case 0x66: /* data32 */
        case 0x67: /* addr32 */
            continue;
        case 0x2e: /* CS */
            __vmread(GUEST_CS_SELECTOR, &sel);
            break;
        case 0x36: /* SS */
            __vmread(GUEST_SS_SELECTOR, &sel);
            break;
        case 0x26: /* ES */
            __vmread(GUEST_ES_SELECTOR, &sel);
            break;
        case 0x64: /* FS */
            __vmread(GUEST_FS_SELECTOR, &sel);
            break;
        case 0x65: /* GS */
            __vmread(GUEST_GS_SELECTOR, &sel);
            break;
        case 0x3e: /* DS */
            /* FALLTHROUGH */
        default:
            /* DS is the default */
            __vmread(GUEST_DS_SELECTOR, &sel);
        }
        return sel == 0 ? 1 : 0;
    }

    return 0;
}

static void vmx_io_instruction(struct cpu_user_regs *regs, 
                   unsigned long exit_qualification, unsigned long inst_len) 
{
    struct vcpu *d = current;
    vcpu_iodata_t *vio;
    ioreq_t *p;
    unsigned long addr;
    unsigned long eip, cs, eflags;
    int vm86;

    __vmread(GUEST_RIP, &eip);
    __vmread(GUEST_CS_SELECTOR, &cs);
    __vmread(GUEST_RFLAGS, &eflags);
    vm86 = eflags & X86_EFLAGS_VM ? 1 : 0;

    VMX_DBG_LOG(DBG_LEVEL_1, 
                "vmx_io_instruction: vm86 %d, eip=%lx:%lx, "
                "exit_qualification = %lx",
                vm86, cs, eip, exit_qualification);

    if (test_bit(6, &exit_qualification))
        addr = (exit_qualification >> 16) & (0xffff);
    else
        addr = regs->edx & 0xffff;

    if (addr == 0x80) {
        __update_guest_eip(inst_len);
        return;
    }

    vio = get_vio(d->domain, d->vcpu_id);
    if (vio == 0) {
        printk("bad shared page: %lx", (unsigned long) vio);
        domain_crash_synchronous(); 
    }
    p = &vio->vp_ioreq;
    p->dir = test_bit(3, &exit_qualification); /* direction */

    p->pdata_valid = 0;
    p->count = 1;
    p->size = (exit_qualification & 7) + 1;

    if (test_bit(4, &exit_qualification)) { /* string instruction */
	unsigned long laddr;

	__vmread(GUEST_LINEAR_ADDRESS, &laddr);
        /*
         * In protected mode, guest linear address is invalid if the
         * selector is null.
         */
        if (!vm86 && check_for_null_selector(eip)) {
            laddr = (p->dir == IOREQ_WRITE) ? regs->esi : regs->edi;
        }
        p->pdata_valid = 1;

        p->u.data = laddr;
        if (vmx_paging_enabled(d))
                p->u.pdata = (void *) gva_to_gpa(p->u.data);
        p->df = (eflags & X86_EFLAGS_DF) ? 1 : 0;

        if (test_bit(5, &exit_qualification)) /* "rep" prefix */
	    p->count = vm86 ? regs->ecx & 0xFFFF : regs->ecx;

        /*
         * Split up string I/O operations that cross page boundaries. Don't
         * advance %eip so that "rep insb" will restart at the next page.
         */
        if ((p->u.data & PAGE_MASK) != 
		((p->u.data + p->count * p->size - 1) & PAGE_MASK)) {
	    VMX_DBG_LOG(DBG_LEVEL_2,
		"String I/O crosses page boundary (cs:eip=0x%lx:0x%lx)\n",
		cs, eip);
            if (p->u.data & (p->size - 1)) {
		printf("Unaligned string I/O operation (cs:eip=0x%lx:0x%lx)\n",
			cs, eip);
                domain_crash_synchronous();     
            }
            p->count = (PAGE_SIZE - (p->u.data & ~PAGE_MASK)) / p->size;
        } else {
            __update_guest_eip(inst_len);
        }
    } else if (p->dir == IOREQ_WRITE) {
        p->u.data = regs->eax;
        __update_guest_eip(inst_len);
    } else
        __update_guest_eip(inst_len);

    p->addr = addr;
    p->port_mm = 0;

    /* Check if the packet needs to be intercepted */
    if (vmx_portio_intercept(p))
	/* no blocking & no evtchn notification */
        return;

    set_bit(ARCH_VMX_IO_WAIT, &d->arch.arch_vmx.flags);
    p->state = STATE_IOREQ_READY;
    evtchn_send(iopacket_port(d->domain));
    vmx_wait_io();
}

enum { COPY_IN = 0, COPY_OUT };

static inline int
vmx_copy(void *buf, unsigned long laddr, int size, int dir)
{
    char *addr;
    unsigned long mfn;

    if ( (size + (laddr & (PAGE_SIZE - 1))) >= PAGE_SIZE )
    {
    	printf("vmx_copy exceeds page boundary\n");
        return 0;
    }

    mfn = phys_to_machine_mapping(laddr >> PAGE_SHIFT);
    addr = (char *)map_domain_page(mfn) + (laddr & ~PAGE_MASK);

    if (dir == COPY_IN)
	    memcpy(buf, addr, size);
    else
	    memcpy(addr, buf, size);

    unmap_domain_page(addr);
    return 1;
}

int
vmx_world_save(struct vcpu *d, struct vmx_assist_context *c)
{
    unsigned long inst_len;
    int error = 0;

    error |= __vmread(INSTRUCTION_LEN, &inst_len);
    error |= __vmread(GUEST_RIP, &c->eip);
    c->eip += inst_len; /* skip transition instruction */
    error |= __vmread(GUEST_RSP, &c->esp);
    error |= __vmread(GUEST_RFLAGS, &c->eflags);

    error |= __vmread(CR0_READ_SHADOW, &c->cr0);
    c->cr3 = d->arch.arch_vmx.cpu_cr3;
    error |= __vmread(CR4_READ_SHADOW, &c->cr4);

    error |= __vmread(GUEST_IDTR_LIMIT, &c->idtr_limit);
    error |= __vmread(GUEST_IDTR_BASE, &c->idtr_base);

    error |= __vmread(GUEST_GDTR_LIMIT, &c->gdtr_limit);
    error |= __vmread(GUEST_GDTR_BASE, &c->gdtr_base);

    error |= __vmread(GUEST_CS_SELECTOR, &c->cs_sel);
    error |= __vmread(GUEST_CS_LIMIT, &c->cs_limit);
    error |= __vmread(GUEST_CS_BASE, &c->cs_base);
    error |= __vmread(GUEST_CS_AR_BYTES, &c->cs_arbytes.bytes);

    error |= __vmread(GUEST_DS_SELECTOR, &c->ds_sel);
    error |= __vmread(GUEST_DS_LIMIT, &c->ds_limit);
    error |= __vmread(GUEST_DS_BASE, &c->ds_base);
    error |= __vmread(GUEST_DS_AR_BYTES, &c->ds_arbytes.bytes);

    error |= __vmread(GUEST_ES_SELECTOR, &c->es_sel);
    error |= __vmread(GUEST_ES_LIMIT, &c->es_limit);
    error |= __vmread(GUEST_ES_BASE, &c->es_base);
    error |= __vmread(GUEST_ES_AR_BYTES, &c->es_arbytes.bytes);

    error |= __vmread(GUEST_SS_SELECTOR, &c->ss_sel);
    error |= __vmread(GUEST_SS_LIMIT, &c->ss_limit);
    error |= __vmread(GUEST_SS_BASE, &c->ss_base);
    error |= __vmread(GUEST_SS_AR_BYTES, &c->ss_arbytes.bytes);

    error |= __vmread(GUEST_FS_SELECTOR, &c->fs_sel);
    error |= __vmread(GUEST_FS_LIMIT, &c->fs_limit);
    error |= __vmread(GUEST_FS_BASE, &c->fs_base);
    error |= __vmread(GUEST_FS_AR_BYTES, &c->fs_arbytes.bytes);

    error |= __vmread(GUEST_GS_SELECTOR, &c->gs_sel);
    error |= __vmread(GUEST_GS_LIMIT, &c->gs_limit);
    error |= __vmread(GUEST_GS_BASE, &c->gs_base);
    error |= __vmread(GUEST_GS_AR_BYTES, &c->gs_arbytes.bytes);

    error |= __vmread(GUEST_TR_SELECTOR, &c->tr_sel);
    error |= __vmread(GUEST_TR_LIMIT, &c->tr_limit);
    error |= __vmread(GUEST_TR_BASE, &c->tr_base);
    error |= __vmread(GUEST_TR_AR_BYTES, &c->tr_arbytes.bytes);

    error |= __vmread(GUEST_LDTR_SELECTOR, &c->ldtr_sel);
    error |= __vmread(GUEST_LDTR_LIMIT, &c->ldtr_limit);
    error |= __vmread(GUEST_LDTR_BASE, &c->ldtr_base);
    error |= __vmread(GUEST_LDTR_AR_BYTES, &c->ldtr_arbytes.bytes);

    return !error;
}

int
vmx_world_restore(struct vcpu *d, struct vmx_assist_context *c)
{
    unsigned long mfn, old_cr4;
    int error = 0;

    error |= __vmwrite(GUEST_RIP, c->eip);
    error |= __vmwrite(GUEST_RSP, c->esp);
    error |= __vmwrite(GUEST_RFLAGS, c->eflags);

    error |= __vmwrite(CR0_READ_SHADOW, c->cr0);

    if (!vmx_paging_enabled(d)) {
	VMX_DBG_LOG(DBG_LEVEL_VMMU, "switching to vmxassist. use phys table");
	__vmwrite(GUEST_CR3, pagetable_get_paddr(d->domain->arch.phys_table));
        goto skip_cr3;
    }

    if (c->cr3 == d->arch.arch_vmx.cpu_cr3) {
	/* 
	 * This is simple TLB flush, implying the guest has 
	 * removed some translation or changed page attributes.
	 * We simply invalidate the shadow.
	 */
	mfn = phys_to_machine_mapping(c->cr3 >> PAGE_SHIFT);
	if (mfn != pagetable_get_pfn(d->arch.guest_table)) {
	    printk("Invalid CR3 value=%x", c->cr3);
	    domain_crash_synchronous();
	    return 0;
	}
	shadow_sync_all(d->domain);
    } else {
	/*
	 * If different, make a shadow. Check if the PDBR is valid
	 * first.
	 */
	VMX_DBG_LOG(DBG_LEVEL_VMMU, "CR3 c->cr3 = %x", c->cr3);
	if ((c->cr3 >> PAGE_SHIFT) > d->domain->max_pages) {
	    printk("Invalid CR3 value=%x", c->cr3);
	    domain_crash_synchronous(); 
	    return 0;
	}
	mfn = phys_to_machine_mapping(c->cr3 >> PAGE_SHIFT);
	d->arch.guest_table = mk_pagetable(mfn << PAGE_SHIFT);
	update_pagetables(d);
	/* 
	 * arch.shadow_table should now hold the next CR3 for shadow
	 */
	d->arch.arch_vmx.cpu_cr3 = c->cr3;
	VMX_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %x", c->cr3);
	__vmwrite(GUEST_CR3, pagetable_get_paddr(d->arch.shadow_table));
    }

skip_cr3:

    error |= __vmread(CR4_READ_SHADOW, &old_cr4);
    error |= __vmwrite(GUEST_CR4, (c->cr4 | X86_CR4_VMXE));
    error |= __vmwrite(CR4_READ_SHADOW, c->cr4);

    error |= __vmwrite(GUEST_IDTR_LIMIT, c->idtr_limit);
    error |= __vmwrite(GUEST_IDTR_BASE, c->idtr_base);

    error |= __vmwrite(GUEST_GDTR_LIMIT, c->gdtr_limit);
    error |= __vmwrite(GUEST_GDTR_BASE, c->gdtr_base);

    error |= __vmwrite(GUEST_CS_SELECTOR, c->cs_sel);
    error |= __vmwrite(GUEST_CS_LIMIT, c->cs_limit);
    error |= __vmwrite(GUEST_CS_BASE, c->cs_base);
    error |= __vmwrite(GUEST_CS_AR_BYTES, c->cs_arbytes.bytes);

    error |= __vmwrite(GUEST_DS_SELECTOR, c->ds_sel);
    error |= __vmwrite(GUEST_DS_LIMIT, c->ds_limit);
    error |= __vmwrite(GUEST_DS_BASE, c->ds_base);
    error |= __vmwrite(GUEST_DS_AR_BYTES, c->ds_arbytes.bytes);

    error |= __vmwrite(GUEST_ES_SELECTOR, c->es_sel);
    error |= __vmwrite(GUEST_ES_LIMIT, c->es_limit);
    error |= __vmwrite(GUEST_ES_BASE, c->es_base);
    error |= __vmwrite(GUEST_ES_AR_BYTES, c->es_arbytes.bytes);

    error |= __vmwrite(GUEST_SS_SELECTOR, c->ss_sel);
    error |= __vmwrite(GUEST_SS_LIMIT, c->ss_limit);
    error |= __vmwrite(GUEST_SS_BASE, c->ss_base);
    error |= __vmwrite(GUEST_SS_AR_BYTES, c->ss_arbytes.bytes);

    error |= __vmwrite(GUEST_FS_SELECTOR, c->fs_sel);
    error |= __vmwrite(GUEST_FS_LIMIT, c->fs_limit);
    error |= __vmwrite(GUEST_FS_BASE, c->fs_base);
    error |= __vmwrite(GUEST_FS_AR_BYTES, c->fs_arbytes.bytes);

    error |= __vmwrite(GUEST_GS_SELECTOR, c->gs_sel);
    error |= __vmwrite(GUEST_GS_LIMIT, c->gs_limit);
    error |= __vmwrite(GUEST_GS_BASE, c->gs_base);
    error |= __vmwrite(GUEST_GS_AR_BYTES, c->gs_arbytes.bytes);

    error |= __vmwrite(GUEST_TR_SELECTOR, c->tr_sel);
    error |= __vmwrite(GUEST_TR_LIMIT, c->tr_limit);
    error |= __vmwrite(GUEST_TR_BASE, c->tr_base);
    error |= __vmwrite(GUEST_TR_AR_BYTES, c->tr_arbytes.bytes);

    error |= __vmwrite(GUEST_LDTR_SELECTOR, c->ldtr_sel);
    error |= __vmwrite(GUEST_LDTR_LIMIT, c->ldtr_limit);
    error |= __vmwrite(GUEST_LDTR_BASE, c->ldtr_base);
    error |= __vmwrite(GUEST_LDTR_AR_BYTES, c->ldtr_arbytes.bytes);

    return !error;
}

enum { VMX_ASSIST_INVOKE = 0, VMX_ASSIST_RESTORE };

int
vmx_assist(struct vcpu *d, int mode)
{
    struct vmx_assist_context c;
    u32 magic;
    unsigned long cp;

    /* make sure vmxassist exists (this is not an error) */
    if (!vmx_copy(&magic, VMXASSIST_MAGIC_OFFSET, sizeof(magic), COPY_IN))
    	return 0;
    if (magic != VMXASSIST_MAGIC)
    	return 0;

    switch (mode) {
    /*
     * Transfer control to vmxassist.
     * Store the current context in VMXASSIST_OLD_CONTEXT and load
     * the new VMXASSIST_NEW_CONTEXT context. This context was created
     * by vmxassist and will transfer control to it.
     */
    case VMX_ASSIST_INVOKE:
	/* save the old context */
	if (!vmx_copy(&cp, VMXASSIST_OLD_CONTEXT, sizeof(cp), COPY_IN))
    	    goto error;
	if (cp != 0) {
    	    if (!vmx_world_save(d, &c))
		goto error;
	    if (!vmx_copy(&c, cp, sizeof(c), COPY_OUT))
		goto error;
	}

	/* restore the new context, this should activate vmxassist */
	if (!vmx_copy(&cp, VMXASSIST_NEW_CONTEXT, sizeof(cp), COPY_IN))
	    goto error;
	if (cp != 0) {
            if (!vmx_copy(&c, cp, sizeof(c), COPY_IN))
		goto error;
    	    if (!vmx_world_restore(d, &c))
		goto error;
    	    return 1;
	}
	break;

    /*
     * Restore the VMXASSIST_OLD_CONTEXT that was saved by VMX_ASSIST_INVOKE
     * above.
     */
    case VMX_ASSIST_RESTORE:
	/* save the old context */
	if (!vmx_copy(&cp, VMXASSIST_OLD_CONTEXT, sizeof(cp), COPY_IN))
    	    goto error;
	if (cp != 0) {
            if (!vmx_copy(&c, cp, sizeof(c), COPY_IN))
		goto error;
    	    if (!vmx_world_restore(d, &c))
		goto error;
	    return 1;
	}
	break;
    }

error:
    printf("Failed to transfer to vmxassist\n");
    domain_crash_synchronous(); 
    return 0;
}

static int vmx_set_cr0(unsigned long value)
{
    struct vcpu *d = current;
    unsigned long mfn;
    unsigned long eip;
    int paging_enabled;
    unsigned long vm_entry_value;
    /* 
     * CR0: We don't want to lose PE and PG.
     */
    paging_enabled = vmx_paging_enabled(d);
    __vmwrite(GUEST_CR0, (value | X86_CR0_PE | X86_CR0_PG));
    __vmwrite(CR0_READ_SHADOW, value);

    VMX_DBG_LOG(DBG_LEVEL_VMMU, "Update CR0 value = %lx\n", value);

    if ((value & X86_CR0_PE) && (value & X86_CR0_PG) && !paging_enabled) {
        /*
         * The guest CR3 must be pointing to the guest physical.
         */
        if ( !VALID_MFN(mfn = phys_to_machine_mapping(
                            d->arch.arch_vmx.cpu_cr3 >> PAGE_SHIFT)) ||
             !get_page(pfn_to_page(mfn), d->domain) )
        {
            printk("Invalid CR3 value = %lx", d->arch.arch_vmx.cpu_cr3);
            domain_crash_synchronous(); /* need to take a clean path */
        }

#if defined(__x86_64__)
        if (test_bit(VMX_CPU_STATE_LME_ENABLED,
              &d->arch.arch_vmx.cpu_state) &&
          !test_bit(VMX_CPU_STATE_PAE_ENABLED,
              &d->arch.arch_vmx.cpu_state)){
            VMX_DBG_LOG(DBG_LEVEL_1, "Enable paging before PAE enable\n");
            vmx_inject_exception(d, TRAP_gp_fault, 0);
        }
        if (test_bit(VMX_CPU_STATE_LME_ENABLED,
              &d->arch.arch_vmx.cpu_state)){
            /* Here the PAE is should to be opened */
            VMX_DBG_LOG(DBG_LEVEL_1, "Enable the Long mode\n");
            set_bit(VMX_CPU_STATE_LMA_ENABLED,
              &d->arch.arch_vmx.cpu_state);
            __vmread(VM_ENTRY_CONTROLS, &vm_entry_value);
            vm_entry_value |= VM_ENTRY_CONTROLS_IA_32E_MODE;
            __vmwrite(VM_ENTRY_CONTROLS, vm_entry_value);

        }

	unsigned long crn;
        /* update CR4's PAE if needed */
        __vmread(GUEST_CR4, &crn);
        if ( (!(crn & X86_CR4_PAE)) &&
          test_bit(VMX_CPU_STATE_PAE_ENABLED,
              &d->arch.arch_vmx.cpu_state)){
            VMX_DBG_LOG(DBG_LEVEL_1, "enable PAE on cr4\n");
            __vmwrite(GUEST_CR4, crn | X86_CR4_PAE);
        }
#elif defined( __i386__)
       	unsigned long old_base_mfn;
        old_base_mfn = pagetable_get_pfn(d->arch.guest_table);
        if (old_base_mfn)
            put_page(pfn_to_page(old_base_mfn));
#endif
        /*
         * Now arch.guest_table points to machine physical.
         */
        d->arch.guest_table = mk_pagetable(mfn << PAGE_SHIFT);
        update_pagetables(d);

        VMX_DBG_LOG(DBG_LEVEL_VMMU, "New arch.guest_table = %lx", 
                (unsigned long) (mfn << PAGE_SHIFT));

        __vmwrite(GUEST_CR3, pagetable_get_paddr(d->arch.shadow_table));
        /* 
         * arch->shadow_table should hold the next CR3 for shadow
         */
        VMX_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx, mfn = %lx", 
                d->arch.arch_vmx.cpu_cr3, mfn);
    }

    /*
     * VMX does not implement real-mode virtualization. We emulate
     * real-mode by performing a world switch to VMXAssist whenever
     * a partition disables the CR0.PE bit.
     */
    if ((value & X86_CR0_PE) == 0) {
        if ( value & X86_CR0_PG ) {
            /* inject GP here */
            vmx_inject_exception(d, TRAP_gp_fault, 0);
            return 0;
        } else {
            /* 
             * Disable paging here.
             * Same to PE == 1 && PG == 0
             */
            if (test_bit(VMX_CPU_STATE_LMA_ENABLED,
                         &d->arch.arch_vmx.cpu_state)){
                clear_bit(VMX_CPU_STATE_LMA_ENABLED,
                          &d->arch.arch_vmx.cpu_state);
                __vmread(VM_ENTRY_CONTROLS, &vm_entry_value);
                vm_entry_value &= ~VM_ENTRY_CONTROLS_IA_32E_MODE;
                __vmwrite(VM_ENTRY_CONTROLS, vm_entry_value);
            }
        }
	__vmread(GUEST_RIP, &eip);
	VMX_DBG_LOG(DBG_LEVEL_1,
	    "Disabling CR0.PE at %%eip 0x%lx\n", eip);
	if (vmx_assist(d, VMX_ASSIST_INVOKE)) {
	    set_bit(VMX_CPU_STATE_ASSIST_ENABLED, &d->arch.arch_vmx.cpu_state);
	    __vmread(GUEST_RIP, &eip);
	    VMX_DBG_LOG(DBG_LEVEL_1,
		"Transfering control to vmxassist %%eip 0x%lx\n", eip);
	    return 0; /* do not update eip! */
	}
    } else if (test_bit(VMX_CPU_STATE_ASSIST_ENABLED,
					&d->arch.arch_vmx.cpu_state)) {
	__vmread(GUEST_RIP, &eip);
	VMX_DBG_LOG(DBG_LEVEL_1,
	    "Enabling CR0.PE at %%eip 0x%lx\n", eip);
	if (vmx_assist(d, VMX_ASSIST_RESTORE)) {
	    clear_bit(VMX_CPU_STATE_ASSIST_ENABLED,
					&d->arch.arch_vmx.cpu_state);
	    __vmread(GUEST_RIP, &eip);
	    VMX_DBG_LOG(DBG_LEVEL_1,
		"Restoring to %%eip 0x%lx\n", eip);
	    return 0; /* do not update eip! */
	}
    }

    return 1;
}

#define CASE_GET_REG(REG, reg)  \
    case REG_ ## REG: value = regs->reg; break

#define CASE_EXTEND_SET_REG \
      CASE_EXTEND_REG(S)
#define CASE_EXTEND_GET_REG \
      CASE_EXTEND_REG(G)

#ifdef __i386__
#define CASE_EXTEND_REG(T)
#else
#define CASE_EXTEND_REG(T)    \
    CASE_ ## T ## ET_REG(R8, r8); \
    CASE_ ## T ## ET_REG(R9, r9); \
    CASE_ ## T ## ET_REG(R10, r10); \
    CASE_ ## T ## ET_REG(R11, r11); \
    CASE_ ## T ## ET_REG(R12, r12); \
    CASE_ ## T ## ET_REG(R13, r13); \
    CASE_ ## T ## ET_REG(R14, r14); \
    CASE_ ## T ## ET_REG(R15, r15);
#endif


/*
 * Write to control registers
 */
static int mov_to_cr(int gp, int cr, struct cpu_user_regs *regs)
{
    unsigned long value;
    unsigned long old_cr;
    struct vcpu *d = current;

    switch (gp) {
        CASE_GET_REG(EAX, eax);
        CASE_GET_REG(ECX, ecx);
        CASE_GET_REG(EDX, edx);
        CASE_GET_REG(EBX, ebx);
        CASE_GET_REG(EBP, ebp);
        CASE_GET_REG(ESI, esi);
        CASE_GET_REG(EDI, edi);
        CASE_EXTEND_GET_REG
    case REG_ESP:
        __vmread(GUEST_RSP, &value);
        break;
    default:
        printk("invalid gp: %d\n", gp);
        __vmx_bug(regs);
    }
    
    VMX_DBG_LOG(DBG_LEVEL_1, "mov_to_cr: CR%d, value = %lx,", cr, value);
    VMX_DBG_LOG(DBG_LEVEL_1, "current = %lx,", (unsigned long) current);

    switch(cr) {
    case 0: 
    {
	return vmx_set_cr0(value);
    }
    case 3: 
    {
        unsigned long old_base_mfn, mfn;

        /*
         * If paging is not enabled yet, simply copy the value to CR3.
         */
        if (!vmx_paging_enabled(d)) {
            d->arch.arch_vmx.cpu_cr3 = value;
            break;
        }
        
        /*
         * We make a new one if the shadow does not exist.
         */
        if (value == d->arch.arch_vmx.cpu_cr3) {
            /* 
             * This is simple TLB flush, implying the guest has 
             * removed some translation or changed page attributes.
             * We simply invalidate the shadow.
             */
            mfn = phys_to_machine_mapping(value >> PAGE_SHIFT);
            if (mfn != pagetable_get_pfn(d->arch.guest_table))
                __vmx_bug(regs);
            shadow_sync_all(d->domain);
        } else {
            /*
             * If different, make a shadow. Check if the PDBR is valid
             * first.
             */
            VMX_DBG_LOG(DBG_LEVEL_VMMU, "CR3 value = %lx", value);
            if ( ((value >> PAGE_SHIFT) > d->domain->max_pages ) ||
                 !VALID_MFN(mfn = phys_to_machine_mapping(value >> PAGE_SHIFT)) ||
                 !get_page(pfn_to_page(mfn), d->domain) )
            {
                printk("Invalid CR3 value=%lx", value);
                domain_crash_synchronous(); /* need to take a clean path */
            }
            old_base_mfn = pagetable_get_pfn(d->arch.guest_table);
            d->arch.guest_table = mk_pagetable(mfn << PAGE_SHIFT);
            if (old_base_mfn)
                put_page(pfn_to_page(old_base_mfn));
            update_pagetables(d);
            /* 
             * arch.shadow_table should now hold the next CR3 for shadow
             */
            d->arch.arch_vmx.cpu_cr3 = value;
            VMX_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx",
                    value);
            __vmwrite(GUEST_CR3, pagetable_get_paddr(d->arch.shadow_table));
        }
        break;
    }
    case 4:         
    {
        /* CR4 */
        unsigned long old_guest_cr;
        unsigned long pae_disabled = 0;

        __vmread(GUEST_CR4, &old_guest_cr);
        if (value & X86_CR4_PAE){
            set_bit(VMX_CPU_STATE_PAE_ENABLED, &d->arch.arch_vmx.cpu_state);
            if(!vmx_paging_enabled(d))
                pae_disabled = 1;
        } else {
            if (test_bit(VMX_CPU_STATE_LMA_ENABLED,
                         &d->arch.arch_vmx.cpu_state)){
                vmx_inject_exception(d, TRAP_gp_fault, 0);
            }
            clear_bit(VMX_CPU_STATE_PAE_ENABLED, &d->arch.arch_vmx.cpu_state);
        }

        __vmread(CR4_READ_SHADOW, &old_cr);
        if (pae_disabled)
            __vmwrite(GUEST_CR4, ((value & ~X86_CR4_PAE) | X86_CR4_VMXE));
        else
            __vmwrite(GUEST_CR4, value| X86_CR4_VMXE);

        __vmwrite(CR4_READ_SHADOW, value);

        /*
         * Writing to CR4 to modify the PSE, PGE, or PAE flag invalidates
         * all TLB entries except global entries.
         */
        if ((old_cr ^ value) & (X86_CR4_PSE | X86_CR4_PGE | X86_CR4_PAE)) {
            shadow_sync_all(d->domain);
        }
        break;
    }
    default:
        printk("invalid cr: %d\n", gp);
        __vmx_bug(regs);
    }

    return 1;
}

#define CASE_SET_REG(REG, reg)      \
    case REG_ ## REG:       \
    regs->reg = value;      \
    break

/*
 * Read from control registers. CR0 and CR4 are read from the shadow.
 */
static void mov_from_cr(int cr, int gp, struct cpu_user_regs *regs)
{
    unsigned long value;
    struct vcpu *d = current;

    if (cr != 3)
        __vmx_bug(regs);

    value = (unsigned long) d->arch.arch_vmx.cpu_cr3;

    switch (gp) {
        CASE_SET_REG(EAX, eax);
        CASE_SET_REG(ECX, ecx);
        CASE_SET_REG(EDX, edx);
        CASE_SET_REG(EBX, ebx);
        CASE_SET_REG(EBP, ebp);
        CASE_SET_REG(ESI, esi);
        CASE_SET_REG(EDI, edi);
    case REG_ESP:
        __vmwrite(GUEST_RSP, value);
        regs->esp = value;
        break;
    default:
        printk("invalid gp: %d\n", gp);
        __vmx_bug(regs);
    }

    VMX_DBG_LOG(DBG_LEVEL_VMMU, "mov_from_cr: CR%d, value = %lx,", cr, value);
}

static int vmx_cr_access(unsigned long exit_qualification, struct cpu_user_regs *regs)
{
    unsigned int gp, cr;
    unsigned long value;

    switch (exit_qualification & CONTROL_REG_ACCESS_TYPE) {
    case TYPE_MOV_TO_CR:
        gp = exit_qualification & CONTROL_REG_ACCESS_REG;
        cr = exit_qualification & CONTROL_REG_ACCESS_NUM;
        return mov_to_cr(gp, cr, regs);
    case TYPE_MOV_FROM_CR:
        gp = exit_qualification & CONTROL_REG_ACCESS_REG;
        cr = exit_qualification & CONTROL_REG_ACCESS_NUM;
        mov_from_cr(cr, gp, regs);
        break;
    case TYPE_CLTS:
        clts();
        setup_fpu(current);

        __vmread(GUEST_CR0, &value);
        value &= ~X86_CR0_TS; /* clear TS */
        __vmwrite(GUEST_CR0, value);

        __vmread(CR0_READ_SHADOW, &value);
        value &= ~X86_CR0_TS; /* clear TS */
        __vmwrite(CR0_READ_SHADOW, value);
        break;
    case TYPE_LMSW:
        __vmread(CR0_READ_SHADOW, &value);
	value = (value & ~0xF) |
		(((exit_qualification & LMSW_SOURCE_DATA) >> 16) & 0xF);
	return vmx_set_cr0(value);
        break;
    default:
        __vmx_bug(regs);
        break;
    }
    return 1;
}

static inline void vmx_do_msr_read(struct cpu_user_regs *regs)
{
    VMX_DBG_LOG(DBG_LEVEL_1, "vmx_do_msr_read: ecx=%lx, eax=%lx, edx=%lx",
                (unsigned long)regs->ecx, (unsigned long)regs->eax, 
                (unsigned long)regs->edx);
    switch (regs->ecx) {
        case MSR_IA32_SYSENTER_CS:
            __vmread(GUEST_SYSENTER_CS, &regs->eax);
            regs->edx = 0;
            break;
        case MSR_IA32_SYSENTER_ESP:	
             __vmread(GUEST_SYSENTER_ESP, &regs->eax);
             regs->edx = 0;
            break;
        case MSR_IA32_SYSENTER_EIP:		
            __vmread(GUEST_SYSENTER_EIP, &regs->eax);
            regs->edx = 0;
            break;
        default:
            if(long_mode_do_msr_read(regs))
                return;
            rdmsr_user(regs->ecx, regs->eax, regs->edx);
            break;
    }

    VMX_DBG_LOG(DBG_LEVEL_1, "vmx_do_msr_read returns: "
                "ecx=%lx, eax=%lx, edx=%lx",
                (unsigned long)regs->ecx, (unsigned long)regs->eax,
                (unsigned long)regs->edx);
}

static inline void vmx_do_msr_write(struct cpu_user_regs *regs)
{
    VMX_DBG_LOG(DBG_LEVEL_1, "vmx_do_msr_write: ecx=%lx, eax=%lx, edx=%lx",
                (unsigned long)regs->ecx, (unsigned long)regs->eax, 
                (unsigned long)regs->edx);
    switch (regs->ecx) {
        case MSR_IA32_SYSENTER_CS:
            __vmwrite(GUEST_SYSENTER_CS, regs->eax);
            break;
        case MSR_IA32_SYSENTER_ESP:	
             __vmwrite(GUEST_SYSENTER_ESP, regs->eax);
            break;
        case MSR_IA32_SYSENTER_EIP:		
            __vmwrite(GUEST_SYSENTER_EIP, regs->eax);
            break;
        default:
            long_mode_do_msr_write(regs);
            break;
    }

    VMX_DBG_LOG(DBG_LEVEL_1, "vmx_do_msr_write returns: "
                "ecx=%lx, eax=%lx, edx=%lx",
                (unsigned long)regs->ecx, (unsigned long)regs->eax,
                (unsigned long)regs->edx);
}

/*
 * Need to use this exit to reschedule
 */
static inline void vmx_vmexit_do_hlt(void)
{
#if VMX_DEBUG
    unsigned long eip;
    __vmread(GUEST_RIP, &eip);
#endif
    VMX_DBG_LOG(DBG_LEVEL_1, "vmx_vmexit_do_hlt:eip=%lx", eip);
    raise_softirq(SCHEDULE_SOFTIRQ);
}

static inline void vmx_vmexit_do_mwait(void)
{
#if VMX_DEBUG
    unsigned long eip;
    __vmread(GUEST_RIP, &eip);
#endif
    VMX_DBG_LOG(DBG_LEVEL_1, "vmx_vmexit_do_mwait:eip=%lx", eip);
    raise_softirq(SCHEDULE_SOFTIRQ);
}

#define BUF_SIZ     256
#define MAX_LINE    80
char print_buf[BUF_SIZ];
static int index;

static void vmx_print_line(const char c, struct vcpu *d) 
{

    if (index == MAX_LINE || c == '\n') {
        if (index == MAX_LINE) {
            print_buf[index++] = c;
        }
        print_buf[index] = '\0';
        printk("(GUEST: %u) %s\n", d->domain->domain_id, (char *) &print_buf);
        index = 0;
    }
    else
        print_buf[index++] = c;
}

void save_vmx_cpu_user_regs(struct cpu_user_regs *ctxt)
{
    __vmread(GUEST_SS_SELECTOR, &ctxt->ss);
    __vmread(GUEST_RSP, &ctxt->esp);
    __vmread(GUEST_RFLAGS, &ctxt->eflags);
    __vmread(GUEST_CS_SELECTOR, &ctxt->cs);
    __vmread(GUEST_RIP, &ctxt->eip);

    __vmread(GUEST_GS_SELECTOR, &ctxt->gs);
    __vmread(GUEST_FS_SELECTOR, &ctxt->fs);
    __vmread(GUEST_ES_SELECTOR, &ctxt->es);
    __vmread(GUEST_DS_SELECTOR, &ctxt->ds);
}

#ifdef XEN_DEBUGGER
void save_cpu_user_regs(struct cpu_user_regs *regs)
{
    __vmread(GUEST_SS_SELECTOR, &regs->xss);
    __vmread(GUEST_RSP, &regs->esp);
    __vmread(GUEST_RFLAGS, &regs->eflags);
    __vmread(GUEST_CS_SELECTOR, &regs->xcs);
    __vmread(GUEST_RIP, &regs->eip);

    __vmread(GUEST_GS_SELECTOR, &regs->xgs);
    __vmread(GUEST_FS_SELECTOR, &regs->xfs);
    __vmread(GUEST_ES_SELECTOR, &regs->xes);
    __vmread(GUEST_DS_SELECTOR, &regs->xds);
}

void restore_cpu_user_regs(struct cpu_user_regs *regs)
{
    __vmwrite(GUEST_SS_SELECTOR, regs->xss);
    __vmwrite(GUEST_RSP, regs->esp);
    __vmwrite(GUEST_RFLAGS, regs->eflags);
    __vmwrite(GUEST_CS_SELECTOR, regs->xcs);
    __vmwrite(GUEST_RIP, regs->eip);

    __vmwrite(GUEST_GS_SELECTOR, regs->xgs);
    __vmwrite(GUEST_FS_SELECTOR, regs->xfs);
    __vmwrite(GUEST_ES_SELECTOR, regs->xes);
    __vmwrite(GUEST_DS_SELECTOR, regs->xds);
}
#endif

asmlinkage void vmx_vmexit_handler(struct cpu_user_regs regs)
{
    unsigned int exit_reason, idtv_info_field;
    unsigned long exit_qualification, eip, inst_len = 0;
    struct vcpu *v = current;
    int error;

    if ((error = __vmread(VM_EXIT_REASON, &exit_reason)))
        __vmx_bug(&regs);
    
    perfc_incra(vmexits, exit_reason);

    __vmread(IDT_VECTORING_INFO_FIELD, &idtv_info_field);
    if (idtv_info_field & INTR_INFO_VALID_MASK) {
	if ((idtv_info_field & 0x0700) != 0x400) { /* exclude soft ints */
            __vmwrite(VM_ENTRY_INTR_INFO_FIELD, idtv_info_field);

	    if (idtv_info_field & 0x800) { /* valid error code */
		unsigned long error_code;
		printk("VMX exit %x: %x/%lx\n",
			exit_reason, idtv_info_field, error_code);
		__vmread(VM_EXIT_INTR_ERROR_CODE, &error_code);
		__vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
	    } else
	    	printk("VMX exit %x: %x\n", exit_reason, idtv_info_field);
	}
        VMX_DBG_LOG(DBG_LEVEL_1, "idtv_info_field=%x", idtv_info_field);
    }

    /* don't bother H/W interrutps */
    if (exit_reason != EXIT_REASON_EXTERNAL_INTERRUPT &&
        exit_reason != EXIT_REASON_VMCALL &&
        exit_reason != EXIT_REASON_IO_INSTRUCTION)
        VMX_DBG_LOG(DBG_LEVEL_0, "exit reason = %x", exit_reason);

    if (exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY) {
        printk("Failed vm entry\n");
        domain_crash_synchronous();         
        return;
    }

    __vmread(GUEST_RIP, &eip);
    TRACE_3D(TRC_VMX_VMEXIT, v->domain->domain_id, eip, exit_reason);

    switch (exit_reason) {
    case EXIT_REASON_EXCEPTION_NMI:
    {
        /*
         * We don't set the software-interrupt exiting (INT n). 
         * (1) We can get an exception (e.g. #PG) in the guest, or
         * (2) NMI
         */
        int error;
        unsigned int vector;
        unsigned long va;

        if ((error = __vmread(VM_EXIT_INTR_INFO, &vector))
            || !(vector & INTR_INFO_VALID_MASK))
            __vmx_bug(&regs);
        vector &= 0xff;

        perfc_incra(cause_vector, vector);

        TRACE_3D(TRC_VMX_VECTOR, v->domain->domain_id, eip, vector);
        switch (vector) {
#ifdef XEN_DEBUGGER
        case TRAP_debug:
        {
            save_cpu_user_regs(&regs);
            pdb_handle_exception(1, &regs, 1);
            restore_cpu_user_regs(&regs);
            break;
        }
        case TRAP_int3:
        {
            save_cpu_user_regs(&regs);
            pdb_handle_exception(3, &regs, 1);
            restore_cpu_user_regs(&regs);
            break;
        }
#else
        case TRAP_debug:
        {
            void store_cpu_user_regs(struct cpu_user_regs *regs);
            long do_sched_op(unsigned long op);


            store_cpu_user_regs(&regs);
            __vm_clear_bit(GUEST_PENDING_DBG_EXCEPTIONS, PENDING_DEBUG_EXC_BS);

            set_bit(_VCPUF_ctrl_pause, &current->vcpu_flags);
            do_sched_op(SCHEDOP_yield);

            break;
        }
#endif
        case TRAP_no_device:
        {
            vmx_do_no_device_fault();
            break;  
        }
        case TRAP_page_fault:
        {
            __vmread(EXIT_QUALIFICATION, &va);
            __vmread(VM_EXIT_INTR_ERROR_CODE, &regs.error_code);
            VMX_DBG_LOG(DBG_LEVEL_VMMU, 
                        "eax=%lx, ebx=%lx, ecx=%lx, edx=%lx, esi=%lx, edi=%lx",
                        (unsigned long)regs.eax, (unsigned long)regs.ebx,
                        (unsigned long)regs.ecx, (unsigned long)regs.edx,
                        (unsigned long)regs.esi, (unsigned long)regs.edi);
            v->domain->arch.vmx_platform.mpci.inst_decoder_regs = &regs;

            if (!(error = vmx_do_page_fault(va, &regs))) {
                /*
                 * Inject #PG using Interruption-Information Fields
                 */
                vmx_inject_exception(v, TRAP_page_fault, regs.error_code);
                v->arch.arch_vmx.cpu_cr2 = va;
                TRACE_3D(TRC_VMX_INT, v->domain->domain_id, TRAP_page_fault, va);
            }
            break;
        }
        case TRAP_nmi:
            do_nmi(&regs, 0);
            break;
        default:
            vmx_reflect_exception(v);
            break;
        }
        break;
    }
    case EXIT_REASON_EXTERNAL_INTERRUPT: 
    {
        extern asmlinkage void do_IRQ(struct cpu_user_regs *);
        extern void smp_apic_timer_interrupt(struct cpu_user_regs *);
        extern void timer_interrupt(int, void *, struct cpu_user_regs *);
        unsigned int    vector;

        if ((error = __vmread(VM_EXIT_INTR_INFO, &vector))
            && !(vector & INTR_INFO_VALID_MASK))
            __vmx_bug(&regs);

        vector &= 0xff;
        local_irq_disable();

        if (vector == LOCAL_TIMER_VECTOR) {
            smp_apic_timer_interrupt(&regs);
        } else {
            regs.entry_vector = vector;
            do_IRQ(&regs);
        }
        break;
    }
    case EXIT_REASON_PENDING_INTERRUPT:
        __vmwrite(CPU_BASED_VM_EXEC_CONTROL, 
              MONITOR_CPU_BASED_EXEC_CONTROLS);
        break;
    case EXIT_REASON_TASK_SWITCH:
        __vmx_bug(&regs);
        break;
    case EXIT_REASON_CPUID:
        __get_instruction_length(inst_len);
        vmx_vmexit_do_cpuid(regs.eax, &regs);
        __update_guest_eip(inst_len);
        break;
    case EXIT_REASON_HLT:
        __get_instruction_length(inst_len);
        __update_guest_eip(inst_len);
        vmx_vmexit_do_hlt();
        break;
    case EXIT_REASON_INVLPG:
    {
        unsigned long   va;

        __vmread(EXIT_QUALIFICATION, &va);
        vmx_vmexit_do_invlpg(va);
        __get_instruction_length(inst_len);
        __update_guest_eip(inst_len);
        break;
    }
    case EXIT_REASON_VMCALL:
        __get_instruction_length(inst_len);
        __vmread(GUEST_RIP, &eip);
        __vmread(EXIT_QUALIFICATION, &exit_qualification);

        vmx_print_line(regs.eax, v); /* provides the current domain */
        __update_guest_eip(inst_len);
        break;
    case EXIT_REASON_CR_ACCESS:
    {
        __vmread(GUEST_RIP, &eip);
        __get_instruction_length(inst_len);
        __vmread(EXIT_QUALIFICATION, &exit_qualification);

        VMX_DBG_LOG(DBG_LEVEL_1, "eip = %lx, inst_len =%lx, exit_qualification = %lx", 
                eip, inst_len, exit_qualification);
        if (vmx_cr_access(exit_qualification, &regs))
	    __update_guest_eip(inst_len);
        break;
    }
    case EXIT_REASON_DR_ACCESS:
        __vmread(EXIT_QUALIFICATION, &exit_qualification);  
        vmx_dr_access(exit_qualification, &regs);
        __get_instruction_length(inst_len);
        __update_guest_eip(inst_len);
        break;
    case EXIT_REASON_IO_INSTRUCTION:
        __vmread(EXIT_QUALIFICATION, &exit_qualification);
        __get_instruction_length(inst_len);
        vmx_io_instruction(&regs, exit_qualification, inst_len);
        break;
    case EXIT_REASON_MSR_READ:
        __get_instruction_length(inst_len);
        vmx_do_msr_read(&regs);
        __update_guest_eip(inst_len);
        break;
    case EXIT_REASON_MSR_WRITE:
        __vmread(GUEST_RIP, &eip);
        vmx_do_msr_write(&regs);
        __get_instruction_length(inst_len);
        __update_guest_eip(inst_len);
        break;
    case EXIT_REASON_MWAIT_INSTRUCTION:
        __get_instruction_length(inst_len);
        __update_guest_eip(inst_len);
        vmx_vmexit_do_mwait();
        break;
    default:
        __vmx_bug(&regs);       /* should not happen */
    }

    vmx_intr_assist(v);
    return;
}

asmlinkage void load_cr2(void)
{
    struct vcpu *d = current;

    local_irq_disable();        
#ifdef __i386__
    asm volatile("movl %0,%%cr2": :"r" (d->arch.arch_vmx.cpu_cr2));
#else
    asm volatile("movq %0,%%cr2": :"r" (d->arch.arch_vmx.cpu_cr2));
#endif
}

#endif /* CONFIG_VMX */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
