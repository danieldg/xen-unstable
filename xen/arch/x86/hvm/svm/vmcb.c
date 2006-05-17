/*
 * vmcb.c: VMCB management
 * Copyright (c) 2005, AMD Corporation.
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
#include <xen/mm.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/shadow.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>
#include <asm/hvm/svm/svm.h>
#include <asm/hvm/svm/intr.h>
#include <xen/event.h>
#include <xen/kernel.h>
#include <xen/domain_page.h>

extern struct host_save_area *host_save_area[];
extern int svm_dbg_on;
extern int asidpool_assign_next( struct vmcb_struct *vmcb, int retire_current,
                                  int oldcore, int newcore);
extern void set_hsa_to_guest( struct arch_svm_struct *arch_svm );

#define round_pgdown(_p) ((_p)&PAGE_MASK) /* coped from domain.c */

#define GUEST_SEGMENT_LIMIT 0xffffffff

#define IOPM_SIZE   (12 * 1024)
#define MSRPM_SIZE  (8  * 1024)

struct vmcb_struct *alloc_vmcb(void) 
{
    struct vmcb_struct *vmcb = NULL;
    unsigned int order;
    order = get_order_from_bytes(sizeof(struct vmcb_struct)); 
    ASSERT(order >= 0);
    vmcb = alloc_xenheap_pages(order);
    ASSERT(vmcb);

    if (vmcb)
        memset(vmcb, 0, sizeof(struct vmcb_struct));

    return vmcb;
}


void free_vmcb(struct vmcb_struct *vmcb)
{
    unsigned int order;

    order = get_order_from_bytes(sizeof(struct vmcb_struct));
    ASSERT(vmcb);

    if (vmcb)
        free_xenheap_pages(vmcb, order);
}


struct host_save_area *alloc_host_save_area(void)
{
    unsigned int order = 0;
    struct host_save_area *hsa = NULL;

    hsa = alloc_xenheap_pages(order);
    ASSERT(hsa);

    if (hsa)
        memset(hsa, 0, PAGE_SIZE);

    return hsa;
}


void free_host_save_area(struct host_save_area *hsa)
{
    unsigned int order;

    order = get_order_from_bytes(PAGE_SIZE);
    ASSERT(hsa);

    if (hsa)
        free_xenheap_pages(hsa, order);
}


/* Set up intercepts to exit the guest into the hypervisor when we want it. */
static int construct_vmcb_controls(struct arch_svm_struct *arch_svm)
{
    struct vmcb_struct *vmcb;
    u32 *iopm;
    u32 *msrpm;

    vmcb = arch_svm->vmcb;

    ASSERT(vmcb);

    /* mask off all general 1 intercepts except those listed here */
    vmcb->general1_intercepts = 
        GENERAL1_INTERCEPT_INTR         | GENERAL1_INTERCEPT_NMI         |
        GENERAL1_INTERCEPT_SMI          | GENERAL1_INTERCEPT_INIT        |
        GENERAL1_INTERCEPT_CPUID        | GENERAL1_INTERCEPT_INVD        |
        GENERAL1_INTERCEPT_HLT          | GENERAL1_INTERCEPT_INVLPG      | 
        GENERAL1_INTERCEPT_INVLPGA      | GENERAL1_INTERCEPT_IOIO_PROT   |
        GENERAL1_INTERCEPT_MSR_PROT     | GENERAL1_INTERCEPT_SHUTDOWN_EVT;

    /* turn on the general 2 intercepts */
    vmcb->general2_intercepts = 
        GENERAL2_INTERCEPT_VMRUN  | GENERAL2_INTERCEPT_VMMCALL | 
        GENERAL2_INTERCEPT_VMLOAD | GENERAL2_INTERCEPT_VMSAVE  |
        GENERAL2_INTERCEPT_STGI   | GENERAL2_INTERCEPT_CLGI    |
        GENERAL2_INTERCEPT_SKINIT | GENERAL2_INTERCEPT_RDTSCP;

    /* read or write all debug registers 0 - 15 */
    vmcb->dr_intercepts = 0;

    /* RD/WR all control registers 0 - 15, but not read CR2 */
    vmcb->cr_intercepts = ~(CR_INTERCEPT_CR2_READ | CR_INTERCEPT_CR2_WRITE);

    /* The following is for I/O and MSR permision map */
    iopm = alloc_xenheap_pages(get_order_from_bytes(IOPM_SIZE));

    ASSERT(iopm);
    memset(iopm, 0xff, IOPM_SIZE);
    clear_bit(PC_DEBUG_PORT, iopm);
    msrpm = alloc_xenheap_pages(get_order_from_bytes(MSRPM_SIZE));

    ASSERT(msrpm);
    memset(msrpm, 0xff, MSRPM_SIZE);

    arch_svm->iopm = iopm;
    arch_svm->msrpm = msrpm;

    vmcb->iopm_base_pa = (u64) virt_to_maddr(iopm);
    vmcb->msrpm_base_pa = (u64) virt_to_maddr(msrpm);

    return 0;
}


/*
 * Initially set the same environement as host.
 */
static int construct_init_vmcb_guest(struct arch_svm_struct *arch_svm, 
                                     struct cpu_user_regs *regs )
{
    int error = 0;
    unsigned long crn;
    segment_attributes_t attrib;
    unsigned long dr7;
    unsigned long eflags;
    unsigned long shadow_cr;
    struct vmcb_struct *vmcb = arch_svm->vmcb;

    /* Allows IRQs to be shares */
    vmcb->vintr.fields.intr_masking = 1;
  
    /* Set up event injection entry in VMCB. Just clear it. */
    vmcb->eventinj.bytes = 0;

    /* TSC */
    vmcb->tsc_offset = 0;
    
    vmcb->cs.sel = regs->cs;
    vmcb->es.sel = regs->es;
    vmcb->ss.sel = regs->ss;
    vmcb->ds.sel = regs->ds; 
    vmcb->fs.sel = regs->fs;
    vmcb->gs.sel = regs->gs;

    /* Guest segment Limits. 64K for real mode*/
    vmcb->cs.limit = GUEST_SEGMENT_LIMIT;
    vmcb->es.limit = GUEST_SEGMENT_LIMIT;
    vmcb->ss.limit = GUEST_SEGMENT_LIMIT;
    vmcb->ds.limit = GUEST_SEGMENT_LIMIT;
    vmcb->fs.limit = GUEST_SEGMENT_LIMIT;
    vmcb->gs.limit = GUEST_SEGMENT_LIMIT;

    /* Base address for segments */
    vmcb->cs.base = 0;
    vmcb->es.base = 0;
    vmcb->ss.base = 0;
    vmcb->ds.base = 0;
    vmcb->fs.base = 0;
    vmcb->gs.base = 0;

    /* Guest Interrupt descriptor table */
    vmcb->idtr.base = 0;
    vmcb->idtr.limit = 0;

    /* Set up segment attributes */
    attrib.bytes = 0;
    attrib.fields.type = 0x3; /* type = 3 */
    attrib.fields.s = 1; /* code or data, i.e. not system */
    attrib.fields.dpl = 0; /* DPL = 0 */
    attrib.fields.p = 1; /* segment present */
    attrib.fields.db = 1; /* 32-bit */
    attrib.fields.g = 1; /* 4K pages in limit */

    /* Data selectors */
    vmcb->es.attributes = attrib; 
    vmcb->ss.attributes = attrib;
    vmcb->ds.attributes = attrib;
    vmcb->fs.attributes = attrib;
    vmcb->gs.attributes = attrib;

    /* Code selector */
    attrib.fields.type = 0xb;   /* type=0xb -> executable/readable, accessed */
    vmcb->cs.attributes = attrib;

    /* Guest Global descriptor table */
    vmcb->gdtr.base = 0;
    vmcb->gdtr.limit = 0;

    /* Guest Local Descriptor Table */
    attrib.fields.s = 0; /* not code or data segement */
    attrib.fields.type = 0x2; /* LDT */
    attrib.fields.db = 0; /* 16-bit */
    attrib.fields.g = 0;   
    vmcb->ldtr.attributes = attrib;

    attrib.fields.type = 0xb; /* 32-bit TSS (busy) */
    vmcb->tr.attributes = attrib;
    vmcb->tr.base = 0;
    vmcb->tr.limit = 0xff;

    __asm__ __volatile__ ("mov %%cr0,%0" : "=r" (crn) :);
    vmcb->cr0 = crn;

    /* Initally PG, PE are not set*/
    shadow_cr = vmcb->cr0;
    shadow_cr &= ~X86_CR0_PG;
    arch_svm->cpu_shadow_cr0 = shadow_cr;

    /* CR3 is set in svm_final_setup_guest */

    __asm__ __volatile__ ("mov %%cr4,%0" : "=r" (crn) :); 
    crn &= ~(X86_CR4_PGE | X86_CR4_PSE | X86_CR4_PAE);
    arch_svm->cpu_shadow_cr4 = crn;
    vmcb->cr4 = crn | SVM_CR4_HOST_MASK;

    vmcb->rsp = 0;
    vmcb->rip = regs->eip;

    eflags = regs->eflags & ~HVM_EFLAGS_RESERVED_0; /* clear 0s */
    eflags |= HVM_EFLAGS_RESERVED_1; /* set 1s */

    vmcb->rflags = eflags;

    __asm__ __volatile__ ("mov %%dr7, %0\n" : "=r" (dr7));
    vmcb->dr7 = dr7;

    return error;
}


/*
 * destroy the vmcb.
 */

void destroy_vmcb(struct arch_svm_struct *arch_svm)
{
    if(arch_svm->vmcb != NULL)
    {
        asidpool_retire(arch_svm->vmcb, arch_svm->asid_core);
         free_vmcb(arch_svm->vmcb);
    }
    if(arch_svm->iopm != NULL) {
        free_xenheap_pages(
            arch_svm->iopm, get_order_from_bytes(IOPM_SIZE));
        arch_svm->iopm = NULL;
    }
    if(arch_svm->msrpm != NULL) {
        free_xenheap_pages(
            arch_svm->msrpm, get_order_from_bytes(MSRPM_SIZE));
        arch_svm->msrpm = NULL;
    }
    arch_svm->vmcb = NULL;
}


/*
 * construct the vmcb.
 */

int construct_vmcb(struct arch_svm_struct *arch_svm, struct cpu_user_regs *regs)
{
    int error;
    long rc=0;

    memset(arch_svm, 0, sizeof(struct arch_svm_struct));

    if (!(arch_svm->vmcb = alloc_vmcb())) {
        printk("Failed to create a new VMCB\n");
        rc = -ENOMEM;
        goto err_out;
    }

    /* update the HSA for the current Core */
    set_hsa_to_guest( arch_svm );
    arch_svm->vmcb_pa  = (u64) virt_to_maddr(arch_svm->vmcb);

    if ((error = construct_vmcb_controls(arch_svm))) 
    {
        printk("construct_vmcb: construct_vmcb_controls failed\n");
        rc = -EINVAL;         
        goto err_out;
    }

    /* guest selectors */
    if ((error = construct_init_vmcb_guest(arch_svm, regs))) 
    {
        printk("construct_vmcb: construct_vmcb_guest failed\n");
        rc = -EINVAL;         
        goto err_out;
    }

    arch_svm->vmcb->exception_intercepts = MONITOR_DEFAULT_EXCEPTION_BITMAP;
    if (regs->eflags & EF_TF)
        arch_svm->vmcb->exception_intercepts |= EXCEPTION_BITMAP_DB;
    else
        arch_svm->vmcb->exception_intercepts &= ~EXCEPTION_BITMAP_DB;

    return 0;

err_out:
    destroy_vmcb(arch_svm);
    return rc;
}


void svm_do_launch(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    int core = smp_processor_id();
    ASSERT(vmcb);

    /* Update CR3, GDT, LDT, TR */
    svm_stts(v);

    /* current core is the one we intend to perform the VMRUN on */
    v->arch.hvm_svm.launch_core = v->arch.hvm_svm.asid_core = core;
    clear_bit(ARCH_SVM_VMCB_ASSIGN_ASID, &v->arch.hvm_svm.flags);
    if ( !asidpool_assign_next( vmcb, 0, core, core ))
        BUG();

    if (v->vcpu_id == 0)
        hvm_setup_platform(v->domain);

    if ( evtchn_bind_vcpu(iopacket_port(v), v->vcpu_id) < 0 )
    {
        printk("HVM domain bind port %d to vcpu %d failed!\n",
               iopacket_port(v), v->vcpu_id);
        domain_crash_synchronous();
    }

    HVM_DBG_LOG(DBG_LEVEL_1, "eport: %x", iopacket_port(v));

    clear_bit(iopacket_port(v),
              &v->domain->shared_info->evtchn_mask[0]);

    if (hvm_apic_support(v->domain))
        vlapic_init(v);
    init_timer(&v->arch.hvm_svm.hlt_timer,
				hlt_timer_fn, v, v->processor);

    vmcb->ldtr.sel = 0;
    vmcb->ldtr.base = 0;
    vmcb->ldtr.limit = 0;
    vmcb->ldtr.attributes.bytes = 0;

    vmcb->efer = EFER_SVME; /* Make sure VMRUN won't return with -1 */
    
    if (svm_dbg_on) 
    {
        unsigned long pt;
        pt = pagetable_get_paddr(v->arch.shadow_table);
        printk("%s: shadow_table = %lx\n", __func__, pt);
        pt = pagetable_get_paddr(v->arch.guest_table);
        printk("%s: guest_table  = %lx\n", __func__, pt);
        pt = pagetable_get_paddr(v->domain->arch.phys_table);
        printk("%s: phys_table   = %lx\n", __func__, pt);
    }

    if ( svm_paging_enabled(v) )
        vmcb->cr3 = pagetable_get_paddr(v->arch.guest_table);
    else
        vmcb->cr3 = pagetable_get_paddr(v->domain->arch.phys_table);

    if (svm_dbg_on) 
    {
        printk("%s: cr3 = %lx ", __func__, (unsigned long)vmcb->cr3);
        printk("init_guest_table: guest_table = 0x%08x, monitor_table = 0x%08x,"
                " shadow_table = 0x%08x\n", (int)v->arch.guest_table.pfn, 
                (int)v->arch.monitor_table.pfn, (int)v->arch.shadow_table.pfn);
    }

    v->arch.schedule_tail = arch_svm_do_resume;

    v->arch.hvm_svm.injecting_event  = 0;
    v->arch.hvm_svm.saved_irq_vector = -1;

    svm_set_guest_time(v, 0);
	
    if (svm_dbg_on)
        svm_dump_vmcb(__func__, vmcb);

    vmcb->tlb_control = 1;
}


void set_hsa_to_guest( struct arch_svm_struct *arch_svm ) 
{
    arch_svm->host_save_area = host_save_area[ smp_processor_id() ];
    arch_svm->host_save_pa   = (u64)virt_to_maddr( arch_svm->host_save_area );
}

/* 
 * Resume the guest.
 */
void svm_do_resume(struct vcpu *v) 
{
    struct domain *d = v->domain;
    struct hvm_virpit *vpit = &d->arch.hvm_domain.vpit;
    struct hvm_time_info *time_info = &vpit->time_info;

    svm_stts(v);

    /* make sure the HSA is set for the current core */
    set_hsa_to_guest( &v->arch.hvm_svm );
    
    /* pick up the elapsed PIT ticks and re-enable pit_timer */
    if ( time_info->first_injected ) {
        if ( v->domain->arch.hvm_domain.guest_time ) {
            svm_set_guest_time(v, v->domain->arch.hvm_domain.guest_time);
            time_info->count_point = NOW();
            v->domain->arch.hvm_domain.guest_time = 0;
        }
        pickup_deactive_ticks(vpit);
    }

    if ( test_bit(iopacket_port(v), &d->shared_info->evtchn_pending[0]) ||
         test_bit(ARCH_HVM_IO_WAIT, &v->arch.hvm_vcpu.ioflags) )
        hvm_wait_io();

    /* We can't resume the guest if we're waiting on I/O */
    ASSERT(!test_bit(ARCH_HVM_IO_WAIT, &v->arch.hvm_vcpu.ioflags));
}

void svm_launch_fail(unsigned long eflags)
{
    BUG();
}


void svm_resume_fail(unsigned long eflags)
{
    BUG();
}


void svm_dump_sel(char *name, segment_selector_t *s)
{
    printf("%s: sel=0x%04x, attr=0x%04x, limit=0x%08x, base=0x%016llx\n", 
           name, s->sel, s->attributes.bytes, s->limit,
	   (unsigned long long)s->base);
}


void svm_dump_vmcb(const char *from, struct vmcb_struct *vmcb)
{
    printf("Dumping guest's current state at %s...\n", from);
    printf("Size of VMCB = %d, address = %p\n", 
            (int) sizeof(struct vmcb_struct), vmcb);

    printf("cr_intercepts = 0x%08x dr_intercepts = 0x%08x exception_intercepts "
            "= 0x%08x\n", vmcb->cr_intercepts, vmcb->dr_intercepts, 
            vmcb->exception_intercepts);
    printf("general1_intercepts = 0x%08x general2_intercepts = 0x%08x\n", 
           vmcb->general1_intercepts, vmcb->general2_intercepts);
    printf("iopm_base_pa = %016llx msrpm_base_pa = 0x%016llx tsc_offset = "
            "0x%016llx\n", 
	    (unsigned long long) vmcb->iopm_base_pa,
	    (unsigned long long) vmcb->msrpm_base_pa,
	    (unsigned long long) vmcb->tsc_offset);
    printf("tlb_control = 0x%08x vintr = 0x%016llx interrupt_shadow = "
            "0x%016llx\n", vmcb->tlb_control,
	    (unsigned long long) vmcb->vintr.bytes,
	    (unsigned long long) vmcb->interrupt_shadow);
    printf("exitcode = 0x%016llx exitintinfo = 0x%016llx\n", 
           (unsigned long long) vmcb->exitcode,
	   (unsigned long long) vmcb->exitintinfo.bytes);
    printf("exitinfo1 = 0x%016llx exitinfo2 = 0x%016llx \n",
           (unsigned long long) vmcb->exitinfo1,
	   (unsigned long long) vmcb->exitinfo2);
    printf("np_enable = 0x%016llx guest_asid = 0x%03x\n", 
           (unsigned long long) vmcb->np_enable, vmcb->guest_asid);
    printf("cpl = %d efer = 0x%016llx star = 0x%016llx lstar = 0x%016llx\n", 
           vmcb->cpl, (unsigned long long) vmcb->efer,
	   (unsigned long long) vmcb->star, (unsigned long long) vmcb->lstar);
    printf("CR0 = 0x%016llx CR2 = 0x%016llx\n",
           (unsigned long long) vmcb->cr0, (unsigned long long) vmcb->cr2);
    printf("CR3 = 0x%016llx CR4 = 0x%016llx\n", 
           (unsigned long long) vmcb->cr3, (unsigned long long) vmcb->cr4);
    printf("RSP = 0x%016llx  RIP = 0x%016llx\n", 
           (unsigned long long) vmcb->rsp, (unsigned long long) vmcb->rip);
    printf("RAX = 0x%016llx  RFLAGS=0x%016llx\n",
           (unsigned long long) vmcb->rax, (unsigned long long) vmcb->rflags);
    printf("DR6 = 0x%016llx, DR7 = 0x%016llx\n", 
           (unsigned long long) vmcb->dr6, (unsigned long long) vmcb->dr7);
    printf("CSTAR = 0x%016llx SFMask = 0x%016llx\n",
           (unsigned long long) vmcb->cstar, (unsigned long long) vmcb->sfmask);
    printf("KernGSBase = 0x%016llx PAT = 0x%016llx \n", 
           (unsigned long long) vmcb->kerngsbase,
	   (unsigned long long) vmcb->g_pat);
    
    /* print out all the selectors */
    svm_dump_sel("CS", &vmcb->cs);
    svm_dump_sel("DS", &vmcb->ds);
    svm_dump_sel("SS", &vmcb->ss);
    svm_dump_sel("ES", &vmcb->es);
    svm_dump_sel("FS", &vmcb->fs);
    svm_dump_sel("GS", &vmcb->gs);
    svm_dump_sel("GDTR", &vmcb->gdtr);
    svm_dump_sel("LDTR", &vmcb->ldtr);
    svm_dump_sel("IDTR", &vmcb->idtr);
    svm_dump_sel("TR", &vmcb->tr);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
