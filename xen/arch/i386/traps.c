/*
 *  linux/arch/i386/traps.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 */

#include <xeno/config.h>
#include <xeno/init.h>
#include <xeno/interrupt.h>
#include <xeno/sched.h>
#include <xeno/lib.h>
#include <xeno/errno.h>
#include <xeno/mm.h>
#include <asm/ptrace.h>
#include <xeno/delay.h>
#include <xeno/spinlock.h>
#include <xeno/irq.h>
#include <asm/domain_page.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/atomic.h>
#include <asm/desc.h>
#include <asm/debugreg.h>
#include <asm/smp.h>
#include <asm/pgalloc.h>
#include <asm/uaccess.h>
#include <asm/i387.h>

#define GTBF_TRAP        1
#define GTBF_TRAP_NOCODE 2
#define GTBF_TRAP_CR2    4
struct guest_trap_bounce {
    unsigned long  error_code;        /*   0 */
    unsigned long  cr2;               /*   4 */
    unsigned short flags;             /*   8 */
    unsigned short cs;                /*  10 */
    unsigned long  eip;               /*  12 */
} guest_trap_bounce[NR_CPUS] = { { 0 } };

asmlinkage int hypervisor_call(void);
asmlinkage void lcall7(void);
asmlinkage void lcall27(void);

/* Master table, and the one used by CPU0. */
struct desc_struct idt_table[256] = { {0, 0}, };
/* All other CPUs have their own copy. */
struct desc_struct *idt_tables[NR_CPUS] = { 0 };

asmlinkage void divide_error(void);
asmlinkage void debug(void);
asmlinkage void nmi(void);
asmlinkage void int3(void);
asmlinkage void overflow(void);
asmlinkage void bounds(void);
asmlinkage void invalid_op(void);
asmlinkage void device_not_available(void);
asmlinkage void double_fault(void);
asmlinkage void coprocessor_segment_overrun(void);
asmlinkage void invalid_TSS(void);
asmlinkage void segment_not_present(void);
asmlinkage void stack_segment(void);
asmlinkage void general_protection(void);
asmlinkage void page_fault(void);
asmlinkage void coprocessor_error(void);
asmlinkage void simd_coprocessor_error(void);
asmlinkage void alignment_check(void);
asmlinkage void spurious_interrupt_bug(void);
asmlinkage void machine_check(void);

int kstack_depth_to_print = 8*20;

static inline int kernel_text_address(unsigned long addr)
{
    if (addr >= (unsigned long) &_stext &&
        addr <= (unsigned long) &_etext)
        return 1;
    return 0;

}

void show_trace(unsigned long * stack)
{
    int i;
    unsigned long addr;

    if (!stack)
        stack = (unsigned long*)&stack;

    printk("Call Trace: ");
    i = 1;
    while (((long) stack & (THREAD_SIZE-1)) != 0) {
        addr = *stack++;
        if (kernel_text_address(addr)) {
            if (i && ((i % 6) == 0))
                printk("\n   ");
            printk("[<%08lx>] ", addr);
            i++;
        }
    }
    printk("\n");
}

void show_trace_task(struct task_struct *tsk)
{
    unsigned long esp = tsk->thread.esp;

    /* User space on another CPU? */
    if ((esp ^ (unsigned long)tsk) & (PAGE_MASK<<1))
        return;
    show_trace((unsigned long *)esp);
}

void show_stack(unsigned long * esp)
{
    unsigned long *stack;
    int i;

    // debugging aid: "show_stack(NULL);" prints the
    // back trace for this cpu.

    if(esp==NULL)
        esp=(unsigned long*)&esp;

    printk("Stack trace from ESP=%p:\n", esp);

    stack = esp;
    for(i=0; i < kstack_depth_to_print; i++) {
        if (((long) stack & (THREAD_SIZE-1)) == 0)
            break;
        if (i && ((i % 8) == 0))
            printk("\n       ");
        if ( kernel_text_address(*stack) )
            printk("[%08lx] ", *stack++);
        else
            printk("%08lx ", *stack++);            
    }
    printk("\n");
    //show_trace(esp);
}

void show_registers(struct pt_regs *regs)
{
    unsigned long esp;
    unsigned short ss;

    esp = (unsigned long) (&regs->esp);
    ss  = __HYPERVISOR_DS;
    if ( regs->xcs & 3 )
    {
        esp = regs->esp;
        ss  = regs->xss & 0xffff;
    }

    printk("CPU:    %d\nEIP:    %04x:[<%08lx>]      \nEFLAGS: %08lx\n",
           smp_processor_id(), 0xffff & regs->xcs, regs->eip, regs->eflags);
    printk("eax: %08lx   ebx: %08lx   ecx: %08lx   edx: %08lx\n",
           regs->eax, regs->ebx, regs->ecx, regs->edx);
    printk("esi: %08lx   edi: %08lx   ebp: %08lx   esp: %08lx\n",
           regs->esi, regs->edi, regs->ebp, esp);
    printk("ds: %04x   es: %04x   fs: %04x   gs: %04x   ss: %04x\n",
           regs->xds & 0xffff, regs->xes & 0xffff, 
           regs->xfs & 0xffff, regs->xgs & 0xffff, ss);

    show_stack(&regs->esp);
}	


spinlock_t die_lock = SPIN_LOCK_UNLOCKED;

void die(const char * str, struct pt_regs * regs, long err)
{
    unsigned long flags;
    spin_lock_irqsave(&die_lock, flags);
    printk("%s: %04lx,%04lx\n", str, err >> 16, err & 0xffff);
    show_registers(regs);
    spin_unlock_irqrestore(&die_lock, flags);
    panic("HYPERVISOR DEATH!!\n");
}

static inline void die_if_kernel(const char * str, struct pt_regs * regs, long err)
{
    if (!(3 & regs->xcs)) die(str, regs, err);
}

static void inline do_trap(int trapnr, char *str,
			   struct pt_regs * regs, 
                           long error_code, int use_error_code)
{
    struct guest_trap_bounce *gtb = guest_trap_bounce+smp_processor_id();
    trap_info_t *ti;
    unsigned long fixup;

    if (!(regs->xcs & 3))
        goto fault_in_hypervisor;

    ti = current->thread.traps + trapnr;
    gtb->flags = use_error_code ? GTBF_TRAP : GTBF_TRAP_NOCODE;
    gtb->error_code = error_code;
    gtb->cs         = ti->cs;
    gtb->eip        = ti->address;
    return; 

 fault_in_hypervisor:

    if ( (fixup = search_exception_table(regs->eip)) != 0 )
    {
        regs->eip = fixup;
        regs->xfs = regs->xgs = 0;
        return;
    }

    show_registers(regs);
    panic("CPU%d FATAL TRAP: vector = %d (%s)\n"
          "[error_code=%08x]\n",
          smp_processor_id(), trapnr, str, error_code);
}

#define DO_ERROR_NOCODE(trapnr, str, name) \
asmlinkage void do_##name(struct pt_regs * regs, long error_code) \
{ \
do_trap(trapnr, str, regs, error_code, 0); \
}

#define DO_ERROR(trapnr, str, name) \
asmlinkage void do_##name(struct pt_regs * regs, long error_code) \
{ \
do_trap(trapnr, str, regs, error_code, 1); \
}

DO_ERROR_NOCODE( 0, "divide error", divide_error)
DO_ERROR_NOCODE( 3, "int3", int3)
DO_ERROR_NOCODE( 4, "overflow", overflow)
DO_ERROR_NOCODE( 5, "bounds", bounds)
DO_ERROR_NOCODE( 6, "invalid operand", invalid_op)
DO_ERROR_NOCODE( 7, "device not available", device_not_available)
DO_ERROR( 8, "double fault", double_fault)
DO_ERROR_NOCODE( 9, "coprocessor segment overrun", coprocessor_segment_overrun)
DO_ERROR(10, "invalid TSS", invalid_TSS)
DO_ERROR(11, "segment not present", segment_not_present)
DO_ERROR(12, "stack segment", stack_segment)
/* Vector 15 reserved by Intel */
DO_ERROR_NOCODE(16, "fpu error", coprocessor_error)
DO_ERROR(17, "alignment check", alignment_check)
DO_ERROR_NOCODE(18, "machine check", machine_check)
DO_ERROR_NOCODE(19, "simd error", simd_coprocessor_error)

asmlinkage void do_page_fault(struct pt_regs *regs, long error_code)
{
    struct guest_trap_bounce *gtb = guest_trap_bounce+smp_processor_id();
    trap_info_t *ti;
    l2_pgentry_t *pl2e;
    l1_pgentry_t *pl1e;
    unsigned long addr, off, fixup, l2e, l1e, *ldt_page;
    struct task_struct *p = current;
    struct pfn_info *page;
    int i;

    __asm__ __volatile__ ("movl %%cr2,%0" : "=r" (addr) : );

    if ( unlikely(addr > PAGE_OFFSET) )
        goto fault_in_xen_space;

 bounce_fault:

    if ( unlikely(!(regs->xcs & 3)) )
        goto fault_in_hypervisor;

    ti = p->thread.traps + 14;
    gtb->flags = GTBF_TRAP_CR2; /* page fault pushes %cr2 */
    gtb->cr2        = addr;
    gtb->error_code = error_code;
    gtb->cs         = ti->cs;
    gtb->eip        = ti->address;
    return; 

    /*
     * FAULT IN XEN ADDRESS SPACE:
     *  We only deal with one kind -- a fault in the shadow LDT mapping.
     *  If this occurs we pull a mapping from the guest's LDT, if it is
     *  valid. Otherwise we send the fault up to the guest OS to be handled.
     */
 fault_in_xen_space:

    if ( (addr < LDT_VIRT_START) || 
         (addr >= (LDT_VIRT_START + (p->mm.ldt_ents*LDT_ENTRY_SIZE))) )
        goto bounce_fault;

    off  = addr - LDT_VIRT_START;
    addr = p->mm.ldt_base + off;

    spin_lock(&p->page_lock);

    pl2e  = map_domain_mem(pagetable_val(p->mm.pagetable));
    l2e   = l2_pgentry_val(pl2e[l2_table_offset(addr)]);
    unmap_domain_mem(pl2e);
    if ( !(l2e & _PAGE_PRESENT) )
        goto unlock_and_bounce_fault;

    pl1e  = map_domain_mem(l2e & PAGE_MASK);
    l1e   = l1_pgentry_val(pl1e[l1_table_offset(addr)]);
    unmap_domain_mem(pl1e);
    if ( !(l1e & _PAGE_PRESENT) )
        goto unlock_and_bounce_fault;

    page = frame_table + (l1e >> PAGE_SHIFT);
    if ( (page->flags & PG_type_mask) != PGT_ldt_page )
    {
        if ( page->type_count != 0 )
            goto unlock_and_bounce_fault;

        /* Check all potential LDT entries in the page. */
        ldt_page = map_domain_mem(l1e & PAGE_MASK);
        for ( i = 0; i < 512; i++ )
            if ( !check_descriptor(ldt_page[i*2], ldt_page[i*2+1]) )
                goto unlock_and_bounce_fault;
        unmap_domain_mem(ldt_page);

        page->flags &= ~PG_type_mask;
        page->flags |= PGT_ldt_page;
    }

    /* Success! */
    get_page_type(page);
    get_page_tot(page);
    p->mm.perdomain_pt[l1_table_offset(off)+16] = mk_l1_pgentry(l1e|_PAGE_RW);
    p->mm.shadow_ldt_mapcnt++;

    spin_unlock(&p->page_lock);
    return;


 unlock_and_bounce_fault:

    spin_unlock(&p->page_lock);
    goto bounce_fault;


 fault_in_hypervisor:

    if ( (fixup = search_exception_table(regs->eip)) != 0 )
    {
        regs->eip = fixup;
        regs->xfs = regs->xgs = 0;
        return;
    }

    if ( addr >= PAGE_OFFSET )
    {
        unsigned long page;
        unsigned long *pde;
        pde = (unsigned long *)idle_pg_table[smp_processor_id()];
        page = pde[addr >> L2_PAGETABLE_SHIFT];
        printk("*pde = %08lx\n", page);
        if ( page & _PAGE_PRESENT )
        {
            page &= PAGE_MASK;
            page = ((unsigned long *) __va(page))[(addr&0x3ff000)>>PAGE_SHIFT];
            printk(" *pte = %08lx\n", page);
        }
    }

    show_registers(regs);
    panic("CPU%d FATAL PAGE FAULT\n"
          "[error_code=%08x]\n"
          "Faulting linear address might be %08lx\n",
          smp_processor_id(), error_code, addr);
}

asmlinkage void do_general_protection(struct pt_regs *regs, long error_code)
{
    struct guest_trap_bounce *gtb = guest_trap_bounce+smp_processor_id();
    trap_info_t *ti;
    unsigned long fixup;

    /* Bad shit if error in ring 0, or result of an interrupt. */
    if (!(regs->xcs & 3) || (error_code & 1))
        goto gp_in_kernel;

    /*
     * Cunning trick to allow arbitrary "INT n" handling.
     * 
     * We set DPL == 0 on all vectors in the IDT. This prevents any INT <n>
     * instruction from trapping to the appropriate vector, when that might not
     * be expected by Xen or the guest OS. For example, that entry might be for
     * a fault handler (unlike traps, faults don't increment EIP), or might
     * expect an error code on the stack (which a software trap never
     * provides), or might be a hardware interrupt handler that doesn't like
     * being called spuriously.
     * 
     * Instead, a GPF occurs with the faulting IDT vector in the error code.
     * Bit 1 is set to indicate that an IDT entry caused the fault. Bit 0 is 
     * clear to indicate that it's a software fault, not hardware.
     * 
     * NOTE: Vectors 3 and 4 are dealt with from their own handler. This is
     * okay because they can only be triggered by an explicit DPL-checked
     * instruction. The DPL specified by the guest OS for these vectors is NOT
     * CHECKED!!
     */
    if ( (error_code & 3) == 2 )
    {
        /*
         * Hypercalls from rings 2 or 3 fall through to here. If permitted, we 
         * will transfer control to the requested hypercall.
         */
        if ( ((error_code>>3) == HYPERVISOR_CALL_VECTOR) &&
             (current->thread.hypercall_pl >= (regs->xcs & 3)) )
        {
            __asm__ __volatile__ (
                "movl %0,%%esp                                         \n"
                "sti                                                   \n"
                "andl $255,%%eax                                       \n"
                "call *hypervisor_call_table(,%%eax,4)                 \n"
                "movl %%eax,0x18(%%esp)                                \n"
                "jmp  ret_from_intr                                    \n"
                : : "r" (regs) );
        }

        /* This fault must be due to <INT n> instruction. */
        ti = current->thread.traps + (error_code>>3);
        if ( ti->dpl >= (regs->xcs & 3) )
        {
            gtb->flags = GTBF_TRAP_NOCODE;
            gtb->cs    = ti->cs;
            gtb->eip   = ti->address;
            regs->eip += 2;
            return;
        }
    }
    
    /* Pass on GPF as is. */
    ti = current->thread.traps + 13;
    gtb->flags      = GTBF_TRAP;
    gtb->error_code = error_code;
    gtb->cs         = ti->cs;
    gtb->eip        = ti->address;
    return;

 gp_in_kernel:

    if ( (fixup = search_exception_table(regs->eip)) != 0 )
    {
        regs->eip = fixup;
        regs->xfs = regs->xgs = 0;
        return;
    }

    die("general protection fault", regs, error_code);
}

static void mem_parity_error(unsigned char reason, struct pt_regs * regs)
{
    printk("Uhhuh. NMI received. Dazed and confused, but trying to continue\n");
    printk("You probably have a hardware problem with your RAM chips\n");

    /* Clear and disable the memory parity error line. */
    reason = (reason & 0xf) | 4;
    outb(reason, 0x61);
}

static void io_check_error(unsigned char reason, struct pt_regs * regs)
{
    unsigned long i;

    printk("NMI: IOCK error (debug interrupt?)\n");
    show_registers(regs);

    /* Re-enable the IOCK line, wait for a few seconds */
    reason = (reason & 0xf) | 8;
    outb(reason, 0x61);
    i = 2000;
    while (--i) udelay(1000);
    reason &= ~8;
    outb(reason, 0x61);
}

static void unknown_nmi_error(unsigned char reason, struct pt_regs * regs)
{
    printk("Uhhuh. NMI received for unknown reason %02x.\n", reason);
    printk("Dazed and confused, but trying to continue\n");
    printk("Do you have a strange power saving mode enabled?\n");
}

asmlinkage void do_nmi(struct pt_regs * regs, long error_code)
{
    unsigned char reason = inb(0x61);

    if (!(reason & 0xc0)) {
        unknown_nmi_error(reason, regs);
        return;
    }
    if (reason & 0x80)
        mem_parity_error(reason, regs);
    if (reason & 0x40)
        io_check_error(reason, regs);
    /*
     * Reassert NMI in case it became active meanwhile
     * as it's edge-triggered.
     */
    outb(0x8f, 0x70);
    inb(0x71);		/* dummy */
    outb(0x0f, 0x70);
    inb(0x71);		/* dummy */
}

asmlinkage void math_state_restore(struct pt_regs *regs, long error_code)
{
    /* Prevent recursion. */
    clts();

    if ( !(current->flags & PF_USEDFPU) )
    {
        if ( current->flags & PF_DONEFPUINIT )
            restore_fpu(current);
        else
            init_fpu();
        current->flags |= PF_USEDFPU;   /* So we fnsave on switch_to() */    
    }

    if ( current->flags & PF_GUEST_STTS )
    {
        struct guest_trap_bounce *gtb = guest_trap_bounce+smp_processor_id();
        gtb->flags      = GTBF_TRAP_NOCODE;
        gtb->cs         = current->thread.traps[7].cs;
        gtb->eip        = current->thread.traps[7].address;
        current->flags &= ~PF_GUEST_STTS;
    }
}


asmlinkage void do_debug(struct pt_regs * regs, long error_code)
{
    unsigned int condition;
    struct task_struct *tsk = current;
    struct guest_trap_bounce *gtb = guest_trap_bounce+smp_processor_id();

    __asm__ __volatile__("movl %%db6,%0" : "=r" (condition));

    /* Mask out spurious debug traps due to lazy DR7 setting */
    if ( (condition & (DR_TRAP0|DR_TRAP1|DR_TRAP2|DR_TRAP3)) &&
         (tsk->thread.debugreg[7] == 0) )
    {
        __asm__("movl %0,%%db7" : : "r" (0));
        return;
    }

    if ( (regs->xcs & 3) == 0 )
    {
        /* Clear TF just for absolute sanity. */
        regs->eflags &= ~EF_TF;
        /*
         * Basically, we ignore watchpoints when they trigger in
         * the hypervisor. This may happen when a buffer is passed
         * to us which previously had a watchpoint set on it.
         * No need to bump EIP; the only faulting trap is an
         * instruction breakpoint, which can't happen to us.
         */
        return;
    }

    /* Save debug status register where guest OS can peek at it */
    tsk->thread.debugreg[6] = condition;

    gtb->flags = GTBF_TRAP_NOCODE;
    gtb->cs    = tsk->thread.traps[1].cs;
    gtb->eip   = tsk->thread.traps[1].address;
}


asmlinkage void do_spurious_interrupt_bug(struct pt_regs * regs,
					  long error_code)
{ /* nothing */ }


#define _set_gate(gate_addr,type,dpl,addr) \
do { \
  int __d0, __d1; \
  __asm__ __volatile__ ("movw %%dx,%%ax\n\t" \
	"movw %4,%%dx\n\t" \
	"movl %%eax,%0\n\t" \
	"movl %%edx,%1" \
	:"=m" (*((long *) (gate_addr))), \
	 "=m" (*(1+(long *) (gate_addr))), "=&a" (__d0), "=&d" (__d1) \
	:"i" ((short) (0x8000+(dpl<<13)+(type<<8))), \
	 "3" ((char *) (addr)),"2" (__HYPERVISOR_CS << 16)); \
} while (0)

void set_intr_gate(unsigned int n, void *addr)
{
    _set_gate(idt_table+n,14,0,addr);
}

static void __init set_system_gate(unsigned int n, void *addr)
{
    _set_gate(idt_table+n,14,3,addr);
}

#define _set_seg_desc(gate_addr,type,dpl,base,limit) {\
	*((gate_addr)+1) = ((base) & 0xff000000) | \
		(((base) & 0x00ff0000)>>16) | \
		((limit) & 0xf0000) | \
		((dpl)<<13) | \
		(0x00408000) | \
		((type)<<8); \
	*(gate_addr) = (((base) & 0x0000ffff)<<16) | \
		((limit) & 0x0ffff); }

#define _set_tssldt_desc(n,addr,limit,type) \
__asm__ __volatile__ ("movw %w3,0(%2)\n\t" \
	"movw %%ax,2(%2)\n\t" \
	"rorl $16,%%eax\n\t" \
	"movb %%al,4(%2)\n\t" \
	"movb %4,5(%2)\n\t" \
	"movb $0,6(%2)\n\t" \
	"movb %%ah,7(%2)\n\t" \
	"rorl $16,%%eax" \
	: "=m"(*(n)) : "a" (addr), "r"(n), "ir"(limit), "i"(type))

void set_tss_desc(unsigned int n, void *addr)
{
    _set_tssldt_desc(gdt_table+__TSS(n), (int)addr, 235, 0x89);
}

void __init trap_init(void)
{
    /*
     * Note that interrupt gates are always used, rather than trap gates. We 
     * must have interrupts disabled until DS/ES/FS/GS are saved because the 
     * first activation must have the "bad" value(s) for these registers and 
     * we may lose them if another activation is installed before they are 
     * saved. The page-fault handler also needs interrupts disabled until %cr2 
     * has been read and saved on the stack.
     */
    set_intr_gate(0,&divide_error);
    set_intr_gate(1,&debug);
    set_intr_gate(2,&nmi);
    set_system_gate(3,&int3);     /* usable from all privilege levels */
    set_system_gate(4,&overflow); /* usable from all privilege levels */
    set_intr_gate(5,&bounds);
    set_intr_gate(6,&invalid_op);
    set_intr_gate(7,&device_not_available);
    set_intr_gate(8,&double_fault);
    set_intr_gate(9,&coprocessor_segment_overrun);
    set_intr_gate(10,&invalid_TSS);
    set_intr_gate(11,&segment_not_present);
    set_intr_gate(12,&stack_segment);
    set_intr_gate(13,&general_protection);
    set_intr_gate(14,&page_fault);
    set_intr_gate(15,&spurious_interrupt_bug);
    set_intr_gate(16,&coprocessor_error);
    set_intr_gate(17,&alignment_check);
    set_intr_gate(18,&machine_check);
    set_intr_gate(19,&simd_coprocessor_error);

    /* Only ring 1 can access monitor services. */
    _set_gate(idt_table+HYPERVISOR_CALL_VECTOR,14,1,&hypervisor_call);

    /* CPU0 uses the master IDT. */
    idt_tables[0] = idt_table;

    /*
     * Should be a barrier for any external CPU state.
     */
    {
        extern void cpu_init(void);
        cpu_init();
    }
}


long do_set_trap_table(trap_info_t *traps)
{
    trap_info_t cur;
    trap_info_t *dst = current->thread.traps;

    for ( ; ; )
    {
        if ( copy_from_user(&cur, traps, sizeof(cur)) ) return -EFAULT;

        if ( cur.address == 0 ) break;

        if ( !VALID_CODESEL(cur.cs) ) return -EPERM;

        memcpy(dst+cur.vector, &cur, sizeof(cur));
        traps++;
    }

    return 0;
}


long do_set_callbacks(unsigned long event_selector,
                      unsigned long event_address,
                      unsigned long failsafe_selector,
                      unsigned long failsafe_address)
{
    struct task_struct *p = current;

    if ( !VALID_CODESEL(event_selector) || !VALID_CODESEL(failsafe_selector) )
        return -EPERM;

    p->event_selector    = event_selector;
    p->event_address     = event_address;
    p->failsafe_selector = failsafe_selector;
    p->failsafe_address  = failsafe_address;

    return 0;
}


long do_set_fast_trap(int idx)
{
    trap_info_t *ti;

    /* Index 0 is special: it disables fast traps. */
    if ( idx == 0 )
    {
        CLEAR_FAST_TRAP(&current->thread);
        SET_DEFAULT_FAST_TRAP(&current->thread);
        return 0;
    }

    /*
     * We only fast-trap vectors 0x20-0x2f, and vector 0x80.
     * The former range is used by Windows and MS-DOS.
     * Vector 0x80 is used by Linux and the BSD variants.
     */
    if ( (idx != 0x80) && ((idx < 0x20) || (idx > 0x2f)) ) return -1;

    ti = current->thread.traps + idx;

    CLEAR_FAST_TRAP(&current->thread);

    current->thread.fast_trap_idx    = idx;
    current->thread.fast_trap_desc.a = (ti->cs << 16) | (ti->address & 0xffff);
    current->thread.fast_trap_desc.b = 
        (ti->address & 0xffff0000) | 0x8f00 | (ti->dpl&3)<<13;

    SET_FAST_TRAP(&current->thread);

    return 0;
}


long do_fpu_taskswitch(void)
{
    current->flags |= PF_GUEST_STTS;
    stts();
    return 0;
}


long do_set_debugreg(int reg, unsigned long value)
{
    int i;

    switch ( reg )
    {
    case 0: 
        if ( value > (PAGE_OFFSET-4) ) return -EPERM;
        __asm__ ( "movl %0, %%db0" : : "r" (value) );
        break;
    case 1: 
        if ( value > (PAGE_OFFSET-4) ) return -EPERM;
        __asm__ ( "movl %0, %%db1" : : "r" (value) );
        break;
    case 2: 
        if ( value > (PAGE_OFFSET-4) ) return -EPERM;
        __asm__ ( "movl %0, %%db2" : : "r" (value) );
        break;
    case 3:
        if ( value > (PAGE_OFFSET-4) ) return -EPERM;
        __asm__ ( "movl %0, %%db3" : : "r" (value) );
        break;
    case 6:
        /*
         * DR6: Bits 4-11,16-31 reserved (set to 1).
         *      Bit 12 reserved (set to 0).
         */
        value &= 0xffffefff; /* reserved bits => 0 */
        value |= 0xffff0ff0; /* reserved bits => 1 */
        __asm__ ( "movl %0, %%db6" : : "r" (value) );
        break;
    case 7:
        /*
         * DR7: Bit 10 reserved (set to 1).
         *      Bits 11-12,14-15 reserved (set to 0).
         * Privileged bits:
         *      GD (bit 13): must be 0.
         *      R/Wn (bits 16-17,20-21,24-25,28-29): mustn't be 10.
         *      LENn (bits 18-19,22-23,26-27,30-31): mustn't be 10.
         */
        /* DR7 == 0 => debugging disabled for this domain. */
        if ( value != 0 )
        {
            value &= 0xffff27ff; /* reserved bits => 0 */
            value |= 0x00000400; /* reserved bits => 1 */
            if ( (value & (1<<13)) != 0 ) return -EPERM;
            for ( i = 0; i < 16; i += 2 )
                if ( ((value >> (i+16)) & 3) == 2 ) return -EPERM;
        }
        __asm__ ( "movl %0, %%db7" : : "r" (value) );
        break;
    default:
        return -EINVAL;
    }

    current->thread.debugreg[reg] = value;
    return 0;
}

unsigned long do_get_debugreg(int reg)
{
    if ( (reg < 0) || (reg > 7) ) return -EINVAL;
    return current->thread.debugreg[reg];
}
