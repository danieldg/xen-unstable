/******************************************************************************
 * arch/i386/traps.c
 * 
 * Modifications to Linux original are copyright (c) 2002-2004, K A Fraser
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 * Gareth Hughes <gareth@valinux.com>, May 2000
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <xen/console.h>
#include <asm/regs.h>
#include <xen/delay.h>
#include <xen/event.h>
#include <xen/spinlock.h>
#include <xen/irq.h>
#include <xen/perfc.h>
#include <xen/softirq.h>
#include <asm/shadow.h>
#include <asm/domain_page.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/atomic.h>
#include <asm/desc.h>
#include <asm/debugreg.h>
#include <asm/smp.h>
#include <asm/flushtlb.h>
#include <asm/uaccess.h>
#include <asm/i387.h>
#include <asm/debugger.h>

#if defined(__i386__)

#define DOUBLEFAULT_STACK_SIZE 1024
static struct tss_struct doublefault_tss;
static unsigned char doublefault_stack[DOUBLEFAULT_STACK_SIZE];

asmlinkage int hypercall(void);

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

void show_guest_stack()
{
    int i;
    execution_context_t *ec = get_execution_context();
    unsigned long *stack = (unsigned long *)ec->esp;
    printk("Guest EIP is %lx\n",ec->eip);

    for ( i = 0; i < kstack_depth_to_print; i++ )
    {
        if ( ((long)stack & (STACK_SIZE-1)) == 0 )
            break;
        if ( i && ((i % 8) == 0) )
            printk("\n       ");
            printk("%08lx ", *stack++);            
    }
    printk("\n");
    
}

void show_trace(unsigned long *esp)
{
    unsigned long *stack, addr;
    int i;

    printk("Call Trace from ESP=%p: ", esp);
    stack = esp;
    i = 0;
    while (((long) stack & (STACK_SIZE-1)) != 0) {
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

void show_stack(unsigned long *esp)
{
    unsigned long *stack;
    int i;

    printk("Stack trace from ESP=%p:\n", esp);

    stack = esp;
    for ( i = 0; i < kstack_depth_to_print; i++ )
    {
        if ( ((long)stack & (STACK_SIZE-1)) == 0 )
            break;
        if ( i && ((i % 8) == 0) )
            printk("\n       ");
        if ( kernel_text_address(*stack) )
            printk("[%08lx] ", *stack++);
        else
            printk("%08lx ", *stack++);            
    }
    printk("\n");

    show_trace( esp );
}

void show_registers(struct xen_regs *regs)
{
    unsigned long esp;
    unsigned short ss, ds, es, fs, gs;

    if ( regs->cs & 3 )
    {
        esp = regs->esp;
        ss  = regs->ss & 0xffff;
        ds  = regs->ds & 0xffff;
        es  = regs->es & 0xffff;
        fs  = regs->fs & 0xffff;
        gs  = regs->gs & 0xffff;
    }
    else
    {
        esp = (unsigned long)(&regs->esp);
        ss  = __HYPERVISOR_DS;
        ds  = __HYPERVISOR_DS;
        es  = __HYPERVISOR_DS;
        fs  = __HYPERVISOR_DS;
        gs  = __HYPERVISOR_DS;
    }

    printk("CPU:    %d\nEIP:    %04x:[<%08lx>]      \nEFLAGS: %08lx\n",
           smp_processor_id(), 0xffff & regs->cs, regs->eip, regs->eflags);
    printk("eax: %08lx   ebx: %08lx   ecx: %08lx   edx: %08lx\n",
           regs->eax, regs->ebx, regs->ecx, regs->edx);
    printk("esi: %08lx   edi: %08lx   ebp: %08lx   esp: %08lx\n",
           regs->esi, regs->edi, regs->ebp, esp);
    printk("ds: %04x   es: %04x   fs: %04x   gs: %04x   ss: %04x\n",
           ds, es, fs, gs, ss);

    show_stack(&regs->esp);
} 

/*
 * This is called for faults at very unexpected times (e.g., when interrupts
 * are disabled). In such situations we can't do much that is safe. We try to
 * print out some tracing and then we just spin.
 */
asmlinkage void fatal_trap(int trapnr, struct xen_regs *regs, long error_code)
{
    int cpu = smp_processor_id();
    static char *trapstr[] = { 
        "divide error", "debug", "nmi", "bkpt", "overflow", "bounds", 
        "invalid operation", "device not available", "double fault", 
        "coprocessor segment", "invalid tss", "segment not found", 
        "stack error", "general protection fault", "page fault", 
        "spurious interrupt", "coprocessor error", "alignment check", 
        "machine check", "simd error"
    };

    show_registers(regs);
    printk("************************************\n");
    printk("CPU%d FATAL TRAP %d (%s), ERROR_CODE %lx%s.\n",
           cpu, trapnr, trapstr[trapnr], error_code,
           (regs->eflags & X86_EFLAGS_IF) ? "" : ", IN INTERRUPT CONTEXT");
    printk("System shutting down -- need manual reset.\n");
    printk("************************************\n");

    /* Lock up the console to prevent spurious output from other CPUs. */
    console_force_lock();

    /* Wait for manual reset. */
    for ( ; ; )
        __asm__ __volatile__ ( "hlt" );
}

static inline int do_trap(int trapnr, char *str,
                           struct xen_regs *regs, 
                           long error_code, int use_error_code)
{
    struct domain *d = current;
    struct trap_bounce *tb = &d->thread.trap_bounce;
    trap_info_t *ti;
    unsigned long fixup;

    DEBUGGER_trap_entry(trapnr, regs, error_code);

    if ( !(regs->cs & 3) )
        goto xen_fault;

    ti = current->thread.traps + trapnr;
    tb->flags = use_error_code ? TBF_TRAP : TBF_TRAP_NOCODE;
    tb->error_code = error_code;
    tb->cs         = ti->cs;
    tb->eip        = ti->address;
    if ( TI_GET_IF(ti) )
        d->shared_info->vcpu_data[0].evtchn_upcall_mask = 1;
    return 0;

 xen_fault:

    if ( likely((fixup = search_exception_table(regs->eip)) != 0) )
    {
        DPRINTK("Trap %d: %08lx -> %08lx\n", trapnr, regs->eip, fixup);
        regs->eip = fixup;
        return 0;
    }

    DEBUGGER_trap_fatal(trapnr, regs, error_code);

    show_registers(regs);
    panic("CPU%d FATAL TRAP: vector = %d (%s)\n"
          "[error_code=%08x]\n",
          smp_processor_id(), trapnr, str, error_code);
    return 0;
}

#define DO_ERROR_NOCODE(trapnr, str, name) \
asmlinkage int do_##name(struct xen_regs * regs, long error_code) \
{ \
    return do_trap(trapnr, str, regs, error_code, 0); \
}

#define DO_ERROR(trapnr, str, name) \
asmlinkage int do_##name(struct xen_regs * regs, long error_code) \
{ \
    return do_trap(trapnr, str, regs, error_code, 1); \
}

DO_ERROR_NOCODE( 0, "divide error", divide_error)
DO_ERROR_NOCODE( 4, "overflow", overflow)
DO_ERROR_NOCODE( 5, "bounds", bounds)
DO_ERROR_NOCODE( 6, "invalid operand", invalid_op)
DO_ERROR_NOCODE( 9, "coprocessor segment overrun", coprocessor_segment_overrun)
DO_ERROR(10, "invalid TSS", invalid_TSS)
DO_ERROR(11, "segment not present", segment_not_present)
DO_ERROR(12, "stack segment", stack_segment)
DO_ERROR_NOCODE(16, "fpu error", coprocessor_error)
DO_ERROR(17, "alignment check", alignment_check)
DO_ERROR_NOCODE(19, "simd error", simd_coprocessor_error)

asmlinkage int do_int3(struct xen_regs *regs, long error_code)
{
    struct domain *d = current;
    struct trap_bounce *tb = &d->thread.trap_bounce;
    trap_info_t *ti;

    DEBUGGER_trap_entry(TRAP_int3, regs, error_code);

    if ( unlikely((regs->cs & 3) == 0) )
    {
        DEBUGGER_trap_fatal(TRAP_int3, regs, error_code);
        show_registers(regs);
        panic("CPU%d FATAL TRAP: vector = 3 (Int3)\n"
              "[error_code=%08x]\n",
              smp_processor_id(), error_code);
    }

    ti = current->thread.traps + 3;
    tb->flags      = TBF_TRAP_NOCODE;
    tb->error_code = error_code;
    tb->cs         = ti->cs;
    tb->eip        = ti->address;
    if ( TI_GET_IF(ti) )
        d->shared_info->vcpu_data[0].evtchn_upcall_mask = 1;

    return 0;
}

asmlinkage void do_double_fault(void)
{
    struct tss_struct *tss = &doublefault_tss;
    unsigned int cpu = ((tss->back_link>>3)-__FIRST_TSS_ENTRY)>>1;

    /* Disable the NMI watchdog. It's useless now. */
    watchdog_on = 0;

    /* Find information saved during fault and dump it to the console. */
    tss = &init_tss[cpu];
    printk("CPU:    %d\nEIP:    %04x:[<%08x>]      \nEFLAGS: %08x\n",
           cpu, tss->cs, tss->eip, tss->eflags);
    printk("CR3:    %08x\n", tss->__cr3);
    printk("eax: %08x   ebx: %08x   ecx: %08x   edx: %08x\n",
           tss->eax, tss->ebx, tss->ecx, tss->edx);
    printk("esi: %08x   edi: %08x   ebp: %08x   esp: %08x\n",
           tss->esi, tss->edi, tss->ebp, tss->esp);
    printk("ds: %04x   es: %04x   fs: %04x   gs: %04x   ss: %04x\n",
           tss->ds, tss->es, tss->fs, tss->gs, tss->ss);
    printk("************************************\n");
    printk("CPU%d DOUBLE FAULT -- system shutdown\n", cpu);
    printk("System needs manual reset.\n");
    printk("************************************\n");

    /* Lock up the console to prevent spurious output from other CPUs. */
    console_force_lock();

    /* Wait for manual reset. */
    for ( ; ; )
        __asm__ __volatile__ ( "hlt" );
}

asmlinkage void do_machine_check(struct xen_regs *regs, long error_code)
{
    fatal_trap(TRAP_machine_check, regs, error_code);
}

asmlinkage int do_page_fault(struct xen_regs *regs, long error_code)
{
    trap_info_t *ti;
    unsigned long off, addr, fixup;
    struct domain *d = current;
    extern int map_ldt_shadow_page(unsigned int);
    struct trap_bounce *tb = &d->thread.trap_bounce;
    int cpu = d->processor;

    __asm__ __volatile__ ("movl %%cr2,%0" : "=r" (addr) : );

    DEBUGGER_trap_entry(TRAP_page_fault, regs, error_code);

    perfc_incrc(page_faults);

    if ( likely(VM_ASSIST(d, VMASST_TYPE_writable_pagetables)) )
    {
        if ( unlikely(ptwr_info[cpu].ptinfo[PTWR_PT_ACTIVE].l1va) &&
             unlikely((addr >> L2_PAGETABLE_SHIFT) ==
                      ptwr_info[cpu].ptinfo[PTWR_PT_ACTIVE].l2_idx) )
        {
            ptwr_flush(PTWR_PT_ACTIVE);
            return EXCRET_fault_fixed;
        }

        if ( (addr < PAGE_OFFSET) &&
             ((error_code & 3) == 3) && /* write-protection fault */
             ptwr_do_page_fault(addr) )
        {
            if ( unlikely(d->mm.shadow_mode) )
                (void)shadow_fault(addr, error_code);
            return EXCRET_fault_fixed;
        }
    }

    if ( unlikely(d->mm.shadow_mode) && 
         (addr < PAGE_OFFSET) && shadow_fault(addr, error_code) )
        return EXCRET_fault_fixed;

    if ( unlikely(addr >= LDT_VIRT_START) && 
         (addr < (LDT_VIRT_START + (d->mm.ldt_ents*LDT_ENTRY_SIZE))) )
    {
        /*
         * Copy a mapping from the guest's LDT, if it is valid. Otherwise we
         * send the fault up to the guest OS to be handled.
         */
        off  = addr - LDT_VIRT_START;
        addr = d->mm.ldt_base + off;
        if ( likely(map_ldt_shadow_page(off >> PAGE_SHIFT)) )
            return EXCRET_fault_fixed; /* successfully copied the mapping */
    }

    if ( unlikely(!(regs->cs & 3)) )
        goto xen_fault;

    ti = d->thread.traps + 14;
    tb->flags = TBF_TRAP_CR2; /* page fault pushes %cr2 */
    tb->cr2        = addr;
    tb->error_code = error_code;
    tb->cs         = ti->cs;
    tb->eip        = ti->address;
    if ( TI_GET_IF(ti) )
        d->shared_info->vcpu_data[0].evtchn_upcall_mask = 1;
    return 0; 

 xen_fault:

    if ( likely((fixup = search_exception_table(regs->eip)) != 0) )
    {
        perfc_incrc(copy_user_faults);
        if ( !d->mm.shadow_mode )
            DPRINTK("Page fault: %08lx -> %08lx\n", regs->eip, fixup);
        regs->eip = fixup;
        return 0;
    }

    DEBUGGER_trap_fatal(TRAP_page_fault, regs, error_code);

    if ( addr >= PAGE_OFFSET )
    {
        unsigned long page;
        page = l2_pgentry_val(idle_pg_table[addr >> L2_PAGETABLE_SHIFT]);
        printk("*pde = %08lx\n", page);
        if ( page & _PAGE_PRESENT )
        {
            page &= PAGE_MASK;
            page = ((unsigned long *) __va(page))[(addr&0x3ff000)>>PAGE_SHIFT];
            printk(" *pte = %08lx\n", page);
        }
#ifdef MEMORY_GUARD
        if ( !(error_code & 1) )
            printk(" -- POSSIBLY AN ACCESS TO FREED MEMORY? --\n");
#endif
    }

    show_registers(regs);
    panic("CPU%d FATAL PAGE FAULT\n"
          "[error_code=%08x]\n"
          "Faulting linear address might be %08lx\n",
          smp_processor_id(), error_code, addr);
    return 0;
}

asmlinkage int do_general_protection(struct xen_regs *regs, long error_code)
{
    struct domain *d = current;
    struct trap_bounce *tb = &d->thread.trap_bounce;
    trap_info_t *ti;
    unsigned long fixup;

    DEBUGGER_trap_entry(TRAP_gp_fault, regs, error_code);
    
    /* Badness if error in ring 0, or result of an interrupt. */
    if ( !(regs->cs & 3) || (error_code & 1) )
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
        /* This fault must be due to <INT n> instruction. */
        ti = current->thread.traps + (error_code>>3);
        if ( TI_GET_DPL(ti) >= (regs->cs & 3) )
        {
            tb->flags = TBF_TRAP_NOCODE;
            regs->eip += 2;
            goto finish_propagation;
        }
    }

#if defined(__i386__)
    if ( VM_ASSIST(d, VMASST_TYPE_4gb_segments) && 
         (error_code == 0) && 
         gpf_emulate_4gb(regs) )
        return 0;
#endif

    /* Pass on GPF as is. */
    ti = current->thread.traps + 13;
    tb->flags      = TBF_TRAP;
    tb->error_code = error_code;
 finish_propagation:
    tb->cs         = ti->cs;
    tb->eip        = ti->address;
    if ( TI_GET_IF(ti) )
        d->shared_info->vcpu_data[0].evtchn_upcall_mask = 1;
    return 0;

 gp_in_kernel:

    if ( likely((fixup = search_exception_table(regs->eip)) != 0) )
    {
        DPRINTK("GPF (%04lx): %08lx -> %08lx\n", error_code, regs->eip, fixup);
        regs->eip = fixup;
        return 0;
    }

    DEBUGGER_trap_fatal(TRAP_gp_fault, regs, error_code);

    show_registers(regs);
    panic("CPU%d GENERAL PROTECTION FAULT\n"
          "[error_code=%08x]\n", smp_processor_id(), error_code);
    return 0;
}

asmlinkage void mem_parity_error(struct xen_regs *regs)
{
    console_force_unlock();
    printk("\n\nNMI - MEMORY ERROR\n");
    fatal_trap(TRAP_nmi, regs, 0);
}

asmlinkage void io_check_error(struct xen_regs *regs)
{
    console_force_unlock();

    printk("\n\nNMI - I/O ERROR\n");
    fatal_trap(TRAP_nmi, regs, 0);
}

static void unknown_nmi_error(unsigned char reason, struct xen_regs * regs)
{
    printk("Uhhuh. NMI received for unknown reason %02x.\n", reason);
    printk("Dazed and confused, but trying to continue\n");
    printk("Do you have a strange power saving mode enabled?\n");
}

asmlinkage void do_nmi(struct xen_regs * regs, unsigned long reason)
{
    ++nmi_count(smp_processor_id());

#if CONFIG_X86_LOCAL_APIC
    if ( nmi_watchdog )
        nmi_watchdog_tick(regs);
    else
#endif
        unknown_nmi_error((unsigned char)(reason&0xff), regs);
}

unsigned long nmi_softirq_reason;
static void nmi_softirq(void)
{
    if ( dom0 == NULL )
        return;

    if ( test_and_clear_bit(0, &nmi_softirq_reason) )
        send_guest_virq(dom0, VIRQ_PARITY_ERR);

    if ( test_and_clear_bit(1, &nmi_softirq_reason) )
        send_guest_virq(dom0, VIRQ_IO_ERR);
}

asmlinkage int math_state_restore(struct xen_regs *regs, long error_code)
{
    /* Prevent recursion. */
    clts();

    if ( !test_bit(DF_USEDFPU, &current->flags) )
    {
        if ( test_bit(DF_DONEFPUINIT, &current->flags) )
            restore_fpu(current);
        else
            init_fpu();
        set_bit(DF_USEDFPU, &current->flags); /* so we fnsave on switch_to() */
    }

    if ( test_and_clear_bit(DF_GUEST_STTS, &current->flags) )
    {
        struct trap_bounce *tb = &current->thread.trap_bounce;
        tb->flags      = TBF_TRAP_NOCODE;
        tb->cs         = current->thread.traps[7].cs;
        tb->eip        = current->thread.traps[7].address;
    }

    return EXCRET_fault_fixed;
}

asmlinkage int do_debug(struct xen_regs *regs, long error_code)
{
    unsigned int condition;
    struct domain *d = current;
    struct trap_bounce *tb = &d->thread.trap_bounce;

    DEBUGGER_trap_entry(TRAP_debug, regs, error_code);

    __asm__ __volatile__("movl %%db6,%0" : "=r" (condition));

    /* Mask out spurious debug traps due to lazy DR7 setting */
    if ( (condition & (DR_TRAP0|DR_TRAP1|DR_TRAP2|DR_TRAP3)) &&
         (d->thread.debugreg[7] == 0) )
    {
        __asm__("movl %0,%%db7" : : "r" (0));
        goto out;
    }

    if ( (regs->cs & 3) == 0 )
    {
        /* Clear TF just for absolute sanity. */
        regs->eflags &= ~EF_TF;
        /*
         * We ignore watchpoints when they trigger within Xen. This may happen
         * when a buffer is passed to us which previously had a watchpoint set
         * on it. No need to bump EIP; the only faulting trap is an instruction
         * breakpoint, which can't happen to us.
         */
        goto out;
    }

    /* Save debug status register where guest OS can peek at it */
    d->thread.debugreg[6] = condition;

    tb->flags = TBF_TRAP_NOCODE;
    tb->cs    = d->thread.traps[1].cs;
    tb->eip   = d->thread.traps[1].address;

 out:
    return EXCRET_not_a_fault;
}

asmlinkage int do_spurious_interrupt_bug(
    struct xen_regs * regs, long error_code)
{
    return EXCRET_not_a_fault;
}

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

static void set_task_gate(unsigned int n, unsigned int sel)
{
    idt_table[n].a = sel << 16;
    idt_table[n].b = 0x8500;
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
    _set_tssldt_desc(gdt_table+__TSS(n), (int)addr, 8299, 0x89);
}

void __init trap_init(void)
{
    /*
     * Make a separate task for double faults. This will get us debug output if
     * we blow the kernel stack.
     */
    struct tss_struct *tss = &doublefault_tss;
    memset(tss, 0, sizeof(*tss));
    tss->ds     = __HYPERVISOR_DS;
    tss->es     = __HYPERVISOR_DS;
    tss->ss     = __HYPERVISOR_DS;
    tss->esp    = (unsigned long)
        &doublefault_stack[DOUBLEFAULT_STACK_SIZE];
    tss->__cr3  = __pa(idle_pg_table);
    tss->cs     = __HYPERVISOR_CS;
    tss->eip    = (unsigned long)do_double_fault;
    tss->eflags = 2;
    tss->bitmap = IOBMP_INVALID_OFFSET;
    _set_tssldt_desc(gdt_table+__DOUBLEFAULT_TSS_ENTRY,
                     (int)tss, 235, 0x89);

    /*
     * Note that interrupt gates are always used, rather than trap gates. We 
     * must have interrupts disabled until DS/ES/FS/GS are saved because the 
     * first activation must have the "bad" value(s) for these registers and 
     * we may lose them if another activation is installed before they are 
     * saved. The page-fault handler also needs interrupts disabled until %cr2 
     * has been read and saved on the stack.
     */
    set_intr_gate(TRAP_divide_error,&divide_error);
    set_intr_gate(TRAP_debug,&debug);
    set_intr_gate(TRAP_nmi,&nmi);
    set_system_gate(TRAP_int3,&int3);         /* usable from all privileges */
    set_system_gate(TRAP_overflow,&overflow); /* usable from all privileges */
    set_intr_gate(TRAP_bounds,&bounds);
    set_intr_gate(TRAP_invalid_op,&invalid_op);
    set_intr_gate(TRAP_no_device,&device_not_available);
    set_task_gate(TRAP_double_fault,__DOUBLEFAULT_TSS_ENTRY<<3);
    set_intr_gate(TRAP_copro_seg,&coprocessor_segment_overrun);
    set_intr_gate(TRAP_invalid_tss,&invalid_TSS);
    set_intr_gate(TRAP_no_segment,&segment_not_present);
    set_intr_gate(TRAP_stack_error,&stack_segment);
    set_intr_gate(TRAP_gp_fault,&general_protection);
    set_intr_gate(TRAP_page_fault,&page_fault);
    set_intr_gate(TRAP_spurious_int,&spurious_interrupt_bug);
    set_intr_gate(TRAP_copro_error,&coprocessor_error);
    set_intr_gate(TRAP_alignment_check,&alignment_check);
    set_intr_gate(TRAP_machine_check,&machine_check);
    set_intr_gate(TRAP_simd_error,&simd_coprocessor_error);

    /* Only ring 1 can access Xen services. */
    _set_gate(idt_table+HYPERCALL_VECTOR,14,1,&hypercall);

    /* CPU0 uses the master IDT. */
    idt_tables[0] = idt_table;

    /*
     * Should be a barrier for any external CPU state.
     */
    {
        extern void cpu_init(void);
        cpu_init();
    }

    open_softirq(NMI_SOFTIRQ, nmi_softirq);
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
    struct domain *d = current;

    if ( !VALID_CODESEL(event_selector) || !VALID_CODESEL(failsafe_selector) )
        return -EPERM;

    d->thread.event_selector    = event_selector;
    d->thread.event_address     = event_address;
    d->thread.failsafe_selector = failsafe_selector;
    d->thread.failsafe_address  = failsafe_address;

    return 0;
}


long set_fast_trap(struct domain *p, int idx)
{
    trap_info_t *ti;

    /* Index 0 is special: it disables fast traps. */
    if ( idx == 0 )
    {
        if ( p == current )
            CLEAR_FAST_TRAP(&p->thread);
        SET_DEFAULT_FAST_TRAP(&p->thread);
        return 0;
    }

    /*
     * We only fast-trap vectors 0x20-0x2f, and vector 0x80.
     * The former range is used by Windows and MS-DOS.
     * Vector 0x80 is used by Linux and the BSD variants.
     */
    if ( (idx != 0x80) && ((idx < 0x20) || (idx > 0x2f)) ) 
        return -1;

    ti = p->thread.traps + idx;

    /*
     * We can't virtualise interrupt gates, as there's no way to get
     * the CPU to automatically clear the events_mask variable.
     */
    if ( TI_GET_IF(ti) )
        return -1;

    if ( p == current )
        CLEAR_FAST_TRAP(&p->thread);

    p->thread.fast_trap_idx    = idx;
    p->thread.fast_trap_desc.a = (ti->cs << 16) | (ti->address & 0xffff);
    p->thread.fast_trap_desc.b = 
        (ti->address & 0xffff0000) | 0x8f00 | (TI_GET_DPL(ti)&3)<<13;

    if ( p == current )
        SET_FAST_TRAP(&p->thread);

    return 0;
}


long do_set_fast_trap(int idx)
{
    return set_fast_trap(current, idx);
}


long do_fpu_taskswitch(void)
{
    set_bit(DF_GUEST_STTS, &current->flags);
    stts();
    return 0;
}


long set_debugreg(struct domain *p, int reg, unsigned long value)
{
    int i;

    switch ( reg )
    {
    case 0: 
        if ( value > (PAGE_OFFSET-4) ) return -EPERM;
        if ( p == current ) 
            __asm__ ( "movl %0, %%db0" : : "r" (value) );
        break;
    case 1: 
        if ( value > (PAGE_OFFSET-4) ) return -EPERM;
        if ( p == current ) 
            __asm__ ( "movl %0, %%db1" : : "r" (value) );
        break;
    case 2: 
        if ( value > (PAGE_OFFSET-4) ) return -EPERM;
        if ( p == current ) 
            __asm__ ( "movl %0, %%db2" : : "r" (value) );
        break;
    case 3:
        if ( value > (PAGE_OFFSET-4) ) return -EPERM;
        if ( p == current ) 
            __asm__ ( "movl %0, %%db3" : : "r" (value) );
        break;
    case 6:
        /*
         * DR6: Bits 4-11,16-31 reserved (set to 1).
         *      Bit 12 reserved (set to 0).
         */
        value &= 0xffffefff; /* reserved bits => 0 */
        value |= 0xffff0ff0; /* reserved bits => 1 */
        if ( p == current ) 
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
        if ( p == current ) 
            __asm__ ( "movl %0, %%db7" : : "r" (value) );
        break;
    default:
        return -EINVAL;
    }

    p->thread.debugreg[reg] = value;
    return 0;
}

long do_set_debugreg(int reg, unsigned long value)
{
    return set_debugreg(current, reg, value);
}

unsigned long do_get_debugreg(int reg)
{
    if ( (reg < 0) || (reg > 7) ) return -EINVAL;
    return current->thread.debugreg[reg];
}

#endif /* __i386__ */
