
#include <xen/config.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <xen/irq.h>
#include <xen/symbols.h>
#include <xen/console.h>
#include <xen/sched.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <asm/msr.h>
#include <asm/shadow.h>
#include <asm/vmx.h>

void show_registers(struct cpu_user_regs *regs)
{
    unsigned long rip, rsp, rflags, cs, cr0, cr3;
    const char *context;

    if ( VMX_DOMAIN(current) && (regs->eflags == 0) )
    {
        __vmread(GUEST_RIP, &rip);
        __vmread(GUEST_RSP, &rsp);
        __vmread(GUEST_RFLAGS, &rflags);
        __vmread(GUEST_CS_SELECTOR, &cs);
        __vmread(CR0_READ_SHADOW, &cr0);
        __vmread(GUEST_CR3, &cr3);
        context = "vmx guest";
    }
    else
    {
        rip     = regs->rip;
        rflags  = regs->rflags;
        cr0     = read_cr0();
        cr3     = read_cr3();
        rsp     = regs->rsp;
        cs      = regs->cs & 0xffff;
        context = GUEST_MODE(regs) ? "guest" : "hypervisor";
    }

    printk("CPU:    %d\nRIP:    %04lx:[<%016lx>]",
           smp_processor_id(), cs, rip);
    if ( !GUEST_MODE(regs) )
        print_symbol(" %s", rip);
    printk("\nRFLAGS: %016lx   CONTEXT: %s\n", rflags, context);
    printk("rax: %016lx   rbx: %016lx   rcx: %016lx\n",
           regs->rax, regs->rbx, regs->rcx);
    printk("rdx: %016lx   rsi: %016lx   rdi: %016lx\n",
           regs->rdx, regs->rsi, regs->rdi);
    printk("rbp: %016lx   rsp: %016lx   r8:  %016lx\n",
           regs->rbp, rsp, regs->r8);
    printk("r9:  %016lx   r10: %016lx   r11: %016lx\n",
           regs->r9,  regs->r10, regs->r11);
    printk("r12: %016lx   r13: %016lx   r14: %016lx\n",
           regs->r12, regs->r13, regs->r14);
    printk("r15: %016lx   cr0: %016lx   cr3: %016lx\n",
           regs->r15, cr0, cr3);

    show_stack(regs);
}

void show_page_walk(unsigned long addr)
{
    unsigned long page = read_cr3();
    
    printk("Pagetable walk from %016lx:\n", addr);

    page &= PAGE_MASK;
    page = ((unsigned long *) __va(page))[l4_table_offset(addr)];
    printk(" L4 = %016lx\n", page);
    if ( !(page & _PAGE_PRESENT) )
        return;

    page &= PAGE_MASK;
    page = ((unsigned long *) __va(page))[l3_table_offset(addr)];
    printk("  L3 = %016lx\n", page);
    if ( !(page & _PAGE_PRESENT) )
        return;

    page &= PAGE_MASK;
    page = ((unsigned long *) __va(page))[l2_table_offset(addr)];
    printk("   L2 = %016lx %s\n", page, (page & _PAGE_PSE) ? "(2MB)" : "");
    if ( !(page & _PAGE_PRESENT) || (page & _PAGE_PSE) )
        return;

    page &= PAGE_MASK;
    page = ((unsigned long *) __va(page))[l1_table_offset(addr)];
    printk("    L1 = %016lx\n", page);
}

asmlinkage void double_fault(void);
asmlinkage void do_double_fault(struct cpu_user_regs *regs)
{
    watchdog_disable();

    console_force_unlock();

    /* Find information saved during fault and dump it to the console. */
    printk("************************************\n");
    show_registers(regs);
    printk("************************************\n");
    printk("CPU%d DOUBLE FAULT -- system shutdown\n", smp_processor_id());
    printk("System needs manual reset.\n");
    printk("************************************\n");

    /* Lock up the console to prevent spurious output from other CPUs. */
    console_force_lock();

    /* Wait for manual reset. */
    for ( ; ; )
        __asm__ __volatile__ ( "hlt" );
}

extern void toggle_guest_mode(struct vcpu *);

long do_iret(void)
{
    struct cpu_user_regs  *regs = guest_cpu_user_regs();
    struct iret_context iret_saved;
    struct vcpu    *v = current;

    if ( unlikely(copy_from_user(&iret_saved, (void *)regs->rsp, sizeof(iret_saved))) ||
         unlikely(pagetable_get_paddr(v->arch.guest_table_user) == 0) )
        return -EFAULT;

    /* returning to user mode */
    if ((iret_saved.cs & 0x03) == 3)
        toggle_guest_mode(v);

    regs->rip    = iret_saved.rip;
    regs->cs     = iret_saved.cs | 3; /* force guest privilege */
    regs->rflags = (iret_saved.rflags & ~(EF_IOPL|EF_VM)) | EF_IE;
    regs->rsp    = iret_saved.rsp;
    regs->ss     = iret_saved.ss | 3; /* force guest privilege */

    if ( !(iret_saved.flags & VGCF_IN_SYSCALL) )
    {
        regs->entry_vector = 0;
        regs->r11 = iret_saved.r11;
        regs->rcx = iret_saved.rcx;
    }

    /* No longer in NMI context */
    clear_bit(_VCPUF_nmi_masked, &current->vcpu_flags);

    /* Saved %rax gets written back to regs->rax in entry.S. */
    return iret_saved.rax;
}

asmlinkage void syscall_enter(void);
void __init percpu_traps_init(void)
{
    char *stack_bottom, *stack;
    int   cpu = smp_processor_id();

    if ( cpu == 0 )
    {
        /* Specify dedicated interrupt stacks for NMIs and double faults. */
        set_intr_gate(TRAP_double_fault, &double_fault);
        idt_table[TRAP_double_fault].a |= 1UL << 32; /* IST1 */
        idt_table[TRAP_nmi].a          |= 2UL << 32; /* IST2 */
    }

    stack_bottom = (char *)get_stack_bottom();
    stack        = (char *)((unsigned long)stack_bottom & ~(STACK_SIZE - 1));

    /* Double-fault handler has its own per-CPU 1kB stack. */
    init_tss[cpu].ist[0] = (unsigned long)&stack[1024];

    /* NMI handler has its own per-CPU 1kB stack. */
    init_tss[cpu].ist[1] = (unsigned long)&stack[2048];

    /*
     * Trampoline for SYSCALL entry from long mode.
     */

    /* Skip the NMI and DF stacks. */
    stack = &stack[2048];
    wrmsr(MSR_LSTAR, (unsigned long)stack, ((unsigned long)stack>>32)); 

    /* movq %rsp, saversp(%rip) */
    stack[0] = 0x48;
    stack[1] = 0x89;
    stack[2] = 0x25;
    *(u32 *)&stack[3] = (stack_bottom - &stack[7]) - 16;

    /* leaq saversp(%rip), %rsp */
    stack[7] = 0x48;
    stack[8] = 0x8d;
    stack[9] = 0x25;
    *(u32 *)&stack[10] = (stack_bottom - &stack[14]) - 16;

    /* pushq %r11 */
    stack[14] = 0x41;
    stack[15] = 0x53;

    /* pushq $__GUEST_CS64 */
    stack[16] = 0x68;
    *(u32 *)&stack[17] = __GUEST_CS64;

    /* jmp syscall_enter */
    stack[21] = 0xe9;
    *(u32 *)&stack[22] = (char *)syscall_enter - &stack[26];

    /*
     * Trampoline for SYSCALL entry from compatibility mode.
     */

    /* Skip the long-mode entry trampoline. */
    stack = &stack[26];
    wrmsr(MSR_CSTAR, (unsigned long)stack, ((unsigned long)stack>>32)); 

    /* movq %rsp, saversp(%rip) */
    stack[0] = 0x48;
    stack[1] = 0x89;
    stack[2] = 0x25;
    *(u32 *)&stack[3] = (stack_bottom - &stack[7]) - 16;

    /* leaq saversp(%rip), %rsp */
    stack[7] = 0x48;
    stack[8] = 0x8d;
    stack[9] = 0x25;
    *(u32 *)&stack[10] = (stack_bottom - &stack[14]) - 16;

    /* pushq %r11 */
    stack[14] = 0x41;
    stack[15] = 0x53;

    /* pushq $__GUEST_CS32 */
    stack[16] = 0x68;
    *(u32 *)&stack[17] = __GUEST_CS32;

    /* jmp syscall_enter */
    stack[21] = 0xe9;
    *(u32 *)&stack[22] = (char *)syscall_enter - &stack[26];

    /*
     * Common SYSCALL parameters.
     */

    wrmsr(MSR_STAR, 0, (FLAT_RING3_CS32<<16) | __HYPERVISOR_CS);
    wrmsr(MSR_SYSCALL_MASK, EF_VM|EF_RF|EF_NT|EF_DF|EF_IE|EF_TF, 0U);
}

long do_set_callbacks(unsigned long event_address,
                      unsigned long failsafe_address,
                      unsigned long syscall_address)
{
    struct vcpu *d = current;

    d->arch.guest_context.event_callback_eip    = event_address;
    d->arch.guest_context.failsafe_callback_eip = failsafe_address;
    d->arch.guest_context.syscall_callback_eip  = syscall_address;

    return 0;
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
