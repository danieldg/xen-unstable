/*
 *  linux/arch/i386/kernel/process.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 */

/*
 * This file handles the architecture-dependent parts of process handling..
 */

#define __KERNEL_SYSCALLS__
#include <xeno/config.h>
#include <xeno/lib.h>
#include <xeno/errno.h>
#include <xeno/sched.h>
#include <xeno/smp.h>
#include <asm/ptrace.h>
#include <xeno/delay.h>
#include <xeno/interrupt.h>
#include <asm/mc146818rtc.h>

#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/i387.h>

#include <xeno/irq.h>
#include <xeno/event.h>

#define GET_SYSCALL_REGS(_p) \
    (((struct pt_regs *)(THREAD_SIZE + (unsigned long)(_p))) - 1)

asmlinkage void ret_from_newdomain(void) __asm__("ret_from_newdomain");

int hlt_counter;

void disable_hlt(void)
{
    hlt_counter++;
}

void enable_hlt(void)
{
    hlt_counter--;
}

/*
 * We use this if we don't have any better
 * idle routine..
 */
static void default_idle(void)
{
    if (!hlt_counter) {
        __cli();
        if (!current->hyp_events && !softirq_pending(smp_processor_id()))
            safe_halt();
        else
            __sti();
    }
}

/*
 * The idle thread. There's no useful work to be
 * done, so just try to conserve power and have a
 * low exit latency (ie sit in a loop waiting for
 * somebody to say that they'd like to reschedule)
 */
void cpu_idle (void)
{
    int cpu = smp_processor_id();

    ASSERT(current->domain == IDLE_DOMAIN_ID);

    current->has_cpu = 1;
    (void)wake_up(current);
    schedule();

    /*
     * Declares CPU setup done to the boot processor.
     * Therefore memory barrier to ensure state is visible.
     */
    smp_mb();
    init_idle();

    for ( ; ; )
    {
        irq_stat[cpu].idle_timestamp = jiffies;
        while (!current->hyp_events && !softirq_pending(cpu))
            default_idle();
        do_hyp_events();
        do_softirq();
    }
}

static long no_idt[2];
static int reboot_mode;
int reboot_thru_bios = 0;

#ifdef CONFIG_SMP
int reboot_smp = 0;
static int reboot_cpu = -1;
/* shamelessly grabbed from lib/vsprintf.c for readability */
#define is_digit(c)	((c) >= '0' && (c) <= '9')
#endif


static inline void kb_wait(void)
{
    int i;

    for (i=0; i<0x10000; i++)
        if ((inb_p(0x64) & 0x02) == 0)
            break;
}


void machine_restart(char * __unused)
{
#if CONFIG_SMP
    int cpuid;
	
    cpuid = GET_APIC_ID(apic_read(APIC_ID));

    if (reboot_smp) {

        /* check to see if reboot_cpu is valid 
           if its not, default to the BSP */
        if ((reboot_cpu == -1) ||  
            (reboot_cpu > (NR_CPUS -1))  || 
            !(phys_cpu_present_map & (1<<cpuid))) 
            reboot_cpu = boot_cpu_physical_apicid;

        reboot_smp = 0;  /* use this as a flag to only go through this once*/
        /* re-run this function on the other CPUs
           it will fall though this section since we have 
           cleared reboot_smp, and do the reboot if it is the
           correct CPU, otherwise it halts. */
        if (reboot_cpu != cpuid)
            smp_call_function((void *)machine_restart , NULL, 1, 0);
    }

    /* if reboot_cpu is still -1, then we want a tradional reboot, 
       and if we are not running on the reboot_cpu,, halt */
    if ((reboot_cpu != -1) && (cpuid != reboot_cpu)) {
        for (;;)
            __asm__ __volatile__ ("hlt");
    }
    /*
     * Stop all CPUs and turn off local APICs and the IO-APIC, so
     * other OSs see a clean IRQ state.
     */
    smp_send_stop();
    disable_IO_APIC();
#endif

    if(!reboot_thru_bios) {
        /* rebooting needs to touch the page at absolute addr 0 */
        *((unsigned short *)__va(0x472)) = reboot_mode;
        for (;;) {
            int i;
            for (i=0; i<100; i++) {
                kb_wait();
                udelay(50);
                outb(0xfe,0x64);         /* pulse reset low */
                udelay(50);
            }
            /* That didn't work - force a triple fault.. */
            __asm__ __volatile__("lidt %0": :"m" (no_idt));
            __asm__ __volatile__("int3");
        }
    }

    panic("Need to reinclude BIOS reboot code\n");
}

void machine_halt(void)
{
    machine_restart(0);
}

void machine_power_off(void)
{
    machine_restart(0);
}

extern void show_trace(unsigned long* esp);

void show_regs(struct pt_regs * regs)
{
    unsigned long cr0 = 0L, cr2 = 0L, cr3 = 0L, cr4 = 0L;

    printk("\n");
    printk("EIP: %04x:[<%08lx>] CPU: %d",0xffff & regs->xcs,regs->eip, smp_processor_id());
    if (regs->xcs & 3)
        printk(" ESP: %04x:%08lx",0xffff & regs->xss,regs->esp);
    printk(" EFLAGS: %08lx\n",regs->eflags);
    printk("EAX: %08lx EBX: %08lx ECX: %08lx EDX: %08lx\n",
           regs->eax,regs->ebx,regs->ecx,regs->edx);
    printk("ESI: %08lx EDI: %08lx EBP: %08lx",
           regs->esi, regs->edi, regs->ebp);
    printk(" DS: %04x ES: %04x FS: %04x GS: %04x\n",
           0xffff & regs->xds, 0xffff & regs->xes,
           0xffff & regs->xfs, 0xffff & regs->xgs);

    __asm__("movl %%cr0, %0": "=r" (cr0));
    __asm__("movl %%cr2, %0": "=r" (cr2));
    __asm__("movl %%cr3, %0": "=r" (cr3));
    /* This could fault if %cr4 does not exist */
    __asm__("1: movl %%cr4, %0		\n"
            "2:				\n"
            ".section __ex_table,\"a\"	\n"
            ".long 1b,2b			\n"
            ".previous			\n"
            : "=r" (cr4): "0" (0));
    printk("CR0: %08lx CR2: %08lx CR3: %08lx CR4: %08lx\n", cr0, cr2, cr3, cr4);
    show_trace(&regs->esp);
}


/*
 * Free current thread data structures etc..
 */
void exit_thread(void)
{
    /* nothing to do ... */
}

void flush_thread(void)
{
    struct task_struct *tsk = current;

    memset(tsk->thread.debugreg, 0, sizeof(unsigned long)*8);
    /*
     * Forget coprocessor state..
     */
    clear_fpu(tsk);
    tsk->flags &= ~PF_DONEFPUINIT;
}

void release_thread(struct task_struct *dead_task)
{
}

void new_thread(struct task_struct *p,
                unsigned long start_pc,
                unsigned long start_stack,
                unsigned long start_info)
{
    struct pt_regs *regs = GET_SYSCALL_REGS(p);
    memset(regs, 0, sizeof(*regs));

    /*
     * Initial register values:
     *  DS,ES,FS,GS = FLAT_RING1_DS
     *       CS:EIP = FLAT_RING1_CS:start_pc
     *       SS:ESP = FLAT_RING1_DS:start_stack
     *          ESI = start_info
     *  [EAX,EBX,ECX,EDX,EDI,EBP are zero]
     */
    p->thread.fs = p->thread.gs = FLAT_RING1_DS;
    regs->xds = regs->xes = regs->xfs = regs->xgs = regs->xss = FLAT_RING1_DS;
    regs->xcs = FLAT_RING1_CS;
    regs->eip = start_pc;
    regs->esp = start_stack;
    regs->esi = start_info;

    p->thread.esp = (unsigned long) regs;
    p->thread.esp0 = (unsigned long) (regs+1);

    p->thread.eip = (unsigned long) ret_from_newdomain;

    __save_flags(regs->eflags);
    regs->eflags |= X86_EFLAGS_IF;

    /* No fast trap at start of day. */
    SET_DEFAULT_FAST_TRAP(&p->thread);
}


/*
 * This special macro can be used to load a debugging register
 */
#define loaddebug(thread,register) \
		__asm__("movl %0,%%db" #register  \
			: /* no output */ \
			:"r" (thread->debugreg[register]))

/*
 *	switch_to(x,yn) should switch tasks from x to y.
 *
 * We fsave/fwait so that an exception goes off at the right time
 * (as a call from the fsave or fwait in effect) rather than to
 * the wrong process. Lazy FP saving no longer makes any sense
 * with modern CPU's, and this simplifies a lot of things (SMP
 * and UP become the same).
 *
 * NOTE! We used to use the x86 hardware context switching. The
 * reason for not using it any more becomes apparent when you
 * try to recover gracefully from saved state that is no longer
 * valid (stale segment register values in particular). With the
 * hardware task-switch, there is no way to fix up bad state in
 * a reasonable manner.
 *
 * The fact that Intel documents the hardware task-switching to
 * be slow is a fairly red herring - this code is not noticeably
 * faster. However, there _is_ some room for improvement here,
 * so the performance issues may eventually be a valid point.
 * More important, however, is the fact that this allows us much
 * more flexibility.
 */
/* NB. prev_p passed in %eax, next_p passed in %edx */
void __switch_to(struct task_struct *prev_p, struct task_struct *next_p)
{
    struct thread_struct *next = &next_p->thread;
    struct tss_struct *tss = init_tss + smp_processor_id();

    unlazy_fpu(prev_p);

    /* Switch the fast-trap handler. */
    CLEAR_FAST_TRAP(&prev_p->thread);
    SET_FAST_TRAP(&next_p->thread);

    tss->esp0 = next->esp0;
    tss->esp1 = next->esp1;
    tss->ss1  = next->ss1;

    /* Switch GDT and LDT. */
    __asm__ __volatile__ ("lgdt %0" : "=m" (*next_p->mm.gdt));
    load_LDT();

    /*
     * Now maybe reload the debug registers
     */
    if (next->debugreg[7]){
        loaddebug(next, 0);
        loaddebug(next, 1);
        loaddebug(next, 2);
        loaddebug(next, 3);
        /* no 4 and 5 */
        loaddebug(next, 6);
        loaddebug(next, 7);
    }

}


/* XXX Currently the 'domain' field is ignored! XXX */
long do_iopl(unsigned int domain, unsigned int new_io_pl)
{
    struct pt_regs *regs = GET_SYSCALL_REGS(current);
    regs->eflags = (regs->eflags & 0xffffcfff) | ((new_io_pl&3) << 12);
    return 0;
}
