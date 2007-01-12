/*
 *  linux/arch/x86-64/kernel/process.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 * 
 *  X86-64 port
 *	Andi Kleen.
 *
 *	CPU hotplug support - ashok.raj@intel.com
 *  $Id: process.c,v 1.38 2002/01/15 10:08:03 ak Exp $
 * 
 *  Jun Nakajima <jun.nakajima@intel.com> 
 *     Modified for Xen
 */

/*
 * This file handles the architecture-dependent parts of process handling..
 */

#include <stdarg.h>

#include <linux/cpu.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/elfcore.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/user.h>
#include <linux/module.h>
#include <linux/a.out.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/ptrace.h>
#include <linux/utsname.h>
#include <linux/random.h>
#include <linux/notifier.h>
#include <linux/kprobes.h>

#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/i387.h>
#include <asm/mmu_context.h>
#include <asm/pda.h>
#include <asm/prctl.h>
#include <asm/kdebug.h>
#include <xen/interface/dom0_ops.h>
#include <xen/interface/physdev.h>
#include <xen/interface/vcpu.h>
#include <asm/desc.h>
#include <asm/proto.h>
#include <asm/hardirq.h>
#include <asm/ia32.h>
#include <asm/idle.h>

#include <xen/cpu_hotplug.h>

asmlinkage extern void ret_from_fork(void);

unsigned long kernel_thread_flags = CLONE_VM | CLONE_UNTRACED;

unsigned long boot_option_idle_override = 0;
EXPORT_SYMBOL(boot_option_idle_override);

/*
 * Powermanagement idle function, if any..
 */
void (*pm_idle)(void);
static DEFINE_PER_CPU(unsigned int, cpu_idle_state);

static ATOMIC_NOTIFIER_HEAD(idle_notifier);

void idle_notifier_register(struct notifier_block *n)
{
	atomic_notifier_chain_register(&idle_notifier, n);
}
EXPORT_SYMBOL_GPL(idle_notifier_register);

void idle_notifier_unregister(struct notifier_block *n)
{
	atomic_notifier_chain_unregister(&idle_notifier, n);
}
EXPORT_SYMBOL(idle_notifier_unregister);

enum idle_state { CPU_IDLE, CPU_NOT_IDLE };
static DEFINE_PER_CPU(enum idle_state, idle_state) = CPU_NOT_IDLE;

void enter_idle(void)
{
	__get_cpu_var(idle_state) = CPU_IDLE;
	atomic_notifier_call_chain(&idle_notifier, IDLE_START, NULL);
}

static void __exit_idle(void)
{
	__get_cpu_var(idle_state) = CPU_NOT_IDLE;
	atomic_notifier_call_chain(&idle_notifier, IDLE_END, NULL);
}

/* Called from interrupts to signify idle end */
void exit_idle(void)
{
	if (current->pid | read_pda(irqcount))
		return;
	__exit_idle();
}

/*
 * On SMP it's slightly faster (but much more power-consuming!)
 * to poll the ->need_resched flag instead of waiting for the
 * cross-CPU IPI to arrive. Use this option with caution.
 */
static void poll_idle(void)
{
	local_irq_enable();

	asm volatile(
		"2:"
		"testl %0,%1;"
		"rep; nop;"
		"je 2b;"
		: :
		"i" (_TIF_NEED_RESCHED),
		"m" (current_thread_info()->flags));
}

static void xen_idle(void)
{
	local_irq_disable();

	if (need_resched())
		local_irq_enable();
	else {
		clear_thread_flag(TIF_POLLING_NRFLAG);
		smp_mb__after_clear_bit();
		safe_halt();
		set_thread_flag(TIF_POLLING_NRFLAG);
	}
}

#ifdef CONFIG_HOTPLUG_CPU
static inline void play_dead(void)
{
	idle_task_exit();
	local_irq_disable();
	cpu_clear(smp_processor_id(), cpu_initialized);
	preempt_enable_no_resched();
	HYPERVISOR_vcpu_op(VCPUOP_down, smp_processor_id(), NULL);
	cpu_bringup();
}
#else
static inline void play_dead(void)
{
	BUG();
}
#endif /* CONFIG_HOTPLUG_CPU */

/*
 * The idle thread. There's no useful work to be
 * done, so just try to conserve power and have a
 * low exit latency (ie sit in a loop waiting for
 * somebody to say that they'd like to reschedule)
 */
void cpu_idle (void)
{
	set_thread_flag(TIF_POLLING_NRFLAG);

	/* endless idle loop with no priority at all */
	while (1) {
		while (!need_resched()) {
			void (*idle)(void);

			if (__get_cpu_var(cpu_idle_state))
				__get_cpu_var(cpu_idle_state) = 0;
			rmb();
			idle = pm_idle;
			if (!idle)
				idle = xen_idle;
			if (cpu_is_offline(smp_processor_id()))
				play_dead();
			enter_idle();
			idle();
			__exit_idle();
		}

		preempt_enable_no_resched();
		schedule();
		preempt_disable();
	}
}

void cpu_idle_wait(void)
{
	unsigned int cpu, this_cpu = get_cpu();
	cpumask_t map;

	set_cpus_allowed(current, cpumask_of_cpu(this_cpu));
	put_cpu();

 	cpus_clear(map);
	for_each_online_cpu(cpu) {
		per_cpu(cpu_idle_state, cpu) = 1;
		cpu_set(cpu, map);
	}

	__get_cpu_var(cpu_idle_state) = 0;

	wmb();
	do {
		ssleep(1);
		for_each_online_cpu(cpu) {
			if (cpu_isset(cpu, map) &&
					!per_cpu(cpu_idle_state, cpu))
				cpu_clear(cpu, map);
		}
		cpus_and(map, map, cpu_online_map);
	} while (!cpus_empty(map));
}
EXPORT_SYMBOL_GPL(cpu_idle_wait);

void __cpuinit select_idle_routine(const struct cpuinfo_x86 *c) 
{
}

static int __init idle_setup (char *str)
{
	if (!strncmp(str, "poll", 4)) {
		printk("using polling idle threads.\n");
		pm_idle = poll_idle;
	}

	boot_option_idle_override = 1;
	return 1;
}

__setup("idle=", idle_setup);

/* Prints also some state that isn't saved in the pt_regs */ 
void __show_regs(struct pt_regs * regs)
{
	unsigned long fs, gs, shadowgs;
	unsigned int fsindex,gsindex;
	unsigned int ds,cs,es; 

	printk("\n");
	print_modules();
	printk("Pid: %d, comm: %.20s %s %s %.*s\n",
		current->pid, current->comm, print_tainted(),
		system_utsname.release,
		(int)strcspn(system_utsname.version, " "),
		system_utsname.version);
	printk("RIP: %04lx:[<%016lx>] ", regs->cs & 0xffff, regs->rip);
	printk_address(regs->rip); 
	printk("\nRSP: %04lx:%016lx  EFLAGS: %08lx\n", regs->ss, regs->rsp,
		regs->eflags);
	printk("RAX: %016lx RBX: %016lx RCX: %016lx\n",
	       regs->rax, regs->rbx, regs->rcx);
	printk("RDX: %016lx RSI: %016lx RDI: %016lx\n",
	       regs->rdx, regs->rsi, regs->rdi); 
	printk("RBP: %016lx R08: %016lx R09: %016lx\n",
	       regs->rbp, regs->r8, regs->r9); 
	printk("R10: %016lx R11: %016lx R12: %016lx\n",
	       regs->r10, regs->r11, regs->r12); 
	printk("R13: %016lx R14: %016lx R15: %016lx\n",
	       regs->r13, regs->r14, regs->r15); 

	asm("mov %%ds,%0" : "=r" (ds)); 
	asm("mov %%cs,%0" : "=r" (cs)); 
	asm("mov %%es,%0" : "=r" (es)); 
	asm("mov %%fs,%0" : "=r" (fsindex));
	asm("mov %%gs,%0" : "=r" (gsindex));

	rdmsrl(MSR_FS_BASE, fs);
	rdmsrl(MSR_GS_BASE, gs); 
	rdmsrl(MSR_KERNEL_GS_BASE, shadowgs); 

	printk("FS:  %016lx(%04x) GS:%016lx(%04x) knlGS:%016lx\n", 
	       fs,fsindex,gs,gsindex,shadowgs); 
	printk("CS:  %04x DS: %04x ES: %04x\n", cs, ds, es); 

}

void show_regs(struct pt_regs *regs)
{
	printk("CPU %d:", smp_processor_id());
	__show_regs(regs);
	show_trace(&regs->rsp);
}

/*
 * Free current thread data structures etc..
 */
void exit_thread(void)
{
	struct task_struct *me = current;
	struct thread_struct *t = &me->thread;

	if (me->thread.io_bitmap_ptr) { 
#ifndef CONFIG_X86_NO_TSS
		struct tss_struct *tss = &per_cpu(init_tss, get_cpu());
#endif
#ifdef CONFIG_XEN
		struct physdev_set_iobitmap iobmp_op = { 0 };
#endif

		kfree(t->io_bitmap_ptr);
		t->io_bitmap_ptr = NULL;
		/*
		 * Careful, clear this in the TSS too:
		 */
#ifndef CONFIG_X86_NO_TSS
		memset(tss->io_bitmap, 0xff, t->io_bitmap_max);
		put_cpu();
#endif
#ifdef CONFIG_XEN
		HYPERVISOR_physdev_op(PHYSDEVOP_set_iobitmap, &iobmp_op);
#endif
		t->io_bitmap_max = 0;
	}
}

void load_gs_index(unsigned gs)
{
	HYPERVISOR_set_segment_base(SEGBASE_GS_USER_SEL, gs);
}

void flush_thread(void)
{
	struct task_struct *tsk = current;
	struct thread_info *t = current_thread_info();

	if (t->flags & _TIF_ABI_PENDING)
		t->flags ^= (_TIF_ABI_PENDING | _TIF_IA32);

	tsk->thread.debugreg0 = 0;
	tsk->thread.debugreg1 = 0;
	tsk->thread.debugreg2 = 0;
	tsk->thread.debugreg3 = 0;
	tsk->thread.debugreg6 = 0;
	tsk->thread.debugreg7 = 0;
	memset(tsk->thread.tls_array, 0, sizeof(tsk->thread.tls_array));	
	/*
	 * Forget coprocessor state..
	 */
	clear_fpu(tsk);
	clear_used_math();
}

void release_thread(struct task_struct *dead_task)
{
	if (dead_task->mm) {
		if (dead_task->mm->context.size) {
			printk("WARNING: dead process %8s still has LDT? <%p/%d>\n",
					dead_task->comm,
					dead_task->mm->context.ldt,
					dead_task->mm->context.size);
			BUG();
		}
	}
}

static inline void set_32bit_tls(struct task_struct *t, int tls, u32 addr)
{
	struct user_desc ud = { 
		.base_addr = addr,
		.limit = 0xfffff,
		.seg_32bit = 1,
		.limit_in_pages = 1,
		.useable = 1,
	};
	struct n_desc_struct *desc = (void *)t->thread.tls_array;
	desc += tls;
	desc->a = LDT_entry_a(&ud); 
	desc->b = LDT_entry_b(&ud); 
}

static inline u32 read_32bit_tls(struct task_struct *t, int tls)
{
	struct desc_struct *desc = (void *)t->thread.tls_array;
	desc += tls;
	return desc->base0 | 
		(((u32)desc->base1) << 16) | 
		(((u32)desc->base2) << 24);
}

/*
 * This gets called before we allocate a new thread and copy
 * the current task into it.
 */
void prepare_to_copy(struct task_struct *tsk)
{
	unlazy_fpu(tsk);
}

int copy_thread(int nr, unsigned long clone_flags, unsigned long rsp, 
		unsigned long unused,
	struct task_struct * p, struct pt_regs * regs)
{
	int err;
	struct pt_regs * childregs;
	struct task_struct *me = current;

	childregs = ((struct pt_regs *)
			(THREAD_SIZE + task_stack_page(p))) - 1;
	*childregs = *regs;

	childregs->rax = 0;
	childregs->rsp = rsp;
	if (rsp == ~0UL)
		childregs->rsp = (unsigned long)childregs;

	p->thread.rsp = (unsigned long) childregs;
	p->thread.rsp0 = (unsigned long) (childregs+1);
	p->thread.userrsp = me->thread.userrsp; 

	set_tsk_thread_flag(p, TIF_FORK);

	p->thread.fs = me->thread.fs;
	p->thread.gs = me->thread.gs;

	asm("mov %%gs,%0" : "=m" (p->thread.gsindex));
	asm("mov %%fs,%0" : "=m" (p->thread.fsindex));
	asm("mov %%es,%0" : "=m" (p->thread.es));
	asm("mov %%ds,%0" : "=m" (p->thread.ds));

	if (unlikely(me->thread.io_bitmap_ptr != NULL)) { 
		p->thread.io_bitmap_ptr = kmalloc(IO_BITMAP_BYTES, GFP_KERNEL);
		if (!p->thread.io_bitmap_ptr) {
			p->thread.io_bitmap_max = 0;
			return -ENOMEM;
		}
		memcpy(p->thread.io_bitmap_ptr, me->thread.io_bitmap_ptr,
				IO_BITMAP_BYTES);
	} 

	/*
	 * Set a new TLS for the child thread?
	 */
	if (clone_flags & CLONE_SETTLS) {
#ifdef CONFIG_IA32_EMULATION
		if (test_thread_flag(TIF_IA32))
			err = ia32_child_tls(p, childregs); 
		else 			
#endif	 
			err = do_arch_prctl(p, ARCH_SET_FS, childregs->r8); 
		if (err) 
			goto out;
	}
        p->thread.iopl = current->thread.iopl;

	err = 0;
out:
	if (err && p->thread.io_bitmap_ptr) {
		kfree(p->thread.io_bitmap_ptr);
		p->thread.io_bitmap_max = 0;
	}
	return err;
}

static inline void __save_init_fpu( struct task_struct *tsk )
{
	asm volatile( "rex64 ; fxsave %0 ; fnclex"
		      : "=m" (tsk->thread.i387.fxsave));
	tsk->thread_info->status &= ~TS_USEDFPU;
}

/*
 *	switch_to(x,y) should switch tasks from x to y.
 *
 * This could still be optimized: 
 * - fold all the options into a flag word and test it with a single test.
 * - could test fs/gs bitsliced
 *
 * Kprobes not supported here. Set the probe on schedule instead.
 */
__kprobes struct task_struct *
__switch_to(struct task_struct *prev_p, struct task_struct *next_p)
{
	struct thread_struct *prev = &prev_p->thread,
				 *next = &next_p->thread;
	int cpu = smp_processor_id();  
#ifndef CONFIG_X86_NO_TSS
	struct tss_struct *tss = &per_cpu(init_tss, cpu);
#endif
	struct physdev_set_iopl iopl_op;
	struct physdev_set_iobitmap iobmp_op;
	multicall_entry_t _mcl[8], *mcl = _mcl;

	/*
	 * This is basically '__unlazy_fpu', except that we queue a
	 * multicall to indicate FPU task switch, rather than
	 * synchronously trapping to Xen.
	 * This must be here to ensure both math_state_restore() and
	 * kernel_fpu_begin() work consistently. 
	 * The AMD workaround requires it to be after DS reload, or
	 * after DS has been cleared, which we do in __prepare_arch_switch.
	 */
	if (prev_p->thread_info->status & TS_USEDFPU) {
		__save_init_fpu(prev_p); /* _not_ save_init_fpu() */
		mcl->op      = __HYPERVISOR_fpu_taskswitch;
		mcl->args[0] = 1;
		mcl++;
	}

	/*
	 * Reload esp0, LDT and the page table pointer:
	 */
	mcl->op      = __HYPERVISOR_stack_switch;
	mcl->args[0] = __KERNEL_DS;
	mcl->args[1] = next->rsp0;
	mcl++;

	/*
	 * Load the per-thread Thread-Local Storage descriptor.
	 * This is load_TLS(next, cpu) with multicalls.
	 */
#define C(i) do {							\
	if (unlikely(next->tls_array[i] != prev->tls_array[i])) {	\
		mcl->op      = __HYPERVISOR_update_descriptor;		\
		mcl->args[0] = virt_to_machine(				\
			&cpu_gdt(cpu)[GDT_ENTRY_TLS_MIN + i]);		\
		mcl->args[1] = next->tls_array[i];			\
		mcl++;							\
	}								\
} while (0)
	C(0); C(1); C(2);
#undef C

	if (unlikely(prev->iopl != next->iopl)) {
		iopl_op.iopl = (next->iopl == 0) ? 1 : next->iopl;
		mcl->op      = __HYPERVISOR_physdev_op;
		mcl->args[0] = PHYSDEVOP_set_iopl;
		mcl->args[1] = (unsigned long)&iopl_op;
		mcl++;
	}

	if (unlikely(prev->io_bitmap_ptr || next->io_bitmap_ptr)) {
		iobmp_op.bitmap   = (char *)next->io_bitmap_ptr;
		iobmp_op.nr_ports = next->io_bitmap_ptr ? IO_BITMAP_BITS : 0;
		mcl->op      = __HYPERVISOR_physdev_op;
		mcl->args[0] = PHYSDEVOP_set_iobitmap;
		mcl->args[1] = (unsigned long)&iobmp_op;
		mcl++;
	}

	(void)HYPERVISOR_multicall(_mcl, mcl - _mcl);
	/* 
	 * Switch DS and ES.
	 * This won't pick up thread selector changes, but I guess that is ok.
	 */
	if (unlikely(next->es))
		loadsegment(es, next->es); 
	
	if (unlikely(next->ds))
		loadsegment(ds, next->ds);

	/* 
	 * Switch FS and GS.
	 */
	if (unlikely(next->fsindex))
		loadsegment(fs, next->fsindex);

	if (next->fs)
		HYPERVISOR_set_segment_base(SEGBASE_FS, next->fs); 
	
	if (unlikely(next->gsindex))
		load_gs_index(next->gsindex);

	if (next->gs)
		HYPERVISOR_set_segment_base(SEGBASE_GS_USER, next->gs); 

	/* 
	 * Switch the PDA and FPU contexts.
	 */
	prev->userrsp = read_pda(oldrsp); 
	write_pda(oldrsp, next->userrsp); 
	write_pda(pcurrent, next_p); 
	write_pda(kernelstack,
		  task_stack_page(next_p) + THREAD_SIZE - PDA_STACKOFFSET);

	/*
	 * Now maybe reload the debug registers
	 */
	if (unlikely(next->debugreg7)) {
		set_debugreg(next->debugreg0, 0);
		set_debugreg(next->debugreg1, 1);
		set_debugreg(next->debugreg2, 2);
		set_debugreg(next->debugreg3, 3);
		/* no 4 and 5 */
		set_debugreg(next->debugreg6, 6);
		set_debugreg(next->debugreg7, 7);
	}

	return prev_p;
}

/*
 * sys_execve() executes a new program.
 */
asmlinkage 
long sys_execve(char __user *name, char __user * __user *argv,
		char __user * __user *envp, struct pt_regs regs)
{
	long error;
	char * filename;

	filename = getname(name);
	error = PTR_ERR(filename);
	if (IS_ERR(filename)) 
		return error;
	error = do_execve(filename, argv, envp, &regs); 
	if (error == 0) {
		task_lock(current);
		current->ptrace &= ~PT_DTRACE;
		task_unlock(current);
	}
	putname(filename);
	return error;
}

void set_personality_64bit(void)
{
	/* inherit personality from parent */

	/* Make sure to be in 64bit mode */
	clear_thread_flag(TIF_IA32); 

	/* TBD: overwrites user setup. Should have two bits.
	   But 64bit processes have always behaved this way,
	   so it's not too bad. The main problem is just that
   	   32bit childs are affected again. */
	current->personality &= ~READ_IMPLIES_EXEC;
}

asmlinkage long sys_fork(struct pt_regs *regs)
{
	return do_fork(SIGCHLD, regs->rsp, regs, 0, NULL, NULL);
}

asmlinkage long
sys_clone(unsigned long clone_flags, unsigned long newsp,
	  void __user *parent_tid, void __user *child_tid, struct pt_regs *regs)
{
	if (!newsp)
		newsp = regs->rsp;
	return do_fork(clone_flags, newsp, regs, 0, parent_tid, child_tid);
}

/*
 * This is trivial, and on the face of it looks like it
 * could equally well be done in user mode.
 *
 * Not so, for quite unobvious reasons - register pressure.
 * In user mode vfork() cannot have a stack frame, and if
 * done by calling the "clone()" system call directly, you
 * do not have enough call-clobbered registers to hold all
 * the information you need.
 */
asmlinkage long sys_vfork(struct pt_regs *regs)
{
	return do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, regs->rsp, regs, 0,
		    NULL, NULL);
}

unsigned long get_wchan(struct task_struct *p)
{
	unsigned long stack;
	u64 fp,rip;
	int count = 0;

	if (!p || p == current || p->state==TASK_RUNNING)
		return 0; 
	stack = (unsigned long)task_stack_page(p);
	if (p->thread.rsp < stack || p->thread.rsp > stack+THREAD_SIZE)
		return 0;
	fp = *(u64 *)(p->thread.rsp);
	do { 
		if (fp < (unsigned long)stack ||
		    fp > (unsigned long)stack+THREAD_SIZE)
			return 0; 
		rip = *(u64 *)(fp+8); 
		if (!in_sched_functions(rip))
			return rip; 
		fp = *(u64 *)fp; 
	} while (count++ < 16); 
	return 0;
}

long do_arch_prctl(struct task_struct *task, int code, unsigned long addr)
{ 
	int ret = 0; 
	int doit = task == current;
	int cpu;

	switch (code) { 
	case ARCH_SET_GS:
		if (addr >= TASK_SIZE_OF(task))
			return -EPERM; 
		cpu = get_cpu();
		/* handle small bases via the GDT because that's faster to 
		   switch. */
		if (addr <= 0xffffffff) {  
			set_32bit_tls(task, GS_TLS, addr); 
			if (doit) { 
				load_TLS(&task->thread, cpu);
				load_gs_index(GS_TLS_SEL); 
			}
			task->thread.gsindex = GS_TLS_SEL; 
			task->thread.gs = 0;
		} else { 
			task->thread.gsindex = 0;
			task->thread.gs = addr;
			if (doit) {
				load_gs_index(0);
				ret = HYPERVISOR_set_segment_base(
					SEGBASE_GS_USER, addr);
			} 
		}
		put_cpu();
		break;
	case ARCH_SET_FS:
		/* Not strictly needed for fs, but do it for symmetry
		   with gs */
		if (addr >= TASK_SIZE_OF(task))
			return -EPERM; 
		cpu = get_cpu();
		/* handle small bases via the GDT because that's faster to 
		   switch. */
		if (addr <= 0xffffffff) { 
			set_32bit_tls(task, FS_TLS, addr);
			if (doit) { 
				load_TLS(&task->thread, cpu); 
				asm volatile("movl %0,%%fs" :: "r"(FS_TLS_SEL));
			}
			task->thread.fsindex = FS_TLS_SEL;
			task->thread.fs = 0;
		} else { 
			task->thread.fsindex = 0;
			task->thread.fs = addr;
			if (doit) {
				/* set the selector to 0 to not confuse
				   __switch_to */
				asm volatile("movl %0,%%fs" :: "r" (0));
                                ret = HYPERVISOR_set_segment_base(SEGBASE_FS,
								  addr);
			}
		}
		put_cpu();
		break;
	case ARCH_GET_FS: { 
		unsigned long base; 
		if (task->thread.fsindex == FS_TLS_SEL)
			base = read_32bit_tls(task, FS_TLS);
		else if (doit)
			rdmsrl(MSR_FS_BASE, base);
		else
			base = task->thread.fs;
		ret = put_user(base, (unsigned long __user *)addr); 
		break; 
	}
	case ARCH_GET_GS: { 
		unsigned long base;
		unsigned gsindex;
		if (task->thread.gsindex == GS_TLS_SEL)
			base = read_32bit_tls(task, GS_TLS);
		else if (doit) {
 			asm("movl %%gs,%0" : "=r" (gsindex));
			if (gsindex)
				rdmsrl(MSR_KERNEL_GS_BASE, base);
			else
				base = task->thread.gs;
		}
		else
			base = task->thread.gs;
		ret = put_user(base, (unsigned long __user *)addr); 
		break;
	}

	default:
		ret = -EINVAL;
		break;
	} 

	return ret;	
} 

long sys_arch_prctl(int code, unsigned long addr)
{
	return do_arch_prctl(current, code, addr);
} 

/* 
 * Capture the user space registers if the task is not running (in user space)
 */
int dump_task_regs(struct task_struct *tsk, elf_gregset_t *regs)
{
	struct pt_regs *pp, ptregs;

	pp = task_pt_regs(tsk);

	ptregs = *pp; 
	ptregs.cs &= 0xffff;
	ptregs.ss &= 0xffff;

	elf_core_copy_regs(regs, &ptregs);
 
        boot_option_idle_override = 1;
	return 1;
}

unsigned long arch_align_stack(unsigned long sp)
{
	if (randomize_va_space)
		sp -= get_random_int() % 8192;
	return sp & ~0xf;
}

#ifndef CONFIG_SMP
void _restore_vcpu(void)
{
}
#endif
