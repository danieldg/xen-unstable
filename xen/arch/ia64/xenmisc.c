/*
 * Xen misc
 * 
 * Functions/decls that are/may be needed to link with Xen because
 * of x86 dependencies
 *
 * Copyright (C) 2004 Hewlett-Packard Co.
 *	Dan Magenheimer (dan.magenheimer@hp.com)
 *
 */

#include <linux/config.h>
#include <xen/sched.h>
#include <linux/efi.h>
#include <asm/processor.h>
#include <xen/serial.h>
#include <asm/io.h>
#include <xen/softirq.h>

efi_memory_desc_t ia64_efi_io_md;
EXPORT_SYMBOL(ia64_efi_io_md);
unsigned long wait_init_idle;
int phys_proc_id[NR_CPUS];
unsigned long loops_per_jiffy = (1<<12);	// from linux/init/main.c

unsigned int watchdog_on = 0;	// from arch/x86/nmi.c ?!?

void unw_init(void) { printf("unw_init() skipped (NEED FOR KERNEL UNWIND)\n"); }
void ia64_mca_init(void) { printf("ia64_mca_init() skipped (Machine check abort handling)\n"); }
void hpsim_setup(char **x) { printf("hpsim_setup() skipped (MAY NEED FOR CONSOLE INPUT!!!)\n"); }	

long
is_platform_hp_ski(void)
{
	int i;
	long cpuid[6];

	for (i = 0; i < 5; ++i)
		cpuid[i] = ia64_get_cpuid(i);
	if ((cpuid[0] & 0xff) != 'H') return 0;
	if ((cpuid[3] & 0xff) != 0x4) return 0;
	if (((cpuid[3] >> 8) & 0xff) != 0x0) return 0;
	if (((cpuid[3] >> 16) & 0xff) != 0x0) return 0;
	if (((cpuid[3] >> 24) & 0x7) != 0x7) return 0;
	return 1;
}

long
platform_is_hp_ski(void)
{
	extern long running_on_sim;
	return running_on_sim;
}

/* calls in xen/common code that are unused on ia64 */

void sync_lazy_execstate_cpuset(unsigned long cpuset) {}
void sync_lazy_execstate_all(void) {}

int grant_table_create(struct domain *d) { return 0; }
void grant_table_destroy(struct domain *d)
{
	printf("grant_table_destroy: domain_destruct not tested!!!\n");
	printf("grant_table_destroy: ensure atomic_* calls work in domain_destruct!!\n");
	dummy();
	return;
}

struct pt_regs *get_execution_context(void) { return ia64_task_regs(current); }

void raise_actimer_softirq(void)
{
	raise_softirq(AC_TIMER_SOFTIRQ);
}

///////////////////////////////
// from arch/x86/apic.c
///////////////////////////////

int reprogram_ac_timer(s_time_t timeout)
{
	struct exec_domain *ed = current;

	local_cpu_data->itm_next = timeout;
	if (is_idle_task(ed->domain)) vcpu_safe_set_itm(timeout);
	else vcpu_set_next_timer(current);
	return 1;
}

///////////////////////////////
// from arch/ia64/page_alloc.c
///////////////////////////////
DEFINE_PER_CPU(struct page_state, page_states) = {0};
unsigned long totalram_pages;

///////////////////////////////
// from arch/x86/flushtlb.c
///////////////////////////////

u32 tlbflush_clock;
u32 tlbflush_time[NR_CPUS];

///////////////////////////////
// from arch/x86/memory.c
///////////////////////////////

void init_percpu_info(void)
{
	dummy();
    //memset(percpu_info, 0, sizeof(percpu_info));
}

void free_page_type(struct pfn_info *page, unsigned int type)
{
	dummy();
}

///////////////////////////////
// from arch/x86/pci.c
///////////////////////////////

int
pcibios_prep_mwi (struct pci_dev *dev)
{
	dummy();
}

///////////////////////////////
// from arch/x86/pci-irq.c
///////////////////////////////

void pcibios_enable_irq(struct pci_dev *dev)
{
	dummy();
}

///////////////////////////////
// from arch/ia64/pci-pc.c
///////////////////////////////

#include <xen/pci.h>

int pcibios_enable_device(struct pci_dev *dev, int mask)
{
	dummy();
	return 0;
}

int (*pci_config_read)(int seg, int bus, int dev, int fn, int reg, int len, u32 *value) = NULL;
int (*pci_config_write)(int seg, int bus, int dev, int fn, int reg, int len, u32 value) = NULL;

//struct pci_fixup pcibios_fixups[] = { { 0 } };
struct pci_fixup pcibios_fixups[] = { { 0 } };

void
pcibios_align_resource(void *data, struct resource *res,
		       unsigned long size, unsigned long align)
{
	dummy();
}

void
pcibios_update_resource(struct pci_dev *dev, struct resource *root,
			struct resource *res, int resource)
{
	dummy();
}

void __devinit  pcibios_fixup_bus(struct pci_bus *b)
{
	dummy();
}

void __init pcibios_init(void)
{
	dummy();
}

char * __devinit  pcibios_setup(char *str)
{
	dummy();
	return 0;
}

///////////////////////////////
// from arch/ia64/traps.c
///////////////////////////////

void show_registers(struct pt_regs *regs)
{
	printf("*** ADD REGISTER DUMP HERE FOR DEBUGGING\n");
}	

///////////////////////////////
// from common/keyhandler.c
///////////////////////////////
void dump_pageframe_info(struct domain *d)
{
	printk("dump_pageframe_info not implemented\n");
}

///////////////////////////////
// from common/physdev.c
///////////////////////////////
void
physdev_init_dom0(struct domain *d)
{
}

int
physdev_pci_access_modify(domid_t id, int bus, int dev, int func, int enable)
{
	return -EINVAL;
}

void physdev_modify_ioport_access_range(struct domain *d, int enable,
	int port, int num)
{
	printk("physdev_modify_ioport_access_range not implemented\n");
	dummy();
}

void physdev_destroy_state(struct domain *d)
{
	printk("physdev_destroy_state not implemented\n");
	dummy();
}

// accomodate linux extable.c
//const struct exception_table_entry *
void *search_module_extables(unsigned long addr)
{
	return NULL;
}

void *module_text_address(unsigned long addr)
{
	return NULL;
}

void cs10foo(void) {}
void cs01foo(void) {}

// context_switch
void context_switch(struct exec_domain *prev, struct exec_domain *next)
{
//printk("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
//printk("@@@@@@ context switch from domain %d (%x) to domain %d (%x)\n",
//prev->domain->id,(long)prev&0xffffff,next->domain->id,(long)next&0xffffff);
//if (prev->domain->id == 1 && next->domain->id == 0) cs10foo();
//if (prev->domain->id == 0 && next->domain->id == 1) cs01foo();
//printk("@@sw %d->%d\n",prev->domain->id,next->domain->id);
	switch_to(prev,next,prev);
// leave this debug for now: it acts as a heartbeat when more than
// one domain is active
{
static long cnt[16] = { 50,50,50,50,50,50,50,50,50,50,50,50,50,50,50,50};
static int i = 100;
int id = ((struct exec_domain *)current)->domain->id & 0xf;
if (!cnt[id]--) { printk("%x",id); cnt[id] = 50; }
if (!i--) { printk("+",id); cnt[id] = 100; }
}
	clear_bit(EDF_RUNNING, &prev->ed_flags);
	//if (!is_idle_task(next->domain) )
		//send_guest_virq(next, VIRQ_TIMER);
	load_region_regs(current);
	if (vcpu_timer_expired(current)) vcpu_pend_timer(current);
}

void panic_domain(struct pt_regs *regs, const char *fmt, ...)
{
	va_list args;
	char buf[128];
	struct exec_domain *ed = current;
	static volatile int test = 1;	// so can continue easily in debug
	extern spinlock_t console_lock;
	unsigned long flags;
    
	printf("$$$$$ PANIC in domain %d (k6=%p): ",
		ed->domain->id, ia64_get_kr(IA64_KR_CURRENT));
	va_start(args, fmt);
	(void)vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	printf(buf);
	if (regs) show_registers(regs);
	domain_pause_by_systemcontroller(current->domain);
	set_bit(DF_CRASHED, ed->domain->d_flags);
	//while(test);
}
