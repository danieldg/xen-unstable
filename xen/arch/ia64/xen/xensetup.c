/******************************************************************************
 * xensetup.c
 * Copyright (c) 2004-2005  Hewlett-Packard Co
 *         Dan Magenheimer <dan.magenheimer@hp.com>
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/errno.h>
//#include <xen/spinlock.h>
#include <xen/multiboot.h>
#include <xen/sched.h>
#include <xen/mm.h>
#include <public/version.h>
//#include <xen/delay.h>
#include <xen/compile.h>
//#include <xen/console.h>
#include <xen/serial.h>
#include <xen/trace.h>
#include <asm/meminit.h>
#include <asm/page.h>
#include <asm/setup.h>
#include <xen/string.h>

unsigned long xenheap_phys_end;

char saved_command_line[COMMAND_LINE_SIZE];

struct vcpu *idle_task[NR_CPUS] = { &idle0_vcpu };

cpumask_t cpu_present_map;

#ifdef CLONE_DOMAIN0
struct domain *clones[CLONE_DOMAIN0];
#endif
extern unsigned long domain0_ready;

int find_max_pfn (unsigned long, unsigned long, void *);
void start_of_day(void);

/* opt_nosmp: If true, secondary processors are ignored. */
static int opt_nosmp = 0;
boolean_param("nosmp", opt_nosmp);

/* maxcpus: maximum number of CPUs to activate. */
static unsigned int max_cpus = NR_CPUS;
integer_param("maxcpus", max_cpus); 

/*
 * opt_xenheap_megabytes: Size of Xen heap in megabytes, including:
 *	xen image
 *	bootmap bits
 *	xen heap
 * Note: To allow xenheap size configurable, the prerequisite is
 * to configure elilo allowing relocation defaultly. Then since
 * elilo chooses 256M as alignment when relocating, alignment issue
 * on IPF can be addressed.
 */
unsigned int opt_xenheap_megabytes = XENHEAP_DEFAULT_MB;
unsigned long xenheap_size = XENHEAP_DEFAULT_SIZE;
extern long running_on_sim;
unsigned long xen_pstart;

static int
xen_count_pages(u64 start, u64 end, void *arg)
{
    unsigned long *count = arg;

    /* FIXME: do we need consider difference between DMA-usable memory and
     * normal memory? Seems that HV has no requirement to operate DMA which
     * is owned by Dom0? */
    *count += (end - start) >> PAGE_SHIFT;
    return 0;
}

/* Find first hole after trunk for xen image */
static int
xen_find_first_hole(u64 start, u64 end, void *arg)
{
    unsigned long *first_hole = arg;

    if ((*first_hole) == 0) {
	if ((start <= KERNEL_START) && (KERNEL_START < end))
	    *first_hole = __pa(end);
    }

    return 0;
}

static void __init do_initcalls(void)
{
    initcall_t *call;
    for ( call = &__initcall_start; call < &__initcall_end; call++ )
        (*call)();
}

/*
 * IPF loader only supports one commaind line currently, for
 * both xen and guest kernel. This function provides pre-parse
 * to mixed command line, to split it into two parts.
 *
 * User should split the parameters by "--", with strings after
 * spliter for guest kernel. Missing "--" means whole line belongs
 * to guest. Example:
 *	"com2=57600,8n1 console=com2 -- console=ttyS1 console=tty
 * root=/dev/sda3 ro"
 */
static char null[4] = { 0 };

void early_cmdline_parse(char **cmdline_p)
{
    char *guest_cmd;
    char *split = "--";

    if (*cmdline_p == NULL) {
	*cmdline_p = &null[0];
	saved_command_line[0] = '\0';
	return;
    }

    guest_cmd = strstr(*cmdline_p, split);
    /* If no spliter, whole line is for guest */
    if (guest_cmd == NULL) {
	guest_cmd = *cmdline_p;
	*cmdline_p = &null[0];
    } else {
	*guest_cmd = '\0';	/* Split boot parameters for xen and guest */
	guest_cmd += strlen(split);
	while (*guest_cmd == ' ') guest_cmd++;
    }

    strlcpy(saved_command_line, guest_cmd, COMMAND_LINE_SIZE);
    return;
}

struct ns16550_defaults ns16550_com1 = {
    .baud      = BAUD_AUTO,
    .data_bits = 8,
    .parity    = 'n',
    .stop_bits = 1
};

struct ns16550_defaults ns16550_com2 = {
    .baud      = BAUD_AUTO,
    .data_bits = 8,
    .parity    = 'n',
    .stop_bits = 1
};

void start_kernel(void)
{
    unsigned char *cmdline;
    void *heap_start;
    int i;
    unsigned long max_mem, nr_pages, firsthole_start;
    unsigned long dom0_memory_start, dom0_memory_size;
    unsigned long dom0_initrd_start, dom0_initrd_size;
    unsigned long initial_images_start, initial_images_end;

    running_on_sim = is_platform_hp_ski();
    /* Kernel may be relocated by EFI loader */
    xen_pstart = ia64_tpa(KERNEL_START);

    /* Must do this early -- e.g., spinlocks rely on get_current(). */
    //set_current(&idle0_vcpu);
    ia64_r13 = (void *)&idle0_vcpu;
    idle0_vcpu.domain = &idle0_domain;

    early_setup_arch(&cmdline);

    /* We initialise the serial devices very early so we can get debugging. */
    if (running_on_sim) hpsim_serial_init();
    else {
	ns16550_init(0, &ns16550_com1);
	/* Also init com2 for Tiger4. */
	ns16550_com2.io_base = 0x2f8;
	ns16550_com2.irq     = 3;
	ns16550_init(1, &ns16550_com2);
    }
    serial_init_preirq();

    init_console();
    set_printk_prefix("(XEN) ");

    /* xenheap should be in same TR-covered range with xen image */
    xenheap_phys_end = xen_pstart + xenheap_size;
    printk("xen image pstart: 0x%lx, xenheap pend: 0x%lx\n",
	    xen_pstart, xenheap_phys_end);

    /* Find next hole */
    firsthole_start = 0;
    efi_memmap_walk(xen_find_first_hole, &firsthole_start);

    if (ia64_boot_param->domain_start == 0
	|| ia64_boot_param->domain_size == 0) {
	    /* This is possible only with the old elilo, which does not support
	       a vmm.  Fix now, and continue without initrd.  */
	    printk ("Your elilo is not Xen-aware.  Bootparams fixed\n");
	    ia64_boot_param->domain_start = ia64_boot_param->initrd_start;
	    ia64_boot_param->domain_size = ia64_boot_param->initrd_size;
	    ia64_boot_param->initrd_start = 0;
	    ia64_boot_param->initrd_size = 0;
    }

    initial_images_start = xenheap_phys_end;
    initial_images_end = initial_images_start +
       PAGE_ALIGN(ia64_boot_param->domain_size);

    /* also reserve space for initrd */
    if (ia64_boot_param->initrd_start && ia64_boot_param->initrd_size)
       initial_images_end += PAGE_ALIGN(ia64_boot_param->initrd_size);
    else {
       /* sanity cleanup */
       ia64_boot_param->initrd_size = 0;
       ia64_boot_param->initrd_start = 0;
    }


    /* Later may find another memory trunk, even away from xen image... */
    if (initial_images_end > firsthole_start) {
	printk("Not enough memory to stash the DOM0 kernel image.\n");
	printk("First hole:0x%lx, relocation end: 0x%lx\n",
		firsthole_start, initial_images_end);
	for ( ; ; );
    }

    /* This copy is time consuming, but elilo may load Dom0 image
     * within xenheap range */
    printk("ready to move Dom0 to 0x%lx with len %lx...", initial_images_start,
          ia64_boot_param->domain_size);

    memmove(__va(initial_images_start),
          __va(ia64_boot_param->domain_start),
          ia64_boot_param->domain_size);
//    ia64_boot_param->domain_start = initial_images_start;

    printk("ready to move initrd to 0x%lx with len %lx...",
          initial_images_start+PAGE_ALIGN(ia64_boot_param->domain_size),
          ia64_boot_param->initrd_size);
    memmove(__va(initial_images_start+PAGE_ALIGN(ia64_boot_param->domain_size)),

	   __va(ia64_boot_param->initrd_start),
	   ia64_boot_param->initrd_size);
    printk("Done\n");

    /* first find highest page frame number */
    max_page = 0;
    efi_memmap_walk(find_max_pfn, &max_page);
    printf("find_memory: efi_memmap_walk returns max_page=%lx\n",max_page);

    heap_start = memguard_init(ia64_imva(&_end));
    printf("Before heap_start: 0x%lx\n", heap_start);
    heap_start = __va(init_boot_allocator(__pa(heap_start)));
    printf("After heap_start: 0x%lx\n", heap_start);

    reserve_memory();

    efi_memmap_walk(filter_rsvd_memory, init_boot_pages);
    efi_memmap_walk(xen_count_pages, &nr_pages);

    printk("System RAM: %luMB (%lukB)\n",
	nr_pages >> (20 - PAGE_SHIFT),
	nr_pages << (PAGE_SHIFT - 10));

    init_frametable();

    ia64_fph_enable();
    __ia64_init_fpu();

    alloc_dom0();

    end_boot_allocator();

    init_xenheap_pages(__pa(heap_start), xenheap_phys_end);
    printk("Xen heap: %luMB (%lukB)\n",
	(xenheap_phys_end-__pa(heap_start)) >> 20,
	(xenheap_phys_end-__pa(heap_start)) >> 10);

    late_setup_arch(&cmdline);
    setup_per_cpu_areas();
    mem_init();

printk("About to call scheduler_init()\n");
    scheduler_init();
    local_irq_disable();
    init_IRQ ();
printk("About to call init_xen_time()\n");
    init_xen_time(); /* initialise the time */
printk("About to call ac_timer_init()\n");
    ac_timer_init();

#ifdef CONFIG_SMP
    if ( opt_nosmp )
    {
        max_cpus = 0;
        smp_num_siblings = 1;
        //boot_cpu_data.x86_num_cores = 1;
    }

    smp_prepare_cpus(max_cpus);

    /* We aren't hotplug-capable yet. */
    //BUG_ON(!cpus_empty(cpu_present_map));
    for_each_cpu ( i )
        cpu_set(i, cpu_present_map);

    //BUG_ON(!local_irq_is_enabled());

    /*  Enable IRQ to receive IPI (needed for ITC sync).  */
    local_irq_enable();

printk("num_online_cpus=%d, max_cpus=%d\n",num_online_cpus(),max_cpus);
    for_each_present_cpu ( i )
    {
        if ( num_online_cpus() >= max_cpus )
            break;
        if ( !cpu_online(i) ) {
printk("About to call __cpu_up(%d)\n",i);
            __cpu_up(i);
	}
    }

    local_irq_disable();

    printk("Brought up %ld CPUs\n", (long)num_online_cpus());
    smp_cpus_done(max_cpus);
#endif

    do_initcalls();
printk("About to call sort_main_extable()\n");
    sort_main_extable();


    /* Create initial domain 0. */
printk("About to call do_createdomain()\n");
    dom0 = do_createdomain(0, 0);
    init_task.domain = &idle0_domain;
    init_task.processor = 0;
//    init_task.mm = &init_mm;
    init_task.domain->arch.mm = &init_mm;
//    init_task.thread = INIT_THREAD;
    //arch_do_createdomain(current);
#ifdef CLONE_DOMAIN0
    {
    int i;
    for (i = 0; i < CLONE_DOMAIN0; i++) {
	clones[i] = do_createdomain(i+1, 0);
        if ( clones[i] == NULL )
            panic("Error creating domain0 clone %d\n",i);
    }
    }
#endif
    if ( dom0 == NULL )
        panic("Error creating domain 0\n");

    set_bit(_DOMF_privileged, &dom0->domain_flags);

    /*
     * We're going to setup domain0 using the module(s) that we stashed safely
     * above our heap. The second module, if present, is an initrd ramdisk.
     */
    printk("About to call construct_dom0()\n");
    dom0_memory_start = __va(initial_images_start);
    dom0_memory_size = ia64_boot_param->domain_size;
    dom0_initrd_start = __va(initial_images_start +
			     PAGE_ALIGN(ia64_boot_param->domain_size));
    dom0_initrd_size = ia64_boot_param->initrd_size;
 
    if ( construct_dom0(dom0, dom0_memory_start, dom0_memory_size,
                        dom0_initrd_start,dom0_initrd_size,
  			0) != 0)
        panic("Could not set up DOM0 guest OS\n");

    /* PIN domain0 on CPU 0.  */
    dom0->vcpu[0]->cpumap=1;
    set_bit(_VCPUF_cpu_pinned, &dom0->vcpu[0]->vcpu_flags);

#ifdef CLONE_DOMAIN0
    {
    int i;
    dom0_memory_start = __va(ia64_boot_param->domain_start);
    dom0_memory_size = ia64_boot_param->domain_size;

    for (i = 0; i < CLONE_DOMAIN0; i++) {
      printk("CONSTRUCTING DOMAIN0 CLONE #%d\n",i+1);
      if ( construct_domU(clones[i], dom0_memory_start, dom0_memory_size,
			  dom0_initrd_start,dom0_initrd_size,
			  0) != 0)
            panic("Could not set up DOM0 clone %d\n",i);
    }
    }
#endif

    /* The stash space for the initial kernel image can now be freed up. */
    init_domheap_pages(ia64_boot_param->domain_start,
                       ia64_boot_param->domain_size);
    /* throw away initrd area passed from elilo */
    if (ia64_boot_param->initrd_size) {
        init_domheap_pages(ia64_boot_param->initrd_start,
                          ia64_boot_param->initrd_size);
    }

    if (!running_on_sim)  // slow on ski and pages are pre-initialized to zero
	scrub_heap_pages();

printk("About to call init_trace_bufs()\n");
    init_trace_bufs();

    /* Give up the VGA console if DOM0 is configured to grab it. */
#ifndef IA64
    console_endboot(cmdline && strstr(cmdline, "tty0"));
#endif

#ifdef CLONE_DOMAIN0
    {
    int i;
    for (i = 0; i < CLONE_DOMAIN0; i++)
	domain_unpause_by_systemcontroller(clones[i]);
    }
#endif
    domain0_ready = 1;

    local_irq_enable();

    printf("About to call schedulers_start dom0=%p, idle0_dom=%p\n",
	   dom0, &idle0_domain);
    schedulers_start();

    domain_unpause_by_systemcontroller(dom0);

printk("About to call startup_cpu_idle_loop()\n");
    startup_cpu_idle_loop();
}

void arch_get_xen_caps(xen_capabilities_info_t info)
{
    char *p=info;

    *p=0;

    p+=sprintf(p,"xen_%d.%d_ia64 ",XEN_VERSION,XEN_SUBVERSION);

    *(p-1) = 0;

    BUG_ON((p-info)>sizeof(xen_capabilities_info_t));

}

