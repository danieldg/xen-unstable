/******************************************************************************
 * kernel.c
 * 
 * This file should contain architecture-independent bootstrap and low-level
 * help routines. It's a bit x86/PC specific right now!
 * 
 * Copyright (c) 2002-2003 K A Fraser
 */

#include <stdarg.h>
#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/spinlock.h>
#include <xen/multiboot.h>
#include <xen/sched.h>
#include <xen/mm.h>
#include <xen/delay.h>
#include <xen/compile.h>
#include <xen/console.h>
#include <xen/serial.h>
#include <xen/trace.h>
#include <asm/shadow.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/domain_page.h>
#include <public/dom0_ops.h>

/* opt_dom0_mem: Kilobytes of memory allocated to domain 0. */
static unsigned int opt_dom0_mem = 16000;
integer_param("dom0_mem", opt_dom0_mem);

/*
 * opt_xenheap_megabytes: Size of Xen heap in megabytes, excluding the
 * pfn_info table and allocation bitmap.
 */
static unsigned int opt_xenheap_megabytes = XENHEAP_DEFAULT_MB;
integer_param("xenheap_megabytes", opt_xenheap_megabytes);

unsigned long xenheap_phys_end;

xmem_cache_t *domain_struct_cachep;
struct domain *dom0;

vm_assist_info_t vm_assist_info[MAX_VMASST_TYPE + 1];

void start_of_day(void);

void cmain(multiboot_info_t *mbi)
{
    unsigned long max_page;
    unsigned char *cmdline;
    module_t *mod = (module_t *)__va(mbi->mods_addr);
    void *heap_start;
    unsigned long max_mem;
    unsigned long dom0_memory_start, dom0_memory_end;
    unsigned long initial_images_start, initial_images_end;

    /* Parse the command-line options. */
    cmdline = (unsigned char *)(mbi->cmdline ? __va(mbi->cmdline) : NULL);
    if ( cmdline != NULL )
    {
        unsigned char *opt_end, *opt;
        struct kernel_param *param;
        while ( *cmdline == ' ' )
            cmdline++;
        cmdline = strchr(cmdline, ' '); /* skip the image name */
        while ( cmdline != NULL )
        {
            while ( *cmdline == ' ' )
                cmdline++;
            if ( *cmdline == '\0' )
                break;
            opt_end = strchr(cmdline, ' ');
            if ( opt_end != NULL )
                *opt_end++ = '\0';
            opt = strchr(cmdline, '=');
            if ( opt != NULL )
                *opt++ = '\0';
            for ( param = &__setup_start; param != &__setup_end; param++ )
            {
                if ( strcmp(param->name, cmdline ) != 0 )
                    continue;
                switch ( param->type )
                {
                case OPT_STR:
                    if ( opt != NULL )
                    {
                        strncpy(param->var, opt, param->len);
                        ((char *)param->var)[param->len-1] = '\0';
                    }
                    break;
                case OPT_UINT:
                    if ( opt != NULL )
                        *(unsigned int *)param->var =
                            simple_strtol(opt, (char **)&opt, 0);
                    break;
                case OPT_BOOL:
                    *(int *)param->var = 1;
                    break;
                }
            }
            cmdline = opt_end;
        }
    }

    /* Must do this early -- e.g., spinlocks rely on get_current(). */
    set_current(&idle0_task);

    /* We initialise the serial devices very early so we can get debugging. */
    serial_init_stage1();

    init_console();

    /* HELLO WORLD --- start-of-day banner text. */
    printk(XEN_BANNER);
    printk(" http://www.cl.cam.ac.uk/netos/xen\n");
    printk(" University of Cambridge Computer Laboratory\n\n");
    printk(" Xen version %d.%d%s (%s@%s) (%s) %s\n",
           XEN_VERSION, XEN_SUBVERSION, XEN_EXTRAVERSION,
           XEN_COMPILE_BY, XEN_COMPILE_DOMAIN,
           XEN_COMPILER, XEN_COMPILE_DATE);
    printk(" Latest ChangeSet: %s\n\n", XEN_CHANGESET);
    set_printk_prefix("(XEN) ");

    /* We require memory and module information. */
    if ( (mbi->flags & 9) != 9 )
    {
        printk("FATAL ERROR: Bad flags passed by bootloader: 0x%x\n", 
               (unsigned)mbi->flags);
        for ( ; ; ) ;
    }

    if ( mbi->mods_count == 0 )
    {
        printk("Require at least one Multiboot module!\n");
        for ( ; ; ) ;
    }

    if ( opt_xenheap_megabytes < 4 )
    {
        printk("Xen heap size is too small to safely continue!\n");
        for ( ; ; ) ;
    }

    xenheap_phys_end = opt_xenheap_megabytes << 20;

    max_mem = max_page = (mbi->mem_upper+1024) >> (PAGE_SHIFT - 10);

#if defined(__i386__)

    initial_images_start = DIRECTMAP_PHYS_END;
    initial_images_end   = initial_images_start + 
        (mod[mbi->mods_count-1].mod_end - mod[0].mod_start);
    if ( initial_images_end > (max_page << PAGE_SHIFT) )
    {
        printk("Not enough memory to stash the DOM0 kernel image.\n");
        for ( ; ; ) ;
    }
    memmove((void *)initial_images_start,  /* use low mapping */
            (void *)mod[0].mod_start,      /* use low mapping */
            mod[mbi->mods_count-1].mod_end - mod[0].mod_start);

    if ( opt_xenheap_megabytes > XENHEAP_DEFAULT_MB )
    {
        printk("Xen heap size is limited to %dMB - you specified %dMB.\n",
               XENHEAP_DEFAULT_MB, opt_xenheap_megabytes);
        for ( ; ; ) ;
    }

    ASSERT((sizeof(struct pfn_info) << 20) <=
           (FRAMETABLE_VIRT_END - FRAMETABLE_VIRT_START));

    init_frametable((void *)FRAMETABLE_VIRT_START, max_page);

#elif defined(__x86_64__)

    init_frametable(__va(xenheap_phys_end), max_page);

    initial_images_start = __pa(frame_table) + frame_table_size;
    initial_images_end   = initial_images_start + 
        (mod[mbi->mods_count-1].mod_end - mod[0].mod_start);
    if ( initial_images_end > (max_page << PAGE_SHIFT) )
    {
        printk("Not enough memory to stash the DOM0 kernel image.\n");
        for ( ; ; ) ;
    }
    memmove(__va(initial_images_start),
            __va(mod[0].mod_start),
            mod[mbi->mods_count-1].mod_end - mod[0].mod_start);

#endif

    dom0_memory_start    = (initial_images_end + ((4<<20)-1)) & ~((4<<20)-1);
    dom0_memory_end      = dom0_memory_start + (opt_dom0_mem << 10);
    dom0_memory_end      = (dom0_memory_end + PAGE_SIZE - 1) & PAGE_MASK;
    
    /* Cheesy sanity check: enough memory for DOM0 allocation + some slack? */
    if ( (dom0_memory_end + (8<<20)) > (max_page << PAGE_SHIFT) )
    {
        printk("Not enough memory for DOM0 memory reservation.\n");
        for ( ; ; ) ;
    }

    printk("Initialised %luMB memory (%lu pages) on a %luMB machine\n",
           max_page >> (20-PAGE_SHIFT), max_page,
	   max_mem  >> (20-PAGE_SHIFT));

    heap_start = memguard_init(&_end);
    heap_start = __va(init_heap_allocator(__pa(heap_start), max_page));
 
    init_xenheap_pages(__pa(heap_start), xenheap_phys_end);
    printk("Xen heap size is %luKB\n", 
	   (xenheap_phys_end-__pa(heap_start))/1024 );

    init_domheap_pages(dom0_memory_end, max_page << PAGE_SHIFT);

    /* Initialise the slab allocator. */
    xmem_cache_init();
    xmem_cache_sizes_init(max_page);

    domain_struct_cachep = xmem_cache_create(
        "domain_cache", sizeof(struct domain),
        0, SLAB_HWCACHE_ALIGN, NULL, NULL);
    if ( domain_struct_cachep == NULL )
        panic("No slab cache for task structs.");

    start_of_day();

    grant_table_init();

    /* Create initial domain 0. */
    dom0 = do_createdomain(0, 0);
    if ( dom0 == NULL )
        panic("Error creating domain 0\n");

    set_bit(DF_PRIVILEGED, &dom0->flags);

    shadow_mode_init();

    /* Grab the DOM0 command line. Skip past the image name. */
    cmdline = (unsigned char *)(mod[0].string ? __va(mod[0].string) : NULL);
    if ( cmdline != NULL )
    {
        while ( *cmdline == ' ' ) cmdline++;
        if ( (cmdline = strchr(cmdline, ' ')) != NULL )
            while ( *cmdline == ' ' ) cmdline++;
    }

    /*
     * We're going to setup domain0 using the module(s) that we stashed safely
     * above our heap. The second module, if present, is an initrd ramdisk.
     */
    if ( construct_dom0(dom0, dom0_memory_start, dom0_memory_end,
                        (char *)initial_images_start, 
                        mod[0].mod_end-mod[0].mod_start,
                        (mbi->mods_count == 1) ? 0 :
                        (char *)initial_images_start + 
                        (mod[1].mod_start-mod[0].mod_start),
                        (mbi->mods_count == 1) ? 0 :
                        mod[mbi->mods_count-1].mod_end - mod[1].mod_start,
                        cmdline) != 0)
        panic("Could not set up DOM0 guest OS\n");

    /* The stash space for the initial kernel image can now be freed up. */
    init_domheap_pages(__pa(frame_table) + frame_table_size,
                       dom0_memory_start);

    scrub_heap_pages();

    init_trace_bufs();

    /* Give up the VGA console if DOM0 is configured to grab it. */
    console_endboot(cmdline && strstr(cmdline, "tty0"));

    domain_unpause_by_systemcontroller(current);
    domain_unpause_by_systemcontroller(dom0);
    startup_cpu_idle_loop();
}

/*
 * Simple hypercalls.
 */

long do_xen_version(int cmd)
{
    if ( cmd != 0 )
        return -ENOSYS;
    return (XEN_VERSION<<16) | (XEN_SUBVERSION);
}

long do_vm_assist(unsigned int cmd, unsigned int type)
{
    return vm_assist(current, cmd, type);
}

long do_ni_hypercall(void)
{
    /* No-op hypercall. */
    return -ENOSYS;
}
