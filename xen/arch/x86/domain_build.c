/******************************************************************************
 * domain_build.c
 * 
 * Copyright (c) 2002-2005, K A Fraser
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/ctype.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/delay.h>
#include <xen/event.h>
#include <xen/elf.h>
#include <xen/kernel.h>
#include <asm/regs.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/i387.h>
#include <asm/shadow.h>

/* opt_dom0_mem: memory allocated to domain 0. */
static unsigned int opt_dom0_mem;
static void parse_dom0_mem(char *s)
{
    unsigned long long bytes = parse_size_and_unit(s);
    /* If no unit is specified we default to kB units, not bytes. */
    if ( isdigit(s[strlen(s)-1]) )
        opt_dom0_mem = (unsigned int)bytes;
    else
        opt_dom0_mem = (unsigned int)(bytes >> 10);
}
custom_param("dom0_mem", parse_dom0_mem);

static unsigned int opt_dom0_shadow = 0;
boolean_param("dom0_shadow", opt_dom0_shadow);

static unsigned int opt_dom0_translate = 0;
boolean_param("dom0_translate", opt_dom0_translate);

#if defined(__i386__)
/* No ring-3 access in initial leaf page tables. */
#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#elif defined(__x86_64__)
/* Allow ring-3 access in long mode as guest cannot use ring 1. */
#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_USER)
#endif
/* Don't change these: Linux expects just these bits to be set. */
/* (And that includes the bogus _PAGE_DIRTY!) */
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)
#define L3_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)
#define L4_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)

#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)
#define round_pgdown(_p)  ((_p)&PAGE_MASK)

static struct pfn_info *alloc_largest(struct domain *d, unsigned long max)
{
    struct pfn_info *page;
    unsigned int order = get_order(max * PAGE_SIZE);
    if ( (max & (max-1)) != 0 )
        order--;
    while ( (page = alloc_domheap_pages(d, order)) == NULL )
        if ( order-- == 0 )
            break;
    return page;
}

int construct_dom0(struct domain *d,
                   unsigned long _image_start, unsigned long image_len, 
                   unsigned long _initrd_start, unsigned long initrd_len,
                   char *cmdline)
{
    char *dst;
    int i, rc;
    unsigned long pfn, mfn;
    unsigned long nr_pages;
    unsigned long nr_pt_pages;
    unsigned long alloc_start;
    unsigned long alloc_end;
    unsigned long count;
    struct pfn_info *page = NULL;
    start_info_t *si;
    struct exec_domain *ed = d->exec_domain[0];
#if defined(__i386__)
    char *image_start  = (char *)_image_start;  /* use lowmem mappings */
    char *initrd_start = (char *)_initrd_start; /* use lowmem mappings */
#elif defined(__x86_64__)
    char *image_start  = __va(_image_start);
    char *initrd_start = __va(_initrd_start);
    l4_pgentry_t *l4tab = NULL, *l4start = NULL;
    l3_pgentry_t *l3tab = NULL, *l3start = NULL;
#endif
    l2_pgentry_t *l2tab = NULL, *l2start = NULL;
    l1_pgentry_t *l1tab = NULL, *l1start = NULL;

    /*
     * This fully describes the memory layout of the initial domain. All 
     * *_start address are page-aligned, except v_start (and v_end) which are 
     * superpage-aligned.
     */
    struct domain_setup_info dsi;
    unsigned long vinitrd_start;
    unsigned long vinitrd_end;
    unsigned long vphysmap_start;
    unsigned long vphysmap_end;
    unsigned long vstartinfo_start;
    unsigned long vstartinfo_end;
    unsigned long vstack_start;
    unsigned long vstack_end;
    unsigned long vpt_start;
    unsigned long vpt_end;
    unsigned long v_end;

    /* Machine address of next candidate page-table page. */
    unsigned long mpt_alloc;

    extern void physdev_init_dom0(struct domain *);
    extern void translate_l2pgtable(struct domain *d, l1_pgentry_t *p2m, unsigned long l2mfn);

    /* Sanity! */
    if ( d->domain_id != 0 ) 
        BUG();
    if ( test_bit(_DOMF_constructed, &d->domain_flags) ) 
        BUG();

    memset(&dsi, 0, sizeof(struct domain_setup_info));
    dsi.image_addr = (unsigned long)image_start;
    dsi.image_len  = image_len;

    printk("*** LOADING DOMAIN 0 ***\n");

    /* By default DOM0 is allocated all available memory. */
    d->max_pages = ~0U;
    if ( (nr_pages = opt_dom0_mem >> (PAGE_SHIFT - 10)) == 0 )
        nr_pages = avail_domheap_pages() +
            ((initrd_len + PAGE_SIZE - 1) >> PAGE_SHIFT) +
            ((image_len  + PAGE_SIZE - 1) >> PAGE_SHIFT);
    if ( (page = alloc_largest(d, nr_pages)) == NULL )
        panic("Not enough RAM for DOM0 reservation.\n");
    alloc_start = page_to_phys(page);
    alloc_end   = alloc_start + (d->tot_pages << PAGE_SHIFT);
    
    if ( (rc = parseelfimage(&dsi)) != 0 )
        return rc;

    /* Align load address to 4MB boundary. */
    dsi.v_start &= ~((1UL<<22)-1);

    /*
     * Why do we need this? The number of page-table frames depends on the 
     * size of the bootstrap address space. But the size of the address space 
     * depends on the number of page-table frames (since each one is mapped 
     * read-only). We have a pair of simultaneous equations in two unknowns, 
     * which we solve by exhaustive search.
     */
    vinitrd_start    = round_pgup(dsi.v_end);
    vinitrd_end      = vinitrd_start + initrd_len;
    vphysmap_start   = round_pgup(vinitrd_end);
    vphysmap_end     = vphysmap_start + (nr_pages * sizeof(u32));
    vpt_start        = round_pgup(vphysmap_end);
    for ( nr_pt_pages = 2; ; nr_pt_pages++ )
    {
        vpt_end          = vpt_start + (nr_pt_pages * PAGE_SIZE);
        vstartinfo_start = vpt_end;
        vstartinfo_end   = vstartinfo_start + PAGE_SIZE;
        vstack_start     = vstartinfo_end;
        vstack_end       = vstack_start + PAGE_SIZE;
        v_end            = (vstack_end + (1UL<<22)-1) & ~((1UL<<22)-1);
        if ( (v_end - vstack_end) < (512UL << 10) )
            v_end += 1UL << 22; /* Add extra 4MB to get >= 512kB padding. */
#if defined(__i386__)
        if ( (((v_end - dsi.v_start + ((1UL<<L2_PAGETABLE_SHIFT)-1)) >> 
               L2_PAGETABLE_SHIFT) + 1) <= nr_pt_pages )
            break;
#elif defined(__x86_64__)
#define NR(_l,_h,_s) \
    (((((_h) + ((1UL<<(_s))-1)) & ~((1UL<<(_s))-1)) - \
       ((_l) & ~((1UL<<(_s))-1))) >> (_s))
        if ( (1 + /* # L4 */
              NR(dsi.v_start, v_end, L4_PAGETABLE_SHIFT) + /* # L3 */
              NR(dsi.v_start, v_end, L3_PAGETABLE_SHIFT) + /* # L2 */
              NR(dsi.v_start, v_end, L2_PAGETABLE_SHIFT))  /* # L1 */
             <= nr_pt_pages )
            break;
#endif
    }

    if ( (v_end - dsi.v_start) > (alloc_end - alloc_start) )
        panic("Insufficient contiguous RAM to build kernel image.\n");

    printk("PHYSICAL MEMORY ARRANGEMENT:\n"
           " Dom0 alloc.:   %p->%p",
           _p(alloc_start), _p(alloc_end));
    if ( d->tot_pages < nr_pages )
        printk(" (%lu pages to be allocated)",
               nr_pages - d->tot_pages);
    printk("\nVIRTUAL MEMORY ARRANGEMENT:\n"
           " Loaded kernel: %p->%p\n"
           " Init. ramdisk: %p->%p\n"
           " Phys-Mach map: %p->%p\n"
           " Page tables:   %p->%p\n"
           " Start info:    %p->%p\n"
           " Boot stack:    %p->%p\n"
           " TOTAL:         %p->%p\n",
           _p(dsi.v_kernstart), _p(dsi.v_kernend), 
           _p(vinitrd_start), _p(vinitrd_end),
           _p(vphysmap_start), _p(vphysmap_end),
           _p(vpt_start), _p(vpt_end),
           _p(vstartinfo_start), _p(vstartinfo_end),
           _p(vstack_start), _p(vstack_end),
           _p(dsi.v_start), _p(v_end));
    printk(" ENTRY ADDRESS: %p\n", _p(dsi.v_kernentry));

    if ( (v_end - dsi.v_start) > (nr_pages * PAGE_SIZE) )
    {
        printk("Initial guest OS requires too much space\n"
               "(%luMB is greater than %luMB limit)\n",
               (v_end-dsi.v_start)>>20, (nr_pages<<PAGE_SHIFT)>>20);
        return -ENOMEM;
    }

    mpt_alloc = (vpt_start - dsi.v_start) + alloc_start;

    /*
     * We're basically forcing default RPLs to 1, so that our "what privilege
     * level are we returning to?" logic works.
     */
    ed->arch.guest_context.kernel_ss = FLAT_KERNEL_SS;
    for ( i = 0; i < 256; i++ ) 
        ed->arch.guest_context.trap_ctxt[i].cs = FLAT_KERNEL_CS;

#if defined(__i386__)

    ed->arch.guest_context.failsafe_callback_cs = FLAT_KERNEL_CS;
    ed->arch.guest_context.event_callback_cs    = FLAT_KERNEL_CS;

    /*
     * Protect the lowest 1GB of memory. We use a temporary mapping there
     * from which we copy the kernel and ramdisk images.
     */
    if ( dsi.v_start < (1UL<<30) )
    {
        printk("Initial loading isn't allowed to lowest 1GB of memory.\n");
        return -EINVAL;
    }

    /* WARNING: The new domain must have its 'processor' field filled in! */
    l2start = l2tab = (l2_pgentry_t *)mpt_alloc; mpt_alloc += PAGE_SIZE;
    memcpy(l2tab, &idle_pg_table[0], PAGE_SIZE);
    l2tab[LINEAR_PT_VIRT_START >> L2_PAGETABLE_SHIFT] =
        l2e_create_phys((unsigned long)l2start, __PAGE_HYPERVISOR);
    l2tab[PERDOMAIN_VIRT_START >> L2_PAGETABLE_SHIFT] =
        l2e_create_phys(__pa(d->arch.mm_perdomain_pt), __PAGE_HYPERVISOR);
    ed->arch.guest_table = mk_pagetable((unsigned long)l2start);

    l2tab += l2_table_offset(dsi.v_start);
    mfn = alloc_start >> PAGE_SHIFT;
    for ( count = 0; count < ((v_end-dsi.v_start)>>PAGE_SHIFT); count++ )
    {
        if ( !((unsigned long)l1tab & (PAGE_SIZE-1)) )
        {
            l1start = l1tab = (l1_pgentry_t *)mpt_alloc; 
            mpt_alloc += PAGE_SIZE;
            *l2tab = l2e_create_phys((unsigned long)l1start, L2_PROT);
            l2tab++;
            clear_page(l1tab);
            if ( count == 0 )
                l1tab += l1_table_offset(dsi.v_start);
        }
        *l1tab = l1e_create_pfn(mfn, L1_PROT);
        l1tab++;
        
        page = &frame_table[mfn];
        if ( !get_page_and_type(page, d, PGT_writable_page) )
            BUG();

        mfn++;
    }

    /* Pages that are part of page tables must be read only. */
    l2tab = l2start + l2_table_offset(vpt_start);
    l1start = l1tab = (l1_pgentry_t *)l2e_get_phys(*l2tab);
    l1tab += l1_table_offset(vpt_start);
    for ( count = 0; count < nr_pt_pages; count++ ) 
    {
        page = &frame_table[l1e_get_pfn(*l1tab)];
        if ( !opt_dom0_shadow )
            l1e_remove_flags(l1tab, _PAGE_RW);
        else
            if ( !get_page_type(page, PGT_writable_page) )
                BUG();

        if ( count == 0 )
        {
            page->u.inuse.type_info &= ~PGT_type_mask;
            page->u.inuse.type_info |= PGT_l2_page_table;

            /*
             * No longer writable: decrement the type_count.
             * Installed as CR3: increment both the ref_count and type_count.
             * Net: just increment the ref_count.
             */
            get_page(page, d); /* an extra ref because of readable mapping */

            /* Get another ref to L2 page so that it can be pinned. */
            if ( !get_page_and_type(page, d, PGT_l2_page_table) )
                BUG();
            set_bit(_PGT_pinned, &page->u.inuse.type_info);
        }
        else
        {
            page->u.inuse.type_info &= ~PGT_type_mask;
            page->u.inuse.type_info |= PGT_l1_page_table;
            page->u.inuse.type_info |= 
                ((dsi.v_start>>L2_PAGETABLE_SHIFT)+(count-1))<<PGT_va_shift;

            /*
             * No longer writable: decrement the type_count.
             * This is an L1 page, installed in a validated L2 page:
             * increment both the ref_count and type_count.
             * Net: just increment the ref_count.
             */
            get_page(page, d); /* an extra ref because of readable mapping */
        }
        if ( !((unsigned long)++l1tab & (PAGE_SIZE - 1)) )
            l1start = l1tab = (l1_pgentry_t *)l2e_get_phys(*++l2tab);
    }

#elif defined(__x86_64__)

    /* Overlap with Xen protected area? */
    if ( (dsi.v_start < HYPERVISOR_VIRT_END) &&
         (v_end > HYPERVISOR_VIRT_START) )
    {
        printk("DOM0 image overlaps with Xen private area.\n");
        return -EINVAL;
    }

    /* WARNING: The new domain must have its 'processor' field filled in! */
    phys_to_page(mpt_alloc)->u.inuse.type_info = PGT_l4_page_table;
    l4start = l4tab = __va(mpt_alloc); mpt_alloc += PAGE_SIZE;
    memcpy(l4tab, &idle_pg_table[0], PAGE_SIZE);
    l4tab[l4_table_offset(LINEAR_PT_VIRT_START)] =
        l4e_create_phys(__pa(l4start), __PAGE_HYPERVISOR);
    l4tab[l4_table_offset(PERDOMAIN_VIRT_START)] =
        l4e_create_phys(__pa(d->arch.mm_perdomain_l3), __PAGE_HYPERVISOR);
    ed->arch.guest_table = mk_pagetable(__pa(l4start));

    l4tab += l4_table_offset(dsi.v_start);
    mfn = alloc_start >> PAGE_SHIFT;
    for ( count = 0; count < ((v_end-dsi.v_start)>>PAGE_SHIFT); count++ )
    {
        if ( !((unsigned long)l1tab & (PAGE_SIZE-1)) )
        {
            phys_to_page(mpt_alloc)->u.inuse.type_info = PGT_l1_page_table;
            l1start = l1tab = __va(mpt_alloc); mpt_alloc += PAGE_SIZE;
            clear_page(l1tab);
            if ( count == 0 )
                l1tab += l1_table_offset(dsi.v_start);
            if ( !((unsigned long)l2tab & (PAGE_SIZE-1)) )
            {
                phys_to_page(mpt_alloc)->u.inuse.type_info = PGT_l2_page_table;
                l2start = l2tab = __va(mpt_alloc); mpt_alloc += PAGE_SIZE;
                clear_page(l2tab);
                if ( count == 0 )
                    l2tab += l2_table_offset(dsi.v_start);
                if ( !((unsigned long)l3tab & (PAGE_SIZE-1)) )
                {
                    phys_to_page(mpt_alloc)->u.inuse.type_info =
                        PGT_l3_page_table;
                    l3start = l3tab = __va(mpt_alloc); mpt_alloc += PAGE_SIZE;
                    clear_page(l3tab);
                    if ( count == 0 )
                        l3tab += l3_table_offset(dsi.v_start);
                    *l4tab = l4e_create_phys(__pa(l3start), L4_PROT);
                    l4tab++;
                }
                *l3tab = l3e_create_phys(__pa(l2start), L3_PROT);
                l3tab++;
            }
            *l2tab = l2e_create_phys(__pa(l1start), L2_PROT);
            l2tab++;
        }
        *l1tab = l1e_create_pfn(mfn, L1_PROT);
        l1tab++;

        page = &frame_table[mfn];
        if ( (page->u.inuse.type_info == 0) &&
             !get_page_and_type(page, d, PGT_writable_page) )
            BUG();

        mfn++;
    }

    /* Pages that are part of page tables must be read only. */
    l4tab = l4start + l4_table_offset(vpt_start);
    l3start = l3tab = l4e_to_l3e(*l4tab);
    l3tab += l3_table_offset(vpt_start);
    l2start = l2tab = l3e_to_l2e(*l3tab);
    l2tab += l2_table_offset(vpt_start);
    l1start = l1tab = l2e_to_l1e(*l2tab);
    l1tab += l1_table_offset(vpt_start);
    for ( count = 0; count < nr_pt_pages; count++ ) 
    {
        l1e_remove_flags(l1tab, _PAGE_RW);
        page = &frame_table[l1e_get_pfn(*l1tab)];

        /* Read-only mapping + PGC_allocated + page-table page. */
        page->count_info         = PGC_allocated | 3;
        page->u.inuse.type_info |= PGT_validated | 1;

        /* Top-level p.t. is pinned. */
        if ( (page->u.inuse.type_info & PGT_type_mask) == PGT_l4_page_table )
        {
            page->count_info        += 1;
            page->u.inuse.type_info += 1 | PGT_pinned;
        }

        /* Iterate. */
        if ( !((unsigned long)++l1tab & (PAGE_SIZE - 1)) )
        {
            if ( !((unsigned long)++l2tab & (PAGE_SIZE - 1)) )
            {
                if ( !((unsigned long)++l3tab & (PAGE_SIZE - 1)) )
                    l3start = l3tab = l4e_to_l3e(*++l4tab); 
                l2start = l2tab = l3e_to_l2e(*l3tab);
            }
            l1start = l1tab = l2e_to_l1e(*l2tab);
        }
    }

#endif /* __x86_64__ */

    /* Mask all upcalls... */
    for ( i = 0; i < MAX_VIRT_CPUS; i++ )
        d->shared_info->vcpu_data[i].evtchn_upcall_mask = 1;
    d->shared_info->n_vcpu = smp_num_cpus;

    /* Set up monitor table */
    update_pagetables(ed);

    /* Install the new page tables. */
    local_irq_disable();
    write_ptbase(ed);

    /* Copy the OS image and free temporary buffer. */
    (void)loadelfimage(&dsi);

    init_domheap_pages(
        _image_start, (_image_start+image_len+PAGE_SIZE-1) & PAGE_MASK);

    /* Copy the initial ramdisk and free temporary buffer. */
    if ( initrd_len != 0 )
    {
        memcpy((void *)vinitrd_start, initrd_start, initrd_len);
        init_domheap_pages(
            _initrd_start, (_initrd_start+initrd_len+PAGE_SIZE-1) & PAGE_MASK);
    }

    d->next_io_page = max_page;

    /* Set up start info area. */
    si = (start_info_t *)vstartinfo_start;
    memset(si, 0, PAGE_SIZE);
    si->nr_pages     = nr_pages;

    if ( opt_dom0_translate )
    {
        si->shared_info  = d->next_io_page << PAGE_SHIFT;
        set_machinetophys(virt_to_phys(d->shared_info) >> PAGE_SHIFT,
                          d->next_io_page);
        d->next_io_page++;
    }
    else
        si->shared_info  = virt_to_phys(d->shared_info);

    si->flags        = SIF_PRIVILEGED | SIF_INITDOMAIN;
    si->pt_base      = vpt_start;
    si->nr_pt_frames = nr_pt_pages;
    si->mfn_list     = vphysmap_start;

    /* Write the phys->machine and machine->phys table entries. */
    for ( pfn = 0; pfn < d->tot_pages; pfn++ )
    {
        mfn = pfn + (alloc_start>>PAGE_SHIFT);
#ifndef NDEBUG
#define REVERSE_START ((v_end - dsi.v_start) >> PAGE_SHIFT)
        if ( !opt_dom0_translate && (pfn > REVERSE_START) )
            mfn = (alloc_end>>PAGE_SHIFT) - (pfn - REVERSE_START);
#endif
        ((u32 *)vphysmap_start)[pfn] = mfn;
        machine_to_phys_mapping[mfn] = pfn;
    }
    while ( pfn < nr_pages )
    {
        if ( (page = alloc_largest(d, nr_pages - d->tot_pages)) == NULL )
            panic("Not enough RAM for DOM0 reservation.\n");
        while ( pfn < d->tot_pages )
        {
            mfn = page_to_pfn(page);
#ifndef NDEBUG
#define pfn (nr_pages - 1 - (pfn - ((alloc_end - alloc_start) >> PAGE_SHIFT)))
#endif
            ((u32 *)vphysmap_start)[pfn] = mfn;
            machine_to_phys_mapping[mfn] = pfn;
#undef pfn
            page++; pfn++;
        }
    }

    if ( initrd_len != 0 )
    {
        si->mod_start = vinitrd_start;
        si->mod_len   = initrd_len;
        printk("Initrd len 0x%lx, start at 0x%lx\n",
               si->mod_len, si->mod_start);
    }

    dst = (char *)si->cmd_line;
    if ( cmdline != NULL )
    {
        for ( i = 0; i < 255; i++ )
        {
            if ( cmdline[i] == '\0' )
                break;
            *dst++ = cmdline[i];
        }
    }
    *dst = '\0';

    /* Reinstate the caller's page tables. */
    write_ptbase(current);
    local_irq_enable();

#if defined(__i386__)
    /* Destroy low mappings - they were only for our convenience. */
    for ( i = 0; i < DOMAIN_ENTRIES_PER_L2_PAGETABLE; i++ )
        if ( l2e_get_flags(l2start[i]) & _PAGE_PSE )
            l2start[i] = l2e_empty();
    zap_low_mappings(); /* Do the same for the idle page tables. */
#endif
    
    /* DOM0 gets access to everything. */
    physdev_init_dom0(d);

    set_bit(_DOMF_constructed, &d->domain_flags);

    new_thread(ed, dsi.v_kernentry, vstack_end, vstartinfo_start);

    if ( opt_dom0_shadow || opt_dom0_translate )
    {
        shadow_mode_enable(d, (opt_dom0_translate
                               ? SHM_enable | SHM_refcounts | SHM_translate
                               : SHM_enable));
        if ( opt_dom0_translate )
        {
            /* Hmm, what does this?
               Looks like isn't portable across 32/64 bit and pae/non-pae ...
               -- kraxel */

            /* mafetter: This code is mostly a hack in order to be able to
             * test with dom0's which are running with shadow translate.
             * I expect we'll rip this out once we have a stable set of
             * domU clients which use the various shadow modes, but it's
             * useful to leave this here for now...
             */

            // map this domain's p2m table into current page table,
            // so that we can easily access it.
            //
            ASSERT( root_get_value(idle_pg_table[1]) == 0 );
            ASSERT( pagetable_val(d->arch.phys_table) );
            idle_pg_table[1] = root_create_phys(
                pagetable_val(d->arch.phys_table), __PAGE_HYPERVISOR);
            translate_l2pgtable(d, (l1_pgentry_t *)(1u << L2_PAGETABLE_SHIFT),
                                pagetable_get_pfn(ed->arch.guest_table));
            idle_pg_table[1] = root_empty();
            local_flush_tlb();
        }

        update_pagetables(ed); /* XXX SMP */
    }

    return 0;
}

int elf_sanity_check(Elf_Ehdr *ehdr)
{
    if ( !IS_ELF(*ehdr) ||
#if defined(__i386__)
         (ehdr->e_ident[EI_CLASS] != ELFCLASS32) ||
         (ehdr->e_machine != EM_386) ||
#elif defined(__x86_64__)
         (ehdr->e_ident[EI_CLASS] != ELFCLASS64) ||
         (ehdr->e_machine != EM_X86_64) ||
#endif
         (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) ||
         (ehdr->e_type != ET_EXEC) )
    {
        printk("DOM0 image is not a Xen-compatible Elf image.\n");
        return 0;
    }

    return 1;
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
