/******************************************************************************
 * dom_mem_ops.c
 *
 * Code to handle memory related requests from domains eg. balloon driver.
 *
 * Copyright (c) 2003-2004, B Dragovic & K A Fraser.
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/perfc.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <asm/domain_page.h>

static long alloc_dom_mem(struct domain *d, 
                          unsigned long *extent_list, 
                          unsigned long  nr_extents,
                          unsigned int   extent_order)
{
    struct pfn_info *page;
    unsigned long    i;

    if ( (extent_order != 0) && !IS_CAPABLE_PHYSDEV(current) )
    {
        DPRINTK("Only I/O-capable domains may allocate > order-0 memory.\n");
        return 0;
    }

    for ( i = 0; i < nr_extents; i++ )
    {
        if ( unlikely((page = alloc_domheap_pages(d, extent_order)) == NULL) )
        {
            DPRINTK("Could not allocate a frame\n");
            return i;
        }

        /* Inform the domain of the new page's machine address. */ 
        if ( unlikely(put_user(page_to_pfn(page), &extent_list[i]) != 0) )
            return i;
    }

    return i;
}
    
static long free_dom_mem(struct domain *d,
                         unsigned long *extent_list, 
                         unsigned long  nr_extents,
                         unsigned int   extent_order)
{
    struct pfn_info *page;
    unsigned long    i, j, mpfn;

    for ( i = 0; i < nr_extents; i++ )
    {
        if ( unlikely(get_user(mpfn, &extent_list[i]) != 0) )
            return i;

        for ( j = 0; j < (1 << extent_order); j++ )
        {
            if ( unlikely((mpfn + j) >= max_page) )
            {
                DPRINTK("Domain %u page number out of range (%08lx>=%08lx)\n", 
                        d->domain, mpfn + j, max_page);
                return i;
            }
            
            page = &frame_table[mpfn + j];
            if ( unlikely(!get_page(page, d)) )
            {
                DPRINTK("Bad page free for domain %u\n", d->domain);
                return i;
            }

            if ( test_and_clear_bit(_PGC_guest_pinned, 
                                    &page->u.inuse.count_info) )
                put_page_and_type(page);
            
            if ( test_and_clear_bit(_PGC_allocated,
                                    &page->u.inuse.count_info) )
                put_page(page);

            put_page(page);
        }
    }

    return i;
}
    
long do_dom_mem_op(unsigned int   op, 
                   unsigned long *extent_list, 
                   unsigned long  nr_extents,
                   unsigned int   extent_order)
{
    if ( op == MEMOP_increase_reservation )
        return alloc_dom_mem(current, extent_list, nr_extents, extent_order);

    if ( op == MEMOP_decrease_reservation )
        return free_dom_mem(current, extent_list, nr_extents, extent_order);

    return -ENOSYS;
}
