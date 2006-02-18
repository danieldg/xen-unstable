/******************************************************************************
 * memory.c
 *
 * Code to handle memory-related requests.
 *
 * Copyright (c) 2003-2004, B Dragovic
 * Copyright (c) 2003-2005, K A Fraser
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/perfc.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/shadow.h>
#include <xen/iocap.h>
#include <asm/current.h>
#include <asm/hardirq.h>
#include <public/memory.h>

/*
 * To allow safe resume of do_memory_op() after preemption, we need to know 
 * at what point in the page list to resume. For this purpose I steal the 
 * high-order bits of the @cmd parameter, which are otherwise unused and zero.
 */
#define START_EXTENT_SHIFT 4 /* cmd[:4] == start_extent */

static long
increase_reservation(
    struct domain *d, 
    unsigned long *extent_list, 
    unsigned int   nr_extents,
    unsigned int   extent_order,
    unsigned int   flags,
    int           *preempted)
{
    struct page_info *page;
    unsigned long     i, mfn;

    if ( (extent_list != NULL) &&
         !array_access_ok(extent_list, nr_extents, sizeof(*extent_list)) )
        return 0;

    if ( (extent_order != 0) &&
         !multipage_allocation_permitted(current->domain) )
        return 0;

    for ( i = 0; i < nr_extents; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            *preempted = 1;
            return i;
        }

        if ( unlikely((page = alloc_domheap_pages(
            d, extent_order, flags)) == NULL) )
        {
            DPRINTK("Could not allocate order=%d extent: "
                    "id=%d flags=%x (%ld of %d)\n",
                    extent_order, d->domain_id, flags, i, nr_extents);
            return i;
        }

        /* Inform the domain of the new page's machine address. */ 
        if ( extent_list != NULL )
        {
            mfn = page_to_mfn(page);
            if ( unlikely(__copy_to_user(&extent_list[i], &mfn, sizeof(mfn))) )
                return i;
        }
    }

    return nr_extents;
}

static long
populate_physmap(
    struct domain *d, 
    unsigned long *extent_list, 
    unsigned int   nr_extents,
    unsigned int   extent_order,
    unsigned int   flags,
    int           *preempted)
{
    struct page_info *page;
    unsigned long    i, j, gpfn, mfn;

    if ( !array_access_ok(extent_list, nr_extents, sizeof(*extent_list)) )
        return 0;

    if ( (extent_order != 0) &&
         !multipage_allocation_permitted(current->domain) )
        return 0;

    for ( i = 0; i < nr_extents; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            *preempted = 1;
            goto out;
        }

        if ( unlikely(__copy_from_user(&gpfn, &extent_list[i], sizeof(gpfn))) )
            goto out;

        if ( unlikely((page = alloc_domheap_pages(
            d, extent_order, flags)) == NULL) )
        {
            DPRINTK("Could not allocate order=%d extent: "
                    "id=%d flags=%x (%ld of %d)\n",
                    extent_order, d->domain_id, flags, i, nr_extents);
            goto out;
        }

        mfn = page_to_mfn(page);

        if ( unlikely(shadow_mode_translate(d)) )
        {
            for ( j = 0; j < (1 << extent_order); j++ )
                guest_physmap_add_page(d, gpfn + j, mfn + j);
        }
        else
        {
            for ( j = 0; j < (1 << extent_order); j++ )
                set_gpfn_from_mfn(mfn + j, gpfn + j);

            /* Inform the domain of the new page's machine address. */ 
            if ( unlikely(__copy_to_user(&extent_list[i], &mfn, sizeof(mfn))) )
                goto out;
        }
    }

 out:
    return i;
}
    
static long
decrease_reservation(
    struct domain *d, 
    unsigned long *extent_list, 
    unsigned int   nr_extents,
    unsigned int   extent_order,
    unsigned int   flags,
    int           *preempted)
{
    struct page_info *page;
    unsigned long    i, j, gmfn, mfn;

    if ( !array_access_ok(extent_list, nr_extents, sizeof(*extent_list)) )
        return 0;

    for ( i = 0; i < nr_extents; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            *preempted = 1;
            return i;
        }

        if ( unlikely(__copy_from_user(&gmfn, &extent_list[i], sizeof(gmfn))) )
            return i;

        for ( j = 0; j < (1 << extent_order); j++ )
        {
            mfn = gmfn_to_mfn(d, gmfn + j);
            if ( unlikely(!mfn_valid(mfn)) )
            {
                DPRINTK("Domain %u page number %lx invalid\n",
                        d->domain_id, mfn);
                return i;
            }
            
            page = mfn_to_page(mfn);
            if ( unlikely(!get_page(page, d)) )
            {
                DPRINTK("Bad page free for domain %u\n", d->domain_id);
                return i;
            }

            if ( test_and_clear_bit(_PGT_pinned, &page->u.inuse.type_info) )
                put_page_and_type(page);
            
            if ( test_and_clear_bit(_PGC_allocated, &page->count_info) )
                put_page(page);

            guest_physmap_remove_page(d, gmfn + j, mfn);

            put_page(page);
        }
    }

    return nr_extents;
}

static long
translate_gpfn_list(
    struct xen_translate_gpfn_list *uop, unsigned long *progress)
{
    struct xen_translate_gpfn_list op;
    unsigned long i, gpfn, mfn;
    struct domain *d;

    if ( copy_from_user(&op, uop, sizeof(op)) )
        return -EFAULT;

    /* Is size too large for us to encode a continuation? */
    if ( op.nr_gpfns > (ULONG_MAX >> START_EXTENT_SHIFT) )
        return -EINVAL;

    if ( !array_access_ok(op.gpfn_list, op.nr_gpfns, sizeof(*op.gpfn_list)) ||
         !array_access_ok(op.mfn_list, op.nr_gpfns, sizeof(*op.mfn_list)) )
        return -EFAULT;

    if ( op.domid == DOMID_SELF )
        op.domid = current->domain->domain_id;
    else if ( !IS_PRIV(current->domain) )
        return -EPERM;

    if ( (d = find_domain_by_id(op.domid)) == NULL )
        return -ESRCH;

    if ( !shadow_mode_translate(d) )
    {
        put_domain(d);
        return -EINVAL;
    }

    for ( i = *progress; i < op.nr_gpfns; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            put_domain(d);
            *progress = i;
            return -EAGAIN;
        }

        if ( unlikely(__copy_from_user(&gpfn, &op.gpfn_list[i],
                                       sizeof(gpfn))) )
        {
            put_domain(d);
            return -EFAULT;
        }

        mfn = gmfn_to_mfn(d, gpfn);

        if ( unlikely(__copy_to_user(&op.mfn_list[i], &mfn,
                                     sizeof(mfn))) )
        {
            put_domain(d);
            return -EFAULT;
        }
    }

    put_domain(d);
    return 0;
}

long do_memory_op(unsigned long cmd, void *arg)
{
    struct domain *d;
    int rc, op, flags = 0, preempted = 0;
    unsigned long start_extent, progress;
    struct xen_memory_reservation reservation;
    domid_t domid;

    op = cmd & ((1 << START_EXTENT_SHIFT) - 1);

    switch ( op )
    {
    case XENMEM_increase_reservation:
    case XENMEM_decrease_reservation:
    case XENMEM_populate_physmap:
        if ( copy_from_user(&reservation, arg, sizeof(reservation)) )
            return -EFAULT;

        /* Is size too large for us to encode a continuation? */
        if ( reservation.nr_extents > (ULONG_MAX >> START_EXTENT_SHIFT) )
            return -EINVAL;

        start_extent = cmd >> START_EXTENT_SHIFT;
        if ( unlikely(start_extent > reservation.nr_extents) )
            return -EINVAL;
        
        if ( reservation.extent_start != NULL )
            reservation.extent_start += start_extent;
        reservation.nr_extents -= start_extent;

        if ( (reservation.address_bits != 0) &&
             (reservation.address_bits <
              (get_order_from_pages(max_page) + PAGE_SHIFT)) )
        {
            if ( reservation.address_bits < 31 )
                return -ENOMEM;
            flags = ALLOC_DOM_DMA;
        }

        if ( likely(reservation.domid == DOMID_SELF) )
            d = current->domain;
        else if ( !IS_PRIV(current->domain) )
            return -EPERM;
        else if ( (d = find_domain_by_id(reservation.domid)) == NULL )
            return -ESRCH;

        switch ( op )
        {
        case XENMEM_increase_reservation:
            rc = increase_reservation(
                d,
                reservation.extent_start,
                reservation.nr_extents,
                reservation.extent_order,
                flags,
                &preempted);
            break;
        case XENMEM_decrease_reservation:
            rc = decrease_reservation(
                d,
                reservation.extent_start,
                reservation.nr_extents,
                reservation.extent_order,
                flags,
                &preempted);
            break;
        case XENMEM_populate_physmap:
        default:
            rc = populate_physmap(
                d,
                reservation.extent_start,
                reservation.nr_extents,
                reservation.extent_order,
                flags,
                &preempted);
            break;
        }

        if ( unlikely(reservation.domid != DOMID_SELF) )
            put_domain(d);

        rc += start_extent;

        if ( preempted )
            return hypercall2_create_continuation(
                __HYPERVISOR_memory_op, op | (rc << START_EXTENT_SHIFT), arg);

        break;

    case XENMEM_maximum_ram_page:
        rc = max_page;
        break;

    case XENMEM_current_reservation:
    case XENMEM_maximum_reservation:
        if ( copy_from_user(&domid, (domid_t *)arg, sizeof(domid)) )
            return -EFAULT;

        if ( likely((domid = (unsigned long)arg) == DOMID_SELF) )
            d = current->domain;
        else if ( !IS_PRIV(current->domain) )
            return -EPERM;
        else if ( (d = find_domain_by_id(domid)) == NULL )
            return -ESRCH;

        rc = (op == XENMEM_current_reservation) ? d->tot_pages : d->max_pages;

        if ( unlikely(domid != DOMID_SELF) )
            put_domain(d);

        break;

    case XENMEM_translate_gpfn_list:
        progress = cmd >> START_EXTENT_SHIFT;
        rc = translate_gpfn_list(arg, &progress);
        if ( rc == -EAGAIN )
            return hypercall2_create_continuation(
                __HYPERVISOR_memory_op,
                op | (progress << START_EXTENT_SHIFT),
                arg);
        break;

    default:
        rc = arch_memory_op(op, arg);
        break;
    }

    return rc;
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
