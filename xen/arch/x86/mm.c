/******************************************************************************
 * arch/x86/mm.c
 * 
 * Copyright (c) 2002-2005 K A Fraser
 * Copyright (c) 2004 Christian Limpach
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
 * A description of the x86 page table API:
 * 
 * Domains trap to do_mmu_update with a list of update requests.
 * This is a list of (ptr, val) pairs, where the requested operation
 * is *ptr = val.
 * 
 * Reference counting of pages:
 * ----------------------------
 * Each page has two refcounts: tot_count and type_count.
 * 
 * TOT_COUNT is the obvious reference count. It counts all uses of a
 * physical page frame by a domain, including uses as a page directory,
 * a page table, or simple mappings via a PTE. This count prevents a
 * domain from releasing a frame back to the free pool when it still holds
 * a reference to it.
 * 
 * TYPE_COUNT is more subtle. A frame can be put to one of three
 * mutually-exclusive uses: it might be used as a page directory, or a
 * page table, or it may be mapped writable by the domain [of course, a
 * frame may not be used in any of these three ways!].
 * So, type_count is a count of the number of times a frame is being 
 * referred to in its current incarnation. Therefore, a page can only
 * change its type when its type count is zero.
 * 
 * Pinning the page type:
 * ----------------------
 * The type of a page can be pinned/unpinned with the commands
 * MMUEXT_[UN]PIN_L?_TABLE. Each page can be pinned exactly once (that is,
 * pinning is not reference counted, so it can't be nested).
 * This is useful to prevent a page's type count falling to zero, at which
 * point safety checks would need to be carried out next time the count
 * is increased again.
 * 
 * A further note on writable page mappings:
 * -----------------------------------------
 * For simplicity, the count of writable mappings for a page may not
 * correspond to reality. The 'writable count' is incremented for every
 * PTE which maps the page with the _PAGE_RW flag set. However, for
 * write access to be possible the page directory entry must also have
 * its _PAGE_RW bit set. We do not check this as it complicates the 
 * reference counting considerably [consider the case of multiple
 * directory entries referencing a single page table, some with the RW
 * bit set, others not -- it starts getting a bit messy].
 * In normal use, this simplification shouldn't be a problem.
 * However, the logic can be added if required.
 * 
 * One more note on read-only page mappings:
 * -----------------------------------------
 * We want domains to be able to map pages for read-only access. The
 * main reason is that page tables and directories should be readable
 * by a domain, but it would not be safe for them to be writable.
 * However, domains have free access to rings 1 & 2 of the Intel
 * privilege model. In terms of page protection, these are considered
 * to be part of 'supervisor mode'. The WP bit in CR0 controls whether
 * read-only restrictions are respected in supervisor mode -- if the 
 * bit is clear then any mapped page is writable.
 * 
 * We get round this by always setting the WP bit and disallowing 
 * updates to it. This is very unlikely to cause a problem for guest
 * OS's, which will generally use the WP bit to simplify copy-on-write
 * implementation (in that case, OS wants a fault when it writes to
 * an application-supplied buffer).
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/errno.h>
#include <xen/perfc.h>
#include <xen/irq.h>
#include <xen/softirq.h>
#include <asm/shadow.h>
#include <asm/page.h>
#include <asm/flushtlb.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/domain_page.h>
#include <asm/ldt.h>

#ifdef VERBOSE
#define MEM_LOG(_f, _a...)                           \
  printk("DOM%u: MEM_LOG(line=%d) " _f "\n", \
         current->domain->id , __LINE__ , ## _a )
#else
#define MEM_LOG(_f, _a...) ((void)0)
#endif

static void free_l2_table(struct pfn_info *page);
static void free_l1_table(struct pfn_info *page);

static int mod_l2_entry(l2_pgentry_t *, l2_pgentry_t, unsigned long);
static int mod_l1_entry(l1_pgentry_t *, l1_pgentry_t);

/* Used to defer flushing of memory structures. */
static struct {
#define DOP_FLUSH_TLB   (1<<0) /* Flush the TLB.                 */
#define DOP_RELOAD_LDT  (1<<1) /* Reload the LDT shadow mapping. */
    unsigned long  deferred_ops;
    /* If non-NULL, specifies a foreign subject domain for some operations. */
    struct domain *foreign;
} __cacheline_aligned percpu_info[NR_CPUS];

/*
 * Returns the current foreign domain; defaults to the currently-executing
 * domain if a foreign override hasn't been specified.
 */
#define FOREIGNDOM (percpu_info[smp_processor_id()].foreign ? : current->domain)

/* Private domain structs for DOMID_XEN and DOMID_IO. */
static struct domain *dom_xen, *dom_io;

/* Frame table and its size in pages. */
struct pfn_info *frame_table;
unsigned long frame_table_size;
unsigned long max_page;

void __init init_frametable(void)
{
    unsigned long i, p;

    frame_table      = (struct pfn_info *)FRAMETABLE_VIRT_START;
    frame_table_size = max_page * sizeof(struct pfn_info);
    frame_table_size = (frame_table_size + PAGE_SIZE - 1) & PAGE_MASK;

    for ( i = 0; i < frame_table_size; i += (4UL << 20) )
    {
        p = alloc_boot_pages(min(frame_table_size - i, 4UL << 20), 4UL << 20);
        if ( p == 0 )
            panic("Not enough memory for frame table\n");
        map_pages(idle_pg_table, FRAMETABLE_VIRT_START + i, p, 
                  4UL << 20, PAGE_HYPERVISOR);
    }

    memset(frame_table, 0, frame_table_size);
}

void arch_init_memory(void)
{
    extern void subarch_init_memory(struct domain *);

    memset(percpu_info, 0, sizeof(percpu_info));

    /*
     * Initialise our DOMID_XEN domain.
     * Any Xen-heap pages that we will allow to be mapped will have
     * their domain field set to dom_xen.
     */
    dom_xen = alloc_domain_struct();
    atomic_set(&dom_xen->refcnt, 1);
    dom_xen->id = DOMID_XEN;

    /*
     * Initialise our DOMID_IO domain.
     * This domain owns no pages but is considered a special case when
     * mapping I/O pages, as the mappings occur at the priv of the caller.
     */
    dom_io = alloc_domain_struct();
    atomic_set(&dom_io->refcnt, 1);
    dom_io->id = DOMID_IO;

    subarch_init_memory(dom_xen);
}

void write_ptbase(struct exec_domain *ed)
{
    write_cr3(pagetable_val(ed->arch.monitor_table));
}

static void __invalidate_shadow_ldt(struct exec_domain *d)
{
    int i;
    unsigned long pfn;
    struct pfn_info *page;
    
    d->arch.shadow_ldt_mapcnt = 0;

    for ( i = 16; i < 32; i++ )
    {
        pfn = l1_pgentry_to_pfn(d->arch.perdomain_ptes[i]);
        if ( pfn == 0 ) continue;
        d->arch.perdomain_ptes[i] = mk_l1_pgentry(0);
        page = &frame_table[pfn];
        ASSERT_PAGE_IS_TYPE(page, PGT_ldt_page);
        ASSERT_PAGE_IS_DOMAIN(page, d->domain);
        put_page_and_type(page);
    }

    /* Dispose of the (now possibly invalid) mappings from the TLB.  */
    percpu_info[d->processor].deferred_ops |= DOP_FLUSH_TLB | DOP_RELOAD_LDT;
}


void invalidate_shadow_ldt(struct exec_domain *d)
{
    if ( d->arch.shadow_ldt_mapcnt != 0 )
        __invalidate_shadow_ldt(d);
}


static int alloc_segdesc_page(struct pfn_info *page)
{
    struct desc_struct *descs;
    int i;

    descs = map_domain_mem((page-frame_table) << PAGE_SHIFT);

    for ( i = 0; i < 512; i++ )
        if ( unlikely(!check_descriptor(&descs[i])) )
            goto fail;

    unmap_domain_mem(descs);
    return 1;

 fail:
    unmap_domain_mem(descs);
    return 0;
}


/* Map shadow page at offset @off. */
int map_ldt_shadow_page(unsigned int off)
{
    struct exec_domain *ed = current;
    struct domain *d = ed->domain;
    unsigned long l1e, nl1e, gpfn, gmfn;
    unsigned gva = ed->arch.ldt_base + (off << PAGE_SHIFT);
    int res;

    if ( unlikely(in_irq()) )
        BUG();

    shadow_sync_va(ed, gva);
    __get_user(l1e, (unsigned long *)&linear_pg_table[l1_linear_offset(gva)]);

    if ( unlikely(!(l1e & _PAGE_PRESENT)) )
        return 0;

    gpfn = l1_pgentry_to_pfn(mk_l1_pgentry(l1e));
    gmfn = __gpfn_to_mfn(d, gpfn);
    if ( unlikely(!gmfn) )
        return 0;

    if ( unlikely(shadow_mode_enabled(d)) )
    {
        shadow_lock(d);
        shadow_remove_all_write_access(d, PGT_l1_shadow, PGT_l1_shadow, gpfn, gmfn);
    }

    res = get_page_and_type(&frame_table[gmfn], d, PGT_ldt_page);

    if ( unlikely(shadow_mode_enabled(d)) )
        shadow_unlock(d);

    if ( unlikely(!res) )
        return 0;

    nl1e = (l1e & ~PAGE_MASK) | (gmfn << PAGE_SHIFT) | _PAGE_RW;

    ed->arch.perdomain_ptes[off + 16] = mk_l1_pgentry(nl1e);
    ed->arch.shadow_ldt_mapcnt++;

    return 1;
}


static int get_page_from_pagenr(unsigned long page_nr, struct domain *d)
{
    struct pfn_info *page = &frame_table[page_nr];

    if ( unlikely(!pfn_is_ram(page_nr)) )
    {
        MEM_LOG("Pfn %p is not RAM", page_nr);
        return 0;
    }

    if ( unlikely(!get_page(page, d)) )
    {
        MEM_LOG("Could not get page ref for pfn %p", page_nr);
        return 0;
    }

    return 1;
}


static int get_page_and_type_from_pagenr(unsigned long page_nr, 
                                         u32 type,
                                         struct domain *d)
{
    struct pfn_info *page = &frame_table[page_nr];

    if ( unlikely(!get_page_from_pagenr(page_nr, d)) )
        return 0;

    if ( unlikely(!get_page_type(page, type)) )
    {
        if ( (type & PGT_type_mask) != PGT_l1_page_table )
            MEM_LOG("Bad page type for pfn %p (%08x)", 
                    page_nr, page->u.inuse.type_info);
        put_page(page);
        return 0;
    }

    return 1;
}


/*
 * We allow root tables to map each other (a.k.a. linear page tables). It
 * needs some special care with reference counts and access permissions:
 *  1. The mapping entry must be read-only, or the guest may get write access
 *     to its own PTEs.
 *  2. We must only bump the reference counts for an *already validated*
 *     L2 table, or we can end up in a deadlock in get_page_type() by waiting
 *     on a validation that is required to complete that validation.
 *  3. We only need to increment the reference counts for the mapped page
 *     frame if it is mapped by a different root table. This is sufficient and
 *     also necessary to allow validation of a root table mapping itself.
 */
static int 
get_linear_pagetable(
    root_pgentry_t re, unsigned long re_pfn, struct domain *d)
{
    u32 x, y;
    struct pfn_info *page;
    unsigned long pfn;

    ASSERT( !shadow_mode_enabled(d) );

    if ( (root_pgentry_val(re) & _PAGE_RW) )
    {
        MEM_LOG("Attempt to create linear p.t. with write perms");
        return 0;
    }

    if ( (pfn = root_pgentry_to_pfn(re)) != re_pfn )
    {
        /* Make sure the mapped frame belongs to the correct domain. */
        if ( unlikely(!get_page_from_pagenr(pfn, d)) )
            return 0;

        /*
         * Make sure that the mapped frame is an already-validated L2 table. 
         * If so, atomically increment the count (checking for overflow).
         */
        page = &frame_table[pfn];
        y = page->u.inuse.type_info;
        do {
            x = y;
            if ( unlikely((x & PGT_count_mask) == PGT_count_mask) ||
                 unlikely((x & (PGT_type_mask|PGT_validated)) != 
                          (PGT_root_page_table|PGT_validated)) )
            {
                put_page(page);
                return 0;
            }
        }
        while ( (y = cmpxchg(&page->u.inuse.type_info, x, x + 1)) != x );
    }

    return 1;
}


int
get_page_from_l1e(
    l1_pgentry_t l1e, struct domain *d)
{
    unsigned long l1v = l1_pgentry_val(l1e);
    unsigned long mfn = l1_pgentry_to_pfn(l1e);
    struct pfn_info *page = &frame_table[mfn];
    extern int domain_iomem_in_pfn(struct domain *d, unsigned long pfn);

    if ( !(l1v & _PAGE_PRESENT) )
        return 1;

    if ( unlikely(l1v & L1_DISALLOW_MASK) )
    {
        MEM_LOG("Bad L1 type settings %p %p", l1v, l1v & L1_DISALLOW_MASK);
        return 0;
    }

    if ( unlikely(!pfn_is_ram(mfn)) )
    {
        /* Revert to caller privileges if FD == DOMID_IO. */
        if ( d == dom_io )
            d = current->domain;

        if ( IS_PRIV(d) )
            return 1;

        if ( IS_CAPABLE_PHYSDEV(d) )
            return domain_iomem_in_pfn(d, mfn);

        MEM_LOG("Non-privileged attempt to map I/O space %p", mfn);
        return 0;
    }

    return ((l1v & _PAGE_RW) ?
            get_page_and_type(page, d, PGT_writable_page) :
            get_page(page, d));
}


/* NB. Virtual address 'l2e' maps to a machine address within frame 'pfn'. */
static int 
get_page_from_l2e(
    l2_pgentry_t l2e, unsigned long pfn,
    struct domain *d, unsigned long va_idx)
{
    int rc;

    ASSERT( !shadow_mode_enabled(d) );

    if ( !(l2_pgentry_val(l2e) & _PAGE_PRESENT) )
        return 1;

    if ( unlikely((l2_pgentry_val(l2e) & L2_DISALLOW_MASK)) )
    {
        MEM_LOG("Bad L2 page type settings %p",
                l2_pgentry_val(l2e) & L2_DISALLOW_MASK);
        return 0;
    }

    rc = get_page_and_type_from_pagenr(
        l2_pgentry_to_pfn(l2e), 
        PGT_l1_page_table | (va_idx<<PGT_va_shift), d);

#if defined(__i386__)
    return rc ? rc : get_linear_pagetable(l2e, pfn, d);
#elif defined(__x86_64__)
    return rc;
#endif
}


#ifdef __x86_64__

static int 
get_page_from_l3e(
    l3_pgentry_t l3e, unsigned long pfn, struct domain *d)
{
    if ( !(l3_pgentry_val(l3e) & _PAGE_PRESENT) )
        return 1;

    if ( unlikely((l3_pgentry_val(l3e) & L3_DISALLOW_MASK)) )
    {
        MEM_LOG("Bad L3 page type settings %p",
                l3_pgentry_val(l3e) & L3_DISALLOW_MASK);
        return 0;
    }

    return get_page_and_type_from_pagenr(
        l3_pgentry_to_pfn(l3e), PGT_l2_page_table, d);
}


static int 
get_page_from_l4e(
    l4_pgentry_t l4e, unsigned long pfn, struct domain *d)
{
    int rc;

    if ( !(l4_pgentry_val(l4e) & _PAGE_PRESENT) )
        return 1;

    if ( unlikely((l4_pgentry_val(l4e) & L4_DISALLOW_MASK)) )
    {
        MEM_LOG("Bad L4 page type settings %p",
                l4_pgentry_val(l4e) & L4_DISALLOW_MASK);
        return 0;
    }

    rc = get_page_and_type_from_pagenr(
        l4_pgentry_to_pfn(l4e), PGT_l3_page_table, d);

    if ( unlikely(!rc) )
        return get_linear_pagetable(l4e, pfn, d);

    return 1;
}

#endif /* __x86_64__ */


void put_page_from_l1e(l1_pgentry_t l1e, struct domain *d)
{
    unsigned long    l1v  = l1_pgentry_val(l1e);
    unsigned long    pfn  = l1_pgentry_to_pfn(l1e);
    struct pfn_info *page = &frame_table[pfn];
    struct domain   *e;

    if ( !(l1v & _PAGE_PRESENT) || !pfn_is_ram(pfn) )
        return;

    e = page_get_owner(page);
    if ( unlikely(e != d) )
    {
        /*
         * Unmap a foreign page that may have been mapped via a grant table.
         * Note that this can fail for a privileged domain that can map foreign
         * pages via MMUEXT_SET_FOREIGNDOM. Such domains can have some mappings
         * counted via a grant entry and some counted directly in the page
         * structure's reference count. Note that reference counts won't get
         * dangerously confused as long as we always try to decrement the
         * grant entry first. We may end up with a mismatch between which
         * mappings and which unmappings are counted via the grant entry, but
         * really it doesn't matter as privileged domains have carte blanche.
         */
        if ( likely(gnttab_check_unmap(e, d, pfn, !(l1v & _PAGE_RW))) )
            return;
        /* Assume this mapping was made via MMUEXT_SET_FOREIGNDOM... */
    }

    if ( l1v & _PAGE_RW )
    {
        put_page_and_type(page);
    }
    else
    {
        /* We expect this is rare so we blow the entire shadow LDT. */
        if ( unlikely(((page->u.inuse.type_info & PGT_type_mask) == 
                       PGT_ldt_page)) &&
             unlikely(((page->u.inuse.type_info & PGT_count_mask) != 0)) )

            // XXX SMP BUG?
            invalidate_shadow_ldt(e->exec_domain[0]);
        put_page(page);
    }
}


/*
 * NB. Virtual address 'l2e' maps to a machine address within frame 'pfn'.
 * Note also that this automatically deals correctly with linear p.t.'s.
 */
static void put_page_from_l2e(l2_pgentry_t l2e, unsigned long pfn)
{
    if ( (l2_pgentry_val(l2e) & _PAGE_PRESENT) && 
         (l2_pgentry_to_pfn(l2e) != pfn) )
        put_page_and_type(&frame_table[l2_pgentry_to_pfn(l2e)]);
}


#ifdef __x86_64__

static void put_page_from_l3e(l3_pgentry_t l3e, unsigned long pfn)
{
    if ( (l3_pgentry_val(l3e) & _PAGE_PRESENT) && 
         (l3_pgentry_to_pfn(l3e) != pfn) )
        put_page_and_type(&frame_table[l3_pgentry_to_pfn(l3e)]);
}


static void put_page_from_l4e(l4_pgentry_t l4e, unsigned long pfn)
{
    if ( (l4_pgentry_val(l4e) & _PAGE_PRESENT) && 
         (l4_pgentry_to_pfn(l4e) != pfn) )
        put_page_and_type(&frame_table[l4_pgentry_to_pfn(l4e)]);
}

#endif /* __x86_64__ */


static int alloc_l1_table(struct pfn_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = page_to_pfn(page);
    l1_pgentry_t  *pl1e;
    int            i;

    ASSERT( !shadow_mode_enabled(d) );

    pl1e = map_domain_mem(pfn << PAGE_SHIFT);

    for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
        if ( is_guest_l1_slot(i) &&
             unlikely(!get_page_from_l1e(pl1e[i], d)) )
            goto fail;

    unmap_domain_mem(pl1e);
    return 1;

 fail:
    while ( i-- > 0 )
        if ( is_guest_l1_slot(i) )
            put_page_from_l1e(pl1e[i], d);

    unmap_domain_mem(pl1e);
    return 0;
}


static int alloc_l2_table(struct pfn_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = page_to_pfn(page);
    l2_pgentry_t  *pl2e;
    int            i;

    if ( (PGT_base_page_table == PGT_l2_page_table) &&
         shadow_mode_enabled(d) )
        return 1;
    ASSERT( !shadow_mode_enabled(d) );
   
    pl2e = map_domain_mem(pfn << PAGE_SHIFT);

    for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
        if ( is_guest_l2_slot(i) &&
             unlikely(!get_page_from_l2e(pl2e[i], pfn, d, i)) )
            goto fail;

#if defined(__i386__)
    /* Xen private mappings. */
    memcpy(&pl2e[ROOT_PAGETABLE_FIRST_XEN_SLOT],
           &idle_pg_table[ROOT_PAGETABLE_FIRST_XEN_SLOT],
           ROOT_PAGETABLE_XEN_SLOTS * sizeof(l2_pgentry_t));
    pl2e[l2_table_offset(LINEAR_PT_VIRT_START)] =
        mk_l2_pgentry((pfn << PAGE_SHIFT) | __PAGE_HYPERVISOR);
    pl2e[l2_table_offset(PERDOMAIN_VIRT_START)] =
        mk_l2_pgentry(__pa(page_get_owner(page)->arch.mm_perdomain_pt) | 
                      __PAGE_HYPERVISOR);
#endif

    unmap_domain_mem(pl2e);
    return 1;

 fail:
    while ( i-- > 0 )
        if ( is_guest_l2_slot(i) )
            put_page_from_l2e(pl2e[i], pfn);

    unmap_domain_mem(pl2e);
    return 0;
}


#ifdef __x86_64__

static int alloc_l3_table(struct pfn_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = page_to_pfn(page);
    l3_pgentry_t  *pl3e = page_to_virt(page);
    int            i;

    ASSERT( !shadow_mode_enabled(d) );

    for ( i = 0; i < L3_PAGETABLE_ENTRIES; i++ )
        if ( is_guest_l3_slot(i) &&
             unlikely(!get_page_from_l3e(pl3e[i], pfn, d)) )
            goto fail;

    return 1;

 fail:
    while ( i-- > 0 )
        if ( is_guest_l3_slot(i) )
            put_page_from_l3e(pl3e[i], pfn);

    return 0;
}


static int alloc_l4_table(struct pfn_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long  pfn = page_to_pfn(page);
    l4_pgentry_t  *pl4e = page_to_virt(page);
    int            i;

    if ( (PGT_base_page_table == PGT_l4_page_table) &&
         shadow_mode_enabled(d) )
        return 1;
    ASSERT( !shadow_mode_enabled(d) );

    for ( i = 0; i < L4_PAGETABLE_ENTRIES; i++ )
        if ( is_guest_l4_slot(i) &&
             unlikely(!get_page_from_l4e(pl4e[i], pfn, d)) )
            goto fail;

    /* Xen private mappings. */
    memcpy(&pl4e[ROOT_PAGETABLE_FIRST_XEN_SLOT],
           &idle_pg_table[ROOT_PAGETABLE_FIRST_XEN_SLOT],
           ROOT_PAGETABLE_XEN_SLOTS * sizeof(l4_pgentry_t));
    pl4e[l4_table_offset(LINEAR_PT_VIRT_START)] =
        mk_l4_pgentry((pfn << PAGE_SHIFT) | __PAGE_HYPERVISOR);
    pl4e[l4_table_offset(PERDOMAIN_VIRT_START)] =
        mk_l4_pgentry(__pa(page_get_owner(page)->arch.mm_perdomain_l3) | 
                      __PAGE_HYPERVISOR);

    return 1;

 fail:
    while ( i-- > 0 )
        if ( is_guest_l4_slot(i) )
            put_page_from_l4e(pl4e[i], pfn);

    return 0;
}

#endif /* __x86_64__ */


static void free_l1_table(struct pfn_info *page)
{
    struct domain *d = page_get_owner(page);
    unsigned long pfn = page_to_pfn(page);
    l1_pgentry_t *pl1e;
    int i;

    pl1e = map_domain_mem(pfn << PAGE_SHIFT);

    for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
        if ( is_guest_l1_slot(i) )
            put_page_from_l1e(pl1e[i], d);

    unmap_domain_mem(pl1e);
}


static void free_l2_table(struct pfn_info *page)
{
    unsigned long pfn = page_to_pfn(page);
    l2_pgentry_t *pl2e;
    int i;

    pl2e = map_domain_mem(pfn << PAGE_SHIFT);

    for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++ )
        if ( is_guest_l2_slot(i) )
            put_page_from_l2e(pl2e[i], pfn);

    unmap_domain_mem(pl2e);
}


#ifdef __x86_64__

static void free_l3_table(struct pfn_info *page)
{
    unsigned long pfn = page_to_pfn(page);
    l3_pgentry_t *pl3e = page_to_virt(page);
    int           i;

    for ( i = 0; i < L3_PAGETABLE_ENTRIES; i++ )
        if ( is_guest_l3_slot(i) )
            put_page_from_l3e(pl3e[i], pfn);
}


static void free_l4_table(struct pfn_info *page)
{
    unsigned long pfn = page_to_pfn(page);
    l4_pgentry_t *pl4e = page_to_virt(page);
    int           i;

    for ( i = 0; i < L4_PAGETABLE_ENTRIES; i++ )
        if ( is_guest_l4_slot(i) )
            put_page_from_l4e(pl4e[i], pfn);
}

#endif /* __x86_64__ */


static inline int update_l1e(l1_pgentry_t *pl1e, 
                             l1_pgentry_t  ol1e, 
                             l1_pgentry_t  nl1e)
{
    unsigned long o = l1_pgentry_val(ol1e);
    unsigned long n = l1_pgentry_val(nl1e);

    if ( unlikely(cmpxchg_user(pl1e, o, n) != 0) ||
         unlikely(o != l1_pgentry_val(ol1e)) )
    {
        MEM_LOG("Failed to update %p -> %p: saw %p",
                l1_pgentry_val(ol1e), l1_pgentry_val(nl1e), o);
        return 0;
    }

    return 1;
}


/* Update the L1 entry at pl1e to new value nl1e. */
static int mod_l1_entry(l1_pgentry_t *pl1e, l1_pgentry_t nl1e)
{
    l1_pgentry_t ol1e;
    unsigned long _ol1e;
    struct domain *d = current->domain;

    ASSERT( !shadow_mode_enabled(d) );

    if ( unlikely(__get_user(_ol1e, (unsigned long *)pl1e) != 0) )
        return 0;
    ol1e = mk_l1_pgentry(_ol1e);

    if ( l1_pgentry_val(nl1e) & _PAGE_PRESENT )
    {
        if ( unlikely(l1_pgentry_val(nl1e) & L1_DISALLOW_MASK) )
        {
            MEM_LOG("Bad L1 type settings %p", 
                    l1_pgentry_val(nl1e) & L1_DISALLOW_MASK);
            return 0;
        }

        /* Fast path for identical mapping, r/w and presence. */
        if ( ((l1_pgentry_val(ol1e) ^ l1_pgentry_val(nl1e)) & 
              ((PADDR_MASK & PAGE_MASK) | _PAGE_RW | _PAGE_PRESENT)) == 0 )
            return update_l1e(pl1e, ol1e, nl1e);

        if ( unlikely(!get_page_from_l1e(nl1e, FOREIGNDOM)) )
            return 0;
        
        if ( unlikely(!update_l1e(pl1e, ol1e, nl1e)) )
        {
            put_page_from_l1e(nl1e, d);
            return 0;
        }
    }
    else
    {
        if ( unlikely(!update_l1e(pl1e, ol1e, nl1e)) )
            return 0;
    }
    
    put_page_from_l1e(ol1e, d);
    return 1;
}


#define UPDATE_ENTRY(_t,_p,_o,_n) ({                                    \
    unsigned long __o = cmpxchg((unsigned long *)(_p),                  \
                                _t ## _pgentry_val(_o),                 \
                                _t ## _pgentry_val(_n));                \
    if ( __o != _t ## _pgentry_val(_o) )                                \
        MEM_LOG("Failed to update %p -> %p: saw %p",                    \
                _t ## _pgentry_val(_o), _t ## _pgentry_val(_n), __o);   \
    (__o == _t ## _pgentry_val(_o)); })


/* Update the L2 entry at pl2e to new value nl2e. pl2e is within frame pfn. */
static int mod_l2_entry(l2_pgentry_t *pl2e, 
                        l2_pgentry_t nl2e, 
                        unsigned long pfn)
{
    l2_pgentry_t ol2e;
    unsigned long _ol2e;

    if ( unlikely(!is_guest_l2_slot(pgentry_ptr_to_slot(pl2e))) )
    {
        MEM_LOG("Illegal L2 update attempt in Xen-private area %p", pl2e);
        return 0;
    }

    if ( unlikely(__get_user(_ol2e, (unsigned long *)pl2e) != 0) )
        return 0;
    ol2e = mk_l2_pgentry(_ol2e);

    if ( l2_pgentry_val(nl2e) & _PAGE_PRESENT )
    {
        if ( unlikely(l2_pgentry_val(nl2e) & L2_DISALLOW_MASK) )
        {
            MEM_LOG("Bad L2 type settings %p", 
                    l2_pgentry_val(nl2e) & L2_DISALLOW_MASK);
            return 0;
        }

        /* Fast path for identical mapping and presence. */
        if ( ((l2_pgentry_val(ol2e) ^ l2_pgentry_val(nl2e)) & 
              ((PADDR_MASK & PAGE_MASK) | _PAGE_PRESENT)) == 0 )
            return UPDATE_ENTRY(l2, pl2e, ol2e, nl2e);

        if ( unlikely(!get_page_from_l2e(nl2e, pfn, current->domain,
                                        ((unsigned long)pl2e & 
                                         ~PAGE_MASK) >> 2)) )
            return 0;

        if ( unlikely(!UPDATE_ENTRY(l2, pl2e, ol2e, nl2e)) )
        {
            put_page_from_l2e(nl2e, pfn);
            return 0;
        }
    }
    else
    {
        if ( unlikely(!UPDATE_ENTRY(l2, pl2e, ol2e, nl2e)) )
            return 0;
    }

    put_page_from_l2e(ol2e, pfn);
    return 1;
}


#ifdef __x86_64__

/* Update the L3 entry at pl3e to new value nl3e. pl3e is within frame pfn. */
static int mod_l3_entry(l3_pgentry_t *pl3e, 
                        l3_pgentry_t nl3e, 
                        unsigned long pfn)
{
    l3_pgentry_t ol3e;
    unsigned long _ol3e;

    if ( unlikely(!is_guest_l3_slot(pgentry_ptr_to_slot(pl3e))) )
    {
        MEM_LOG("Illegal L3 update attempt in Xen-private area %p", pl3e);
        return 0;
    }

    if ( unlikely(__get_user(_ol3e, (unsigned long *)pl3e) != 0) )
        return 0;
    ol3e = mk_l3_pgentry(_ol3e);

    if ( l3_pgentry_val(nl3e) & _PAGE_PRESENT )
    {
        if ( unlikely(l3_pgentry_val(nl3e) & L3_DISALLOW_MASK) )
        {
            MEM_LOG("Bad L3 type settings %p", 
                    l3_pgentry_val(nl3e) & L3_DISALLOW_MASK);
            return 0;
        }

        /* Fast path for identical mapping and presence. */
        if ( ((l3_pgentry_val(ol3e) ^ l3_pgentry_val(nl3e)) & 
              ((PADDR_MASK & PAGE_MASK) | _PAGE_PRESENT)) == 0 )
            return UPDATE_ENTRY(l3, pl3e, ol3e, nl3e);

        if ( unlikely(!get_page_from_l3e(nl3e, pfn, current->domain)) )
            return 0;

        if ( unlikely(!UPDATE_ENTRY(l3, pl3e, ol3e, nl3e)) )
        {
            put_page_from_l3e(nl3e, pfn);
            return 0;
        }
        
        put_page_from_l3e(ol3e, pfn);
        return 1;
    }

    if ( unlikely(!UPDATE_ENTRY(l3, pl3e, ol3e, nl3e)) )
        return 0;

    put_page_from_l3e(ol3e, pfn);
    return 1;
}


/* Update the L4 entry at pl4e to new value nl4e. pl4e is within frame pfn. */
static int mod_l4_entry(l4_pgentry_t *pl4e, 
                        l4_pgentry_t nl4e, 
                        unsigned long pfn)
{
    l4_pgentry_t ol4e;
    unsigned long _ol4e;

    if ( unlikely(!is_guest_l4_slot(pgentry_ptr_to_slot(pl4e))) )
    {
        MEM_LOG("Illegal L4 update attempt in Xen-private area %p", pl4e);
        return 0;
    }

    if ( unlikely(__get_user(_ol4e, (unsigned long *)pl4e) != 0) )
        return 0;
    ol4e = mk_l4_pgentry(_ol4e);

    if ( l4_pgentry_val(nl4e) & _PAGE_PRESENT )
    {
        if ( unlikely(l4_pgentry_val(nl4e) & L4_DISALLOW_MASK) )
        {
            MEM_LOG("Bad L4 type settings %p", 
                    l4_pgentry_val(nl4e) & L4_DISALLOW_MASK);
            return 0;
        }

        /* Fast path for identical mapping and presence. */
        if ( ((l4_pgentry_val(ol4e) ^ l4_pgentry_val(nl4e)) & 
              ((PADDR_MASK & PAGE_MASK) | _PAGE_PRESENT)) == 0 )
            return UPDATE_ENTRY(l4, pl4e, ol4e, nl4e);

        if ( unlikely(!get_page_from_l4e(nl4e, pfn, current->domain)) )
            return 0;

        if ( unlikely(!UPDATE_ENTRY(l4, pl4e, ol4e, nl4e)) )
        {
            put_page_from_l4e(nl4e, pfn);
            return 0;
        }
        
        put_page_from_l4e(ol4e, pfn);
        return 1;
    }

    if ( unlikely(!UPDATE_ENTRY(l4, pl4e, ol4e, nl4e)) )
        return 0;

    put_page_from_l4e(ol4e, pfn);
    return 1;
}

#endif /* __x86_64__ */


int alloc_page_type(struct pfn_info *page, unsigned int type)
{
    switch ( type )
    {
    case PGT_l1_page_table:
        return alloc_l1_table(page);
    case PGT_l2_page_table:
        return alloc_l2_table(page);
#ifdef __x86_64__
    case PGT_l3_page_table:
        return alloc_l3_table(page);
    case PGT_l4_page_table:
        return alloc_l4_table(page);
#endif
    case PGT_gdt_page:
    case PGT_ldt_page:
        return alloc_segdesc_page(page);
    default:
        printk("Bad type in alloc_page_type %x t=%x c=%x\n", 
               type, page->u.inuse.type_info,
               page->count_info);
        BUG();
    }

    return 0;
}


void free_page_type(struct pfn_info *page, unsigned int type)
{
    struct domain *owner = page_get_owner(page);
    if ( likely(owner != NULL) && unlikely(shadow_mode_enabled(owner)) )
        return;

    switch ( type )
    {
    case PGT_l1_page_table:
        free_l1_table(page);
        break;

    case PGT_l2_page_table:
        free_l2_table(page);
        break;

#ifdef __x86_64__
    case PGT_l3_page_table:
        free_l3_table(page);
        break;

    case PGT_l4_page_table:
        free_l4_table(page);
        break;
#endif

    default:
        BUG();
    }
}


void put_page_type(struct pfn_info *page)
{
    u32 nx, x, y = page->u.inuse.type_info;

 again:
    do {
        x  = y;
        nx = x - 1;

        ASSERT((x & PGT_count_mask) != 0);

        /*
         * The page should always be validated while a reference is held. The 
         * exception is during domain destruction, when we forcibly invalidate 
         * page-table pages if we detect a referential loop.
         * See domain.c:relinquish_list().
         */
        ASSERT((x & PGT_validated) || 
               test_bit(DF_DYING, &page_get_owner(page)->d_flags));

        if ( unlikely((nx & PGT_count_mask) == 0) )
        {
            /* Record TLB information for flush later. Races are harmless. */
            page->tlbflush_timestamp = tlbflush_current_time();
            
            if ( unlikely((nx & PGT_type_mask) <= PGT_l4_page_table) &&
                 likely(nx & PGT_validated) )
            {
                /*
                 * Page-table pages must be unvalidated when count is zero. The
                 * 'free' is safe because the refcnt is non-zero and validated
                 * bit is clear => other ops will spin or fail.
                 */
                if ( unlikely((y = cmpxchg(&page->u.inuse.type_info, x, 
                                           x & ~PGT_validated)) != x) )
                    goto again;
                /* We cleared the 'valid bit' so we do the clean up. */
                free_page_type(page, x & PGT_type_mask);
                /* Carry on, but with the 'valid bit' now clear. */
                x  &= ~PGT_validated;
                nx &= ~PGT_validated;
            }
        }
        else if ( unlikely(((nx & (PGT_pinned | PGT_count_mask)) == 
                            (PGT_pinned | 1)) &&
                           ((nx & PGT_type_mask) != PGT_writable_page)) )
        {
            /* Page is now only pinned. Make the back pointer mutable again. */
            nx |= PGT_va_mutable;
        }
    }
    while ( unlikely((y = cmpxchg(&page->u.inuse.type_info, x, nx)) != x) );
}


int get_page_type(struct pfn_info *page, u32 type)
{
    u32 nx, x, y = page->u.inuse.type_info;

 again:
    do {
        x  = y;
        nx = x + 1;
        if ( unlikely((nx & PGT_count_mask) == 0) )
        {
            MEM_LOG("Type count overflow on pfn %p", page_to_pfn(page));
            return 0;
        }
        else if ( unlikely((x & PGT_count_mask) == 0) )
        {
            if ( (x & (PGT_type_mask|PGT_va_mask)) != type )
            {
                /*
                 * On type change we check to flush stale TLB entries. This 
                 * may be unnecessary (e.g., page was GDT/LDT) but those
                 * circumstances should be very rare.
                 */
                struct domain *d = page_get_owner(page);

                // XXX SMP bug?
                if ( unlikely(NEED_FLUSH(tlbflush_time[d->exec_domain[0]->
                                                      processor],
                                         page->tlbflush_timestamp)) )
                {
                    perfc_incr(need_flush_tlb_flush);
                    flush_tlb_cpu(d->exec_domain[0]->processor);
                }

                /* We lose existing type, back pointer, and validity. */
                nx &= ~(PGT_type_mask | PGT_va_mask | PGT_validated);
                nx |= type;

                /* No special validation needed for writable pages. */
                /* Page tables and GDT/LDT need to be scanned for validity. */
                if ( type == PGT_writable_page )
                    nx |= PGT_validated;
            }
        }
        else if ( unlikely(!(x & PGT_validated)) )
        {
            /* Someone else is updating validation of this page. Wait... */
            while ( (y = page->u.inuse.type_info) == x )
            {
                rep_nop();
                barrier();
            }
            goto again;
        }
        else if ( unlikely((x & (PGT_type_mask|PGT_va_mask)) != type) )
        {
            if ( unlikely((x & PGT_type_mask) != (type & PGT_type_mask) ) )
            {
                if ( ((x & PGT_type_mask) != PGT_l2_page_table) ||
                     ((type & PGT_type_mask) != PGT_l1_page_table) )
                    MEM_LOG("Bad type (saw %08x != exp %08x) for pfn %p",
                            x, type, page_to_pfn(page));
                return 0;
            }
            else if ( (x & PGT_va_mask) == PGT_va_mutable )
            {
                /* The va backpointer is mutable, hence we update it. */
                nx &= ~PGT_va_mask;
                nx |= type; /* we know the actual type is correct */
            }
            else if ( unlikely((x & PGT_va_mask) != (type & PGT_va_mask)) )
            {
                /* This table is potentially mapped at multiple locations. */
                nx &= ~PGT_va_mask;
                nx |= PGT_va_unknown;
            }
        }
    }
    while ( unlikely((y = cmpxchg(&page->u.inuse.type_info, x, nx)) != x) );

    if ( unlikely(!(nx & PGT_validated)) )
    {
        /* Try to validate page type; drop the new reference on failure. */
        if ( unlikely(!alloc_page_type(page, type & PGT_type_mask)) )
        {
            MEM_LOG("Error while validating pfn %p for type %08x."
                    " caf=%08x taf=%08x",
                    page_to_pfn(page), type,
                    page->count_info,
                    page->u.inuse.type_info);
            /* Noone else can get a reference. We hold the only ref. */
            page->u.inuse.type_info = 0;
            return 0;
        }

        /* Noone else is updating simultaneously. */
        __set_bit(_PGT_validated, &page->u.inuse.type_info);
    }

    return 1;
}


int new_guest_cr3(unsigned long mfn)
{
    struct exec_domain *ed = current;
    struct domain *d = ed->domain;
    int okay;
    unsigned long old_base_mfn;

    if ( shadow_mode_enabled(d) )
        okay = get_page_from_pagenr(mfn, d);
    else
        okay = get_page_and_type_from_pagenr(mfn, PGT_root_page_table, d);

    if ( likely(okay) )
    {
        invalidate_shadow_ldt(ed);

        old_base_mfn = pagetable_val(ed->arch.guest_table) >> PAGE_SHIFT;
        ed->arch.guest_table = mk_pagetable(mfn << PAGE_SHIFT);
        update_pagetables(ed); /* update shadow_table and monitor_table */

        write_ptbase(ed);

        if ( shadow_mode_enabled(d) )
            put_page(&frame_table[old_base_mfn]);
        else
            put_page_and_type(&frame_table[old_base_mfn]);
    }
    else
    {
        MEM_LOG("Error while installing new baseptr %p", mfn);
    }

    return okay;
}

static int do_extended_command(unsigned long ptr, unsigned long val)
{
    int okay = 1, cpu = smp_processor_id();
    unsigned int cmd = val & MMUEXT_CMD_MASK, type;
    struct exec_domain *ed = current;
    struct domain *d = ed->domain, *e;
    unsigned long gpfn = ptr >> PAGE_SHIFT;
    unsigned long mfn = __gpfn_to_mfn(d, gpfn);
    struct pfn_info *page = &frame_table[mfn];
    u32 x, y, _d, _nd;
    domid_t domid;
    grant_ref_t gntref;

    switch ( cmd )
    {
    case MMUEXT_PIN_L1_TABLE:
        /*
         * We insist that, if you pin an L1 page, it's the first thing that
         * you do to it. This is because we require the backptr to still be
         * mutable. This assumption seems safe.
         */
        type = PGT_l1_page_table | PGT_va_mutable;

    pin_page:
        if ( unlikely(percpu_info[cpu].foreign &&
                      (shadow_mode_translate(d) ||
                       shadow_mode_translate(percpu_info[cpu].foreign))) )
        {
            // oops -- we should be using the foreign domain's P2M
            mfn = __gpfn_to_mfn(FOREIGNDOM, gpfn);
            page = &frame_table[mfn];
        }

        if ( shadow_mode_enabled(FOREIGNDOM) )
            type = PGT_writable_page;

        okay = get_page_and_type_from_pagenr(mfn, type, FOREIGNDOM);
        if ( unlikely(!okay) )
        {
            MEM_LOG("Error while pinning mfn %p", mfn);
            break;
        }

        if ( unlikely(test_and_set_bit(_PGT_pinned,
                                       &page->u.inuse.type_info)) )
        {
            MEM_LOG("mfn %p already pinned", mfn);
            put_page_and_type(page);
            okay = 0;
            break;
        }

        break;

    case MMUEXT_PIN_L2_TABLE:
        type = PGT_l2_page_table;
        goto pin_page;

#ifdef __x86_64__
    case MMUEXT_PIN_L3_TABLE:
        type = PGT_l3_page_table;
        goto pin_page;

    case MMUEXT_PIN_L4_TABLE:
        type = PGT_l4_page_table;
        goto pin_page;
#endif /* __x86_64__ */

    case MMUEXT_UNPIN_TABLE:
        if ( unlikely(percpu_info[cpu].foreign &&
                      (shadow_mode_translate(d) ||
                       shadow_mode_translate(percpu_info[cpu].foreign))) )
        {
            // oops -- we should be using the foreign domain's P2M
            mfn = __gpfn_to_mfn(FOREIGNDOM, gpfn);
            page = &frame_table[mfn];
        }

        if ( unlikely(!(okay = get_page_from_pagenr(mfn, FOREIGNDOM))) )
        {
            MEM_LOG("mfn %p bad domain (dom=%p)",
                    mfn, page_get_owner(page));
        }
        else if ( likely(test_and_clear_bit(_PGT_pinned, 
                                            &page->u.inuse.type_info)) )
        {
            put_page_and_type(page);
            put_page(page);
        }
        else
        {
            okay = 0;
            put_page(page);
            MEM_LOG("mfn %p not pinned", mfn);
        }
        break;

    case MMUEXT_NEW_BASEPTR:
        okay = new_guest_cr3(mfn);
        percpu_info[cpu].deferred_ops &= ~DOP_FLUSH_TLB;
        break;
        
#ifdef __x86_64__
    case MMUEXT_NEW_USER_BASEPTR:
        okay = get_page_and_type_from_pagenr(mfn, PGT_root_page_table, d);
        if ( unlikely(!okay) )
        {
            MEM_LOG("Error while installing new baseptr %p", mfn);
        }
        else
        {
            unsigned long old_mfn =
                pagetable_val(ed->arch.guest_table_user) >> PAGE_SHIFT;
            ed->arch.guest_table_user = mk_pagetable(mfn << PAGE_SHIFT);
            if ( old_mfn != 0 )
                put_page_and_type(&frame_table[old_mfn]);
        }
        break;
#endif
        
    case MMUEXT_TLB_FLUSH:
        percpu_info[cpu].deferred_ops |= DOP_FLUSH_TLB;
        break;
    
    case MMUEXT_INVLPG:
        __flush_tlb_one(ptr);
        if ( shadow_mode_enabled(d) )
            shadow_invlpg(ed, ptr);
        break;

    case MMUEXT_FLUSH_CACHE:
        if ( unlikely(!IS_CAPABLE_PHYSDEV(d)) )
        {
            MEM_LOG("Non-physdev domain tried to FLUSH_CACHE.");
            okay = 0;
        }
        else
        {
            wbinvd();
        }
        break;

    case MMUEXT_SET_LDT:
    {
        ASSERT( !shadow_mode_external(d) );

        unsigned long ents = val >> MMUEXT_CMD_SHIFT;
        if ( ((ptr & (PAGE_SIZE-1)) != 0) || 
             (ents > 8192) ||
             ((ptr+ents*LDT_ENTRY_SIZE) < ptr) ||
             ((ptr+ents*LDT_ENTRY_SIZE) > PAGE_OFFSET) )
        {
            okay = 0;
            MEM_LOG("Bad args to SET_LDT: ptr=%p, ents=%p", ptr, ents);
        }
        else if ( (ed->arch.ldt_ents != ents) || 
                  (ed->arch.ldt_base != ptr) )
        {
            invalidate_shadow_ldt(ed);
            shadow_sync_all(d);
            ed->arch.ldt_base = ptr;
            ed->arch.ldt_ents = ents;
            load_LDT(ed);
            percpu_info[cpu].deferred_ops &= ~DOP_RELOAD_LDT;
            if ( ents != 0 )
                percpu_info[cpu].deferred_ops |= DOP_RELOAD_LDT;
        }
        break;
    }

    case MMUEXT_SET_FOREIGNDOM:
        domid = (domid_t)(val >> 16);

        if ( (e = percpu_info[cpu].foreign) != NULL )
            put_domain(e);
        percpu_info[cpu].foreign = NULL;

        if ( !IS_PRIV(d) )
        {
            switch ( domid )
            {
            case DOMID_IO:
                get_knownalive_domain(dom_io);
                percpu_info[cpu].foreign = dom_io;
                break;
            default:
                MEM_LOG("Dom %u cannot set foreign dom", d->id);
                okay = 0;
                break;
            }
        }
        else
        {
            percpu_info[cpu].foreign = e = find_domain_by_id(domid);
            if ( e == NULL )
            {
                switch ( domid )
                {
                case DOMID_XEN:
                    get_knownalive_domain(dom_xen);
                    percpu_info[cpu].foreign = dom_xen;
                    break;
                case DOMID_IO:
                    get_knownalive_domain(dom_io);
                    percpu_info[cpu].foreign = dom_io;
                    break;
                default:
                    MEM_LOG("Unknown domain '%u'", domid);
                    okay = 0;
                    break;
                }
            }
        }
        break;

    case MMUEXT_TRANSFER_PAGE:
        domid  = (domid_t)(val >> 16);
        gntref = (grant_ref_t)((val & 0xFF00) | ((ptr >> 2) & 0x00FF));
        
        if ( unlikely(IS_XEN_HEAP_FRAME(page)) ||
             unlikely(!pfn_is_ram(mfn)) ||
             unlikely((e = find_domain_by_id(domid)) == NULL) )
        {
            MEM_LOG("Bad frame (%p) or bad domid (%d).", mfn, domid);
            okay = 0;
            break;
        }

        spin_lock(&d->page_alloc_lock);

        /*
         * The tricky bit: atomically release ownership while there is just one
         * benign reference to the page (PGC_allocated). If that reference
         * disappears then the deallocation routine will safely spin.
         */
        _d  = pickle_domptr(d);
        _nd = page->u.inuse._domain;
        y   = page->count_info;
        do {
            x = y;
            if ( unlikely((x & (PGC_count_mask|PGC_allocated)) != 
                          (1|PGC_allocated)) ||
                 unlikely(_nd != _d) )
            {
                MEM_LOG("Bad page values %p: ed=%p(%u), sd=%p,"
                        " caf=%08x, taf=%08x", page_to_pfn(page),
                        d, d->id, unpickle_domptr(_nd), x, 
                        page->u.inuse.type_info);
                spin_unlock(&d->page_alloc_lock);
                put_domain(e);
                return 0;
            }
            __asm__ __volatile__(
                LOCK_PREFIX "cmpxchg8b %2"
                : "=d" (_nd), "=a" (y),
                "=m" (*(volatile u64 *)(&page->count_info))
                : "0" (_d), "1" (x), "c" (NULL), "b" (x) );
        } 
        while ( unlikely(_nd != _d) || unlikely(y != x) );

        /*
         * Unlink from 'd'. At least one reference remains (now anonymous), so
         * noone else is spinning to try to delete this page from 'd'.
         */
        d->tot_pages--;
        list_del(&page->list);
        
        spin_unlock(&d->page_alloc_lock);

        spin_lock(&e->page_alloc_lock);

        /*
         * Check that 'e' will accept the page and has reservation headroom.
         * Also, a domain mustn't have PGC_allocated pages when it is dying.
         */
        ASSERT(e->tot_pages <= e->max_pages);
        if ( unlikely(test_bit(DF_DYING, &e->d_flags)) ||
             unlikely(e->tot_pages == e->max_pages) ||
             unlikely(!gnttab_prepare_for_transfer(e, d, gntref)) )
        {
            MEM_LOG("Transferee has no reservation headroom (%d,%d), or "
                    "provided a bad grant ref, or is dying (%p).",
                    e->tot_pages, e->max_pages, e->d_flags);
            spin_unlock(&e->page_alloc_lock);
            put_domain(e);
            okay = 0;
            break;
        }

        /* Okay, add the page to 'e'. */
        if ( unlikely(e->tot_pages++ == 0) )
            get_knownalive_domain(e);
        list_add_tail(&page->list, &e->page_list);
        page_set_owner(page, e);

        spin_unlock(&e->page_alloc_lock);

        /* Transfer is all done: tell the guest about its new page frame. */
        gnttab_notify_transfer(e, gntref, mfn);
        
        put_domain(e);
        break;

    case MMUEXT_REASSIGN_PAGE:
        if ( unlikely(!IS_PRIV(d)) )
        {
            MEM_LOG("Dom %u has no reassignment priv", d->id);
            okay = 0;
            break;
        }

        e = percpu_info[cpu].foreign;
        if ( unlikely(e == NULL) )
        {
            MEM_LOG("No FOREIGNDOM to reassign mfn %p to", mfn);
            okay = 0;
            break;
        }

        if ( unlikely(!pfn_is_ram(mfn)) )
        {
            MEM_LOG("Can't reassign non-ram mfn %p", mfn);
            okay = 0;
            break;
        }

        /*
         * Grab both page_list locks, in order. This prevents the page from
         * disappearing elsewhere while we modify the owner, and we'll need
         * both locks if we're successful so that we can change lists.
         */
        if ( d < e )
        {
            spin_lock(&d->page_alloc_lock);
            spin_lock(&e->page_alloc_lock);
        }
        else
        {
            spin_lock(&e->page_alloc_lock);
            spin_lock(&d->page_alloc_lock);
        }

        /* A domain shouldn't have PGC_allocated pages when it is dying. */
        if ( unlikely(test_bit(DF_DYING, &e->d_flags)) ||
             unlikely(IS_XEN_HEAP_FRAME(page)) )
        {
            MEM_LOG("Reassignment page is Xen heap, or dest dom is dying.");
            okay = 0;
            goto reassign_fail;
        }

        /*
         * The tricky bit: atomically change owner while there is just one
         * benign reference to the page (PGC_allocated). If that reference
         * disappears then the deallocation routine will safely spin.
         */
        _d  = pickle_domptr(d);
        _nd = page->u.inuse._domain;
        y   = page->count_info;
        do {
            x = y;
            if ( unlikely((x & (PGC_count_mask|PGC_allocated)) != 
                          (1|PGC_allocated)) ||
                 unlikely(_nd != _d) )
            {
                MEM_LOG("Bad page values %p: ed=%p(%u), sd=%p,"
                        " caf=%08x, taf=%08x", page_to_pfn(page),
                        d, d->id, unpickle_domptr(_nd), x,
                        page->u.inuse.type_info);
                okay = 0;
                goto reassign_fail;
            }
            __asm__ __volatile__(
                LOCK_PREFIX "cmpxchg8b %3"
                : "=d" (_nd), "=a" (y), "=c" (e),
                "=m" (*(volatile u64 *)(&page->count_info))
                : "0" (_d), "1" (x), "c" (e), "b" (x) );
        } 
        while ( unlikely(_nd != _d) || unlikely(y != x) );
        
        /*
         * Unlink from 'd'. We transferred at least one reference to 'e', so
         * noone else is spinning to try to delete this page from 'd'.
         */
        d->tot_pages--;
        list_del(&page->list);
        
        /*
         * Add the page to 'e'. Someone may already have removed the last
         * reference and want to remove the page from 'e'. However, we have
         * the lock so they'll spin waiting for us.
         */
        if ( unlikely(e->tot_pages++ == 0) )
            get_knownalive_domain(e);
        list_add_tail(&page->list, &e->page_list);

    reassign_fail:        
        spin_unlock(&d->page_alloc_lock);
        spin_unlock(&e->page_alloc_lock);
        break;

    case MMUEXT_CLEAR_FOREIGNDOM:
        if ( (e = percpu_info[cpu].foreign) != NULL )
            put_domain(e);
        percpu_info[cpu].foreign = NULL;
        break;

    default:
        MEM_LOG("Invalid extended pt command 0x%p", val & MMUEXT_CMD_MASK);
        okay = 0;
        break;
    }

    return okay;
}

int do_mmu_update(
    mmu_update_t *ureqs, unsigned int count, unsigned int *pdone)
{
/*
 * We steal the m.s.b. of the @count parameter to indicate whether this
 * invocation of do_mmu_update() is resuming a previously preempted call.
 * We steal the next 15 bits to remember the current FOREIGNDOM.
 */
#define MMU_UPDATE_PREEMPTED          (~(~0U>>1))
#define MMU_UPDATE_PREEMPT_FDOM_SHIFT ((sizeof(int)*8)-16)
#define MMU_UPDATE_PREEMPT_FDOM_MASK  (0x7FFFU<<MMU_UPDATE_PREEMPT_FDOM_SHIFT)

    mmu_update_t req;
    unsigned long va = 0, deferred_ops, gpfn, mfn, prev_mfn = 0;
    struct pfn_info *page;
    int rc = 0, okay = 1, i = 0, cpu = smp_processor_id();
    unsigned int cmd, done = 0;
    struct exec_domain *ed = current;
    struct domain *d = ed->domain;
    u32 type_info;
    domid_t domid;

    LOCK_BIGLOCK(d);

    cleanup_writable_pagetable(d);

    if ( unlikely(shadow_mode_enabled(d)) )
    {
        check_pagetable(ed, "pre-mmu"); /* debug */
    }

    /*
     * If we are resuming after preemption, read how much work we have already
     * done. This allows us to set the @done output parameter correctly.
     * We also reset FOREIGNDOM here.
     */
    if ( unlikely(count&(MMU_UPDATE_PREEMPTED|MMU_UPDATE_PREEMPT_FDOM_MASK)) )
    {
        if ( !(count & MMU_UPDATE_PREEMPTED) )
        {
            /* Count overflow into private FOREIGNDOM field. */
            MEM_LOG("do_mmu_update count is too large");
            rc = -EINVAL;
            goto out;
        }
        count &= ~MMU_UPDATE_PREEMPTED;
        domid = count >> MMU_UPDATE_PREEMPT_FDOM_SHIFT;
        count &= ~MMU_UPDATE_PREEMPT_FDOM_MASK;
        if ( unlikely(pdone != NULL) )
            (void)get_user(done, pdone);
        if ( (domid != current->domain->id) &&
             !do_extended_command(0, MMUEXT_SET_FOREIGNDOM | (domid << 16)) )
        {
            rc = -EINVAL;
            goto out;
        }
    }

    perfc_incrc(calls_to_mmu_update); 
    perfc_addc(num_page_updates, count);

    if ( unlikely(!array_access_ok(VERIFY_READ, ureqs, count, sizeof(req))) )
    {
        rc = -EFAULT;
        goto out;
    }

    for ( i = 0; i < count; i++ )
    {
        if ( hypercall_preempt_check() )
        {
            rc = hypercall3_create_continuation(
                __HYPERVISOR_mmu_update, ureqs, 
                (count - i) |
                (FOREIGNDOM->id << MMU_UPDATE_PREEMPT_FDOM_SHIFT) | 
                MMU_UPDATE_PREEMPTED, pdone);
            break;
        }

        if ( unlikely(__copy_from_user(&req, ureqs, sizeof(req)) != 0) )
        {
            MEM_LOG("Bad __copy_from_user");
            rc = -EFAULT;
            break;
        }

        cmd = req.ptr & (sizeof(l1_pgentry_t)-1);
        gpfn = req.ptr >> PAGE_SHIFT;
        mfn = __gpfn_to_mfn(d, gpfn);

        okay = 0;

        switch ( cmd )
        {
            /*
             * MMU_NORMAL_PT_UPDATE: Normal update to any level of page table.
             */
        case MMU_NORMAL_PT_UPDATE:
            if ( unlikely(!get_page_from_pagenr(mfn, current->domain)) )
            {
                MEM_LOG("Could not get page for normal update");
                break;
            }

            if ( likely(prev_mfn == mfn) )
            {
                va = (va & PAGE_MASK) | (req.ptr & ~PAGE_MASK);
            }
            else
            {
                if ( prev_mfn != 0 )
                    unmap_domain_mem((void *)va);
                va = (unsigned long)map_domain_mem(req.ptr);
                prev_mfn = mfn;
            }

            page = &frame_table[mfn];
            switch ( (type_info = page->u.inuse.type_info) & PGT_type_mask )
            {
            case PGT_l1_page_table: 
                ASSERT(!shadow_mode_enabled(d));
                if ( likely(get_page_type(
                    page, type_info & (PGT_type_mask|PGT_va_mask))) )
                {
                    okay = mod_l1_entry((l1_pgentry_t *)va, 
                                        mk_l1_pgentry(req.val));
                    put_page_type(page);
                }
                break;
            case PGT_l2_page_table:
                ASSERT(!shadow_mode_enabled(d));
                if ( likely(get_page_type(page, PGT_l2_page_table)) )
                {
                    okay = mod_l2_entry((l2_pgentry_t *)va, 
                                        mk_l2_pgentry(req.val),
                                        mfn);
                    put_page_type(page);
                }
                break;
#ifdef __x86_64__
            case PGT_l3_page_table:
                ASSERT(!shadow_mode_enabled(d));
                if ( likely(get_page_type(page, PGT_l3_page_table)) )
                {
                    okay = mod_l3_entry((l3_pgentry_t *)va, 
                                        mk_l3_pgentry(req.val),
                                        mfn);
                    put_page_type(page);
                }
                break;
            case PGT_l4_page_table:
                ASSERT(!shadow_mode_enabled(d));
                if ( likely(get_page_type(page, PGT_l4_page_table)) )
                {
                    okay = mod_l4_entry((l4_pgentry_t *)va, 
                                        mk_l4_pgentry(req.val),
                                        mfn);
                    put_page_type(page);
                }
                break;
#endif /* __x86_64__ */
            default:
                if ( likely(get_page_type(page, PGT_writable_page)) )
                {
                    if ( shadow_mode_enabled(d) )
                    {
                        shadow_lock(d);

                        if ( shadow_mode_log_dirty(d) )
                            __mark_dirty(d, mfn);

                        if ( page_is_page_table(page) )
                            shadow_mark_mfn_out_of_sync(ed, gpfn, mfn);
                    }

                    *(unsigned long *)va = req.val;
                    okay = 1;

                    if ( shadow_mode_enabled(d) )
                        shadow_unlock(d);

                    put_page_type(page);
                }
                break;
            }

            put_page(page);
            break;

        case MMU_MACHPHYS_UPDATE:
            if ( unlikely(!get_page_from_pagenr(mfn, FOREIGNDOM)) )
            {
                MEM_LOG("Could not get page for mach->phys update");
                break;
            }

            if ( unlikely(shadow_mode_translate(FOREIGNDOM) && !IS_PRIV(d)) )
            {
                MEM_LOG("can't mutate the m2p of translated guests");
                break;
            }

            set_machinetophys(mfn, req.val);
            okay = 1;

            /*
             * If in log-dirty mode, mark the corresponding
             * page as dirty.
             */
            if ( unlikely(shadow_mode_log_dirty(FOREIGNDOM)) &&
                 mark_dirty(FOREIGNDOM, mfn) )
                FOREIGNDOM->arch.shadow_dirty_block_count++;

            put_page(&frame_table[mfn]);
            break;

            /*
             * MMU_EXTENDED_COMMAND: Extended command is specified
             * in the least-siginificant bits of the 'value' field.
             */
        case MMU_EXTENDED_COMMAND:
            req.ptr &= ~(sizeof(l1_pgentry_t) - 1);
            okay = do_extended_command(req.ptr, req.val);
            break;

        default:
            MEM_LOG("Invalid page update command %p", req.ptr);
            break;
        }

        if ( unlikely(!okay) )
        {
            rc = -EINVAL;
            break;
        }

        ureqs++;
    }

 out:
    if ( prev_mfn != 0 )
        unmap_domain_mem((void *)va);

    deferred_ops = percpu_info[cpu].deferred_ops;
    percpu_info[cpu].deferred_ops = 0;

    if ( deferred_ops & DOP_FLUSH_TLB )
    {
        local_flush_tlb();
        if ( shadow_mode_enabled(d) )
            shadow_sync_all(d);
    }
        
    if ( deferred_ops & DOP_RELOAD_LDT )
        (void)map_ldt_shadow_page(0);

    if ( unlikely(percpu_info[cpu].foreign != NULL) )
    {
        put_domain(percpu_info[cpu].foreign);
        percpu_info[cpu].foreign = NULL;
    }

    /* Add incremental work we have done to the @done output parameter. */
    if ( unlikely(pdone != NULL) )
        __put_user(done + i, pdone);

    if ( unlikely(shadow_mode_enabled(d)) )
        check_pagetable(ed, "post-mmu"); /* debug */

    UNLOCK_BIGLOCK(d);
    return rc;
}


int do_update_va_mapping(unsigned long va,
                         unsigned long val, 
                         unsigned long flags)
{
    struct exec_domain *ed = current;
    struct domain *d = ed->domain;
    int err = 0;
    unsigned int cpu = ed->processor;
    unsigned long deferred_ops;

    perfc_incrc(calls_to_update_va);

    if ( unlikely(!__addr_ok(va) && !shadow_mode_external(d)) )
        return -EINVAL;

    LOCK_BIGLOCK(d);

    cleanup_writable_pagetable(d);

    /*
     * XXX When we make this support 4MB superpages we should also deal with 
     * the case of updating L2 entries.
     */
    if ( likely(!shadow_mode_enabled(d)) )
    {
        if ( unlikely(!mod_l1_entry(&linear_pg_table[l1_linear_offset(va)],
                                    mk_l1_pgentry(val))) )
            err = -EINVAL;
    }
    else
    {
        unsigned long l1mfn;

        if ( unlikely(percpu_info[cpu].foreign &&
                      (shadow_mode_translate(d) ||
                       shadow_mode_translate(percpu_info[cpu].foreign))) )
        {
            // The foreign domain's pfn's are in a different namespace.
            // We wouldn't be able to figure out how to (re-)shadow our
            // gpte without additional context.
            //
            domain_crash();
        }
    
        check_pagetable(ed, "pre-va"); /* debug */
        shadow_lock(d);
        
        // This is actually overkill - we don't need to sync the L1 itself,
        // just everything involved in getting to this L1 (i.e. we need
        // linear_pg_table[l1_linear_offset(va)] to be in sync)...
        //
        __shadow_sync_va(ed, va);

#if 1 /* keep check_pagetables() happy */
        /*
         * However, the above doesn't guarantee that there's no snapshot of
         * the L1 table in question; it just says that the relevant L2 and L1
         * entries for VA are in-sync.  There might still be a snapshot.
         *
         * The checking code in _check_pagetables() assumes that no one will
         * mutate the shadow of a page that has a snapshot.  It's actually
         * OK to not sync this page, but it seems simpler to:
         * 1) keep all code paths the same, and
         * 2) maintain the invariant for _check_pagetables(), rather than try
         *    to teach it about this boundary case.
         * So we flush this L1 page, if it's out of sync.
         */
        l1mfn = (l2_pgentry_val(linear_l2_table(ed)[l2_table_offset(va)]) >>
                 PAGE_SHIFT);
        if ( mfn_out_of_sync(l1mfn) )
        {
            perfc_incrc(extra_va_update_sync);
            __shadow_sync_mfn(d, l1mfn);
        }
#endif /* keep check_pagetables() happy */

        if ( unlikely(__put_user(val, &l1_pgentry_val(
                                     linear_pg_table[l1_linear_offset(va)]))) )
            err = -EINVAL;
        else
        {
            // also need to update the shadow
            unsigned long spte;

            l1pte_propagate_from_guest(d, val, &spte);
            shadow_set_l1e(va, spte, 0);

            /*
             * If we're in log-dirty mode then we need to note that we've updated
             * the PTE in the PT-holding page. We need the machine frame number
             * for this.
             */
            if ( shadow_mode_log_dirty(d) )
                mark_dirty(d, va_to_l1mfn(ed, va));

            shadow_unlock(d);
            check_pagetable(ed, "post-va"); /* debug */
        }
    }

    deferred_ops = percpu_info[cpu].deferred_ops;
    percpu_info[cpu].deferred_ops = 0;

    if ( unlikely(deferred_ops & DOP_FLUSH_TLB) || 
         unlikely(flags & UVMF_FLUSH_TLB) )
    {
        local_flush_tlb();
        if ( unlikely(shadow_mode_enabled(d)) )
            shadow_sync_all(d);
    }
    else if ( unlikely(flags & UVMF_INVLPG) )
    {
        __flush_tlb_one(va);
        if ( unlikely(shadow_mode_enabled(d)) )
            shadow_invlpg(current, va);
    }

    if ( unlikely(deferred_ops & DOP_RELOAD_LDT) )
        (void)map_ldt_shadow_page(0);
    
    UNLOCK_BIGLOCK(d);

    return err;
}

int do_update_va_mapping_otherdomain(unsigned long va,
                                     unsigned long val, 
                                     unsigned long flags,
                                     domid_t domid)
{
    unsigned int cpu = smp_processor_id();
    struct domain *d;
    int rc;

    if ( unlikely(!IS_PRIV(current->domain)) )
        return -EPERM;

    percpu_info[cpu].foreign = d = find_domain_by_id(domid);
    if ( unlikely(d == NULL) )
    {
        MEM_LOG("Unknown domain '%u'", domid);
        return -ESRCH;
    }

    rc = do_update_va_mapping(va, val, flags);

    put_domain(d);
    percpu_info[cpu].foreign = NULL;

    return rc;
}



/*************************
 * Descriptor Tables
 */

void destroy_gdt(struct exec_domain *ed)
{
    int i;
    unsigned long pfn;

    for ( i = 0; i < 16; i++ )
    {
        if ( (pfn = l1_pgentry_to_pfn(ed->arch.perdomain_ptes[i])) != 0 )
            put_page_and_type(&frame_table[pfn]);
        ed->arch.perdomain_ptes[i] = mk_l1_pgentry(0);
    }
}


long set_gdt(struct exec_domain *ed, 
             unsigned long *frames,
             unsigned int entries)
{
    struct domain *d = ed->domain;
    /* NB. There are 512 8-byte entries per GDT page. */
    int i = 0, nr_pages = (entries + 511) / 512;
    struct desc_struct *vgdt;
    unsigned long pfn;

    /* Check the first page in the new GDT. */
    if ( (pfn = frames[0]) >= max_page )
        goto fail;

    shadow_sync_all(d);

    /* The first page is special because Xen owns a range of entries in it. */
    if ( !get_page_and_type(&frame_table[pfn], d, PGT_gdt_page) )
    {
        /* GDT checks failed: try zapping the Xen reserved entries. */
        if ( !get_page_and_type(&frame_table[pfn], d, PGT_writable_page) )
            goto fail;
        vgdt = map_domain_mem(pfn << PAGE_SHIFT);
        memset(vgdt + FIRST_RESERVED_GDT_ENTRY, 0,
               NR_RESERVED_GDT_ENTRIES*8);
        unmap_domain_mem(vgdt);
        put_page_and_type(&frame_table[pfn]);

        /* Okay, we zapped the entries. Now try the GDT checks again. */
        if ( !get_page_and_type(&frame_table[pfn], d, PGT_gdt_page) )
            goto fail;
    }

    /* Check the remaining pages in the new GDT. */
    for ( i = 1; i < nr_pages; i++ )
        if ( ((pfn = frames[i]) >= max_page) ||
             !get_page_and_type(&frame_table[pfn], d, PGT_gdt_page) )
            goto fail;

    /* Copy reserved GDT entries to the new GDT. */
    vgdt = map_domain_mem(frames[0] << PAGE_SHIFT);
    memcpy(vgdt + FIRST_RESERVED_GDT_ENTRY, 
           gdt_table + FIRST_RESERVED_GDT_ENTRY, 
           NR_RESERVED_GDT_ENTRIES*8);
    unmap_domain_mem(vgdt);

    /* Tear down the old GDT. */
    destroy_gdt(ed);

    /* Install the new GDT. */
    for ( i = 0; i < nr_pages; i++ )
        ed->arch.perdomain_ptes[i] =
            mk_l1_pgentry((frames[i] << PAGE_SHIFT) | __PAGE_HYPERVISOR);

    SET_GDT_ADDRESS(ed, GDT_VIRT_START(ed));
    SET_GDT_ENTRIES(ed, entries);

    return 0;

 fail:
    while ( i-- > 0 )
        put_page_and_type(&frame_table[frames[i]]);
    return -EINVAL;
}


long do_set_gdt(unsigned long *frame_list, unsigned int entries)
{
    int nr_pages = (entries + 511) / 512;
    unsigned long frames[16];
    long ret;

    if ( (entries <= LAST_RESERVED_GDT_ENTRY) || (entries > 8192) ) 
        return -EINVAL;
    
    if ( copy_from_user(frames, frame_list, nr_pages * sizeof(unsigned long)) )
        return -EFAULT;

    LOCK_BIGLOCK(current->domain);

    if ( (ret = set_gdt(current, frames, entries)) == 0 )
    {
        local_flush_tlb();
        __asm__ __volatile__ ("lgdt %0" : "=m" (*current->arch.gdt));
    }

    UNLOCK_BIGLOCK(current->domain);

    return ret;
}


long do_update_descriptor(
    unsigned long pa, unsigned long word1, unsigned long word2)
{
    struct domain *dom = current->domain;
    unsigned long gpfn = pa >> PAGE_SHIFT;
    unsigned long mfn;
    struct desc_struct *gdt_pent, d;
    struct pfn_info *page;
    struct exec_domain *ed;
    long ret = -EINVAL;

    d.a = (u32)word1;
    d.b = (u32)word2;

    LOCK_BIGLOCK(dom);

    if ( !(mfn = __gpfn_to_mfn(dom, gpfn)) ) {
        UNLOCK_BIGLOCK(dom);
        return -EINVAL;
    }

    if ( (pa & 7) || (mfn >= max_page) || !check_descriptor(&d) ) {
        UNLOCK_BIGLOCK(dom);
        return -EINVAL;
    }

    page = &frame_table[mfn];
    if ( unlikely(!get_page(page, dom)) ) {
        UNLOCK_BIGLOCK(dom);
        return -EINVAL;
    }

    /* Check if the given frame is in use in an unsafe context. */
    switch ( page->u.inuse.type_info & PGT_type_mask )
    {
    case PGT_gdt_page:
        /* Disallow updates of Xen-reserved descriptors in the current GDT. */
        for_each_exec_domain(dom, ed) {
            if ( (l1_pgentry_to_pfn(ed->arch.perdomain_ptes[0]) == mfn) &&
                 (((pa&(PAGE_SIZE-1))>>3) >= FIRST_RESERVED_GDT_ENTRY) &&
                 (((pa&(PAGE_SIZE-1))>>3) <= LAST_RESERVED_GDT_ENTRY) )
                goto out;
        }
        if ( unlikely(!get_page_type(page, PGT_gdt_page)) )
            goto out;
        break;
    case PGT_ldt_page:
        if ( unlikely(!get_page_type(page, PGT_ldt_page)) )
            goto out;
        break;
    default:
        if ( unlikely(!get_page_type(page, PGT_writable_page)) )
            goto out;
        break;
    }

    if ( shadow_mode_enabled(dom) )
    {
        shadow_lock(dom);

        if ( shadow_mode_log_dirty(dom) )
            __mark_dirty(dom, mfn);

        if ( page_is_page_table(page) )
            shadow_mark_mfn_out_of_sync(current, gpfn, mfn);
    }

    /* All is good so make the update. */
    gdt_pent = map_domain_mem((mfn << PAGE_SHIFT) | (pa & ~PAGE_MASK));
    memcpy(gdt_pent, &d, 8);
    unmap_domain_mem(gdt_pent);

    if ( shadow_mode_enabled(dom) )
        shadow_unlock(dom);

    put_page_type(page);

    ret = 0; /* success */

 out:
    put_page(page);

    UNLOCK_BIGLOCK(dom);

    return ret;
}



/*************************
 * Writable Pagetables
 */

ptwr_info_t ptwr_info[NR_CPUS];

#ifdef VERBOSE
int ptwr_debug = 0x0;
#define PTWR_PRINTK(_f, _a...) \
 do { if ( unlikely(ptwr_debug) ) printk( _f , ## _a ); } while ( 0 )
#define PTWR_PRINT_WHICH (which ? 'I' : 'A')
#else
#define PTWR_PRINTK(_f, _a...) ((void)0)
#endif

/* Flush the given writable p.t. page and write-protect it again. */
void ptwr_flush(const int which)
{
    unsigned long  pte, *ptep, l1va;
    l1_pgentry_t  *pl1e, ol1e, nl1e;
    l2_pgentry_t  *pl2e;
    int            i, cpu = smp_processor_id();
    struct exec_domain *ed = current;
    struct domain *d = ed->domain;

    // not supported in combination with various shadow modes!
    ASSERT( !shadow_mode_enabled(d) );
    
    l1va = ptwr_info[cpu].ptinfo[which].l1va;
    ptep = (unsigned long *)&linear_pg_table[l1_linear_offset(l1va)];

    /*
     * STEP 1. Write-protect the p.t. page so no more updates can occur.
     */

    if ( unlikely(__get_user(pte, ptep)) )
    {
        MEM_LOG("ptwr: Could not read pte at %p", ptep);
        /*
         * Really a bug. We could read this PTE during the initial fault,
         * and pagetables can't have changed meantime. XXX Multi-CPU guests?
         */
        BUG();
    }
    PTWR_PRINTK("[%c] disconnected_l1va at %p is %p\n",
                PTWR_PRINT_WHICH, ptep, pte);
    pte &= ~_PAGE_RW;

    /* Write-protect the p.t. page in the guest page table. */
    if ( unlikely(__put_user(pte, ptep)) )
    {
        MEM_LOG("ptwr: Could not update pte at %p", ptep);
        /*
         * Really a bug. We could write this PTE during the initial fault,
         * and pagetables can't have changed meantime. XXX Multi-CPU guests?
         */
        BUG();
    }

    /* Ensure that there are no stale writable mappings in any TLB. */
    /* NB. INVLPG is a serialising instruction: flushes pending updates. */
#if 1
    __flush_tlb_one(l1va); /* XXX Multi-CPU guests? */
#else
    flush_tlb_all();
#endif
    PTWR_PRINTK("[%c] disconnected_l1va at %p now %p\n",
                PTWR_PRINT_WHICH, ptep, pte);

    /*
     * STEP 2. Validate any modified PTEs.
     */

    pl1e = ptwr_info[cpu].ptinfo[which].pl1e;
    for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
    {
        ol1e = ptwr_info[cpu].ptinfo[which].page[i];
        nl1e = pl1e[i];

        if ( likely(l1_pgentry_val(ol1e) == l1_pgentry_val(nl1e)) )
            continue;

        /*
         * Fast path for PTEs that have merely been write-protected
         * (e.g., during a Unix fork()). A strict reduction in privilege.
         */
        if ( likely(l1_pgentry_val(ol1e) == (l1_pgentry_val(nl1e)|_PAGE_RW)) )
        {
            if ( likely(l1_pgentry_val(nl1e) & _PAGE_PRESENT) )
                put_page_type(&frame_table[l1_pgentry_to_pfn(nl1e)]);
            continue;
        }

        if ( unlikely(!get_page_from_l1e(nl1e, d)) )
        {
            MEM_LOG("ptwr: Could not re-validate l1 page\n");
            /*
             * Make the remaining p.t's consistent before crashing, so the
             * reference counts are correct.
             */
            memcpy(&pl1e[i], &ptwr_info[cpu].ptinfo[which].page[i],
                   (L1_PAGETABLE_ENTRIES - i) * sizeof(l1_pgentry_t));
            unmap_domain_mem(pl1e);
            ptwr_info[cpu].ptinfo[which].l1va = 0;
            UNLOCK_BIGLOCK(d);
            domain_crash();
        }
        
        if ( unlikely(l1_pgentry_val(ol1e) & _PAGE_PRESENT) )
            put_page_from_l1e(ol1e, d);
    }

    unmap_domain_mem(pl1e);

    /*
     * STEP 3. Reattach the L1 p.t. page into the current address space.
     */

    if ( which == PTWR_PT_ACTIVE )
    {
        pl2e = &linear_l2_table(ed)[ptwr_info[cpu].ptinfo[which].l2_idx];
        *pl2e = mk_l2_pgentry(l2_pgentry_val(*pl2e) | _PAGE_PRESENT); 
    }

    /*
     * STEP 4. Final tidy-up.
     */

    ptwr_info[cpu].ptinfo[which].l1va = 0;
}

/* Write page fault handler: check if guest is trying to modify a PTE. */
int ptwr_do_page_fault(unsigned long addr)
{
    struct exec_domain *ed = current;
    unsigned long    pte, pfn, l2e;
    struct pfn_info *page;
    l2_pgentry_t    *pl2e;
    int              which, cpu = smp_processor_id();
    u32              l2_idx;

    // not supported in combination with various shadow modes!
    ASSERT( !shadow_mode_enabled(ed->domain) );
    
#ifdef __x86_64__
    return 0; /* Writable pagetables need fixing for x86_64. */
#endif

    /*
     * Attempt to read the PTE that maps the VA being accessed. By checking for
     * PDE validity in the L2 we avoid many expensive fixups in __get_user().
     */
    if ( !(l2_pgentry_val(linear_l2_table(ed)[addr>>L2_PAGETABLE_SHIFT]) &
           _PAGE_PRESENT) ||
         __get_user(pte, (unsigned long *)
                    &linear_pg_table[l1_linear_offset(addr)]) )
    {
        return 0;
    }

    pfn  = pte >> PAGE_SHIFT;
    page = &frame_table[pfn];

    /* We are looking only for read-only mappings of p.t. pages. */
    if ( ((pte & (_PAGE_RW | _PAGE_PRESENT)) != _PAGE_PRESENT) ||
         ((page->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table) )
    {
        return 0;
    }
    
    /* Get the L2 index at which this L1 p.t. is always mapped. */
    l2_idx = page->u.inuse.type_info & PGT_va_mask;
    if ( unlikely(l2_idx >= PGT_va_unknown) )
    {
        domain_crash(); /* Urk! This L1 is mapped in multiple L2 slots! */
    }
    l2_idx >>= PGT_va_shift;

    if ( l2_idx == (addr >> L2_PAGETABLE_SHIFT) )
    {
        MEM_LOG("PTWR failure! Pagetable maps itself at %p", addr);
        domain_crash();
    }

    /*
     * Is the L1 p.t. mapped into the current address space? If so we call it
     * an ACTIVE p.t., otherwise it is INACTIVE.
     */
    pl2e = &linear_l2_table(ed)[l2_idx];
    l2e  = l2_pgentry_val(*pl2e);
    which = PTWR_PT_INACTIVE;
    if ( (l2e >> PAGE_SHIFT) == pfn )
    {
        /* Check the PRESENT bit to set ACTIVE. */
        if ( likely(l2e & _PAGE_PRESENT) )
            which = PTWR_PT_ACTIVE;
        else {
            /*
             * If the PRESENT bit is clear, we may be conflicting with
             * the current ACTIVE p.t. (it may be the same p.t. mapped
             * at another virt addr).
             * The ptwr_flush call below will restore the PRESENT bit.
             */
            if ( ptwr_info[cpu].ptinfo[PTWR_PT_ACTIVE].l1va &&
                 l2_idx == ptwr_info[cpu].ptinfo[PTWR_PT_ACTIVE].l2_idx )
                which = PTWR_PT_ACTIVE;
        }
    }
    
    PTWR_PRINTK("[%c] page_fault on l1 pt at va %p, pt for %08x, "
                "pfn %p\n", PTWR_PRINT_WHICH,
                addr, l2_idx << L2_PAGETABLE_SHIFT, pfn);
    
    /*
     * We only allow one ACTIVE and one INACTIVE p.t. to be updated at at 
     * time. If there is already one, we must flush it out.
     */
    if ( ptwr_info[cpu].ptinfo[which].l1va )
        ptwr_flush(which);

    ptwr_info[cpu].ptinfo[which].l1va   = addr | 1;
    ptwr_info[cpu].ptinfo[which].l2_idx = l2_idx;
    
    /* For safety, disconnect the L1 p.t. page from current space. */
    if ( which == PTWR_PT_ACTIVE )
    {
        *pl2e = mk_l2_pgentry(l2e & ~_PAGE_PRESENT);
#if 1
        flush_tlb(); /* XXX Multi-CPU guests? */
#else
        flush_tlb_all();
#endif
    }
    
    /* Temporarily map the L1 page, and make a copy of it. */
    ptwr_info[cpu].ptinfo[which].pl1e = map_domain_mem(pfn << PAGE_SHIFT);
    memcpy(ptwr_info[cpu].ptinfo[which].page,
           ptwr_info[cpu].ptinfo[which].pl1e,
           L1_PAGETABLE_ENTRIES * sizeof(l1_pgentry_t));
    
    /* Finally, make the p.t. page writable by the guest OS. */
    pte |= _PAGE_RW;
    PTWR_PRINTK("[%c] update %p pte to %p\n", PTWR_PRINT_WHICH,
                &linear_pg_table[addr>>PAGE_SHIFT], pte);
    if ( unlikely(__put_user(pte, (unsigned long *)
                             &linear_pg_table[addr>>PAGE_SHIFT])) )
    {
        MEM_LOG("ptwr: Could not update pte at %p", (unsigned long *)
                &linear_pg_table[addr>>PAGE_SHIFT]);
        /* Toss the writable pagetable state and crash. */
        unmap_domain_mem(ptwr_info[cpu].ptinfo[which].pl1e);
        ptwr_info[cpu].ptinfo[which].l1va = 0;
        domain_crash();
    }
    
    return EXCRET_fault_fixed;
}

static __init int ptwr_init(void)
{
    int i;

    for ( i = 0; i < smp_num_cpus; i++ )
    {
        ptwr_info[i].ptinfo[PTWR_PT_ACTIVE].page =
            (void *)alloc_xenheap_page();
        ptwr_info[i].ptinfo[PTWR_PT_INACTIVE].page =
            (void *)alloc_xenheap_page();
    }

    return 0;
}
__initcall(ptwr_init);




/************************************************************************/
/************************************************************************/
/************************************************************************/

#ifndef NDEBUG

void ptwr_status(void)
{
    unsigned long pte, *ptep, pfn;
    struct pfn_info *page;
    int cpu = smp_processor_id();

    ptep = (unsigned long *)&linear_pg_table
        [ptwr_info[cpu].ptinfo[PTWR_PT_INACTIVE].l1va>>PAGE_SHIFT];

    if ( __get_user(pte, ptep) ) {
        MEM_LOG("ptwr: Could not read pte at %p", ptep);
        domain_crash();
    }

    pfn = pte >> PAGE_SHIFT;
    page = &frame_table[pfn];
    printk("need to alloc l1 page %p\n", page);
    /* make pt page writable */
    printk("need to make read-only l1-page at %p is %p\n",
           ptep, pte);

    if ( ptwr_info[cpu].ptinfo[PTWR_PT_ACTIVE].l1va == 0 )
        return;

    if ( __get_user(pte, (unsigned long *)
                    ptwr_info[cpu].ptinfo[PTWR_PT_ACTIVE].l1va) ) {
        MEM_LOG("ptwr: Could not read pte at %p", (unsigned long *)
                ptwr_info[cpu].ptinfo[PTWR_PT_ACTIVE].l1va);
        domain_crash();
    }
    pfn = pte >> PAGE_SHIFT;
    page = &frame_table[pfn];
}

#endif /* NDEBUG */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 */
