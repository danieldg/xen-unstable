
#ifndef __XENO_MM_H__
#define __XENO_MM_H__

#include <xeno/config.h>
#include <asm/atomic.h>
#include <xeno/list.h>
#include <hypervisor-ifs/hypervisor-if.h>

/* XXX KAF: These may die eventually, but so many refs in slab.c :((( */

/* Zone modifiers in GFP_ZONEMASK (see linux/mmzone.h - low four bits) */
#define __GFP_DMA       0x01

/* Action modifiers - doesn't change the zoning */
#define __GFP_WAIT      0x10    /* Can wait and reschedule? */
#define __GFP_HIGH      0x20    /* Should access emergency pools? */
#define __GFP_IO        0x40    /* Can start low memory physical IO? */
#define __GFP_HIGHIO    0x80    /* Can start high mem physical IO? */
#define __GFP_FS        0x100   /* Can call down to low-level FS? */

#define GFP_ATOMIC      (__GFP_HIGH)
#define GFP_KERNEL      (__GFP_HIGH | __GFP_WAIT | __GFP_IO | __GFP_HIGHIO | __GFP_FS)

/* Flag - indicates that the buffer will be suitable for DMA.  Ignored on some
   platforms, used as appropriate on others */

#define GFP_DMA         __GFP_DMA


/******************************************************************************
 * The following is for page_alloc.c.
 */

void init_page_allocator(unsigned long min, unsigned long max);
unsigned long __get_free_pages(int mask, int order);
void __free_pages(unsigned long p, int order);
#define get_free_page(_m) (__get_free_pages((_m),0))
#define __get_free_page(_m) (__get_free_pages((_m),0))
#define free_pages(_p,_o) (__free_pages(_p,_o))
#define free_page(_p) (__free_pages(_p,0))


/******************************************************************************
 * The following is the array of page info. One entry per page owned
 * by the hypervisor, indexed from `mem_map', just like Linux.
 *
 * 12.11.02. We no longer use struct page or mem_map, these are replaced
 * with struct pfn_info and frame_table respectively. Boris Dragovic
 */

/*
 * This is still fatter than I'd like. Do we need the count?
 * Do we need the flags? The list at least seems req'd by slab.c.
 */
typedef struct pfn_info {
    struct list_head list;      /* ->mapping has some page lists. */
    unsigned long next;         /* used for threading pages belonging */
    unsigned long prev;         /* to same domain */
    unsigned long flags;        /* atomic flags. */
    unsigned long tot_count;    /* Total domain usage count. */
    unsigned long type_count;   /* pagetable/dir, or domain-writeable refs. */
} frame_table_t;

/*
 * We use a high bit to indicate that a page is pinned.
 * We do not use the top bit as that would mean that we'd get confused with
 * -ve error numbers in some places in common/memory.c.
 */
#define REFCNT_PIN_BIT 0x40000000UL

#define get_page_tot(p)		 ((p)->tot_count++)
#define put_page_tot(p)		 (--(p)->tot_count)
#define page_tot_count(p)	 ((p)->tot_count)
#define set_page_tot_count(p,v)  ((p)->tot_count = v)

#define get_page_type(p)	 ((p)->type_count++)
#define put_page_type(p)	 (--(p)->type_count)
#define page_type_count(p)	 ((p)->type_count)
#define set_page_type_count(p,v) ((p)->type_count = v)

#define PG_domain_mask 0x00ffffff /* owning domain (24 bits) */
/* hypervisor flags (domain == 0) */
#define PG_slab	       24
/* domain flags (domain != 0) */
/*
 * NB. The following three flags are MUTUALLY EXCLUSIVE!
 * At most one can be true at any point, and 'type_count' counts how many
 * references exist of teh current type. A change in type can only occur
 * when type_count == 0.
 */
#define PG_type_mask        (7<<25) /* bits 25-27 */
#define PGT_none            (0<<25) /* no special uses of this page */
#define PGT_l1_page_table   (1<<25) /* using this page as an L1 page table? */
#define PGT_l2_page_table   (2<<25) /* using this page as an L2 page table? */
#define PGT_l3_page_table   (3<<25) /* using this page as an L3 page table? */
#define PGT_l4_page_table   (4<<25) /* using this page as an L4 page table? */
#define PGT_writeable_page  (7<<25) /* has writable mappings of this page? */

#define PageSlab(page)		test_bit(PG_slab, &(page)->flags)
#define PageSetSlab(page)	set_bit(PG_slab, &(page)->flags)
#define PageClearSlab(page)	clear_bit(PG_slab, &(page)->flags)

/* The array of struct pfn_info,  
 * free pfn list and number of free pfns in the free list
 */
extern frame_table_t * frame_table;
extern unsigned long frame_table_size;
extern struct list_head free_list;
extern unsigned int free_pfns;
extern unsigned long max_page;
void init_frametable(unsigned long nr_pages);

/* Part of the domain API. */
int do_process_page_updates(page_update_request_t *updates, int count);

#endif /* __XENO_MM_H__ */
