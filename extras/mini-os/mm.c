/* 
 ****************************************************************************
 * (C) 2003 - Rolf Neugebauer - Intel Research Cambridge
 * (C) 2005 - Grzegorz Milos - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: mm.c
 *      Author: Rolf Neugebauer (neugebar@dcs.gla.ac.uk)
 *     Changes: Grzegorz Milos
 *              
 *        Date: Aug 2003, chages Aug 2005
 * 
 * Environment: Xen Minimal OS
 * Description: memory management related functions
 *              contains buddy page allocator from Xen.
 *
 ****************************************************************************
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 * DEALINGS IN THE SOFTWARE.
 */

#include <os.h>
#include <hypervisor.h>
#include <mm.h>
#include <types.h>
#include <lib.h>
#include <xmalloc.h>

#ifdef MM_DEBUG
#define DEBUG(_f, _a...) \
    printk("MINI_OS(file=mm.c, line=%d) " _f "\n", __LINE__, ## _a)
#else
#define DEBUG(_f, _a...)    ((void)0)
#endif

unsigned long *phys_to_machine_mapping;
extern char *stack;
extern void page_walk(unsigned long virt_addr);

/*********************
 * ALLOCATION BITMAP
 *  One bit per page of memory. Bit set => page is allocated.
 */

static unsigned long *alloc_bitmap;
#define PAGES_PER_MAPWORD (sizeof(unsigned long) * 8)

#define allocated_in_map(_pn) \
(alloc_bitmap[(_pn)/PAGES_PER_MAPWORD] & (1<<((_pn)&(PAGES_PER_MAPWORD-1))))

/*
 * Hint regarding bitwise arithmetic in map_{alloc,free}:
 *  -(1<<n)  sets all bits >= n. 
 *  (1<<n)-1 sets all bits <  n.
 * Variable names in map_{alloc,free}:
 *  *_idx == Index into `alloc_bitmap' array.
 *  *_off == Bit offset within an element of the `alloc_bitmap' array.
 */

static void map_alloc(unsigned long first_page, unsigned long nr_pages)
{
    unsigned long start_off, end_off, curr_idx, end_idx;

    curr_idx  = first_page / PAGES_PER_MAPWORD;
    start_off = first_page & (PAGES_PER_MAPWORD-1);
    end_idx   = (first_page + nr_pages) / PAGES_PER_MAPWORD;
    end_off   = (first_page + nr_pages) & (PAGES_PER_MAPWORD-1);

    if ( curr_idx == end_idx )
    {
        alloc_bitmap[curr_idx] |= ((1<<end_off)-1) & -(1<<start_off);
    }
    else 
    {
        alloc_bitmap[curr_idx] |= -(1<<start_off);
        while ( ++curr_idx < end_idx ) alloc_bitmap[curr_idx] = ~0L;
        alloc_bitmap[curr_idx] |= (1<<end_off)-1;
    }
}


static void map_free(unsigned long first_page, unsigned long nr_pages)
{
    unsigned long start_off, end_off, curr_idx, end_idx;

    curr_idx = first_page / PAGES_PER_MAPWORD;
    start_off = first_page & (PAGES_PER_MAPWORD-1);
    end_idx   = (first_page + nr_pages) / PAGES_PER_MAPWORD;
    end_off   = (first_page + nr_pages) & (PAGES_PER_MAPWORD-1);

    if ( curr_idx == end_idx )
    {
        alloc_bitmap[curr_idx] &= -(1<<end_off) | ((1<<start_off)-1);
    }
    else 
    {
        alloc_bitmap[curr_idx] &= (1<<start_off)-1;
        while ( ++curr_idx != end_idx ) alloc_bitmap[curr_idx] = 0;
        alloc_bitmap[curr_idx] &= -(1<<end_off);
    }
}



/*************************
 * BINARY BUDDY ALLOCATOR
 */

typedef struct chunk_head_st chunk_head_t;
typedef struct chunk_tail_st chunk_tail_t;

struct chunk_head_st {
    chunk_head_t  *next;
    chunk_head_t **pprev;
    int            level;
};

struct chunk_tail_st {
    int level;
};

/* Linked lists of free chunks of different powers-of-two in size. */
#define FREELIST_SIZE ((sizeof(void*)<<3)-PAGE_SHIFT)
static chunk_head_t *free_head[FREELIST_SIZE];
static chunk_head_t  free_tail[FREELIST_SIZE];
#define FREELIST_EMPTY(_l) ((_l)->next == NULL)

#define round_pgdown(_p)  ((_p)&PAGE_MASK)
#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)

#ifdef MM_DEBUG
/*
 * Prints allocation[0/1] for @nr_pages, starting at @start
 * address (virtual).
 */
USED static void print_allocation(void *start, int nr_pages)
{
    unsigned long pfn_start = virt_to_pfn(start);
    int count;
    for(count = 0; count < nr_pages; count++)
        if(allocated_in_map(pfn_start + count)) printk("1");
        else printk("0");
        
    printk("\n");        
}

/*
 * Prints chunks (making them with letters) for @nr_pages starting
 * at @start (virtual).
 */
USED static void print_chunks(void *start, int nr_pages)
{
    char chunks[1001], current='A';
    int order, count;
    chunk_head_t *head;
    unsigned long pfn_start = virt_to_pfn(start);
   
    memset(chunks, (int)'_', 1000);
    if(nr_pages > 1000) 
    {
        DEBUG("Can only pring 1000 pages. Increase buffer size.");
    }
    
    for(order=0; order < FREELIST_SIZE; order++)
    {
        head = free_head[order];
        while(!FREELIST_EMPTY(head))
        {
            for(count = 0; count < 1<< head->level; count++)
            {
                if(count + virt_to_pfn(head) - pfn_start < 1000)
                    chunks[count + virt_to_pfn(head) - pfn_start] = current;
            }
            head = head->next;
            current++;
        }
    }
    chunks[nr_pages] = '\0';
    printk("%s\n", chunks);
}
#endif


/*
 * Initialise allocator, placing addresses [@min,@max] in free pool.
 * @min and @max are PHYSICAL addresses.
 */
static void init_page_allocator(unsigned long min, unsigned long max)
{
    int i;
    unsigned long range, bitmap_size;
    chunk_head_t *ch;
    chunk_tail_t *ct;
    for ( i = 0; i < FREELIST_SIZE; i++ )
    {
        free_head[i]       = &free_tail[i];
        free_tail[i].pprev = &free_head[i];
        free_tail[i].next  = NULL;
    }

    min = round_pgup  (min);
    max = round_pgdown(max);

    /* Allocate space for the allocation bitmap. */
    bitmap_size  = (max+1) >> (PAGE_SHIFT+3);
    bitmap_size  = round_pgup(bitmap_size);
    alloc_bitmap = (unsigned long *)to_virt(min);
    min         += bitmap_size;
    range        = max - min;

    /* All allocated by default. */
    memset(alloc_bitmap, ~0, bitmap_size);
    /* Free up the memory we've been given to play with. */
    map_free(min>>PAGE_SHIFT, range>>PAGE_SHIFT);

    /* The buddy lists are addressed in high memory. */
    min += VIRT_START;
    max += VIRT_START;

    while ( range != 0 )
    {
        /*
         * Next chunk is limited by alignment of min, but also
         * must not be bigger than remaining range.
         */
        for ( i = PAGE_SHIFT; (1<<(i+1)) <= range; i++ )
            if ( min & (1<<i) ) break;


        ch = (chunk_head_t *)min;
        min   += (1<<i);
        range -= (1<<i);
        ct = (chunk_tail_t *)min-1;
        i -= PAGE_SHIFT;
        ch->level       = i;
        ch->next        = free_head[i];
        ch->pprev       = &free_head[i];
        ch->next->pprev = &ch->next;
        free_head[i]    = ch;
        ct->level       = i;
    }
}


/* Allocate 2^@order contiguous pages. Returns a VIRTUAL address. */
unsigned long alloc_pages(int order)
{
    int i;
    chunk_head_t *alloc_ch, *spare_ch;
    chunk_tail_t            *spare_ct;


    /* Find smallest order which can satisfy the request. */
    for ( i = order; i < FREELIST_SIZE; i++ ) {
	if ( !FREELIST_EMPTY(free_head[i]) ) 
	    break;
    }

    if ( i == FREELIST_SIZE ) goto no_memory;
 
    /* Unlink a chunk. */
    alloc_ch = free_head[i];
    free_head[i] = alloc_ch->next;
    alloc_ch->next->pprev = alloc_ch->pprev;

    /* We may have to break the chunk a number of times. */
    while ( i != order )
    {
        /* Split into two equal parts. */
        i--;
        spare_ch = (chunk_head_t *)((char *)alloc_ch + (1<<(i+PAGE_SHIFT)));
        spare_ct = (chunk_tail_t *)((char *)spare_ch + (1<<(i+PAGE_SHIFT)))-1;

        /* Create new header for spare chunk. */
        spare_ch->level = i;
        spare_ch->next  = free_head[i];
        spare_ch->pprev = &free_head[i];
        spare_ct->level = i;

        /* Link in the spare chunk. */
        spare_ch->next->pprev = &spare_ch->next;
        free_head[i] = spare_ch;
    }
    
    map_alloc(to_phys(alloc_ch)>>PAGE_SHIFT, 1<<order);

    return((unsigned long)alloc_ch);

 no_memory:

    printk("Cannot handle page request order %d!\n", order);

    return 0;
}

void free_pages(void *pointer, int order)
{
    chunk_head_t *freed_ch, *to_merge_ch;
    chunk_tail_t *freed_ct;
    unsigned long mask;
    
    /* First free the chunk */
    map_free(virt_to_pfn(pointer), 1 << order);
    
    /* Create free chunk */
    freed_ch = (chunk_head_t *)pointer;
    freed_ct = (chunk_tail_t *)((char *)pointer + (1<<(order + PAGE_SHIFT)))-1;
    
    /* Now, possibly we can conseal chunks together */
    while(order < FREELIST_SIZE)
    {
        mask = 1 << (order + PAGE_SHIFT);
        if((unsigned long)freed_ch & mask) 
        {
            to_merge_ch = (chunk_head_t *)((char *)freed_ch - mask);
            if(allocated_in_map(virt_to_pfn(to_merge_ch)) ||
                    to_merge_ch->level != order)
                break;
            
            /* Merge with predecessor */
            freed_ch = to_merge_ch;   
        }
        else 
        {
            to_merge_ch = (chunk_head_t *)((char *)freed_ch + mask);
            if(allocated_in_map(virt_to_pfn(to_merge_ch)) ||
                    to_merge_ch->level != order)
                break;
            
            /* Merge with successor */
            freed_ct = (chunk_tail_t *)((char *)to_merge_ch + mask) - 1;
        }
        
        /* We are commited to merging, unlink the chunk */
        *(to_merge_ch->pprev) = to_merge_ch->next;
        to_merge_ch->next->pprev = to_merge_ch->pprev;
        
        order++;
    }

    /* Link the new chunk */
    freed_ch->level = order;
    freed_ch->next  = free_head[order];
    freed_ch->pprev = &free_head[order];
    freed_ct->level = order;
    
    freed_ch->next->pprev = &freed_ch->next;
    free_head[order] = freed_ch;   
   
}


void new_pt_frame(unsigned long *pt_pfn, unsigned long prev_l_mfn, 
                                unsigned long offset, unsigned long level)
{   
    pgentry_t *tab = (pgentry_t *)start_info.pt_base;
    unsigned long pt_page = (unsigned long)pfn_to_virt(*pt_pfn); 
    unsigned long prot_e, prot_t, pincmd;
    mmu_update_t mmu_updates[1];
    struct mmuext_op pin_request;
    
    DEBUG("Allocating new L%d pt frame for pt_pfn=%lx, "
           "prev_l_mfn=%lx, offset=%lx", 
           level, *pt_pfn, prev_l_mfn, offset);

    /* We need to clear the page, otherwise we might fail to map it
       as a page table page */
    memset((unsigned long*)pfn_to_virt(*pt_pfn), 0, PAGE_SIZE);  
 
    switch ( level )
    {
    case L1_FRAME:
         prot_e = L1_PROT;
         prot_t = L2_PROT;
         pincmd = MMUEXT_PIN_L1_TABLE;
         break;
#if defined(__x86_64__) || defined(CONFIG_X86_PAE)
    case L2_FRAME:
         prot_e = L2_PROT;
         prot_t = L3_PROT;
         pincmd = MMUEXT_PIN_L2_TABLE;
         break;
#endif
#if defined(__x86_64__)
    case L3_FRAME:
         prot_e = L3_PROT;
         prot_t = L4_PROT;
         pincmd = MMUEXT_PIN_L3_TABLE;
         break;
#endif
    default:
         printk("new_pt_frame() called with invalid level number %d\n", level);
         do_exit();
         break;
    }
    /* Update the entry */
#if defined(__x86_64__)
    tab = pte_to_virt(tab[l4_table_offset(pt_page)]);
    tab = pte_to_virt(tab[l3_table_offset(pt_page)]);
#endif
#if defined(CONFIG_X86_PAE)
    tab = pte_to_virt(tab[l3_table_offset(pt_page)]);
#endif

    mmu_updates[0].ptr = ((pgentry_t)tab[l2_table_offset(pt_page)] & PAGE_MASK) + 
                         sizeof(pgentry_t) * l1_table_offset(pt_page);
    mmu_updates[0].val = (pgentry_t)pfn_to_mfn(*pt_pfn) << PAGE_SHIFT | 
                         (prot_e & ~_PAGE_RW);
    if(HYPERVISOR_mmu_update(mmu_updates, 1, NULL, DOMID_SELF) < 0)
    {
         printk("PTE for new page table page could not be updated\n");
         do_exit();
    }
                        
    /* Pin the page to provide correct protection */
    pin_request.cmd = pincmd;
    pin_request.arg1.mfn = pfn_to_mfn(*pt_pfn);
    if(HYPERVISOR_mmuext_op(&pin_request, 1, NULL, DOMID_SELF) < 0)
    {
        printk("ERROR: pinning failed\n");
        do_exit();
    }

    /* Now fill the new page table page with entries.
       Update the page directory as well. */
    mmu_updates[0].ptr = ((pgentry_t)prev_l_mfn << PAGE_SHIFT) + sizeof(pgentry_t) * offset;
    mmu_updates[0].val = (pgentry_t)pfn_to_mfn(*pt_pfn) << PAGE_SHIFT | prot_t;
    if(HYPERVISOR_mmu_update(mmu_updates, 1, NULL, DOMID_SELF) < 0) 
    {
       printk("ERROR: mmu_update failed\n");
       do_exit();
    }
    *pt_pfn += 1;
}

/* Checks if a pagetable frame is needed (if weren't allocated by Xen) */
static int need_pt_frame(unsigned long virt_address, int level)
{
    unsigned long hyp_virt_start = HYPERVISOR_VIRT_START;
#if defined(__x86_64__)
    unsigned long hyp_virt_end = HYPERVISOR_VIRT_END;
#else
    unsigned long hyp_virt_end = 0xffffffff;
#endif

    /* In general frames will _not_ be needed if they were already
       allocated to map the hypervisor into our VA space */
#if defined(__x86_64__)
    if(level == L3_FRAME)
    {
        if(l4_table_offset(virt_address) >= 
           l4_table_offset(hyp_virt_start) &&
           l4_table_offset(virt_address) <= 
           l4_table_offset(hyp_virt_end))
            return 0;
        return 1;
    } else
#endif

#if defined(__x86_64__) || defined(CONFIG_X86_PAE)
    if(level == L2_FRAME)
    {
#if defined(__x86_64__)
        if(l4_table_offset(virt_address) >= 
           l4_table_offset(hyp_virt_start) &&
           l4_table_offset(virt_address) <= 
           l4_table_offset(hyp_virt_end))
#endif
            if(l3_table_offset(virt_address) >= 
               l3_table_offset(hyp_virt_start) &&
               l3_table_offset(virt_address) <= 
               l3_table_offset(hyp_virt_end))
                return 0;

        return 1;
    } else 
#endif /* defined(__x86_64__) || defined(CONFIG_X86_PAE) */

    /* Always need l1 frames */
    if(level == L1_FRAME)
        return 1;

    printk("ERROR: Unknown frame level %d, hypervisor %llx,%llx\n", 
        level, hyp_virt_start, hyp_virt_end);
    return -1;
}

void build_pagetable(unsigned long *start_pfn, unsigned long *max_pfn)
{
    unsigned long start_address, end_address;
    unsigned long pfn_to_map, pt_pfn = *start_pfn;
    static mmu_update_t mmu_updates[L1_PAGETABLE_ENTRIES + 1];
    pgentry_t *tab = (pgentry_t *)start_info.pt_base, page;
    unsigned long mfn = pfn_to_mfn(virt_to_pfn(start_info.pt_base));
    unsigned long offset;
    int count = 0;

    pfn_to_map = (start_info.nr_pt_frames - NOT_L1_FRAMES) * L1_PAGETABLE_ENTRIES;

    if (*max_pfn >= virt_to_pfn(HYPERVISOR_VIRT_START))
    {
        printk("WARNING: Mini-OS trying to use Xen virtual space. "
               "Truncating memory from %dMB to ",
               ((unsigned long)pfn_to_virt(*max_pfn) - (unsigned long)&_text)>>20);
        *max_pfn = virt_to_pfn(HYPERVISOR_VIRT_START - PAGE_SIZE);
        printk("%dMB\n",
               ((unsigned long)pfn_to_virt(*max_pfn) - (unsigned long)&_text)>>20);
    }

    start_address = (unsigned long)pfn_to_virt(pfn_to_map);
    end_address = (unsigned long)pfn_to_virt(*max_pfn);

    /* We worked out the virtual memory range to map, now mapping loop */
    printk("Mapping memory range 0x%lx - 0x%lx\n", start_address, end_address);

    while(start_address < end_address)
    {
        tab = (pgentry_t *)start_info.pt_base;
        mfn = pfn_to_mfn(virt_to_pfn(start_info.pt_base));

#if defined(__x86_64__)
        offset = l4_table_offset(start_address);
        /* Need new L3 pt frame */
        if(!(start_address & L3_MASK)) 
            if(need_pt_frame(start_address, L3_FRAME)) 
                new_pt_frame(&pt_pfn, mfn, offset, L3_FRAME);

        page = tab[offset];
        mfn = pte_to_mfn(page);
        tab = to_virt(mfn_to_pfn(mfn) << PAGE_SHIFT);
#endif
#if defined(__x86_64__) || defined(CONFIG_X86_PAE)
        offset = l3_table_offset(start_address);
        /* Need new L2 pt frame */
        if(!(start_address & L2_MASK))
            if(need_pt_frame(start_address, L2_FRAME))
                new_pt_frame(&pt_pfn, mfn, offset, L2_FRAME);

        page = tab[offset];
        mfn = pte_to_mfn(page);
        tab = to_virt(mfn_to_pfn(mfn) << PAGE_SHIFT);
#endif
        offset = l2_table_offset(start_address);        
        /* Need new L1 pt frame */
        if(!(start_address & L1_MASK))
            if(need_pt_frame(start_address, L1_FRAME)) 
                new_pt_frame(&pt_pfn, mfn, offset, L1_FRAME);

        page = tab[offset];
        mfn = pte_to_mfn(page);
        offset = l1_table_offset(start_address);

        mmu_updates[count].ptr = ((pgentry_t)mfn << PAGE_SHIFT) + sizeof(pgentry_t) * offset;
        mmu_updates[count].val = (pgentry_t)pfn_to_mfn(pfn_to_map++) << PAGE_SHIFT | L1_PROT;
        count++;
        if (count == L1_PAGETABLE_ENTRIES || pfn_to_map == *max_pfn)
        {
            if(HYPERVISOR_mmu_update(mmu_updates, count, NULL, DOMID_SELF) < 0)
            {
                printk("PTE could not be updated\n");
                do_exit();
            }
            count = 0;
        }
        start_address += PAGE_SIZE;
    }
    *start_pfn = pt_pfn;
}


void mem_test(unsigned long *start_add, unsigned long *end_add)
{
    unsigned long mask = 0x10000;
    unsigned long *pointer;

    for(pointer = start_add; pointer < end_add; pointer++)
    {
        if(!(((unsigned long)pointer) & 0xfffff))
        {
            printk("Writing to %lx\n", pointer);
            page_walk((unsigned long)pointer);
        }
        *pointer = (unsigned long)pointer & ~mask;
    }

    for(pointer = start_add; pointer < end_add; pointer++)
    {
        if(((unsigned long)pointer & ~mask) != *pointer)
            printk("Read error at 0x%lx. Read: 0x%lx, should read 0x%lx\n",
                (unsigned long)pointer, 
                *pointer, 
                ((unsigned long)pointer & ~mask));
    }

}

static pgentry_t *demand_map_pgt;
static void *demand_map_area_start;

static void init_demand_mapping_area(unsigned long max_pfn)
{
    unsigned long mfn;
    pgentry_t *tab;
    unsigned long start_addr;
    unsigned long pt_pfn;
    unsigned offset;

    /* Round up to four megs.  + 1024 rather than + 1023 since we want
       to be sure we don't end up in the same place we started. */
    max_pfn = (max_pfn + L1_PAGETABLE_ENTRIES) & ~(L1_PAGETABLE_ENTRIES - 1);
    if (max_pfn == 0 ||
            (unsigned long)pfn_to_virt(max_pfn + L1_PAGETABLE_ENTRIES) >=
            HYPERVISOR_VIRT_START) {
        printk("Too much memory; no room for demand map hole.\n");
        do_exit();
    }

    demand_map_area_start = pfn_to_virt(max_pfn);
    printk("Demand map pfns start at %lx (%p).\n", max_pfn,
            demand_map_area_start);
    start_addr = (unsigned long)demand_map_area_start;

    tab = (pgentry_t *)start_info.pt_base;
    mfn = virt_to_mfn(start_info.pt_base);
    pt_pfn = virt_to_pfn(alloc_page());

#if defined(__x86_64__)
    offset = l4_table_offset(start_addr);
    if (!(tab[offset] & _PAGE_PRESENT)) {
        new_pt_frame(&pt_pfn, mfn, offset, L3_FRAME);
        pt_pfn = virt_to_pfn(alloc_page());
    }
    ASSERT(tab[offset] & _PAGE_PRESENT);
    mfn = pte_to_mfn(tab[offset]);
    tab = to_virt(mfn_to_pfn(mfn) << PAGE_SHIFT);
#endif
#if defined(__x86_64__) || defined(CONFIG_X86_PAE)
    offset = l3_table_offset(start_addr);
    if (!(tab[offset] & _PAGE_PRESENT)) {
        new_pt_frame(&pt_pfn, mfn, offset, L2_FRAME);
        pt_pfn = virt_to_pfn(alloc_page());
    }
    ASSERT(tab[offset] & _PAGE_PRESENT);
    mfn = pte_to_mfn(tab[offset]);
    tab = to_virt(mfn_to_pfn(mfn) << PAGE_SHIFT);
#endif
    offset = l2_table_offset(start_addr);
    if (tab[offset] & _PAGE_PRESENT) {
        printk("Demand map area already has a page table covering it?\n");
        BUG();
    }
    demand_map_pgt = pfn_to_virt(pt_pfn);
    new_pt_frame(&pt_pfn, mfn, offset, L1_FRAME);
    ASSERT(tab[offset] & _PAGE_PRESENT);
}

void *map_frames(unsigned long *f, unsigned long n)
{
    unsigned long x;
    unsigned long y = 0;
    mmu_update_t mmu_updates[16];
    int rc;

    if (n > 16) {
        printk("Tried to map too many (%ld) frames at once.\n", n);
        return NULL;
    }

    /* Find a run of n contiguous frames */
    for (x = 0; x <= 1024 - n; x += y + 1) {
        for (y = 0; y < n; y++)
            if (demand_map_pgt[x+y] & _PAGE_PRESENT)
                break;
        if (y == n)
            break;
    }
    if (y != n) {
        printk("Failed to map %ld frames!\n", n);
        return NULL;
    }

    /* Found it at x.  Map it in. */
    for (y = 0; y < n; y++) {
        mmu_updates[y].ptr = virt_to_mach(&demand_map_pgt[x + y]);
        mmu_updates[y].val = (f[y] << PAGE_SHIFT) | L1_PROT;
    }

    rc = HYPERVISOR_mmu_update(mmu_updates, n, NULL, DOMID_SELF);
    if (rc < 0) {
        printk("Map %ld failed: %d.\n", n, rc);
        return NULL;
    } else {
        return (void *)(unsigned long)((unsigned long)demand_map_area_start +
                x * PAGE_SIZE);
    }
}

void init_mm(void)
{

    unsigned long start_pfn, max_pfn;

    printk("MM: Init\n");

    printk("  _text:        %p\n", &_text);
    printk("  _etext:       %p\n", &_etext);
    printk("  _edata:       %p\n", &_edata);
    printk("  stack start:  %p\n", &stack);
    printk("  _end:         %p\n", &_end);

    /* First page follows page table pages and 3 more pages (store page etc) */
    start_pfn = PFN_UP(to_phys(start_info.pt_base)) + 
                start_info.nr_pt_frames + 3;
    max_pfn = start_info.nr_pages;
   
    printk("  start_pfn:    %lx\n", start_pfn);
    printk("  max_pfn:      %lx\n", max_pfn);

    build_pagetable(&start_pfn, &max_pfn);

    /*
     * now we can initialise the page allocator
     */
    printk("MM: Initialise page allocator for %lx(%lx)-%lx(%lx)\n",
           (u_long)to_virt(PFN_PHYS(start_pfn)), PFN_PHYS(start_pfn), 
           (u_long)to_virt(PFN_PHYS(max_pfn)), PFN_PHYS(max_pfn));
    init_page_allocator(PFN_PHYS(start_pfn), PFN_PHYS(max_pfn));
    printk("MM: done\n");

    init_demand_mapping_area(max_pfn);
    printk("Initialised demand area.\n");
}

void sanity_check(void)
{
    int x;
    chunk_head_t *head;

    for (x = 0; x < FREELIST_SIZE; x++) {
        for (head = free_head[x]; !FREELIST_EMPTY(head); head = head->next) {
            ASSERT(!allocated_in_map(virt_to_pfn(head)));
            if (head->next)
                ASSERT(head->next->pprev == &head->next);
        }
        if (free_head[x]) {
            ASSERT(free_head[x]->pprev == &free_head[x]);
        }
    }
}
