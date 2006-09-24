/*
 * Xen memory allocator routines
 *
 * Copyright (C) 2005 Hewlett-Packard Co
 *	Dan Magenheimer <dan.magenheimer@hp.com>
 * Copyright (C) 2005 Intel Corp.
 *
 * Routines used by ia64 machines with contiguous (or virtually contiguous)
 * memory.
 */

#include <linux/config.h>
#include <asm/pgtable.h>
#include <xen/mm.h>

#ifdef CONFIG_VIRTUAL_FRAME_TABLE
#include <linux/efi.h>
#include <asm/pgalloc.h>

extern unsigned long frametable_pg_dir[];

#define FRAMETABLE_PGD_OFFSET(ADDR) \
	(frametable_pg_dir + (((ADDR) >> PGDIR_SHIFT) & \
	((1UL << (PAGE_SHIFT - 3)) - 1)))

#define FRAMETABLE_PMD_OFFSET(PGD, ADDR) \
	__va((unsigned long *)(PGD) + (((ADDR) >> PMD_SHIFT) & \
	((1UL << (PAGE_SHIFT - 3)) - 1)))

#define FRAMETABLE_PTE_OFFSET(PMD, ADDR) \
	(pte_t *)__va((unsigned long *)(PMD) + (((ADDR) >> PAGE_SHIFT) & \
	((1UL << (PAGE_SHIFT - 3)) - 1)))

static unsigned long table_size;
static int opt_contig_mem = 0;
boolean_param("contig_mem", opt_contig_mem);
#else
#define opt_contig_mem 1
#endif

struct page_info *frame_table;
unsigned long max_page;

/*
 * Set up the page tables.
 */
volatile unsigned long *mpt_table;

void
paging_init (void)
{
	unsigned int mpt_order;
	unsigned long mpt_table_size;
	unsigned long i;

	if (!opt_contig_mem) {
		/* mpt_table is already allocated at this point. */
		return;
	}

	/* Create machine to physical mapping table
	 * NOTE: similar to frame table, later we may need virtually
	 * mapped mpt table if large hole exists. Also MAX_ORDER needs
	 * to be changed in common code, which only support 16M by far
	 */
	mpt_table_size = max_page * sizeof(unsigned long);
	mpt_order = get_order(mpt_table_size);
	ASSERT(mpt_order <= MAX_ORDER);
	if ((mpt_table = alloc_xenheap_pages(mpt_order)) == NULL)
		panic("Not enough memory to bootstrap Xen.\n");

	printk("machine to physical table: 0x%lx mpt_table_size 0x%lx\n"
	       "mpt_order %u max_page 0x%lx\n",
	       (u64)mpt_table, mpt_table_size, mpt_order, max_page);
	for (i = 0;
	     i < ((1UL << mpt_order) << PAGE_SHIFT) / sizeof(mpt_table[0]);
	     i++) {
		mpt_table[i] = INVALID_M2P_ENTRY;
	}
}

#ifdef CONFIG_VIRTUAL_FRAME_TABLE

static unsigned long
alloc_dir_page(void)
{
	unsigned long mfn = alloc_boot_pages(1, 1);
	unsigned long dir;
	if (!mfn)
		panic("Not enough memory for virtual frame table!\n");
	++table_size;
	dir = mfn << PAGE_SHIFT;
	memset(__va(dir), 0, PAGE_SIZE);
	return dir;
}

static inline unsigned long
alloc_table_page(unsigned long fill)
{
	unsigned long mfn = alloc_boot_pages(1, 1);
	unsigned long *table;
	unsigned long i;
	if (!mfn)
		panic("Not enough memory for virtual frame table!\n");
	++table_size;
	table = (unsigned long *)__va((mfn << PAGE_SHIFT));
	for (i = 0; i < PAGE_SIZE / sizeof(unsigned long); i++)
	    table[i] = fill;
	return mfn;
}

static void
create_page_table(unsigned long start_page, unsigned long end_page,
                  unsigned long fill)
{
	unsigned long address;
	unsigned long *dir;
	pte_t *pteptr;

	for (address = start_page; address < end_page; address += PAGE_SIZE) {
		dir = FRAMETABLE_PGD_OFFSET(address);
		if (!*dir)
			*dir = alloc_dir_page();
		dir = FRAMETABLE_PMD_OFFSET(*dir, address);
		if (!*dir)
			*dir = alloc_dir_page();
		pteptr = FRAMETABLE_PTE_OFFSET(*dir, address);
		if (pte_none(*pteptr))
			set_pte(pteptr, pfn_pte(alloc_table_page(fill),
			                        PAGE_KERNEL));
	}
}

static int
create_frametable_page_table (u64 start, u64 end, void *arg)
{
	struct page_info *map_start, *map_end;
	unsigned long start_page, end_page;

	map_start = frame_table + (__pa(start) >> PAGE_SHIFT);
	map_end   = frame_table + (__pa(end) >> PAGE_SHIFT);

	start_page = (unsigned long) map_start & PAGE_MASK;
	end_page = PAGE_ALIGN((unsigned long) map_end);

	create_page_table(start_page, end_page, 0L);
	return 0;
}

static int
create_mpttable_page_table (u64 start, u64 end, void *arg)
{
	unsigned long map_start, map_end;
	unsigned long start_page, end_page;

	map_start = (unsigned long)(mpt_table + (__pa(start) >> PAGE_SHIFT));
	map_end   = (unsigned long)(mpt_table + (__pa(end) >> PAGE_SHIFT));

	start_page = map_start & PAGE_MASK;
	end_page = PAGE_ALIGN(map_end);

	create_page_table(start_page, end_page, INVALID_M2P_ENTRY);
	return 0;
}

void init_virtual_frametable(void)
{
	/* Allocate virtual frame_table */
	frame_table = (struct page_info *) VIRT_FRAME_TABLE_ADDR;
	table_size = 0;
	efi_memmap_walk(create_frametable_page_table, NULL);

	printk("size of virtual frame_table: %lukB\n",
	       ((table_size << PAGE_SHIFT) >> 10));

	/* Allocate virtual mpt_table */
	table_size = 0;
	mpt_table = (unsigned long *)VIRT_FRAME_TABLE_END - max_page;
	efi_memmap_walk(create_mpttable_page_table, NULL);

	printk("virtual machine to physical table: %p size: %lukB\n"
	       "max_page: 0x%lx\n",
	       mpt_table, ((table_size << PAGE_SHIFT) >> 10), max_page);
}

int
ia64_mfn_valid (unsigned long pfn)
{
	extern long ia64_frametable_probe(unsigned long);
	struct page_info *pg;
	int valid;

	if (opt_contig_mem)
		return 1;
	pg = mfn_to_page(pfn);
	valid = ia64_frametable_probe((unsigned long)pg);
	/* more check the whole struct of page_info */
	if (valid)
		valid = ia64_frametable_probe((unsigned long)(pg+1)-1);
	return valid;
}

EXPORT_SYMBOL(ia64_mfn_valid);

#endif /* CONFIG_VIRTUAL_FRAME_TABLE */

/* FIXME: postpone support to machines with big holes between physical memorys.
 * Current hack allows only efi memdesc upto 4G place. (See efi.c)
 */
#define FT_ALIGN_SIZE	(16UL << 20)
void __init init_frametable(void)
{
	unsigned long pfn;
	unsigned long frame_table_size;

#ifdef CONFIG_VIRTUAL_FRAME_TABLE
	if (!opt_contig_mem) {
		init_virtual_frametable();
		return;
	}
#endif

	frame_table_size = max_page * sizeof(struct page_info);
	frame_table_size = (frame_table_size + PAGE_SIZE - 1) & PAGE_MASK;

	/* Request continuous trunk from boot allocator, since HV
	 * address is identity mapped */
	pfn = alloc_boot_pages(
            frame_table_size >> PAGE_SHIFT, FT_ALIGN_SIZE >> PAGE_SHIFT);
	if (pfn == 0)
		panic("Not enough memory for frame table.\n");

	frame_table = __va(pfn << PAGE_SHIFT);
	memset(frame_table, 0, frame_table_size);
	printk("size of frame_table: %lukB\n",
		frame_table_size >> 10);
}
