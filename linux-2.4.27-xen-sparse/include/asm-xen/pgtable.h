#ifndef _I386_PGTABLE_H
#define _I386_PGTABLE_H

#include <linux/config.h>

/*
 * The Linux memory management assumes a three-level page table setup. On
 * the i386, we use that, but "fold" the mid level into the top-level page
 * table, so that we physically have the same two-level page table as the
 * i386 mmu expects.
 *
 * This file contains the functions and defines necessary to modify and use
 * the i386 page table tree.
 */
#ifndef __ASSEMBLY__
#include <asm/processor.h>
#include <asm/hypervisor.h>
#include <linux/threads.h>
#include <asm/fixmap.h>

#ifndef _I386_BITOPS_H
#include <asm/bitops.h>
#endif

#define swapper_pg_dir 0
extern void paging_init(void);

/* Caches aren't brain-dead on the intel. */
#define flush_cache_all()			do { } while (0)
#define flush_cache_mm(mm)			do { } while (0)
#define flush_cache_range(mm, start, end)	do { } while (0)
#define flush_cache_page(vma, vmaddr)		do { } while (0)
#define flush_page_to_ram(page)			do { } while (0)
#define flush_dcache_page(page)			do { } while (0)
#define flush_icache_range(start, end)		do { } while (0)
#define flush_icache_page(vma,pg)		do { } while (0)
#define flush_icache_user_range(vma,pg,adr,len)	do { } while (0)

extern unsigned long pgkern_mask;

#define __flush_tlb() ({ queue_tlb_flush(); XEN_flush_page_update_queue(); })
#define __flush_tlb_global() __flush_tlb()
#define __flush_tlb_all() __flush_tlb_global()
#define __flush_tlb_one(addr) ({ queue_invlpg(addr); XEN_flush_page_update_queue(); })
#define __flush_tlb_single(addr) ({ queue_invlpg(addr); XEN_flush_page_update_queue(); })

/*
 * ZERO_PAGE is a global shared page that is always zero: used
 * for zero-mapped memory areas etc..
 */
extern unsigned long empty_zero_page[1024];
#define ZERO_PAGE(vaddr) (virt_to_page(empty_zero_page))

#endif /* !__ASSEMBLY__ */

/*
 * The Linux x86 paging architecture is 'compile-time dual-mode', it
 * implements both the traditional 2-level x86 page tables and the
 * newer 3-level PAE-mode page tables.
 */
#ifndef __ASSEMBLY__
#if CONFIG_X86_PAE
# include <asm/pgtable-3level.h>

/*
 * Need to initialise the X86 PAE caches
 */
extern void pgtable_cache_init(void);

#else
# include <asm/pgtable-2level.h>

/*
 * No page table caches to initialise
 */
#define pgtable_cache_init()	do { } while (0)

#endif
#endif

#define PMD_SIZE	(1UL << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE-1))
#define PGDIR_SIZE	(1UL << PGDIR_SHIFT)
#define PGDIR_MASK	(~(PGDIR_SIZE-1))

#define USER_PTRS_PER_PGD	(TASK_SIZE/PGDIR_SIZE)
#define FIRST_USER_PGD_NR	0

#define USER_PGD_PTRS (PAGE_OFFSET >> PGDIR_SHIFT)
#define KERNEL_PGD_PTRS (PTRS_PER_PGD-USER_PGD_PTRS)

#define TWOLEVEL_PGDIR_SHIFT	22
#define BOOT_USER_PGD_PTRS (__PAGE_OFFSET >> TWOLEVEL_PGDIR_SHIFT)
#define BOOT_KERNEL_PGD_PTRS (1024-BOOT_USER_PGD_PTRS)


#ifndef __ASSEMBLY__
/* 4MB is just a nice "safety zone". Also, we align to a fresh pde. */
#define VMALLOC_OFFSET	(4*1024*1024)
extern void * high_memory;
#define VMALLOC_START	(((unsigned long) high_memory + 2*VMALLOC_OFFSET-1) & \
						~(VMALLOC_OFFSET-1))
#define VMALLOC_VMADDR(x) ((unsigned long)(x))
#if CONFIG_HIGHMEM
# define VMALLOC_END	(PKMAP_BASE-2*PAGE_SIZE)
#else
# define VMALLOC_END	(FIXADDR_START-2*PAGE_SIZE)
#endif

#define _PAGE_BIT_PRESENT	0
#define _PAGE_BIT_RW		1
#define _PAGE_BIT_USER		2
#define _PAGE_BIT_PWT		3
#define _PAGE_BIT_PCD		4
#define _PAGE_BIT_ACCESSED	5
#define _PAGE_BIT_DIRTY		6
#define _PAGE_BIT_PSE		7	/* 4 MB (or 2MB) page, Pentium+, if present.. */
#define _PAGE_BIT_GLOBAL	8	/* Global TLB entry PPro+ */

#define _PAGE_PRESENT	0x001
#define _PAGE_RW	0x002
#define _PAGE_USER	0x004
#define _PAGE_PWT	0x008
#define _PAGE_PCD	0x010
#define _PAGE_ACCESSED	0x020
#define _PAGE_DIRTY	0x040
#define _PAGE_PSE	0x080	/* 4 MB (or 2MB) page, Pentium+, if present.. */
#define _PAGE_GLOBAL	0x100	/* Global TLB entry PPro+ */

#define _PAGE_PROTNONE	0x080	/* If not present */

#define _PAGE_TABLE	(_PAGE_PRESENT | _PAGE_RW | _PAGE_USER | _PAGE_ACCESSED | _PAGE_DIRTY)
#define _KERNPG_TABLE	(_PAGE_PRESENT | _PAGE_RW | _PAGE_ACCESSED | _PAGE_DIRTY)
#define _PAGE_CHG_MASK	(PTE_MASK | _PAGE_ACCESSED | _PAGE_DIRTY)

#define PAGE_NONE	__pgprot(_PAGE_PROTNONE | _PAGE_ACCESSED)
#define PAGE_SHARED	__pgprot(_PAGE_PRESENT | _PAGE_RW | _PAGE_USER | _PAGE_ACCESSED)
#define PAGE_COPY	__pgprot(_PAGE_PRESENT | _PAGE_USER | _PAGE_ACCESSED)
#define PAGE_READONLY	__pgprot(_PAGE_PRESENT | _PAGE_USER | _PAGE_ACCESSED)

#define __PAGE_KERNEL \
	(_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED)
#define __PAGE_KERNEL_NOCACHE \
	(_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | _PAGE_PCD | _PAGE_ACCESSED)
#define __PAGE_KERNEL_RO \
	(_PAGE_PRESENT | _PAGE_DIRTY | _PAGE_ACCESSED)

#if 0
#define MAKE_GLOBAL(x) __pgprot((x) | _PAGE_GLOBAL)
#else
#define MAKE_GLOBAL(x) __pgprot(x)
#endif

#define PAGE_KERNEL MAKE_GLOBAL(__PAGE_KERNEL)
#define PAGE_KERNEL_RO MAKE_GLOBAL(__PAGE_KERNEL_RO)
#define PAGE_KERNEL_NOCACHE MAKE_GLOBAL(__PAGE_KERNEL_NOCACHE)

/*
 * The i386 can't do page protection for execute, and considers that
 * the same are read. Also, write permissions imply read permissions.
 * This is the closest we can get..
 */
#define __P000	PAGE_NONE
#define __P001	PAGE_READONLY
#define __P010	PAGE_COPY
#define __P011	PAGE_COPY
#define __P100	PAGE_READONLY
#define __P101	PAGE_READONLY
#define __P110	PAGE_COPY
#define __P111	PAGE_COPY

#define __S000	PAGE_NONE
#define __S001	PAGE_READONLY
#define __S010	PAGE_SHARED
#define __S011	PAGE_SHARED
#define __S100	PAGE_READONLY
#define __S101	PAGE_READONLY
#define __S110	PAGE_SHARED
#define __S111	PAGE_SHARED

#define pte_present(x)	((x).pte_low & (_PAGE_PRESENT | _PAGE_PROTNONE))
#define pte_clear(xp)	queue_l1_entry_update(xp, 0)

#define pmd_none(x)	(!(x).pmd)
#define pmd_present(x)	((x).pmd & _PAGE_PRESENT)
#define pmd_clear(xp)	do { set_pmd(xp, __pmd(0)); } while (0)
#define	pmd_bad(x)	(((x).pmd & (~PAGE_MASK & ~_PAGE_USER)) != _KERNPG_TABLE)


#define pages_to_mb(x) ((x) >> (20-PAGE_SHIFT))

/*
 * The following only work if pte_present() is true.
 * Undefined behaviour if not..
 */
static inline int pte_read(pte_t pte)		{ return (pte).pte_low & _PAGE_USER; }
static inline int pte_exec(pte_t pte)		{ return (pte).pte_low & _PAGE_USER; }
static inline int pte_dirty(pte_t pte)		{ return (pte).pte_low & _PAGE_DIRTY; }
static inline int pte_young(pte_t pte)		{ return (pte).pte_low & _PAGE_ACCESSED; }
static inline int pte_write(pte_t pte)		{ return (pte).pte_low & _PAGE_RW; }

static inline pte_t pte_rdprotect(pte_t pte)	{ (pte).pte_low &= ~_PAGE_USER; return pte; }
static inline pte_t pte_exprotect(pte_t pte)	{ (pte).pte_low &= ~_PAGE_USER; return pte; }
static inline pte_t pte_mkclean(pte_t pte)	{ (pte).pte_low &= ~_PAGE_DIRTY; return pte; }
static inline pte_t pte_mkold(pte_t pte)	{ (pte).pte_low &= ~_PAGE_ACCESSED; return pte; }
static inline pte_t pte_wrprotect(pte_t pte)	{ (pte).pte_low &= ~_PAGE_RW; return pte; }
static inline pte_t pte_mkread(pte_t pte)	{ (pte).pte_low |= _PAGE_USER; return pte; }
static inline pte_t pte_mkexec(pte_t pte)	{ (pte).pte_low |= _PAGE_USER; return pte; }
static inline pte_t pte_mkdirty(pte_t pte)	{ (pte).pte_low |= _PAGE_DIRTY; return pte; }
static inline pte_t pte_mkyoung(pte_t pte)	{ (pte).pte_low |= _PAGE_ACCESSED; return pte; }
static inline pte_t pte_mkwrite(pte_t pte)	{ (pte).pte_low |= _PAGE_RW; return pte; }

static inline int ptep_test_and_clear_dirty(pte_t *ptep)
{
    unsigned long pteval = *(unsigned long *)ptep;
    int ret = pteval & _PAGE_DIRTY;
    if ( ret ) queue_l1_entry_update(ptep, pteval & ~_PAGE_DIRTY);
    return ret;
}
static inline  int ptep_test_and_clear_young(pte_t *ptep)
{
    unsigned long pteval = *(unsigned long *)ptep;
    int ret = pteval & _PAGE_ACCESSED;
    if ( ret ) queue_l1_entry_update(ptep, pteval & ~_PAGE_ACCESSED);
    return ret;
}
static inline void ptep_set_wrprotect(pte_t *ptep)
{
    unsigned long pteval = *(unsigned long *)ptep;
    if ( (pteval & _PAGE_RW) )
        queue_l1_entry_update(ptep, pteval & ~_PAGE_RW);
}
static inline void ptep_mkdirty(pte_t *ptep)
{
    unsigned long pteval = *(unsigned long *)ptep;
    if ( !(pteval & _PAGE_DIRTY) )
        queue_l1_entry_update(ptep, pteval | _PAGE_DIRTY);
}

/*
 * Conversion functions: convert a page and protection to a page entry,
 * and a page entry and page directory to the page they refer to.
 */

#define mk_pte(page, pgprot)	__mk_pte((page) - mem_map, (pgprot))

/* This takes a physical page address that is used by the remapping functions */
#define mk_pte_phys(physpage, pgprot)	__mk_pte((physpage) >> PAGE_SHIFT, pgprot)

static inline pte_t pte_modify(pte_t pte, pgprot_t newprot)
{
	pte.pte_low &= _PAGE_CHG_MASK;
	pte.pte_low |= pgprot_val(newprot);
	return pte;
}

#define page_pte(page) page_pte_prot(page, __pgprot(0))

#define pmd_page(pmd) \
((unsigned long) __va(pmd_val(pmd) & PAGE_MASK))

/* to find an entry in a page-table-directory. */
#define pgd_index(address) ((address >> PGDIR_SHIFT) & (PTRS_PER_PGD-1))

#define __pgd_offset(address) pgd_index(address)

#define pgd_offset(mm, address) ((mm)->pgd+pgd_index(address))

/* to find an entry in a kernel page-table-directory */
#define pgd_offset_k(address) pgd_offset(&init_mm, address)

#define __pmd_offset(address) \
		(((address) >> PMD_SHIFT) & (PTRS_PER_PMD-1))

/* Find an entry in the third-level page table.. */
#define __pte_offset(address) \
		((address >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))
#define pte_offset(dir, address) ((pte_t *) pmd_page(*(dir)) + \
			__pte_offset(address))

/*
 * The i386 doesn't have any external MMU info: the kernel page
 * tables contain all the necessary information.
 */
#define update_mmu_cache(vma,address,pte) do { } while (0)

/* Encode and de-code a swap entry */
#define SWP_TYPE(x)			(((x).val >> 1) & 0x3f)
#define SWP_OFFSET(x)			((x).val >> 8)
#define SWP_ENTRY(type, offset)		((swp_entry_t) { ((type) << 1) | ((offset) << 8) })
#define pte_to_swp_entry(pte)		((swp_entry_t) { (pte).pte_low })
#define swp_entry_to_pte(x)		((pte_t) { (x).val })

struct page;
int change_page_attr(struct page *, int, pgprot_t prot);

static inline void __make_page_readonly(void *va)
{
    pgd_t *pgd = pgd_offset_k((unsigned long)va);
    pmd_t *pmd = pmd_offset(pgd, (unsigned long)va);
    pte_t *pte = pte_offset(pmd, (unsigned long)va);
    queue_l1_entry_update(pte, (*(unsigned long *)pte)&~_PAGE_RW);
}

static inline void __make_page_writable(void *va)
{
    pgd_t *pgd = pgd_offset_k((unsigned long)va);
    pmd_t *pmd = pmd_offset(pgd, (unsigned long)va);
    pte_t *pte = pte_offset(pmd, (unsigned long)va);
    queue_l1_entry_update(pte, (*(unsigned long *)pte)|_PAGE_RW);
}

static inline void make_page_readonly(void *va)
{
    pgd_t *pgd = pgd_offset_k((unsigned long)va);
    pmd_t *pmd = pmd_offset(pgd, (unsigned long)va);
    pte_t *pte = pte_offset(pmd, (unsigned long)va);
    queue_l1_entry_update(pte, (*(unsigned long *)pte)&~_PAGE_RW);
    if ( (unsigned long)va >= VMALLOC_START )
        __make_page_readonly(machine_to_virt(
            *(unsigned long *)pte&PAGE_MASK));
}

static inline void make_page_writable(void *va)
{
    pgd_t *pgd = pgd_offset_k((unsigned long)va);
    pmd_t *pmd = pmd_offset(pgd, (unsigned long)va);
    pte_t *pte = pte_offset(pmd, (unsigned long)va);
    queue_l1_entry_update(pte, (*(unsigned long *)pte)|_PAGE_RW);
    if ( (unsigned long)va >= VMALLOC_START )
        __make_page_writable(machine_to_virt(
            *(unsigned long *)pte&PAGE_MASK));
}

static inline void make_pages_readonly(void *va, unsigned int nr)
{
    while ( nr-- != 0 )
    {
        make_page_readonly(va);
        va = (void *)((unsigned long)va + PAGE_SIZE);
    }
}

static inline void make_pages_writable(void *va, unsigned int nr)
{
    while ( nr-- != 0 )
    {
        make_page_writable(va);
        va = (void *)((unsigned long)va + PAGE_SIZE);
    }
}

static inline unsigned long arbitrary_virt_to_phys(void *va)
{
    pgd_t *pgd = pgd_offset_k((unsigned long)va);
    pmd_t *pmd = pmd_offset(pgd, (unsigned long)va);
    pte_t *pte = pte_offset(pmd, (unsigned long)va);
    unsigned long pa = (*(unsigned long *)pte) & PAGE_MASK;
    return pa | ((unsigned long)va & (PAGE_SIZE-1));
}

#endif /* !__ASSEMBLY__ */

/* Needs to be defined here and not in linux/mm.h, as it is arch dependent */
#define PageSkip(page)		(0)
#define kern_addr_valid(addr)	(1)

#define io_remap_page_range remap_page_range

#endif /* _I386_PGTABLE_H */
