#ifndef _ASM_IA64_PAGE_H
#define _ASM_IA64_PAGE_H
/*
 * Pagetable related stuff.
 *
 * Copyright (C) 1998, 1999, 2002 Hewlett-Packard Co
 *	David Mosberger-Tang <davidm@hpl.hp.com>
 */

#include <linux/config.h>

#include <asm/intrinsics.h>
#include <asm/types.h>

/*
 * The top three bits of an IA64 address are its Region Number.
 * Different regions are assigned to different purposes.
 */
#define RGN_SHIFT	(61)
#define RGN_BASE(r)	(__IA64_UL_CONST(r)<<RGN_SHIFT)
#define RGN_BITS	(RGN_BASE(-1))

#define RGN_KERNEL	7	/* Identity mapped region */
#define RGN_UNCACHED    6	/* Identity mapped I/O region */
#define RGN_GATE	5	/* Gate page, Kernel text, etc */
#define RGN_HPAGE	4	/* For Huge TLB pages */

/*
 * PAGE_SHIFT determines the actual kernel page size.
 */
#if defined(CONFIG_IA64_PAGE_SIZE_4KB)
# define PAGE_SHIFT	12
#elif defined(CONFIG_IA64_PAGE_SIZE_8KB)
# define PAGE_SHIFT	13
#elif defined(CONFIG_IA64_PAGE_SIZE_16KB)
# define PAGE_SHIFT	14
#elif defined(CONFIG_IA64_PAGE_SIZE_64KB)
# define PAGE_SHIFT	16
#else
# error Unsupported page size!
#endif

#define PAGE_SIZE		(__IA64_UL_CONST(1) << PAGE_SHIFT)
#define PAGE_MASK		(~(PAGE_SIZE - 1))
#define PAGE_ALIGN(addr)	(((addr) + PAGE_SIZE - 1) & PAGE_MASK)

#define PERCPU_PAGE_SHIFT	16	/* log2() of max. size of per-CPU area */
#define PERCPU_PAGE_SIZE	(__IA64_UL_CONST(1) << PERCPU_PAGE_SHIFT)


#ifdef CONFIG_HUGETLB_PAGE
# define HPAGE_REGION_BASE	RGN_BASE(RGN_HPAGE)
# define HPAGE_SHIFT		hpage_shift
# define HPAGE_SHIFT_DEFAULT	28	/* check ia64 SDM for architecture supported size */
# define HPAGE_SIZE		(__IA64_UL_CONST(1) << HPAGE_SHIFT)
# define HPAGE_MASK		(~(HPAGE_SIZE - 1))

# define HAVE_ARCH_HUGETLB_UNMAPPED_AREA
# define ARCH_HAS_HUGEPAGE_ONLY_RANGE
#endif /* CONFIG_HUGETLB_PAGE */

#ifdef __ASSEMBLY__
# define __pa(x)		((x) - PAGE_OFFSET)
# define __va(x)		((x) + PAGE_OFFSET)
#else /* !__ASSEMBLY */
# ifdef __KERNEL__
#  define STRICT_MM_TYPECHECKS

extern void clear_page (void *page);
extern void copy_page (void *to, void *from);

/*
 * clear_user_page() and copy_user_page() can't be inline functions because
 * flush_dcache_page() can't be defined until later...
 */
#define clear_user_page(addr, vaddr, page)	\
do {						\
	clear_page(addr);			\
	flush_dcache_page(page);		\
} while (0)

#define copy_user_page(to, from, vaddr, page)	\
do {						\
	copy_page((to), (from));		\
	flush_dcache_page(page);		\
} while (0)


#define alloc_zeroed_user_highpage(vma, vaddr) \
({						\
	struct page *page = alloc_page_vma(GFP_HIGHUSER | __GFP_ZERO, vma, vaddr); \
	if (page)				\
 		flush_dcache_page(page);	\
	page;					\
})

#define __HAVE_ARCH_ALLOC_ZEROED_USER_HIGHPAGE

#define virt_addr_valid(kaddr)	pfn_valid(__pa(kaddr) >> PAGE_SHIFT)

#ifdef CONFIG_VIRTUAL_MEM_MAP
extern int ia64_pfn_valid (unsigned long pfn);
#elif defined(CONFIG_FLATMEM)
# define ia64_pfn_valid(pfn) 1
#endif

#ifdef CONFIG_FLATMEM
# define pfn_valid(pfn)		(((pfn) < max_mapnr) && ia64_pfn_valid(pfn))
# define page_to_pfn(page)	((unsigned long) (page - mem_map))
# define pfn_to_page(pfn)	(mem_map + (pfn))
#elif defined(CONFIG_DISCONTIGMEM)
extern struct page *vmem_map;
extern unsigned long min_low_pfn;
extern unsigned long max_low_pfn;
# define pfn_valid(pfn)		(((pfn) >= min_low_pfn) && ((pfn) < max_low_pfn) && ia64_pfn_valid(pfn))
# define page_to_pfn(page)	((unsigned long) (page - vmem_map))
# define pfn_to_page(pfn)	(vmem_map + (pfn))
#endif

#define virt_to_page(kaddr)	pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)
#define pfn_to_kaddr(pfn)	__va((pfn) << PAGE_SHIFT)

typedef union ia64_va {
	struct {
		unsigned long off : 61;		/* intra-region offset */
		unsigned long reg :  3;		/* region number */
	} f;
	unsigned long l;
	void *p;
} ia64_va;

/*
 * Note: These macros depend on the fact that PAGE_OFFSET has all
 * region bits set to 1 and all other bits set to zero.  They are
 * expressed in this way to ensure they result in a single "dep"
 * instruction.
 */
#define __pa(x)		({ia64_va _v; _v.l = (long) (x); _v.f.reg = 0; _v.l;})
#define __va(x)		({ia64_va _v; _v.l = (long) (x); _v.f.reg = -1; _v.p;})

#define REGION_NUMBER(x)	({ia64_va _v; _v.l = (long) (x); _v.f.reg;})
#define REGION_OFFSET(x)	({ia64_va _v; _v.l = (long) (x); _v.f.off;})

#ifdef CONFIG_HUGETLB_PAGE
# define htlbpage_to_page(x)	(((unsigned long) REGION_NUMBER(x) << 61)			\
				 | (REGION_OFFSET(x) >> (HPAGE_SHIFT-PAGE_SHIFT)))
# define HUGETLB_PAGE_ORDER	(HPAGE_SHIFT - PAGE_SHIFT)
# define is_hugepage_only_range(mm, addr, len)		\
	 (REGION_NUMBER(addr) == RGN_HPAGE &&	\
	  REGION_NUMBER((addr)+(len)-1) == RGN_HPAGE)
extern unsigned int hpage_shift;
#endif

static __inline__ int
get_order (unsigned long size)
{
	long double d = size - 1;
	long order;

	order = ia64_getf_exp(d);
	order = order - PAGE_SHIFT - 0xffff + 1;
	if (order < 0)
		order = 0;
	return order;
}

# endif /* __KERNEL__ */
#endif /* !__ASSEMBLY__ */

#ifdef STRICT_MM_TYPECHECKS
  /*
   * These are used to make use of C type-checking..
   */
  typedef struct { unsigned long pte; } pte_t;
  typedef struct { unsigned long pmd; } pmd_t;
#ifdef CONFIG_PGTABLE_4
  typedef struct { unsigned long pud; } pud_t;
#endif
  typedef struct { unsigned long pgd; } pgd_t;
  typedef struct { unsigned long pgprot; } pgprot_t;

# define pte_val(x)	((x).pte)
# define pmd_val(x)	((x).pmd)
#ifdef CONFIG_PGTABLE_4
# define pud_val(x)	((x).pud)
#endif
# define pgd_val(x)	((x).pgd)
# define pgprot_val(x)	((x).pgprot)

# define __pte(x)	((pte_t) { (x) } )
# define __pgprot(x)	((pgprot_t) { (x) } )

#else /* !STRICT_MM_TYPECHECKS */
  /*
   * .. while these make it easier on the compiler
   */
# ifndef __ASSEMBLY__
    typedef unsigned long pte_t;
    typedef unsigned long pmd_t;
    typedef unsigned long pgd_t;
    typedef unsigned long pgprot_t;
# endif

# define pte_val(x)	(x)
# define pmd_val(x)	(x)
# define pgd_val(x)	(x)
# define pgprot_val(x)	(x)

# define __pte(x)	(x)
# define __pgd(x)	(x)
# define __pgprot(x)	(x)
#endif /* !STRICT_MM_TYPECHECKS */

#define PAGE_OFFSET			RGN_BASE(RGN_KERNEL)

#define VM_DATA_DEFAULT_FLAGS		(VM_READ | VM_WRITE |					\
					 VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC |		\
					 (((current->personality & READ_IMPLIES_EXEC) != 0)	\
					  ? VM_EXEC : 0))

#ifndef __ASSEMBLY__
#ifdef CONFIG_XEN

#define INVALID_P2M_ENTRY	(~0UL)

#ifndef CONFIG_XEN_IA64_DOM0_VP

#define virt_to_machine(v) __pa(v)
#define machine_to_virt(m) __va(m)
#define virt_to_mfn(v)	((__pa(v)) >> PAGE_SHIFT)
#define mfn_to_virt(m)	(__va((m) << PAGE_SHIFT))

#else

#include <linux/kernel.h>
#include <asm/hypervisor.h>
#include <xen/features.h>	// to compile netback, netfront
typedef unsigned long maddr_t;	// to compile netback, netfront

/*
 * XXX hack!
 * Linux/IA64 uses PG_arch_1.
 * This hack will be removed once PG_foreign bit is taken.
 * #include <xen/foreign_page.h>
 */
#ifdef __ASM_XEN_FOREIGN_PAGE_H__
# error "don't include include/xen/foreign_page.h!"
#endif

extern struct address_space xen_ia64_foreign_dummy_mapping;
#define PageForeign(page)	\
	((page)->mapping == &xen_ia64_foreign_dummy_mapping)

#define SetPageForeign(page, dtor) do {				\
	set_page_private((page), (unsigned long)(dtor));	\
	(page)->mapping = &xen_ia64_foreign_dummy_mapping;	\
	smp_rmb();						\
} while (0)

#define ClearPageForeign(page) do {	\
	(page)->mapping = NULL;		\
	smp_rmb();			\
	set_page_private((page), 0);	\
} while (0)

#define PageForeignDestructor(page)	\
	( (void (*) (struct page *)) page_private(page) )

#define arch_free_page(_page,_order)			\
({      int foreign = PageForeign(_page);               \
	if (foreign)                                    \
		(PageForeignDestructor(_page))(_page);  \
	foreign;                                        \
})
#define HAVE_ARCH_FREE_PAGE

/* XXX xen page size != page size */

static inline unsigned long
pfn_to_mfn_for_dma(unsigned long pfn)
{
	unsigned long mfn;
	mfn = HYPERVISOR_phystomach(pfn);
	BUG_ON(mfn == 0); // XXX
	BUG_ON(mfn == INVALID_P2M_ENTRY); // XXX
	BUG_ON(mfn == INVALID_MFN);
	return mfn;
}

static inline unsigned long
phys_to_machine_for_dma(unsigned long phys)
{
	unsigned long machine =
	              pfn_to_mfn_for_dma(phys >> PAGE_SHIFT) << PAGE_SHIFT;
	machine |= (phys & ~PAGE_MASK);
	return machine;
}

static inline unsigned long
mfn_to_pfn_for_dma(unsigned long mfn)
{
	unsigned long pfn;
	pfn = HYPERVISOR_machtophys(mfn);
	BUG_ON(pfn == 0);
	//BUG_ON(pfn == INVALID_M2P_ENTRY);
	return pfn;
}

static inline unsigned long
machine_to_phys_for_dma(unsigned long machine)
{
	unsigned long phys =
	              mfn_to_pfn_for_dma(machine >> PAGE_SHIFT) << PAGE_SHIFT;
	phys |= (machine & ~PAGE_MASK);
	return phys;
}

#define set_phys_to_machine(pfn, mfn) do { } while (0)
#define xen_machphys_update(mfn, pfn) do { } while (0)

/* XXX to compile set_phys_to_machine(vaddr, FOREIGN_FRAME(m)) */
#define FOREIGN_FRAME(m)        (INVALID_P2M_ENTRY)

#define mfn_to_pfn(mfn)			(mfn)
#define mfn_to_virt(mfn)		(__va((mfn) << PAGE_SHIFT))
#define pfn_to_mfn(pfn)			(pfn)
#define virt_to_mfn(virt)		(__pa(virt) >> PAGE_SHIFT)
#define virt_to_machine(virt)		__pa(virt) // for tpmfront.c

static inline unsigned long
mfn_to_local_pfn(unsigned long mfn)
{
	extern unsigned long max_mapnr;
	unsigned long pfn = mfn_to_pfn(mfn);
	if (!pfn_valid(pfn))
		return INVALID_P2M_ENTRY;
	return pfn;
}

#endif /* CONFIG_XEN_IA64_DOM0_VP */
#endif /* CONFIG_XEN */
#endif /* __ASSEMBLY__ */

#endif /* _ASM_IA64_PAGE_H */
