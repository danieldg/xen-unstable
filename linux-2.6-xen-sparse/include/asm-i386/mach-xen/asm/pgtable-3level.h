#ifndef _I386_PGTABLE_3LEVEL_H
#define _I386_PGTABLE_3LEVEL_H

#include <asm-generic/pgtable-nopud.h>

/*
 * Intel Physical Address Extension (PAE) Mode - three-level page
 * tables on PPro+ CPUs.
 *
 * Copyright (C) 1999 Ingo Molnar <mingo@redhat.com>
 */

#define pte_ERROR(e) \
	printk("%s:%d: bad pte %p(%016Lx pfn %08lx).\n", __FILE__, __LINE__, \
	       &(e), __pte_val(e), pte_pfn(e))
#define pmd_ERROR(e) \
	printk("%s:%d: bad pmd %p(%016Lx pfn %08Lx).\n", __FILE__, __LINE__, \
	       &(e), __pmd_val(e), (pmd_val(e) & PTE_MASK) >> PAGE_SHIFT)
#define pgd_ERROR(e) \
	printk("%s:%d: bad pgd %p(%016Lx pfn %08Lx).\n", __FILE__, __LINE__, \
	       &(e), __pgd_val(e), (pgd_val(e) & PTE_MASK) >> PAGE_SHIFT)

#define pud_none(pud)				0
#define pud_bad(pud)				0
#define pud_present(pud)			1

/*
 * Is the pte executable?
 */
static inline int pte_x(pte_t pte)
{
	return !(__pte_val(pte) & _PAGE_NX);
}

/*
 * All present user-pages with !NX bit are user-executable:
 */
static inline int pte_exec(pte_t pte)
{
	return pte_user(pte) && pte_x(pte);
}
/*
 * All present pages with !NX bit are kernel-executable:
 */
static inline int pte_exec_kernel(pte_t pte)
{
	return pte_x(pte);
}

/* Rules for using set_pte: the pte being assigned *must* be
 * either not present or in a state where the hardware will
 * not attempt to update the pte.  In places where this is
 * not possible, use pte_get_and_clear to obtain the old pte
 * value and then use set_pte to update it.  -ben
 */
#define __HAVE_ARCH_SET_PTE_ATOMIC

static inline void set_pte(pte_t *ptep, pte_t pte)
{
	ptep->pte_high = pte.pte_high;
	smp_wmb();
	ptep->pte_low = pte.pte_low;
}
#define set_pte_atomic(pteptr,pteval) \
		set_64bit((unsigned long long *)(pteptr),__pte_val(pteval))

#define set_pte_at(_mm,addr,ptep,pteval) do {				\
	if (((_mm) != current->mm && (_mm) != &init_mm) ||		\
	    HYPERVISOR_update_va_mapping((addr), (pteval), 0))		\
		set_pte((ptep), (pteval));				\
} while (0)

#define set_pte_at_sync(_mm,addr,ptep,pteval) do {			\
	if (((_mm) != current->mm && (_mm) != &init_mm) ||		\
	    HYPERVISOR_update_va_mapping((addr), (pteval), UVMF_INVLPG)) { \
		set_pte((ptep), (pteval));				\
		xen_invlpg((addr));					\
	}								\
} while (0)

#define set_pmd(pmdptr,pmdval)				\
		xen_l2_entry_update((pmdptr), (pmdval))
#define set_pud(pudptr,pudval) \
		xen_l3_entry_update((pudptr), (pudval))

/*
 * Pentium-II erratum A13: in PAE mode we explicitly have to flush
 * the TLB via cr3 if the top-level pgd is changed...
 * We do not let the generic code free and clear pgd entries due to
 * this erratum.
 */
static inline void pud_clear (pud_t * pud) { }

#define pud_page(pud) \
((struct page *) __va(pud_val(pud) & PAGE_MASK))

#define pud_page_kernel(pud) \
((unsigned long) __va(pud_val(pud) & PAGE_MASK))


/* Find an entry in the second-level page table.. */
#define pmd_offset(pud, address) ((pmd_t *) pud_page(*(pud)) + \
			pmd_index(address))

static inline int pte_none(pte_t pte)
{
	return !(pte.pte_low | pte.pte_high);
}

/*
 * For PTEs and PDEs, we must clear the P-bit first when clearing a page table
 * entry, so clear the bottom half first and enforce ordering with a compiler
 * barrier.
 */
static inline void pte_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	if ((mm != current->mm && mm != &init_mm)
	    || HYPERVISOR_update_va_mapping(addr, __pte(0), 0)) {
		ptep->pte_low = 0;
		smp_wmb();
		ptep->pte_high = 0;
	}
}

#define pmd_clear(xp)	do { set_pmd(xp, __pmd(0)); } while (0)

static inline pte_t ptep_get_and_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	pte_t pte = *ptep;
	if (!pte_none(pte)) {
		if (mm != &init_mm) {
			uint64_t val = __pte_val(pte);
			if (__cmpxchg64(ptep, val, 0) != val) {
				/* xchg acts as a barrier before the setting of the high bits */
				pte.pte_low = xchg(&ptep->pte_low, 0);
				pte.pte_high = ptep->pte_high;
				ptep->pte_high = 0;
			}
		} else
			HYPERVISOR_update_va_mapping(addr, __pte(0), 0);
	}
	return pte;
}

#define ptep_clear_flush(vma, addr, ptep)			\
({								\
	pte_t *__ptep = (ptep);					\
	pte_t __res = *__ptep;					\
	if (!pte_none(__res) &&					\
	    ((vma)->vm_mm != current->mm ||			\
	     HYPERVISOR_update_va_mapping(addr,	__pte(0),	\
			(unsigned long)(vma)->vm_mm->cpu_vm_mask.bits| \
				UVMF_INVLPG|UVMF_MULTI))) {	\
		__ptep->pte_low = 0;				\
		smp_wmb();					\
		__ptep->pte_high = 0;				\
		flush_tlb_page(vma, addr);			\
	}							\
	__res;							\
})

static inline int pte_same(pte_t a, pte_t b)
{
	return a.pte_low == b.pte_low && a.pte_high == b.pte_high;
}

#define pte_page(x)	pfn_to_page(pte_pfn(x))

#define __pte_mfn(_pte) (((_pte).pte_low >> PAGE_SHIFT) | \
			 ((_pte).pte_high << (32-PAGE_SHIFT)))
#define pte_mfn(_pte) ((_pte).pte_low & _PAGE_PRESENT ? \
	__pte_mfn(_pte) : pfn_to_mfn(__pte_mfn(_pte)))
#define pte_pfn(_pte) ((_pte).pte_low & _PAGE_PRESENT ? \
	mfn_to_local_pfn(__pte_mfn(_pte)) : __pte_mfn(_pte))

extern unsigned long long __supported_pte_mask;

static inline pte_t pfn_pte(unsigned long page_nr, pgprot_t pgprot)
{
	return __pte((((unsigned long long)page_nr << PAGE_SHIFT) |
			pgprot_val(pgprot)) & __supported_pte_mask);
}

static inline pmd_t pfn_pmd(unsigned long page_nr, pgprot_t pgprot)
{
	return __pmd((((unsigned long long)page_nr << PAGE_SHIFT) |
			pgprot_val(pgprot)) & __supported_pte_mask);
}

/*
 * Bits 0, 6 and 7 are taken in the low part of the pte,
 * put the 32 bits of offset into the high part.
 */
#define pte_to_pgoff(pte) ((pte).pte_high)
#define pgoff_to_pte(off) ((pte_t) { _PAGE_FILE, (off) })
#define PTE_FILE_MAX_BITS       32

/* Encode and de-code a swap entry */
#define __swp_type(x)			(((x).val) & 0x1f)
#define __swp_offset(x)			((x).val >> 5)
#define __swp_entry(type, offset)	((swp_entry_t){(type) | (offset) << 5})
#define __pte_to_swp_entry(pte)		((swp_entry_t){ (pte).pte_high })
#define __swp_entry_to_pte(x)		((pte_t){ 0, (x).val })

#define __pmd_free_tlb(tlb, x)		do { } while (0)

void vmalloc_sync_all(void);

#endif /* _I386_PGTABLE_3LEVEL_H */
