#ifndef _ASM_IA64_TLBFLUSH_H
#define _ASM_IA64_TLBFLUSH_H

/*
 * Copyright (C) 2002 Hewlett-Packard Co
 *	David Mosberger-Tang <davidm@hpl.hp.com>
 */

#include <linux/config.h>

#include <linux/mm.h>

#include <asm/intrinsics.h>
#include <asm/mmu_context.h>
#include <asm/page.h>

/*
 * Now for some TLB flushing routines.  This is the kind of stuff that
 * can be very expensive, so try to avoid them whenever possible.
 */

/*
 * Flush everything (kernel mapping may also have changed due to
 * vmalloc/vfree).
 */
extern void local_flush_tlb_all (void);

#ifdef CONFIG_SMP
  extern void smp_flush_tlb_all (void);
  extern void smp_flush_tlb_mm (struct mm_struct *mm);
# define flush_tlb_all()	smp_flush_tlb_all()
#else
# define flush_tlb_all()	local_flush_tlb_all()
#endif

static inline void
local_finish_flush_tlb_mm (struct mm_struct *mm)
{
#ifndef XEN
// FIXME SMP?
	if (mm == current->active_mm)
		activate_context(mm);
#endif
}

/*
 * Flush a specified user mapping.  This is called, e.g., as a result of fork() and
 * exit().  fork() ends up here because the copy-on-write mechanism needs to write-protect
 * the PTEs of the parent task.
 */
static inline void
flush_tlb_mm (struct mm_struct *mm)
{
	if (!mm)
		return;

#ifndef XEN
// FIXME SMP?
	mm->context = 0;
#endif

	if (atomic_read(&mm->mm_users) == 0)
		return;		/* happens as a result of exit_mmap() */

#ifdef CONFIG_SMP
	smp_flush_tlb_mm(mm);
#else
	local_finish_flush_tlb_mm(mm);
#endif
}

extern void flush_tlb_range (struct vm_area_struct *vma, unsigned long start, unsigned long end);

/*
 * Page-granular tlb flush.
 */
static inline void
flush_tlb_page (struct vm_area_struct *vma, unsigned long addr)
{
#ifdef CONFIG_SMP
	flush_tlb_range(vma, (addr & PAGE_MASK), (addr & PAGE_MASK) + PAGE_SIZE);
#else
	if (vma->vm_mm == current->active_mm)
		ia64_ptcl(addr, (PAGE_SHIFT << 2));
#ifndef XEN
// FIXME SMP?
	else
		vma->vm_mm->context = 0;
#endif
#endif
}

/*
 * Flush the TLB entries mapping the virtually mapped linear page
 * table corresponding to address range [START-END).
 */
static inline void
flush_tlb_pgtables (struct mm_struct *mm, unsigned long start, unsigned long end)
{
	/*
	 * Deprecated.  The virtual page table is now flushed via the normal gather/flush
	 * interface (see tlb.h).
	 */
}


#define flush_tlb_kernel_range(start, end)	flush_tlb_all()	/* XXX fix me */
#ifdef XEN
extern void flush_tlb_mask(cpumask_t mask);
#endif

#endif /* _ASM_IA64_TLBFLUSH_H */
