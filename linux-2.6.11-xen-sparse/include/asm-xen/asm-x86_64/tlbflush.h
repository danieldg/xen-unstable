#ifndef _X8664_TLBFLUSH_H
#define _X8664_TLBFLUSH_H

#include <linux/config.h>
#include <linux/mm.h>
#include <asm/processor.h>

#define __flush_tlb()	xen_tlb_flush()

/*
 * Global pages have to be flushed a bit differently. Not a real
 * performance problem because this does not happen often.
 */
#define __flush_tlb_global()	xen_tlb_flush()


extern unsigned long pgkern_mask;

#define __flush_tlb_all() __flush_tlb_global()

#define __flush_tlb_one(addr)	xen_invlpg(addr)


/*
 * TLB flushing:
 *
 *  - flush_tlb() flushes the current mm struct TLBs
 *  - flush_tlb_all() flushes all processes TLBs
 *  - flush_tlb_mm(mm) flushes the specified mm context TLB's
 *  - flush_tlb_page(vma, vmaddr) flushes one page
 *  - flush_tlb_range(vma, start, end) flushes a range of pages
 *  - flush_tlb_kernel_range(start, end) flushes a range of kernel pages
 *  - flush_tlb_pgtables(mm, start, end) flushes a range of page tables
 *
 * ..but the x86_64 has somewhat limited tlb flushing capabilities,
 * and page-granular flushes are available only on i486 and up.
 */

#ifndef CONFIG_SMP

#define flush_tlb() __flush_tlb()
#define flush_tlb_all() __flush_tlb_all()
#define local_flush_tlb() __flush_tlb()

static inline void flush_tlb_mm(struct mm_struct *mm)
{
	/* XEN: cpu_vm_mask is more accurate than active_mm. */
	if (cpu_isset(smp_processor_id(), mm->cpu_vm_mask))
		__flush_tlb();
}

static inline void flush_tlb_page(struct vm_area_struct *vma,
	unsigned long addr)
{
	/* XEN: cpu_vm_mask is more accurate than active_mm. */
	if (cpu_isset(smp_processor_id(), vma->vm_mm->cpu_vm_mask))
		__flush_tlb_one(addr);
}

static inline void flush_tlb_range(struct vm_area_struct *vma,
	unsigned long start, unsigned long end)
{
	/* XEN: cpu_vm_mask is more accurate than active_mm. */
	if (cpu_isset(smp_processor_id(), vma->vm_mm->cpu_vm_mask))
		__flush_tlb();
}

#else

#include <asm/smp.h>

#define local_flush_tlb() \
	__flush_tlb()

extern void flush_tlb_all(void);
extern void flush_tlb_current_task(void);
extern void flush_tlb_mm(struct mm_struct *);
extern void flush_tlb_page(struct vm_area_struct *, unsigned long);

#define flush_tlb()	flush_tlb_current_task()

static inline void flush_tlb_range(struct vm_area_struct * vma, unsigned long start, unsigned long end)
{
	flush_tlb_mm(vma->vm_mm);
}

#define TLBSTATE_OK	1
#define TLBSTATE_LAZY	2

#endif

#define flush_tlb_kernel_range(start, end) flush_tlb_all()

static inline void flush_tlb_pgtables(struct mm_struct *mm,
				      unsigned long start, unsigned long end)
{
	/* x86_64 does not keep any page table caches in TLB */
}

#endif /* _X8664_TLBFLUSH_H */
