#ifndef __i386_MMU_H
#define __i386_MMU_H

#include <asm/semaphore.h>
/*
 * The i386 doesn't have a mmu context, but
 * we put the segment information here.
 *
 * cpu_vm_mask is used to optimize ldt flushing.
 */
typedef struct { 
	int size;
	struct semaphore sem;
	void *ldt;
	unsigned pinned:1;
} mm_context_t;

/* mm/memory.c:exit_mmap hook */
extern void _arch_exit_mmap(struct mm_struct *mm);
#define arch_exit_mmap(_mm) _arch_exit_mmap(_mm)

#endif
