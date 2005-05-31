/******************************************************************************
 * flushtlb.h
 * 
 * TLB flushes are timestamped using a global virtual 'clock' which ticks
 * on any TLB flush on any processor.
 * 
 * Copyright (c) 2003-2004, K A Fraser
 */

#ifndef __FLUSHTLB_H__
#define __FLUSHTLB_H__

#include <xen/config.h>
#include <xen/smp.h>

/* The current time as shown by the virtual TLB clock. */
extern u32 tlbflush_clock;

/* Time at which each CPU's TLB was last flushed. */
extern u32 tlbflush_time[NR_CPUS];

#define tlbflush_current_time() tlbflush_clock

/*
 * @cpu_stamp is the timestamp at last TLB flush for the CPU we are testing.
 * @lastuse_stamp is a timestamp taken when the PFN we are testing was last 
 * used for a purpose that may have caused the CPU's TLB to become tainted.
 */
static inline int NEED_FLUSH(u32 cpu_stamp, u32 lastuse_stamp)
{
    u32 curr_time = tlbflush_current_time();
    /*
     * Two cases:
     *  1. During a wrap, the clock ticks over to 0 while CPUs catch up. For
     *     safety during this period, we force a flush if @curr_time == 0.
     *  2. Otherwise, we look to see if @cpu_stamp <= @lastuse_stamp.
     *     To detect false positives because @cpu_stamp has wrapped, we
     *     also check @curr_time. If less than @lastuse_stamp we definitely
     *     wrapped, so there's no need for a flush (one is forced every wrap).
     */
    return ((curr_time == 0) ||
            ((cpu_stamp <= lastuse_stamp) &&
             (lastuse_stamp <= curr_time)));
}

/*
 * Filter the given set of CPUs, returning only those that may not have
 * flushed their TLBs since @page_timestamp.
 */
static inline unsigned long tlbflush_filter_cpuset(
    unsigned long cpuset, u32 page_timestamp)
{
    int i;
    unsigned long remain;

    for ( i = 0, remain = ~0UL; (cpuset & remain) != 0; i++, remain <<= 1 )
    {
        if ( (cpuset & (1UL << i)) &&
             !NEED_FLUSH(tlbflush_time[i], page_timestamp) )
            cpuset &= ~(1UL << i);
    }

    return cpuset;
}

extern void new_tlbflush_clock_period(void);

/* Read pagetable base. */
static inline unsigned long read_cr3(void)
{
    unsigned long cr3;
    __asm__ __volatile__ (
        "mov %%cr3, %0" : "=r" (cr3) : );
    return cr3;
}

/* Write pagetable base and implicitly tick the tlbflush clock. */
extern void write_cr3(unsigned long cr3);

#define local_flush_tlb()                                         \
    do {                                                          \
        unsigned long cr3 = read_cr3();                           \
        write_cr3(cr3);                                           \
    } while ( 0 )

#define local_flush_tlb_pge()                                     \
    do {                                                          \
        __pge_off();                                              \
        local_flush_tlb();                                        \
        __pge_on();                                               \
    } while ( 0 )

#define local_flush_tlb_one(__addr) \
    __asm__ __volatile__("invlpg %0": :"m" (*(char *) (__addr)))

#define flush_tlb_all()     flush_tlb_mask((1 << num_online_cpus()) - 1)

#ifndef CONFIG_SMP
#define flush_tlb_all_pge()          local_flush_tlb_pge()
#define flush_tlb_mask(_mask)        local_flush_tlb()
#define flush_tlb_one_mask(_mask,_v) local_flush_tlb_one(_v)
#else
#include <xen/smp.h>
#define FLUSHVA_ALL (~0UL)
extern void flush_tlb_all_pge(void);
extern void __flush_tlb_mask(unsigned long mask, unsigned long va);
#define flush_tlb_mask(_mask)        __flush_tlb_mask(_mask,FLUSHVA_ALL)
#define flush_tlb_one_mask(_mask,_v) __flush_tlb_mask(_mask,_v)
#endif

#endif /* __FLUSHTLB_H__ */
