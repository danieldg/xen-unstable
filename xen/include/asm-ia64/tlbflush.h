#ifndef __FLUSHTLB_H__
#define __FLUSHTLB_H__

#include <xen/sched.h>

/* TLB flushes can be either local (current vcpu only) or domain wide (on
   all vcpus).
   TLB flushes can be either all-flush or range only.

   vTLB flushing means flushing VCPU virtual TLB + machine TLB + machine VHPT.
*/

/* Local all flush of vTLB.  */
void vcpu_flush_vtlb_all (void);

/* Local range flush of machine TLB only (not full VCPU virtual TLB!!!)  */
void vcpu_flush_tlb_vhpt_range (u64 vadr, u64 log_range);

/* Global all flush of vTLB  */
void domain_flush_vtlb_all (void);

/* Global range-flush of vTLB.  */
void domain_flush_vtlb_range (struct domain *d, u64 vadr, u64 addr_range);

/* Final vTLB flush on every dirty cpus.  */
void domain_flush_destroy (struct domain *d);

/* Flush v-tlb on cpus set in mask for current domain.  */
void flush_tlb_mask(cpumask_t mask);

/* Flush local machine TLB.  */
void local_flush_tlb_all (void);

#define tlbflush_current_time() 0
#define tlbflush_filter(x,y) ((void)0)

#endif
