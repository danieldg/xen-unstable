#ifndef __ASM_DOMAIN_H__
#define __ASM_DOMAIN_H__

#include <xen/config.h>
#include <xen/mm.h>
#include <asm/hvm/vcpu.h>
#include <asm/hvm/domain.h>

struct trap_bounce {
    unsigned long  error_code;
    unsigned short flags; /* TBF_ */
    unsigned short cs;
    unsigned long  eip;
};

#define MAPHASH_ENTRIES 8
#define MAPHASH_HASHFN(pfn) ((pfn) & (MAPHASH_ENTRIES-1))
#define MAPHASHENT_NOTINUSE ((u16)~0U)
struct vcpu_maphash {
    struct vcpu_maphash_entry {
        unsigned long pfn;
        uint16_t      idx;
        uint16_t      refcnt;
    } hash[MAPHASH_ENTRIES];
} __cacheline_aligned;

#define MAPCACHE_ORDER   10
#define MAPCACHE_ENTRIES (1 << MAPCACHE_ORDER)
struct mapcache {
    /* The PTEs that provide the mappings, and a cursor into the array. */
    l1_pgentry_t *l1tab;
    unsigned int cursor;

    /* Protects map_domain_page(). */
    spinlock_t lock;

    /* Garbage mappings are flushed from TLBs in batches called 'epochs'. */
    unsigned int epoch, shadow_epoch[MAX_VIRT_CPUS];
    u32 tlbflush_timestamp;

    /* Which mappings are in use, and which are garbage to reap next epoch? */
    unsigned long inuse[BITS_TO_LONGS(MAPCACHE_ENTRIES)];
    unsigned long garbage[BITS_TO_LONGS(MAPCACHE_ENTRIES)];

    /* Lock-free per-VCPU hash of recently-used mappings. */
    struct vcpu_maphash vcpu_maphash[MAX_VIRT_CPUS];
};

extern void mapcache_init(struct domain *);

/* x86/64: toggle guest between kernel and user modes. */
extern void toggle_guest_mode(struct vcpu *);

/*
 * Initialise a hypercall-transfer page. The given pointer must be mapped
 * in Xen virtual address space (accesses are not validated or checked).
 */
extern void hypercall_page_initialise(struct domain *d, void *);

struct arch_domain
{
    l1_pgentry_t *mm_perdomain_pt;
#ifdef CONFIG_X86_64
    l2_pgentry_t *mm_perdomain_l2;
    l3_pgentry_t *mm_perdomain_l3;
#endif

#ifdef CONFIG_X86_32
    /* map_domain_page() mapping cache. */
    struct mapcache mapcache;
#endif

    /* I/O-port admin-specified access capabilities. */
    struct rangeset *ioport_caps;

    /* Shadow mode status and controls. */
    struct shadow_ops *ops;
    unsigned int shadow_mode;  /* flags to control shadow table operation */
    unsigned int shadow_nest;  /* Recursive depth of shadow_lock() nesting */

    /* shadow hashtable */
    struct shadow_status *shadow_ht;
    struct shadow_status *shadow_ht_free;
    struct shadow_status *shadow_ht_extras; /* extra allocation units */
    unsigned int shadow_extras_count;

    /* shadow dirty bitmap */
    unsigned long *shadow_dirty_bitmap;
    unsigned int shadow_dirty_bitmap_size;  /* in pages, bit per page */

    /* shadow mode stats */
    unsigned int shadow_page_count;
    unsigned int hl2_page_count;
    unsigned int snapshot_page_count;

    unsigned int shadow_fault_count;
    unsigned int shadow_dirty_count;

    /* full shadow mode */
    struct out_of_sync_entry *out_of_sync; /* list of out-of-sync pages */
    struct out_of_sync_entry *out_of_sync_free;
    struct out_of_sync_entry *out_of_sync_extras;
    unsigned int out_of_sync_extras_count;

    struct list_head free_shadow_frames;

    pagetable_t         phys_table;         /* guest 1:1 pagetable */
    struct hvm_domain   hvm_domain;

    /* Shadow-translated guest: Pseudophys base address of reserved area. */
    unsigned long first_reserved_pfn;
} __cacheline_aligned;

#ifdef CONFIG_X86_PAE
struct pae_l3_cache {
    /*
     * Two low-memory (<4GB) PAE L3 tables, used as fallback when the guest
     * supplies a >=4GB PAE L3 table. We need two because we cannot set up
     * an L3 table while we are currently running on it (without using
     * expensive atomic 64-bit operations).
     */
    l3_pgentry_t  table[2][4] __attribute__((__aligned__(32)));
    unsigned long high_mfn;  /* The >=4GB MFN being shadowed. */
    unsigned int  inuse_idx; /* Which of the two cache slots is in use? */
    spinlock_t    lock;
};
#define pae_l3_cache_init(c) spin_lock_init(&(c)->lock)
#else /* !CONFIG_X86_PAE */
struct pae_l3_cache { };
#define pae_l3_cache_init(c) ((void)0)
#endif

struct arch_vcpu
{
    /* Needs 16-byte aligment for FXSAVE/FXRSTOR. */
    struct vcpu_guest_context guest_context
    __attribute__((__aligned__(16)));

    struct pae_l3_cache pae_l3_cache;

    unsigned long      flags; /* TF_ */

    void (*schedule_tail) (struct vcpu *);

    void (*ctxt_switch_from) (struct vcpu *);
    void (*ctxt_switch_to) (struct vcpu *);

    /* Bounce information for propagating an exception to guest OS. */
    struct trap_bounce trap_bounce;

    /* I/O-port access bitmap. */
    u8 *iobmp;        /* Guest kernel virtual address of the bitmap. */
    int iobmp_limit;  /* Number of ports represented in the bitmap.  */
    int iopl;         /* Current IOPL for this VCPU. */

#ifdef CONFIG_X86_32
    struct desc_struct int80_desc;
#endif

    /* Virtual Machine Extensions */
    struct hvm_vcpu hvm_vcpu;

    /*
     * Every domain has a L1 pagetable of its own. Per-domain mappings
     * are put in this table (eg. the current GDT is mapped here).
     */
    l1_pgentry_t *perdomain_ptes;

    pagetable_t  guest_table_user;      /* x86/64: user-space pagetable. */
    pagetable_t  guest_table;           /* (MA) guest notion of cr3 */
    pagetable_t  shadow_table;          /* (MA) shadow of guest */
    pagetable_t  monitor_table;         /* (MA) used in hypervisor */

    l2_pgentry_t *guest_vtable;         /* virtual address of pagetable */
    l2_pgentry_t *shadow_vtable;        /* virtual address of shadow_table */
    l2_pgentry_t *monitor_vtable;		/* virtual address of monitor_table */
    l1_pgentry_t *hl2_vtable;			/* virtual address of hl2_table */

#ifdef CONFIG_X86_64
    l3_pgentry_t *guest_vl3table;
    l4_pgentry_t *guest_vl4table;
#endif

    unsigned long monitor_shadow_ref;

    /* Current LDT details. */
    unsigned long shadow_ldt_mapcnt;
} __cacheline_aligned;

/* shorthands to improve code legibility */
#define hvm_vmx         hvm_vcpu.u.vmx
#define hvm_svm         hvm_vcpu.u.svm

#endif /* __ASM_DOMAIN_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
