/******************************************************************************
 * hypervisor.h
 * 
 * Linux-specific hypervisor handling.
 * 
 * Copyright (c) 2002, K A Fraser
 */

#ifndef __HYPERVISOR_H__
#define __HYPERVISOR_H__

#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/hypervisor-ifs/hypervisor-if.h>
#include <asm/hypervisor-ifs/dom0_ops.h>
#include <asm/ptrace.h>
#include <asm/page.h>

/* arch/xeno/kernel/setup.c */
union start_info_union
{
    start_info_t start_info;
    char padding[512];
};
extern union start_info_union start_info_union;
#define start_info (start_info_union.start_info)

/* arch/xeno/kernel/hypervisor.c */
void do_hypervisor_callback(struct pt_regs *regs);


/* arch/xeno/mm/hypervisor.c */
/*
 * NB. ptr values should be PHYSICAL, not MACHINE. 'vals' should be already
 * be MACHINE addresses.
 */

extern unsigned int mmu_update_queue_idx;

void queue_l1_entry_update(pte_t *ptr, unsigned long val);
void queue_l2_entry_update(pmd_t *ptr, unsigned long val);
void queue_pt_switch(unsigned long ptr);
void queue_tlb_flush(void);
void queue_invlpg(unsigned long ptr);
void queue_pgd_pin(unsigned long ptr);
void queue_pgd_unpin(unsigned long ptr);
void queue_pte_pin(unsigned long ptr);
void queue_pte_unpin(unsigned long ptr);
void queue_set_ldt(unsigned long ptr, unsigned long bytes);
#define MMU_UPDATE_DEBUG 0

#define queue_unchecked_mmu_update(_p,_v) queue_l1_entry_update( \
  (pte_t *)((unsigned long)(_p)|MMU_UNCHECKED_PT_UPDATE),(_v))

#if MMU_UPDATE_DEBUG > 0
typedef struct {
    void *ptr;
    unsigned long val, pteval;
    void *ptep;
    int line; char *file;
} page_update_debug_t;
extern page_update_debug_t update_debug_queue[];
#define queue_l1_entry_update(_p,_v) ({                           \
 update_debug_queue[mmu_update_queue_idx].ptr  = (_p);             \
 update_debug_queue[mmu_update_queue_idx].val  = (_v);             \
 update_debug_queue[mmu_update_queue_idx].line = __LINE__;         \
 update_debug_queue[mmu_update_queue_idx].file = __FILE__;         \
 queue_l1_entry_update((_p),(_v));                                \
})
#define queue_l2_entry_update(_p,_v) ({                           \
 update_debug_queue[mmu_update_queue_idx].ptr  = (_p);             \
 update_debug_queue[mmu_update_queue_idx].val  = (_v);             \
 update_debug_queue[mmu_update_queue_idx].line = __LINE__;         \
 update_debug_queue[mmu_update_queue_idx].file = __FILE__;         \
 queue_l2_entry_update((_p),(_v));                                \
})
#endif

#if MMU_UPDATE_DEBUG > 1
#undef queue_l1_entry_update
#undef queue_l2_entry_update
#define queue_l1_entry_update(_p,_v) ({                           \
 update_debug_queue[mmu_update_queue_idx].ptr  = (_p);             \
 update_debug_queue[mmu_update_queue_idx].val  = (_v);             \
 update_debug_queue[mmu_update_queue_idx].line = __LINE__;         \
 update_debug_queue[mmu_update_queue_idx].file = __FILE__;         \
 printk("L1 %s %d: %08lx (%08lx -> %08lx)\n", __FILE__, __LINE__, \
        (_p), pte_val(_p),                                        \
        (unsigned long)(_v));                                     \
 queue_l1_entry_update((_p),(_v));                                \
})
#define queue_l2_entry_update(_p,_v) ({                           \
 update_debug_queue[mmu_update_queue_idx].ptr  = (_p);             \
 update_debug_queue[mmu_update_queue_idx].val  = (_v);             \
 update_debug_queue[mmu_update_queue_idx].line = __LINE__;         \
 update_debug_queue[mmu_update_queue_idx].file = __FILE__;         \
 printk("L2 %s %d: %08lx (%08lx -> %08lx)\n", __FILE__, __LINE__, \
        (_p), pmd_val(_p),                                        \
        (unsigned long)(_v));                                     \
 queue_l2_entry_update((_p),(_v));                                \
})
#define queue_pt_switch(_p) ({                                    \
 printk("PTSWITCH %s %d: %08lx\n", __FILE__, __LINE__, (_p));     \
 queue_pt_switch(_p);                                             \
})   
#define queue_tlb_flush() ({                                      \
 printk("TLB FLUSH %s %d\n", __FILE__, __LINE__);                 \
 queue_tlb_flush();                                               \
})   
#define queue_invlpg(_p) ({                                       \
 printk("INVLPG %s %d: %08lx\n", __FILE__, __LINE__, (_p));       \
 queue_invlpg(_p);                                                \
})   
#define queue_pgd_pin(_p) ({                                      \
 printk("PGD PIN %s %d: %08lx\n", __FILE__, __LINE__, (_p));      \
 queue_pgd_pin(_p);                                               \
})   
#define queue_pgd_unpin(_p) ({                                    \
 printk("PGD UNPIN %s %d: %08lx\n", __FILE__, __LINE__, (_p));    \
 queue_pgd_unpin(_p);                                             \
})   
#define queue_pte_pin(_p) ({                                      \
 printk("PTE PIN %s %d: %08lx\n", __FILE__, __LINE__, (_p));      \
 queue_pte_pin(_p);                                               \
})   
#define queue_pte_unpin(_p) ({                                    \
 printk("PTE UNPIN %s %d: %08lx\n", __FILE__, __LINE__, (_p));    \
 queue_pte_unpin(_p);                                             \
})   
#define queue_set_ldt(_p,_l) ({                                        \
 printk("SETL LDT %s %d: %08lx %d\n", __FILE__, __LINE__, (_p), (_l)); \
 queue_set_ldt((_p), (_l));                                            \
})   
#endif

void _flush_page_update_queue(void);
static inline int flush_page_update_queue(void)
{
    unsigned int idx = mmu_update_queue_idx;
    if ( idx != 0 ) _flush_page_update_queue();
    return idx;
}
#define XENO_flush_page_update_queue() (_flush_page_update_queue())
void MULTICALL_flush_page_update_queue(void);


/*
 * Assembler stubs for hyper-calls.
 */

static inline int HYPERVISOR_set_trap_table(trap_info_t *table)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_trap_table),
        "b" (table) : "memory" );

    return ret;
}


static inline int HYPERVISOR_mmu_update(mmu_update_t *req, int count)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_mmu_update), 
        "b" (req), "c" (count) : "memory" );

    if ( unlikely(ret < 0) )
    {
        extern void show_trace(unsigned long *);
        show_trace(NULL);
        panic("Failed mmu update: %p, %d", req, count);
    }

    return ret;
}


static inline int HYPERVISOR_console_write(const char *str, int count)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_console_write), 
        "b" (str), "c" (count) : "memory" );


    return ret;
}

static inline int HYPERVISOR_set_gdt(unsigned long *frame_list, int entries)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_gdt), 
        "b" (frame_list), "c" (entries) : "memory" );


    return ret;
}

static inline int HYPERVISOR_stack_switch(unsigned long ss, unsigned long esp)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_stack_switch),
        "b" (ss), "c" (esp) : "memory" );

    return ret;
}

static inline int HYPERVISOR_set_callbacks(
    unsigned long event_selector, unsigned long event_address,
    unsigned long failsafe_selector, unsigned long failsafe_address)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_callbacks),
        "b" (event_selector), "c" (event_address), 
        "d" (failsafe_selector), "S" (failsafe_address) : "memory" );

    return ret;
}

static inline int HYPERVISOR_net_io_op(netop_t *op)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_net_io_op),
        "b" (op) : "memory" );

    return ret;
}

static inline int HYPERVISOR_fpu_taskswitch(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_fpu_taskswitch) : "memory" );

    return ret;
}

static inline int HYPERVISOR_yield(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_sched_op),
        "b" (SCHEDOP_yield) : "memory" );

    return ret;
}

static inline int HYPERVISOR_block(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_sched_op),
        "b" (SCHEDOP_block) : "memory" );

    return ret;
}

static inline int HYPERVISOR_exit(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_sched_op),
        "b" (SCHEDOP_exit) : "memory" );

    return ret;
}

static inline int HYPERVISOR_stop(unsigned long srec)
{
    int ret;
    /* NB. On suspend, control software expects a suspend record in %esi. */
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_sched_op),
        "b" (SCHEDOP_stop), "S" (srec) : "memory" );

    return ret;
}

static inline long HYPERVISOR_set_dom_timer(u64 timeout)
{
    int ret;
    unsigned long timeout_hi = (unsigned long)(timeout>>32);
    unsigned long timeout_lo = (unsigned long)timeout;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_dom_timer),
        "b" (timeout_hi), "c" (timeout_lo) : "memory" );

    return ret;
}

static inline int HYPERVISOR_dom0_op(dom0_op_t *dom0_op)
{
    int ret;
    dom0_op->interface_version = DOM0_INTERFACE_VERSION;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_dom0_op),
        "b" (dom0_op) : "memory" );

    return ret;
}

static inline int HYPERVISOR_network_op(void *network_op)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_network_op),
        "b" (network_op) : "memory" );

    return ret;
}

static inline int HYPERVISOR_block_io_op(void *block_io_op)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_block_io_op),
        "b" (block_io_op) : "memory" ); 

    return ret;
}

static inline int HYPERVISOR_set_debugreg(int reg, unsigned long value)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_debugreg),
        "b" (reg), "c" (value) : "memory" );

    return ret;
}

static inline unsigned long HYPERVISOR_get_debugreg(int reg)
{
    unsigned long ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_get_debugreg),
        "b" (reg) : "memory" );

    return ret;
}

static inline int HYPERVISOR_update_descriptor(
    unsigned long pa, unsigned long word1, unsigned long word2)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_update_descriptor), 
        "b" (pa), "c" (word1), "d" (word2) : "memory" );

    return ret;
}

static inline int HYPERVISOR_set_fast_trap(int idx)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_fast_trap), 
        "b" (idx) : "memory" );

    return ret;
}

static inline int HYPERVISOR_dom_mem_op(void *dom_mem_op)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_dom_mem_op),
        "b" (dom_mem_op) : "memory" );

    return ret;
}

static inline int HYPERVISOR_multicall(void *call_list, int nr_calls)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_multicall),
        "b" (call_list), "c" (nr_calls) : "memory" );

    return ret;
}

static inline long HYPERVISOR_kbd_op(unsigned char op, unsigned char val)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_kbd_op),
        "b" (op), "c" (val) : "memory" );

    return ret;
}

static inline int HYPERVISOR_update_va_mapping(
    unsigned long page_nr, pte_t new_val, unsigned long flags)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_update_va_mapping), 
        "b" (page_nr), "c" ((new_val).pte_low), "d" (flags) : "memory" );

    if ( unlikely(ret < 0) )
        panic("Failed update VA mapping: %08lx, %08lx, %08lx",
              page_nr, (new_val).pte_low, flags);
    
    return ret;
}

#endif /* __HYPERVISOR_H__ */
