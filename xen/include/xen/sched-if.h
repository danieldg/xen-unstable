#include <asm/types.h>

/*
 * Additional declarations for the generic scheduler interface.  This should
 * only be included by files that implement conforming schedulers.
 *
 * Portions by Mark Williamson are (C) 2004 Intel Research Cambridge
 */

#define BUCKETS 10

typedef struct schedule_data_st
{
    spinlock_t          schedule_lock;  /* spinlock protecting curr pointer
                                            TODO check this */
    struct exec_domain  *curr;          /* current task */
    struct exec_domain  *idle;          /* idle task for this cpu */
    void *              sched_priv;
    struct ac_timer     s_timer;        /* scheduling timer  */
#ifdef BUCKETS
    u32                 hist[BUCKETS];  /* for scheduler latency histogram */
#endif
} __cacheline_aligned schedule_data_t;


typedef struct task_slice_st
{
    struct exec_domain *task;
    s_time_t            time;
} task_slice_t;

struct scheduler
{
    char *name;             /* full name for this scheduler      */
    char *opt_name;         /* option name for this scheduler    */
    unsigned int sched_id;  /* ID for this scheduler             */

    int          (*init_scheduler) ();
    int          (*init_idle_task) (struct exec_domain *);
    int          (*alloc_task)     (struct exec_domain *);
    void         (*add_task)       (struct exec_domain *);
    void         (*free_task)      (struct domain *);
    void         (*rem_task)       (struct exec_domain *);
    void         (*sleep)          (struct exec_domain *);
    void         (*wake)           (struct exec_domain *);
    void         (*do_block)       (struct exec_domain *);
    task_slice_t (*do_schedule)    (s_time_t);
    int          (*control)        (struct sched_ctl_cmd *);
    int          (*adjdom)         (struct domain *,
                                    struct sched_adjdom_cmd *);
    void         (*dump_settings)  (void);
    void         (*dump_cpu_state) (int);
    int          (*prn_state)      (int);
};

/* per CPU scheduler information */
extern schedule_data_t schedule_data[];


