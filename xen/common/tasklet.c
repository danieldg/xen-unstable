/******************************************************************************
 * tasklet.c
 * 
 * Tasklets are dynamically-allocatable tasks run in VCPU context
 * (specifically, the idle VCPU's context) on at most one CPU at a time.
 * 
 * Copyright (c) 2010, Citrix Systems, Inc.
 * Copyright (c) 1992, Linus Torvalds
 * 
 * Authors:
 *    Keir Fraser <keir.fraser@citrix.com>
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/softirq.h>
#include <xen/tasklet.h>

/* Some subsystems call into us before we are initialised. We ignore them. */
static bool_t tasklets_initialised;

/*
 * NB. Any modification to a tasklet_list requires the scheduler to run
 * on the related CPU so that its idle VCPU's priority is set correctly.
 */
static DEFINE_PER_CPU(struct list_head, tasklet_list);

/* Protects all lists and tasklet structures. */
static DEFINE_SPINLOCK(tasklet_lock);

void tasklet_schedule_on_cpu(struct tasklet *t, unsigned int cpu)
{
    unsigned long flags;

    spin_lock_irqsave(&tasklet_lock, flags);

    if ( tasklets_initialised && !t->is_dead )
    {
        t->scheduled_on = cpu;
        if ( !t->is_running )
        {
            list_del(&t->list);
            list_add_tail(&t->list, &per_cpu(tasklet_list, cpu));
            cpu_raise_softirq(cpu, SCHEDULE_SOFTIRQ);
        }
    }

    spin_unlock_irqrestore(&tasklet_lock, flags);
}

void tasklet_schedule(struct tasklet *t)
{
    tasklet_schedule_on_cpu(t, smp_processor_id());
}

void do_tasklet(void)
{
    unsigned int cpu = smp_processor_id();
    struct list_head *list = &per_cpu(tasklet_list, cpu);
    struct tasklet *t;

    if ( likely(list_empty(list)) )
        return;

    spin_lock_irq(&tasklet_lock);

    if ( unlikely(list_empty(list)) )
    {
        spin_unlock_irq(&tasklet_lock);
        return;
    }

    t = list_entry(list->next, struct tasklet, list);
    list_del_init(&t->list);

    BUG_ON(t->is_dead || t->is_running || (t->scheduled_on != cpu));
    t->scheduled_on = -1;
    t->is_running = 1;

    spin_unlock_irq(&tasklet_lock);
    sync_local_execstate();
    t->func(t->data);
    spin_lock_irq(&tasklet_lock);

    t->is_running = 0;

    if ( t->scheduled_on >= 0 )
    {
        BUG_ON(t->is_dead || !list_empty(&t->list));
        list_add_tail(&t->list, &per_cpu(tasklet_list, t->scheduled_on));
        if ( t->scheduled_on != cpu )
            cpu_raise_softirq(t->scheduled_on, SCHEDULE_SOFTIRQ);
    }

    raise_softirq(SCHEDULE_SOFTIRQ);

    spin_unlock_irq(&tasklet_lock);
}

bool_t tasklet_queue_empty(unsigned int cpu)
{
    return list_empty(&per_cpu(tasklet_list, cpu));
}

void tasklet_kill(struct tasklet *t)
{
    unsigned long flags;

    spin_lock_irqsave(&tasklet_lock, flags);

    if ( !list_empty(&t->list) )
    {
        BUG_ON(t->is_dead || t->is_running || (t->scheduled_on < 0));
        list_del_init(&t->list);
        cpu_raise_softirq(t->scheduled_on, SCHEDULE_SOFTIRQ);
    }

    t->scheduled_on = -1;
    t->is_dead = 1;

    while ( t->is_running )
    {
        spin_unlock_irqrestore(&tasklet_lock, flags);
        cpu_relax();
        spin_lock_irqsave(&tasklet_lock, flags);
    }

    spin_unlock_irqrestore(&tasklet_lock, flags);
}

void migrate_tasklets_from_cpu(unsigned int cpu)
{
    struct list_head *list = &per_cpu(tasklet_list, cpu);
    unsigned long flags;
    struct tasklet *t;

    spin_lock_irqsave(&tasklet_lock, flags);

    while ( !list_empty(list) )
    {
        t = list_entry(list->next, struct tasklet, list);
        BUG_ON(t->scheduled_on != cpu);
        t->scheduled_on = smp_processor_id();
        list_del(&t->list);
        list_add_tail(&t->list, &this_cpu(tasklet_list));
    }

    raise_softirq(SCHEDULE_SOFTIRQ);

    spin_unlock_irqrestore(&tasklet_lock, flags);
}

void tasklet_init(
    struct tasklet *t, void (*func)(unsigned long), unsigned long data)
{
    memset(t, 0, sizeof(*t));
    INIT_LIST_HEAD(&t->list);
    t->scheduled_on = -1;
    t->func = func;
    t->data = data;
}

void __init tasklet_subsys_init(void)
{
    unsigned int cpu;

    for_each_possible_cpu ( cpu )
        INIT_LIST_HEAD(&per_cpu(tasklet_list, cpu));

    tasklets_initialised = 1;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */