/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2004      Grzegorz Milos - University of Cambridge
 * Based on the implementation of the BVT scheduler by Rolf Neugebauer
 * and Mark Williamson (look in sched_bvt.c)
 ****************************************************************************
 *
 *        File: common/sched_fair_bvt.c
 *      Author: Grzegorz Milos
 *
 * Description: CPU scheduling
 *              implements Fair Borrowed Virtual Time Scheduler.
 *              FBVT is modification of BVT (see Duda & Cheriton SOSP'99)
 *              which tries to allocate fair shares of processor even 
 *              when there is mix between CPU and I/O bound domains.
 *              TODO - more information about the scheduler in TODO
 */
#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/delay.h>
#include <xen/event.h>
#include <xen/time.h>
#include <xen/ac_timer.h>
#include <xen/perfc.h>
#include <xen/sched-if.h>
#include <xen/slab.h>
#include <xen/trace.h>

/* For tracing - TODO - put all the defines in some common hearder file */
#define TRC_SCHED_FBVT_DO_SCHED             0x00020000
#define TRC_SCHED_FBVT_DO_SCHED_UPDATE      0x00020001


/* all per-domain BVT-specific scheduling info is stored here */
struct fbvt_dom_info
{
    unsigned long mcu_advance;      /* inverse of weight */
    u32           avt;              /* actual virtual time */
    u32           evt;              /* effective virtual time */
    u32		      time_slept;	    /* records amount of time slept, used for scheduling */
    int           warpback;         /* warp?  */
    long          warp;             /* virtual time warp */
    long          warpl;            /* warp limit */
    long          warpu;            /* unwarp time requirement */
    s_time_t      warped;           /* time it ran warped last time */
    s_time_t      uwarped;          /* time it ran unwarped last time */
};

struct fbvt_cpu_info
{
    unsigned long svt; /* XXX check this is unsigned long! */
    u32		      vtb;	    	    /* virtual time bonus */
    u32           r_time;           /* last time to run */  
};


#define FBVT_INFO(p)   ((struct fbvt_dom_info *)(p)->sched_priv)
#define CPU_INFO(cpu) ((struct fbvt_cpu_info *)(schedule_data[cpu]).sched_priv)
#define CPU_SVT(cpu)  (CPU_INFO(cpu)->svt)
#define LAST_VTB(cpu) (CPU_INFO(cpu)->vtb)
#define R_TIME(cpu)   (CPU_INFO(cpu)->r_time) 

#define MCU            (s32)MICROSECS(100)    /* Minimum unit */
#define MCU_ADVANCE    10                     /* default weight */
#define TIME_SLOP      (s32)MICROSECS(50)     /* allow time to slip a bit */
static s32 ctx_allow = (s32)MILLISECS(5);     /* context switch allowance */
static s32 max_vtb   = (s32)MILLISECS(5);

/* SLAB cache for struct fbvt_dom_info objects */
static kmem_cache_t *dom_info_cache;

/*
 * Calculate the effective virtual time for a domain. Take into account 
 * warping limits
 */
static void __calc_evt(struct fbvt_dom_info *inf)
{
    s_time_t now = NOW();

    if ( inf->warpback ) 
    {
        if ( ((now - inf->warped) < inf->warpl) &&
             ((now - inf->uwarped) > inf->warpu) )
        {
            /* allowed to warp */
            inf->evt = inf->avt - inf->warp;
        } 
        else 
        {
            /* warped for too long -> unwarp */
            inf->evt      = inf->avt;
            inf->uwarped  = now;
            inf->warpback = 0;
        }
    } 
    else 
    {
        inf->evt = inf->avt;
    }
}

/**
 * fbvt_alloc_task - allocate FBVT private structures for a task
 * @p:              task to allocate private structures for
 *
 * Returns non-zero on failure.
 */
int fbvt_alloc_task(struct domain *p)
{
    p->sched_priv = kmem_cache_alloc(dom_info_cache);
    if ( p->sched_priv == NULL )
        return -1;
    
    return 0;
}

/*
 * Add and remove a domain
 */
void fbvt_add_task(struct domain *p) 
{
    struct fbvt_dom_info *inf = FBVT_INFO(p);

    ASSERT(inf != NULL);
    ASSERT(p   != NULL);

    inf->mcu_advance = MCU_ADVANCE;
    if ( p->domain == IDLE_DOMAIN_ID )
    {
        inf->avt = inf->evt = ~0U;
    } 
    else 
    {
        /* Set avt and evt to system virtual time. */
        inf->avt         = CPU_SVT(p->processor);
        inf->evt         = CPU_SVT(p->processor);
        /* Set some default values here. */
		inf->time_slept  = 0;
        inf->warpback    = 0;
        inf->warp        = 0;
        inf->warpl       = 0;
        inf->warpu       = 0;
    }

    return;
}

/**
 * fbvt_free_task - free FBVT private structures for a task
 * @p:             task
 */
void fbvt_free_task(struct domain *p)
{
    ASSERT( p->sched_priv != NULL );
    kmem_cache_free( dom_info_cache, p->sched_priv );
}


void fbvt_wake_up(struct domain *p)
{
    struct fbvt_dom_info *inf = FBVT_INFO(p);
    s32 io_warp;

    ASSERT(inf != NULL);
    

    /* set the BVT parameters */
    if (inf->avt < CPU_SVT(p->processor))
    {
		/*
	  	 *We want IO bound processes to gain
		 *dispatch precedence. It is especially for
		 *device driver domains. Therefore AVT should not be updated
		 *to SVT but to a value marginally smaller.
		 *Since frequently sleeping domains have high time_slept
		 *values, the virtual time can be determined as:
		 *SVT - const * TIME_SLEPT
	 	 */
	
		io_warp = (int)(0.5 * inf->time_slept);
		if(io_warp > 1000) io_warp = 1000;

		ASSERT(inf->time_slept + CPU_SVT(p->processor) > inf->avt + io_warp);
		inf->time_slept += CPU_SVT(p->processor) - inf->avt - io_warp;
        inf->avt = CPU_SVT(p->processor) - io_warp;
    }

    /* deal with warping here */
    inf->warpback  = 1;
    inf->warped    = NOW();
    __calc_evt(inf);
    __add_to_runqueue_head(p);
}

/* 
 * Block the currently-executing domain until a pertinent event occurs.
 */
static void fbvt_do_block(struct domain *p)
{
    FBVT_INFO(p)->warpback = 0; 
}

/* Control the scheduler. */
int fbvt_ctl(struct sched_ctl_cmd *cmd)
{
    struct fbvt_ctl *params = &cmd->u.fbvt;

    if ( cmd->direction == SCHED_INFO_PUT )
    { 
        ctx_allow = params->ctx_allow;
        /* The max_vtb should be of the order o the ctx_allow */
        max_vtb = ctx_allow;
    }
    else
    {
        params->ctx_allow = ctx_allow;
    }
    
    return 0;
}

/* Adjust scheduling parameter for a given domain. */
int fbvt_adjdom(struct domain *p,
               struct sched_adjdom_cmd *cmd)
{
    struct fbvt_adjdom *params = &cmd->u.fbvt;
    unsigned long flags;

    if ( cmd->direction == SCHED_INFO_PUT )
    {
        unsigned long mcu_adv = params->mcu_adv,
            warp  = params->warp,
            warpl = params->warpl,
            warpu = params->warpu;
        
        struct fbvt_dom_info *inf = FBVT_INFO(p);
        
        DPRINTK("Get domain %u fbvt mcu_adv=%ld, warp=%ld, "
                "warpl=%ld, warpu=%ld\n",
                p->domain, inf->mcu_advance, inf->warp,
                inf->warpl, inf->warpu );

        /* Sanity -- this can avoid divide-by-zero. */
        if ( mcu_adv == 0 )
            return -EINVAL;
        
        spin_lock_irqsave(&schedule_lock[p->processor], flags);   
        inf->mcu_advance = mcu_adv;
        inf->warp = warp;
        inf->warpl = warpl;
        inf->warpu = warpu;

        DPRINTK("Set domain %u fbvt mcu_adv=%ld, warp=%ld, "
                "warpl=%ld, warpu=%ld\n",
                p->domain, inf->mcu_advance, inf->warp,
                inf->warpl, inf->warpu );

        spin_unlock_irqrestore(&schedule_lock[p->processor], flags);
    }
    else if ( cmd->direction == SCHED_INFO_GET )
    {
        struct fbvt_dom_info *inf = FBVT_INFO(p);

        spin_lock_irqsave(&schedule_lock[p->processor], flags);   
        params->mcu_adv = inf->mcu_advance;
        params->warp    = inf->warp;
        params->warpl   = inf->warpl;
        params->warpu   = inf->warpu;
        spin_unlock_irqrestore(&schedule_lock[p->processor], flags);
    }
    
    return 0;
}


/* 
 * The main function
 * - deschedule the current domain.
 * - pick a new domain.
 *   i.e., the domain with lowest EVT.
 *   The runqueue should be ordered by EVT so that is easy.
 */
static task_slice_t fbvt_do_schedule(s_time_t now)
{
    struct domain *prev = current, *next = NULL, *next_prime, *p;
    struct list_head   *tmp;
    int                 cpu = prev->processor;
    s32                 r_time;     /* time for new dom to run */
    s32                 ranfor;     /* assume we never run longer than 2.1s! */
    s32                 mcus;
    u32                 next_evt, next_prime_evt, min_avt;
    u32                 sl_decrement;
    struct fbvt_dom_info *prev_inf       = FBVT_INFO(prev),
                        *p_inf          = NULL,
                        *next_inf       = NULL,
                        *next_prime_inf = NULL;
    task_slice_t        ret;

    ASSERT(prev->sched_priv != NULL);
    ASSERT(prev_inf != NULL);

    if ( likely(!is_idle_task(prev)) ) 
    {
        ranfor = (s32)(now - prev->lastschd);
        /* Calculate mcu and update avt. */
        mcus = (ranfor + MCU - 1) / MCU;
        
        TRACE_3D(TRC_SCHED_FBVT_DO_SCHED_UPDATE, prev->domain, mcus, LAST_VTB(cpu));
    
        sl_decrement = mcus * LAST_VTB(cpu) / R_TIME(cpu);
        prev_inf->time_slept -=  sl_decrement;
        prev_inf->avt += mcus * prev_inf->mcu_advance - sl_decrement;
  
        /*if(mcus * prev_inf->mcu_advance < LAST_VTB(cpu))
	    {
	        ASSERT(prev_inf->time_slept >= mcus * prev_inf->mcu_advance);
    	    prev_inf->time_slept -= mcus * prev_inf->mcu_advance;
	    }
	    else
	    {
	        prev_inf->avt += mcus * prev_inf->mcu_advance - LAST_VTB(cpu);
		
	        ASSERT(prev_inf->time_slept >= LAST_VTB(cpu));
	        prev_inf->time_slept -= LAST_VTB(cpu);
 	    }*/
        
        __calc_evt(prev_inf);
        
        __del_from_runqueue(prev);
        
        if ( domain_runnable(prev) )
            __add_to_runqueue_tail(prev);
    }

    /* We should at least have the idle task */
    ASSERT(!list_empty(&schedule_data[cpu].runqueue));

    /*
     * scan through the run queue and pick the task with the lowest evt
     * *and* the task the second lowest evt.
     * this code is O(n) but we expect n to be small.
     */
    next       = schedule_data[cpu].idle;
    next_prime = NULL;

    next_evt       = ~0U;
    next_prime_evt = ~0U;
    min_avt        = ~0U;

    list_for_each ( tmp, &schedule_data[cpu].runqueue )
    {
        p     = list_entry(tmp, struct domain, run_list);
        p_inf = FBVT_INFO(p);

        if ( p_inf->evt < next_evt )
        {
            next_prime     = next;
            next_prime_evt = next_evt;
            next = p;
            next_evt = p_inf->evt;
        } 
        else if ( next_prime_evt == ~0U )
        {
            next_prime_evt = p_inf->evt;
            next_prime     = p;
        } 
        else if ( p_inf->evt < next_prime_evt )
        {
            next_prime_evt = p_inf->evt;
            next_prime     = p;
        }

        /* Determine system virtual time. */
        if ( p_inf->avt < min_avt )
            min_avt = p_inf->avt;
    }

    /* Update system virtual time. */
    if ( min_avt != ~0U )
        CPU_SVT(cpu) = min_avt;

    /* check for virtual time overrun on this cpu */
    if ( CPU_SVT(cpu) >= 0xf0000000 )
    {
        u_long t_flags; 
        write_lock_irqsave(&tasklist_lock, t_flags); 
        for_each_domain ( p )
        {
            if ( p->processor == cpu )
            {
                p_inf = FBVT_INFO(p);
                p_inf->evt -= 0xe0000000;
                p_inf->avt -= 0xe0000000;
            }
        } 
        write_unlock_irqrestore(&tasklist_lock, t_flags); 
        CPU_SVT(cpu) -= 0xe0000000;
    }

    next_prime_inf = FBVT_INFO(next_prime);
    next_inf       = FBVT_INFO(next);
    
    /* check for time_slept overrun for the domain we schedule to run*/
    if(next_inf->time_slept >= 0xf0000000)
    {
        printk("Domain %d is assigned more CPU then it is able to use.\n"
               "FBVT slept_time=%d, halving. Mcu_advance=%ld\n",next->domain, 
               next_inf->time_slept, next_inf->mcu_advance);

        next_inf->time_slept /= 2;
    }


   /*
     * In here we decide on Virtual Time Bonus. The idea is, for the
     * domains that have large time_slept values to be allowed to run
     * for longer. Thus regaining the share of CPU originally allocated.
     * This is acompanied by the warp mechanism (which moves IO-bound
     * domains earlier in virtual time). Together this should give quite
     * good control both for CPU and IO-bound domains.
     */
    LAST_VTB(cpu) = (int)(0.2 * next_inf->time_slept);
    if(LAST_VTB(cpu) / next_inf->mcu_advance > max_vtb / MCU) 
        LAST_VTB(cpu) = max_vtb * next_inf->mcu_advance / MCU;


    /* work out time for next run through scheduler */
    if ( is_idle_task(next) ) 
    {
        r_time = ctx_allow;
        goto sched_done;
    }

    if ( (next_prime == NULL) || is_idle_task(next_prime) )
    {
        /* We have only one runnable task besides the idle task. */
        r_time = 10 * ctx_allow;     /* RN: random constant */
        goto sched_done;
    }

    /*
     * If we are here then we have two runnable tasks.
     * Work out how long 'next' can run till its evt is greater than
     * 'next_prime's evt. Take context switch allowance into account.
     */
    ASSERT(next_prime_inf->evt >= next_inf->evt);
  
    ASSERT(LAST_VTB(cpu) >= 0);

    r_time = MCU * ((next_prime_inf->evt + LAST_VTB(cpu) - next_inf->evt)/next_inf->mcu_advance)
        + ctx_allow;

    ASSERT(r_time >= ctx_allow);

 sched_done:
    R_TIME(cpu) = r_time / MCU;
    TRACE_3D(TRC_SCHED_FBVT_DO_SCHED, next->domain, r_time, LAST_VTB(cpu));
    next->min_slice = ctx_allow;
    ret.task = next;
    ret.time = r_time;
 
    return ret;
}


static void fbvt_dump_runq_el(struct domain *p)
{
    struct fbvt_dom_info *inf = FBVT_INFO(p);
    
    printk("mcua=%04lu ev=%08u av=%08u sl=%08u",
           inf->mcu_advance, inf->evt, inf->avt, inf->time_slept);
}

static void fbvt_dump_settings(void)
{
    printk("FBVT: mcu=0x%08Xns ctx_allow=0x%08Xns ", (u32)MCU, (s32)ctx_allow );
}

static void fbvt_dump_cpu_state(int i)
{
    printk("svt=0x%08lX ", CPU_SVT(i));
}


/* Initialise the data structures. */
int fbvt_init_scheduler()
{
    int i;

    for ( i = 0; i < NR_CPUS; i++ )
    {
        schedule_data[i].sched_priv = kmalloc(sizeof(struct fbvt_cpu_info));
        if ( schedule_data[i].sched_priv == NULL )
        {
            printk("Failed to allocate FBVT scheduler per-CPU memory!\n");
            return -1;
        }

        CPU_SVT(i) = 0; /* XXX do I really need to do this? */
    }

    dom_info_cache = kmem_cache_create("FBVT dom info",
                                       sizeof(struct fbvt_dom_info),
                                       0, 0, NULL, NULL);

    if ( dom_info_cache == NULL )
    {
        printk("FBVT: Failed to allocate domain info SLAB cache");
        return -1;
    }

    return 0;
}

static void fbvt_pause(struct domain *p)
{
    if( __task_on_runqueue(p) )
    {
        __del_from_runqueue(p);
    }
}

static void fbvt_unpause(struct domain *p)
{
	struct fbvt_dom_info *inf = FBVT_INFO(p);

	if ( p->domain == IDLE_DOMAIN_ID )
    {
        inf->avt = inf->evt = ~0U;
    } 
    else 
    {
        /* Set avt to system virtual time. */
        inf->avt         = CPU_SVT(p->processor);
        /* Set some default values here. */
		LAST_VTB(p->processor) = 0;
		__calc_evt(inf);
    }
}

struct scheduler sched_fbvt_def = {
    .name     = "Fair Borrowed Virtual Time",
    .opt_name = "fbvt",
    .sched_id = SCHED_FBVT,
    
    .init_scheduler = fbvt_init_scheduler,
    .alloc_task     = fbvt_alloc_task,
    .add_task       = fbvt_add_task,
    .free_task      = fbvt_free_task,
    .wake_up        = fbvt_wake_up,
    .do_block       = fbvt_do_block,
    .do_schedule    = fbvt_do_schedule,
    .control        = fbvt_ctl,
    .adjdom         = fbvt_adjdom,
    .dump_settings  = fbvt_dump_settings,
    .dump_cpu_state = fbvt_dump_cpu_state,
    .dump_runq_el   = fbvt_dump_runq_el,
    .pause          = fbvt_pause,
    .unpause	    = fbvt_unpause,
};

