/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2002 - Rolf Neugebauer - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: i386/time.c
 *      Author: 
 *     Changes: 
 *              
 *        Date: Jan 2003
 * 
 * Environment: Xen Hypervisor
 * Description: modified version of Linux' time.c
 *              implements system and wall clock time.
 *              based on freebsd's implementation.
 *
 ****************************************************************************
 * $Id: c-insert.c,v 1.7 2002/11/08 16:04:34 rn Exp $
 ****************************************************************************
 */

/*
 *  linux/arch/i386/kernel/time.c
 *
 *  Copyright (C) 1991, 1992, 1995  Linus Torvalds
 */

#include <xeno/errno.h>
#include <xeno/sched.h>
#include <xeno/lib.h>
#include <xeno/config.h>
#include <xeno/init.h>
#include <xeno/interrupt.h>
#include <xeno/time.h>
#include <xeno/ac_timer.h>

#include <asm/io.h>
#include <xeno/smp.h>
#include <xeno/irq.h>
#include <asm/msr.h>
#include <asm/mpspec.h>
#include <asm/processor.h>
#include <asm/fixmap.h>
#include <asm/mc146818rtc.h>

#ifdef TIME_TRACE
#define TRC(_x) _x
#else
#define TRC(_x)
#endif

unsigned long cpu_khz;  /* Detected as we calibrate the TSC */
unsigned long ticks_per_usec; /* TSC ticks per microsecond. */

/* We use this to prevent overflow of 31-bit RDTSC "diffs". */
static unsigned int rdtsc_bitshift;

spinlock_t rtc_lock = SPIN_LOCK_UNLOCKED;

int timer_ack=0;
extern spinlock_t i8259A_lock;
static inline void do_timer_interrupt(int irq, 
                                      void *dev_id, struct pt_regs *regs)
{
#ifdef CONFIG_X86_IO_APIC
    if (timer_ack) {
        /*
         * Subtle, when I/O APICs are used we have to ack timer IRQ manually 
         * to reset the IRR bit for do_slow_gettimeoffset(). This will also 
         * deassert NMI lines for the watchdog if run on an 82489DX-based 
         * system.
         */
        spin_lock(&i8259A_lock);
        outb(0x0c, 0x20);
        /* Ack the IRQ; AEOI will end it automatically. */
        inb(0x20);
        spin_unlock(&i8259A_lock);
    }
#endif
    do_timer(regs);
}

/*
 * This is only temporarily. Once the APIC s up and running this 
 * timer interrupt is turned off.
 */
static void timer_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
    do_timer_interrupt(irq, NULL, regs);
}

static struct irqaction irq0  = { timer_interrupt, SA_INTERRUPT, 0,
                                  "timer", NULL, NULL};

/* ------ Calibrate the TSC ------- 
 * Return processor ticks per second / CALIBRATE_FRAC.
 */

#define CLOCK_TICK_RATE 1193180 /* system crystal frequency (Hz) */
#define CALIBRATE_FRAC  20      /* calibrate over 50ms */
#define CALIBRATE_LATCH ((CLOCK_TICK_RATE+(CALIBRATE_FRAC/2))/CALIBRATE_FRAC)

static unsigned long __init calibrate_tsc(void)
{
    /* Set the Gate high, disable speaker */
    outb((inb(0x61) & ~0x02) | 0x01, 0x61);

    /*
     * Now let's take care of CTC channel 2
     *
     * Set the Gate high, program CTC channel 2 for mode 0, (interrupt on
     * terminal count mode), binary count, load 5 * LATCH count, (LSB and MSB)
     * to begin countdown.
     */
    outb(0xb0, 0x43);           /* binary, mode 0, LSB/MSB, Ch 2 */
    outb(CALIBRATE_LATCH & 0xff, 0x42); /* LSB of count */
    outb(CALIBRATE_LATCH >> 8, 0x42);   /* MSB of count */

    {
        unsigned long startlow, starthigh;
        unsigned long endlow, endhigh;
        unsigned long count;

        rdtsc(startlow,starthigh);
        count = 0;
        do {
            count++;
        } while ((inb(0x61) & 0x20) == 0);
        rdtsc(endlow,endhigh);

        /* Error: ECTCNEVERSET */
        if (count <= 1)
            goto bad_ctc;

        /* 64-bit subtract - gcc just messes up with long longs */
        __asm__("subl %2,%0\n\t"
                "sbbl %3,%1"
                :"=a" (endlow), "=d" (endhigh)
                :"g" (startlow), "g" (starthigh),
                "0" (endlow), "1" (endhigh));

        /* Error: ECPUTOOFAST */
        if (endhigh)
            goto bad_ctc;

        return endlow;
    }

    /*
     * The CTC wasn't reliable: we got a hit on the very first read, or the CPU
     * was so fast/slow that the quotient wouldn't fit in 32 bits..
     */
 bad_ctc:
    return 0;
}

/***************************************************************************
 * CMOS Timer functions
 ***************************************************************************/

/* Converts Gregorian date to seconds since 1970-01-01 00:00:00.
 * Assumes input in normal date format, i.e. 1980-12-31 23:59:59
 * => year=1980, mon=12, day=31, hour=23, min=59, sec=59.
 *
 * [For the Julian calendar (which was used in Russia before 1917,
 * Britain & colonies before 1752, anywhere else before 1582,
 * and is still in use by some communities) leave out the
 * -year/100+year/400 terms, and add 10.]
 *
 * This algorithm was first published by Gauss (I think).
 *
 * WARNING: this function will overflow on 2106-02-07 06:28:16 on
 * machines were long is 32-bit! (However, as time_t is signed, we
 * will already get problems at other places on 2038-01-19 03:14:08)
 */
static inline unsigned long
mktime (unsigned int year, unsigned int mon,
        unsigned int day, unsigned int hour,
        unsigned int min, unsigned int sec)
{
    if (0 >= (int) (mon -= 2)) {   /* 1..12 -> 11,12,1..10 */
        mon += 12;                 /* Puts Feb last since it has leap day */
        year -= 1;
    }
    return ((((unsigned long)(year/4 - year/100 + year/400 + 367*mon/12 + day)+
              year*365 - 719499
        )*24 + hour /* now have hours */
        )*60 + min /* now have minutes */
        )*60 + sec; /* finally seconds */
}

static unsigned long __get_cmos_time(void)
{
    unsigned int year, mon, day, hour, min, sec;
    /* Linux waits here for a the Update-In-Progress (UIP) flag going
     * from 1 to 0. This can take up to a second. This is not acceptable
     * for the use in Xen and this code is therfor removed at the cost
     * of reduced accuracy. */
    sec = CMOS_READ(RTC_SECONDS);
    min = CMOS_READ(RTC_MINUTES);
    hour = CMOS_READ(RTC_HOURS);
    day = CMOS_READ(RTC_DAY_OF_MONTH);
    mon = CMOS_READ(RTC_MONTH);
    year = CMOS_READ(RTC_YEAR);
    
    if (!(CMOS_READ(RTC_CONTROL) & RTC_DM_BINARY) || RTC_ALWAYS_BCD)
    {
        BCD_TO_BIN(sec);
        BCD_TO_BIN(min);
        BCD_TO_BIN(hour);
        BCD_TO_BIN(day);
        BCD_TO_BIN(mon);
        BCD_TO_BIN(year);
    }

    if ((year += 1900) < 1970)
        year += 100;

    return mktime(year, mon, day, hour, min, sec);
}

/* This version is fast: it bails if there's an update in progress. */
static unsigned long maybe_get_cmos_time(void)
{
    unsigned long ct, retval = 0, flags;

    spin_lock_irqsave(&rtc_lock, flags);

    if ( (CMOS_READ(RTC_FREQ_SELECT) & RTC_UIP) )
        goto out;

    ct = __get_cmos_time();

    if ( !(CMOS_READ(RTC_FREQ_SELECT) & RTC_UIP) )
        retval = ct;
    
 out:
    spin_unlock_irqrestore(&rtc_lock, flags);
    return retval;
}

/* the more accurate version waits for a change */
static unsigned long get_cmos_time(void)
{
    unsigned long res, flags;
    int i;

    spin_lock_irqsave(&rtc_lock, flags);
    /* The Linux interpretation of the CMOS clock register contents:
     * When the Update-In-Progress (UIP) flag goes from 1 to 0, the
     * RTC registers show the second which has precisely just started.
     * Let's hope other operating systems interpret the RTC the same way.
     */
    /* read RTC exactly on falling edge of update flag */
    for (i = 0 ; i < 1000000 ; i++) /* may take up to 1 second... */
        if (CMOS_READ(RTC_FREQ_SELECT) & RTC_UIP)
            break;
    for (i = 0 ; i < 1000000 ; i++) /* must try at least 2.228 ms */
        if (!(CMOS_READ(RTC_FREQ_SELECT) & RTC_UIP))
            break;
    res = __get_cmos_time();
    spin_unlock_irqrestore(&rtc_lock, flags);
    return res;
}

/***************************************************************************
 * Time
 * XXX RN: Will be able to remove some of the locking once the time is
 * update by the APIC on only one CPU. 
 ***************************************************************************/

static spinlock_t stime_lock;
static u32  st_scale_f;
static u32  st_scale_i;
u32         stime_pcc;   /* cycle counter value at last timer irq */
s_time_t    stime_now;   /* time in ns at last timer IRQ */

static inline s_time_t __get_s_time(void)
{
    s32      delta_tsc;
    u32      low;
    u64      delta, tsc;
    
    rdtscll(tsc);
    low = (u32)(tsc >> rdtsc_bitshift);
    delta_tsc = (s32)(low - stime_pcc);
    if ( unlikely(delta_tsc < 0) ) delta_tsc = 0;
    delta = ((u64)delta_tsc * st_scale_f);
    delta >>= 32;
    delta += ((u64)delta_tsc * st_scale_i);

    return stime_now + delta;
}

s_time_t get_s_time(void)
{
    s_time_t now;
    unsigned long flags;
    spin_lock_irqsave(&stime_lock, flags);
    now = __get_s_time();
    spin_unlock_irqrestore(&stime_lock, flags);
    return now; 
}


/* Wall Clock time */
struct timeval    wall_clock_time; /* wall clock time at last update */
s_time_t          wctime_st;       /* system time at last update */

void do_gettimeofday(struct timeval *tv)
{
    unsigned long flags;
    unsigned long usec, sec;

    spin_lock_irqsave(&stime_lock, flags);
    usec = ((unsigned long)(__get_s_time() - wctime_st))/1000;
    sec = wall_clock_time.tv_sec;
    usec += wall_clock_time.tv_usec;
    spin_unlock_irqrestore(&stime_lock, flags);

    while (usec >= 1000000) {
        usec -= 1000000;
        sec++;
    }
    tv->tv_sec = sec;
    tv->tv_usec = usec;
}

void do_settimeofday(struct timeval *tv)
{
    printk("XXX: do_settimeofday not implemented\n");
}

/***************************************************************************
 * Update times
 ***************************************************************************/

/* update a domains notion of time */
void update_dom_time(shared_info_t *si)
{
    unsigned long flags;

    spin_lock_irqsave(&stime_lock, flags);
    si->cpu_freq       = cpu_freq;
    si->rdtsc_bitshift = rdtsc_bitshift;
    si->system_time    = stime_now;
    si->st_timestamp   = stime_pcc;
    si->tv_sec         = wall_clock_time.tv_sec;
    si->tv_usec        = wall_clock_time.tv_usec;
    si->wc_timestamp   = wctime_st;
    si->wc_version++;
    spin_unlock_irqrestore(&stime_lock, flags);

    TRC(printk(" 0x%08X%08X\n", (u32)(wctime_st>>32), (u32)wctime_st));
}

/*
 * VERY crude way to keep system time from drfiting.
 * Update the scaling factor using the RTC
 * This is done periodically of it's own timer
 * We maintain an array of cpu frequencies.
 * - index 0 -> go slower
 * - index 1 -> frequency as determined during calibration
 * - index 2 -> go faster
 */
/*
 * NB. The period is not a whole number of seconds since we want to avoid
 * being in sync with the CMOS update-in-progress flag, which causes this
 * routine to bail.
 */
/*
 * NB2. Note that update_scale is called from update_time with the stime_lock
 * still held. This is because we must only slow down cpu_freq at a timebase
 * change. If we did it in the middle of an update period then time would
 * seem to jump backwards since BASE+OLD_FREQ*DIFF > BASE+NEW_FREQ*DIFF.
 */
#define SCALE_UPDATE_PERIOD   MILLISECS(50200)
static unsigned long   init_cmos_time;
static u64             cpu_freqs[3];
static void update_scale(void)
{
    unsigned long  cmos_time;
    u32            st, ct;
    s32            dt;
    u64            scale;
    int            freq_index;

    if ( (cmos_time = maybe_get_cmos_time()) == 0 )
        return;

    ct = (u32)(cmos_time - init_cmos_time);
    st = (u32)(stime_now/SECONDS(1));
    dt = (s32)(ct - st);

    /* work out adjustment to scaling factor. allow +/- 1s drift */
    if (dt < -1) freq_index = 0;       /* go slower */
    else if (dt > 1) freq_index = 2;   /* go faster */
    else freq_index = 1;               /* correct speed */

    if ((dt <= -10) || (dt >= 10))
        printk("Large time drift (cmos time - system time = %ds)\n", dt);

    /* set new frequency  */
    cpu_freq = cpu_freqs[freq_index];

    /* adjust scaling factor */
    scale = 1000000000LL << (32 + rdtsc_bitshift);
    scale /= cpu_freq;
    st_scale_f = scale & 0xffffffff;
    st_scale_i = scale >> 32;
}


/*
 * Update hypervisors notion of time
 * This is done periodically of it's own timer
 */
#define TIME_UPDATE_PERIOD    MILLISECS(200)
static struct ac_timer update_timer;
static void update_time(unsigned long foo)
{
    unsigned long  flags;
    s_time_t       new_st;
    unsigned long  usec;
    u64            full_pcc;
    static int     calls_since_scale_update = 0;

    spin_lock_irqsave(&stime_lock, flags);

    /* Update system time. */
    stime_now = new_st = __get_s_time();
    rdtscll(full_pcc);
    stime_pcc = (u32)(full_pcc >> rdtsc_bitshift);

    /* Update wall clock time. */
    usec = ((unsigned long)(new_st - wctime_st))/1000;
    usec += wall_clock_time.tv_usec;
    while (usec >= 1000000) {
        usec -= 1000000;
        wall_clock_time.tv_sec++;
    }
    wall_clock_time.tv_usec = usec;
    wctime_st = new_st;

    /* Maybe update our rate to be in sync with the RTC. */
    if ( ++calls_since_scale_update >= 
         (SCALE_UPDATE_PERIOD/TIME_UPDATE_PERIOD) )
    {
        update_scale();
        calls_since_scale_update = 0;
    }

    spin_unlock_irqrestore(&stime_lock, flags);

    TRC(printk("TIME[%02d] update time: stime_now=%lld now=%lld,wct=%ld:%ld\n",
               smp_processor_id(), stime_now, new_st, wall_clock_time.tv_sec,
               wall_clock_time.tv_usec));

    /* Reload the timer. */
    update_timer.expires = new_st + TIME_UPDATE_PERIOD;
    add_ac_timer(&update_timer);
}


/***************************************************************************
 * Init Xeno Time
 * This has to be done after all CPUs have been booted
 ***************************************************************************/
int __init init_xeno_time()
{
    int      cpu = smp_processor_id();
    u32      cpu_cycle;  /* time of one cpu cyle in pico-seconds */
    u64      scale;      /* scale factor */
    s64      freq_off;
    u64      full_pcc;
    unsigned int cpu_ghz;

    spin_lock_init(&stime_lock);

    cpu_ghz = (unsigned int)(cpu_freq / 1000000000ULL);
    for ( rdtsc_bitshift = 0; cpu_ghz != 0; rdtsc_bitshift++, cpu_ghz >>= 1 )
        continue;

    printk("Init Time[%02d]: %u\n", cpu, rdtsc_bitshift);

    /* System Time */
    cpu_cycle   = (u32) (1000000000LL/cpu_khz); /* in pico seconds */

    /* calculate adjusted frequencies */
    freq_off  = cpu_freq/1000; /* .1%  */
    cpu_freqs[0] = cpu_freq + freq_off;
    cpu_freqs[1] = cpu_freq;
    cpu_freqs[2] = cpu_freq - freq_off;

    scale = 1000000000LL << (32 + rdtsc_bitshift);
    scale /= cpu_freq;
    st_scale_f = scale & 0xffffffff;
    st_scale_i = scale >> 32;

    /* Wall Clock time */
    wall_clock_time.tv_sec  = get_cmos_time();
    wall_clock_time.tv_usec = 0;

    /* init cmos_time for synchronising */
    init_cmos_time = wall_clock_time.tv_sec;

    /* set starting times */
    stime_now = (s_time_t)0;
    rdtscll(full_pcc);
    stime_pcc = (u32)(full_pcc >> rdtsc_bitshift);
    wctime_st = NOW();

    /* start timer to update time periodically */
    init_ac_timer(&update_timer, 0);
    update_timer.data = 1;
    update_timer.function = &update_time;
    update_time(0);
 
    printk(".... System Time: %lldns\n",   NOW());
    printk(".....cpu_freq:    %08X%08X\n", (u32)(cpu_freq>>32), (u32)cpu_freq);
    printk(".....cpu_cycle:   %u ps\n",    cpu_cycle);
    printk(".....scale:       %08X%08X\n", (u32)(scale>>32), (u32)scale);
    printk(".... st_scale_f:  %X\n",       st_scale_f);
    printk(".... st_scale_i:  %X\n",       st_scale_i);
    printk(".... stime_pcc:   %u\n",       stime_pcc);

    printk(".... Wall Clock:  %lds %ldus\n", wall_clock_time.tv_sec,
           wall_clock_time.tv_usec);
    printk(".... wctime_st:   %lld\n", wctime_st);

    return 0;
}


/***************************************************************************
 * Init
 ***************************************************************************/

void __init time_init(void)
{
    unsigned long ticks_per_frac = calibrate_tsc();

    if ( !ticks_per_frac )
        panic("Error calibrating TSC\n");

    ticks_per_usec = ticks_per_frac / (1000000/CALIBRATE_FRAC);
    cpu_khz = ticks_per_frac / (1000/CALIBRATE_FRAC);

    printk("Detected %lu.%03lu MHz processor.\n", 
           cpu_khz / 1000, cpu_khz % 1000);

    setup_irq(0, &irq0);
}
