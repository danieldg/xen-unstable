/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2002 - Rolf Neugebauer - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: time.h
 *      Author: Rolf Neugebauer (neugebar@dcs.gla.ac.uk)
 *     Changes: 
 *              
 *        Date: Nov 2002
 * 
 * Environment: Xen Hypervisor
 * Description: This file provides a one stop shop for all time related
 *              issues within the hypervisor. 
 * 
 *              The Hypervisor provides the following notions of time:
 *              Cycle Counter Time, System Time, Wall Clock Time, and 
 *              Domain Virtual Time.
 *
 ****************************************************************************
 * $Id: h-insert.h,v 1.4 2002/11/08 16:03:55 rn Exp $
 ****************************************************************************
 */



#ifndef __XEN_TIME_H__
#define __XEN_TIME_H__

#include <xen/types.h>
#include <hypervisor-ifs/hypervisor-if.h>

extern int init_xen_time();

extern unsigned long cpu_khz;

/*
 * System Time
 * 64 bit value containing the nanoseconds elapsed since boot time.
 * This value is adjusted by frequency drift.
 * NOW() returns the current time.
 * The other macros are for convenience to approximate short intervals
 * of real time into system time 
 */

typedef s64 s_time_t;

s_time_t get_s_time(void);

#define NOW()           ((s_time_t)get_s_time())
#define SECONDS(_s)     (((s_time_t)(_s))  * 1000000000ULL )
#define MILLISECS(_ms)  (((s_time_t)(_ms)) * 1000000ULL )
#define MICROSECS(_us)  (((s_time_t)(_us)) * 1000ULL )

extern void update_dom_time(shared_info_t *si);
extern void do_settime(unsigned long secs, unsigned long usecs, 
                       u64 system_time_base);

#endif /* __XEN_TIME_H__ */
