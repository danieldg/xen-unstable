/******************************************************************************
 * dom0_ops.h
 * 
 * Process command requests from domain-0 guest OS.
 * 
 * Copyright (c) 2002, K A Fraser, B Dragovic
 * 
 * MUST BE KEPT IN SYNC WITH xenolinux<*>/arch/xeno/drivers/dom0/dom0_ops.h
 */


#ifndef __DOM0_OPS_H__
#define __DOM0_OPS_H__

#define DOM0_NEWDOMAIN   0
#define DOM0_KILLDOMAIN  1
#define DOM0_GETMEMLIST  2
#define DOM0_STARTDOM    4
#define DOM0_BVTCTL      6
#define DOM0_ADJUSTDOM   7

#define MAX_CMD_LEN    256

typedef struct dom0_newdomain_st 
{
    unsigned int domain;    // return parameter
    unsigned int memory_kb; 
    unsigned int num_vifs;  // temporary
    unsigned long pg_head;  // return parameter
} dom0_newdomain_t;

typedef struct dom0_killdomain_st
{
    unsigned int domain;
    int          force;
} dom0_killdomain_t;

typedef struct dom0_getmemlist_st
{
    unsigned long start_pfn;
    unsigned long num_pfns;
    void *buffer;
} dom0_getmemlist_t;

typedef struct domain_launch
{
    unsigned int domain;
    unsigned long l2_pgt_addr;
    unsigned long virt_load_addr;
    unsigned long virt_shinfo_addr;
    unsigned long virt_startinfo_addr;
    unsigned int num_vifs;
    char cmd_line[MAX_CMD_LEN];
    unsigned long virt_mod_addr;
    unsigned long virt_mod_len;
} dom_meminfo_t;

typedef struct dom0_bvtctl_st
{
	unsigned long ctx_allow;	/* context switch allowance */
} dom0_bvtctl_t;

typedef struct dom0_adjustdom_st
{
    unsigned int  domain;	/* domain id */
	unsigned long mcu_adv;	/* mcu advance: inverse of weight */
	unsigned long warp;     /* time warp */
	unsigned long warpl;    /* warp limit */
	unsigned long warpu;    /* unwarp time requirement */
} dom0_adjustdom_t;

typedef struct dom0_op_st
{
    unsigned long cmd;
    union
    {
        dom0_newdomain_t newdomain;
        dom0_killdomain_t killdomain;
        dom0_getmemlist_t getmemlist;
		dom0_bvtctl_t bvtctl;
		dom0_adjustdom_t adjustdom;
        dom_meminfo_t meminfo;
    }
    u;
} dom0_op_t;

#endif
