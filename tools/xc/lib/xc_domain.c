/******************************************************************************
 * xc_domain.c
 * 
 * API for manipulating and obtaining information on domains.
 * 
 * Copyright (c) 2003, K A Fraser.
 */

#include "xc_private.h"

int xc_domain_create(int xc_handle,
                     unsigned int mem_kb, 
                     const char *name,
                     u64 *pdomid)
{
    int err;
    dom0_op_t op;

    op.cmd = DOM0_CREATEDOMAIN;
    op.u.createdomain.memory_kb = mem_kb;
    strncpy(op.u.createdomain.name, name, MAX_DOMAIN_NAME);
    op.u.createdomain.name[MAX_DOMAIN_NAME-1] = '\0';

    if ( (err = do_dom0_op(xc_handle, &op)) == 0 )
        *pdomid = (u64)op.u.createdomain.domain;

    return err;
}    


int xc_domain_start(int xc_handle,
                    u64 domid)
{
    dom0_op_t op;
    op.cmd = DOM0_STARTDOMAIN;
    op.u.startdomain.domain = (domid_t)domid;
    return do_dom0_op(xc_handle, &op);
}    


int xc_domain_stop(int xc_handle, 
                   u64 domid)
{
    dom0_op_t op;
    op.cmd = DOM0_STOPDOMAIN;
    op.u.stopdomain.domain = (domid_t)domid;
    return do_dom0_op(xc_handle, &op);
}    


int xc_domain_destroy(int xc_handle,
                      u64 domid, 
                      int force)
{
    dom0_op_t op;
    op.cmd = DOM0_DESTROYDOMAIN;
    op.u.destroydomain.domain = (domid_t)domid;
    op.u.destroydomain.force  = !!force;
    return do_dom0_op(xc_handle, &op);
}

int xc_domain_pincpu(int xc_handle,
                     u64 domid, 
                     int cpu)
{
    dom0_op_t op;
    op.cmd = DOM0_PINCPUDOMAIN;
    op.u.pincpudomain.domain = (domid_t)domid;
    op.u.pincpudomain.cpu  = cpu;
    return do_dom0_op(xc_handle, &op);
}


int xc_domain_getinfo(int xc_handle,
                      u64 first_domid,
                      unsigned int max_doms,
                      xc_dominfo_t *info)
{
    unsigned int nr_doms;
    u64 next_domid = first_domid;
    dom0_op_t op;

    for ( nr_doms = 0; nr_doms < max_doms; nr_doms++ )
    {
        op.cmd = DOM0_GETDOMAININFO;
        op.u.getdomaininfo.domain = (domid_t)next_domid;
        if ( do_dom0_op(xc_handle, &op) < 0 )
            break;
        info->domid   = (u64)op.u.getdomaininfo.domain;
        info->cpu     = op.u.getdomaininfo.processor;
        info->has_cpu = op.u.getdomaininfo.has_cpu;
        info->stopped = (op.u.getdomaininfo.state == DOMSTATE_STOPPED);
        info->nr_pages = op.u.getdomaininfo.tot_pages;
        info->shared_info_frame = op.u.getdomaininfo.shared_info_frame;
        info->cpu_time = op.u.getdomaininfo.cpu_time;
        strncpy(info->name, op.u.getdomaininfo.name, XC_DOMINFO_MAXNAME);
        info->name[XC_DOMINFO_MAXNAME-1] = '\0';

        next_domid = (u64)op.u.getdomaininfo.domain + 1;
        info++;
    }

    return nr_doms;
}
