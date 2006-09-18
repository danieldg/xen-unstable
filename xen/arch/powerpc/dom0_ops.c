/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/guest_access.h>
#include <xen/shadow.h>
#include <public/xen.h>
#include <public/domctl.h>
#include <public/sysctl.h>
#include <asm/processor.h>

void arch_getdomaininfo_ctxt(struct vcpu *, vcpu_guest_context_t *);
void arch_getdomaininfo_ctxt(struct vcpu *v, vcpu_guest_context_t *c)
{ 
    memcpy(&c->user_regs, &v->arch.ctxt, sizeof(struct cpu_user_regs));
    /* XXX fill in rest of vcpu_guest_context_t */
}

long arch_do_domctl(struct xen_domctl *domctl,
                    XEN_GUEST_HANDLE(xen_domctl_t) u_domctl);
long arch_do_domctl(struct xen_domctl *domctl,
                    XEN_GUEST_HANDLE(xen_domctl_t) u_domctl)
{
    long ret = 0;

    switch (domctl->cmd) {
    case XEN_DOMCTL_getmemlist:
    {
        int i;
        struct domain *d = find_domain_by_id(domctl->domain);
        unsigned long max_pfns = domctl->u.getmemlist.max_pfns;
        xen_pfn_t mfn;
        struct list_head *list_ent;

        ret = -EINVAL;
        if ( d != NULL )
        {
            ret = 0;

            spin_lock(&d->page_alloc_lock);
            list_ent = d->page_list.next;
            for ( i = 0; (i < max_pfns) && (list_ent != &d->page_list); i++ )
            {
                mfn = page_to_mfn(list_entry(
                    list_ent, struct page_info, list));
                if ( copy_to_guest_offset(domctl->u.getmemlist.buffer,
                                          i, &mfn, 1) )
                {
                    ret = -EFAULT;
                    break;
                }
                list_ent = mfn_to_page(mfn)->list.next;
            }
            spin_unlock(&d->page_alloc_lock);

            domctl->u.getmemlist.num_pfns = i;
            copy_to_guest(u_domctl, domctl, 1);
            
            put_domain(d);
        }
    }
    break;
    case XEN_DOMCTL_shadow_op:
    {
        struct domain *d;
        ret = -ESRCH;
        d = find_domain_by_id(domctl->domain);
        if ( d != NULL )
        {
            ret = shadow_domctl(d, &domctl->u.shadow_op, u_domctl);
            put_domain(d);
            copy_to_guest(u_domctl, domctl, 1);
        } 
    }
    break;
    case XEN_DOMCTL_real_mode_area:
    {
        struct domain *d;
        unsigned int log = domctl->u.real_mode_area.log;

        d = find_domain_by_id(domctl->domain);
        if (d == NULL)
            return -ESRCH;

        if (!cpu_rma_valid(log))
            return -EINVAL;

        ret = allocate_rma(d, log - PAGE_SHIFT);
        put_domain(d);
    }
    break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

long arch_do_sysctl(struct xen_sysctl *sysctl,
                    XEN_GUEST_HANDLE(xen_sysctl_t) u_sysctl);
long arch_do_sysctl(struct xen_sysctl *sysctl,
                    XEN_GUEST_HANDLE(xen_sysctl_t) u_sysctl)
{
    long ret = 0;

    switch (sysctl->cmd) {
    case XEN_SYSCTL_physinfo:
    {
        xen_sysctl_physinfo_t *pi = &sysctl->u.physinfo;

        pi->threads_per_core = 1;
        pi->cores_per_socket = 1;
        pi->sockets_per_node = 1;
        pi->nr_nodes         = 1;
        pi->total_pages      = total_pages;
        pi->free_pages       = avail_domheap_pages();
        pi->cpu_khz          = cpu_khz;
        memset(pi->hw_cap, 0, sizeof(pi->hw_cap));
        ret = 0;
        if ( copy_to_guest(u_sysctl, sysctl, 1) )
            ret = -EFAULT;
    }
    break;

    default:
        printk("%s: unsupported sysctl: 0x%x\n", __func__, (sysctl->cmd));
        ret = -ENOSYS;
        break;
    }

    return ret;
}

