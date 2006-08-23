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
#include <public/xen.h>
#include <public/dom0_ops.h>

extern void arch_getdomaininfo_ctxt(struct vcpu *v, vcpu_guest_context_t *c);
extern long arch_do_dom0_op(struct dom0_op *op, XEN_GUEST_HANDLE(dom0_op_t) u_dom0_op);

void arch_getdomaininfo_ctxt(struct vcpu *v, vcpu_guest_context_t *c)
{ 
    memcpy(&c->user_regs, &v->arch.ctxt, sizeof(struct cpu_user_regs));
    /* XXX fill in rest of vcpu_guest_context_t */
}

long arch_do_dom0_op(struct dom0_op *op, XEN_GUEST_HANDLE(dom0_op_t) u_dom0_op)
{
    long ret = 0;

    switch (op->cmd) {
    case DOM0_GETMEMLIST:
    {
        int i;
        struct domain *d = find_domain_by_id(op->u.getmemlist.domain);
        unsigned long max_pfns = op->u.getmemlist.max_pfns;
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
                if ( copy_to_guest_offset(op->u.getmemlist.buffer,
                                          i, &mfn, 1) )
                {
                    ret = -EFAULT;
                    break;
                }
                list_ent = mfn_to_page(mfn)->list.next;
            }
            spin_unlock(&d->page_alloc_lock);

            op->u.getmemlist.num_pfns = i;
            copy_to_guest(u_dom0_op, op, 1);
            
            put_domain(d);
        }
    }
    break;

    case DOM0_PHYSINFO:
    {
        dom0_physinfo_t *pi = &op->u.physinfo;

        pi->threads_per_core = 1;
        pi->cores_per_socket = 1;
        pi->sockets_per_node = 1;
        pi->nr_nodes         = 1;
        pi->total_pages      = total_pages;
        pi->free_pages       = avail_domheap_pages();
        pi->cpu_khz          = cpu_khz;
        memset(pi->hw_cap, 0, sizeof(pi->hw_cap));
        ret = 0;
        if ( copy_to_guest(u_dom0_op, op, 1) )
            ret = -EFAULT;
    }
    break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}
