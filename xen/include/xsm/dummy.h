/*
 *  Default XSM hooks - IS_PRIV and IS_PRIV_FOR checks
 *
 *  Author: Daniel De Graaf <dgdegra@tyhco.nsa.gov>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 */

#include <xen/sched.h>
#include <xsm/xsm.h>

static XSM_DEFAULT(void, security_domaininfo)(struct domain *d,
                                    struct xen_domctl_getdomaininfo *info)
{
    return;
}

static XSM_DEFAULT(int, setvcpucontext)(struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(int, pausedomain) (struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(int, unpausedomain) (struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(int, resumedomain) (struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(int, domain_create)(struct domain *d, u32 ssidref)
{
    return 0;
}

static XSM_DEFAULT(int, max_vcpus)(struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(int, destroydomain) (struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(int, vcpuaffinity) (int cmd, struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(int, scheduler) (struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(int, getdomaininfo) (struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(int, getvcpucontext) (struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(int, getvcpuinfo) (struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(int, domain_settime) (struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(int, set_target) (struct domain *d, struct domain *e)
{
    return 0;
}

static XSM_DEFAULT(int, domctl)(struct domain *d, int cmd)
{
    switch ( cmd )
    {
    case XEN_DOMCTL_ioport_mapping:
    case XEN_DOMCTL_memory_mapping:
    case XEN_DOMCTL_bind_pt_irq:
    case XEN_DOMCTL_unbind_pt_irq: {
        if ( !IS_PRIV_FOR(current->domain, d) )
            return -EPERM;
        break;
    }
    default:
        if ( !IS_PRIV(current->domain) )
            return -EPERM;
    }
    return 0;
}

static XSM_DEFAULT(int, sysctl)(int cmd)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, set_virq_handler)(struct domain *d, uint32_t virq)
{
    return 0;
}

static XSM_DEFAULT(int, tbufcontrol) (void)
{
    return 0;
}

static XSM_DEFAULT(int, readconsole) (uint32_t clear)
{
    return 0;
}

static XSM_DEFAULT(int, sched_id) (void)
{
    return 0;
}

static XSM_DEFAULT(int, setdomainmaxmem) (struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(int, setdomainhandle) (struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(int, setdebugging) (struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(int, perfcontrol) (void)
{
    return 0;
}

static XSM_DEFAULT(int, debug_keys) (void)
{
    return 0;
}

static XSM_DEFAULT(int, getcpuinfo) (void)
{
    return 0;
}

static XSM_DEFAULT(int, get_pmstat) (void)
{
    return 0;
}

static XSM_DEFAULT(int, setpminfo) (void)
{
    return 0;
}

static XSM_DEFAULT(int, pm_op) (void)
{
    return 0;
}

static XSM_DEFAULT(int, do_mca) (void)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, availheap) (void)
{
    return 0;
}

static XSM_DEFAULT(int, alloc_security_domain) (struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(void, free_security_domain) (struct domain *d)
{
    return;
}

static XSM_DEFAULT(int, grant_mapref) (struct domain *d1, struct domain *d2,
                                                                uint32_t flags)
{
    return 0;
}

static XSM_DEFAULT(int, grant_unmapref) (struct domain *d1, struct domain *d2)
{
    return 0;
}

static XSM_DEFAULT(int, grant_setup) (struct domain *d1, struct domain *d2)
{
    if ( d1 != d2 && !IS_PRIV_FOR(d1, d2) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, grant_transfer) (struct domain *d1, struct domain *d2)
{
    return 0;
}

static XSM_DEFAULT(int, grant_copy) (struct domain *d1, struct domain *d2)
{
    return 0;
}

static XSM_DEFAULT(int, grant_query_size) (struct domain *d1, struct domain *d2)
{
    if ( d1 != d2 && !IS_PRIV_FOR(d1, d2) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, memory_adjust_reservation) (struct domain *d1,
                                                            struct domain *d2)
{
    if ( d1 != d2 && !IS_PRIV_FOR(d1, d2) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, memory_stat_reservation) (struct domain *d1, struct domain *d2)
{
    if ( d1 != d2 && !IS_PRIV_FOR(d1, d2) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, console_io) (struct domain *d, int cmd)
{
#ifndef VERBOSE
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
#endif
    return 0;
}

static XSM_DEFAULT(int, profile) (struct domain *d, int op)
{
    return 0;
}

static XSM_DEFAULT(int, kexec) (void)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, schedop_shutdown) (struct domain *d1, struct domain *d2)
{
    if ( !IS_PRIV_FOR(d1, d2) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, memory_pin_page) (struct domain *d1, struct domain *d2,
                                          struct page_info *page)
{
    return 0;
}

static XSM_DEFAULT(int, evtchn_unbound) (struct domain *d, struct evtchn *chn,
                                         domid_t id2)
{
    if ( current->domain != d && !IS_PRIV_FOR(current->domain, d) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, evtchn_interdomain) (struct domain *d1, struct evtchn
                                *chan1, struct domain *d2, struct evtchn *chan2)
{
    return 0;
}

static XSM_DEFAULT(void, evtchn_close_post) (struct evtchn *chn)
{
    return;
}

static XSM_DEFAULT(int, evtchn_send) (struct domain *d, struct evtchn *chn)
{
    return 0;
}

static XSM_DEFAULT(int, evtchn_status) (struct domain *d, struct evtchn *chn)
{
    if ( current->domain != d && !IS_PRIV_FOR(current->domain, d) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, evtchn_reset) (struct domain *d1, struct domain *d2)
{
    if ( d1 != d2 && !IS_PRIV_FOR(d1, d2) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, alloc_security_evtchn) (struct evtchn *chn)
{
    return 0;
}

static XSM_DEFAULT(void, free_security_evtchn) (struct evtchn *chn)
{
    return;
}

static XSM_DEFAULT(char *, show_security_evtchn) (struct domain *d, const struct evtchn *chn)
{
    return NULL;
}

static XSM_DEFAULT(int, get_pod_target)(struct domain *d)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, set_pod_target)(struct domain *d)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, get_device_group) (uint32_t machine_bdf)
{
    return 0;
}

static XSM_DEFAULT(int, test_assign_device) (uint32_t machine_bdf)
{
    return 0;
}

static XSM_DEFAULT(int, assign_device) (struct domain *d, uint32_t machine_bdf)
{
    return 0;
}

static XSM_DEFAULT(int, deassign_device) (struct domain *d, uint32_t machine_bdf)
{
    return 0;
}

static XSM_DEFAULT(int, resource_plug_core) (void)
{
    return 0;
}

static XSM_DEFAULT(int, resource_unplug_core) (void)
{
    return 0;
}

static XSM_DEFAULT(int, resource_plug_pci) (uint32_t machine_bdf)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, resource_unplug_pci) (uint32_t machine_bdf)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, resource_setup_pci) (uint32_t machine_bdf)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, resource_setup_gsi) (int gsi)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, resource_setup_misc) (void)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, page_offline) (uint32_t cmd)
{
    return 0;
}

static XSM_DEFAULT(int, lockprof) (void)
{
    return 0;
}

static XSM_DEFAULT(int, cpupool_op) (void)
{
    return 0;
}

static XSM_DEFAULT(int, sched_op) (void)
{
    return 0;
}

static XSM_DEFAULT(long, do_xsm_op)(XEN_GUEST_HANDLE_PARAM(xsm_op_t) op)
{
    return -ENOSYS;
}

static XSM_DEFAULT(char *, show_irq_sid) (int irq)
{
    return NULL;
}

static XSM_DEFAULT(int, map_domain_pirq) (struct domain *d, int irq, void *data)
{
    return 0;
}

static XSM_DEFAULT(int, unmap_domain_pirq) (struct domain *d, int irq)
{
    if ( !IS_PRIV_FOR(current->domain, d) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, irq_permission) (struct domain *d, int pirq, uint8_t allow)
{
    return 0;
}

static XSM_DEFAULT(int, iomem_permission) (struct domain *d, uint64_t s, uint64_t e, uint8_t allow)
{
    return 0;
}

static XSM_DEFAULT(int, iomem_mapping) (struct domain *d, uint64_t s, uint64_t e, uint8_t allow)
{
    return 0;
}

static XSM_DEFAULT(int, pci_config_permission) (struct domain *d, uint32_t machine_bdf,
                                        uint16_t start, uint16_t end,
                                        uint8_t access)
{
    return 0;
}

#ifdef CONFIG_X86
static XSM_DEFAULT(int, shadow_control) (struct domain *d, uint32_t op)
{
    return 0;
}

static XSM_DEFAULT(int, getpageframeinfo) (struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(int, getmemlist) (struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(int, hypercall_init) (struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(int, hvmcontext) (struct domain *d, uint32_t cmd)
{
    return 0;
}

static XSM_DEFAULT(int, address_size) (struct domain *d, uint32_t cmd)
{
    return 0;
}

static XSM_DEFAULT(int, machine_address_size) (struct domain *d, uint32_t cmd)
{
    return 0;
}

static XSM_DEFAULT(int, hvm_param) (struct domain *d, unsigned long op)
{
    if ( current->domain != d && !IS_PRIV_FOR(current->domain, d) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, hvm_set_pci_intx_level) (struct domain *d)
{
    if ( !IS_PRIV_FOR(current->domain, d) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, hvm_set_isa_irq_level) (struct domain *d)
{
    if ( !IS_PRIV_FOR(current->domain, d) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, hvm_set_pci_link_route) (struct domain *d)
{
    if ( !IS_PRIV_FOR(current->domain, d) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, hvm_inject_msi) (struct domain *d)
{
    if ( !IS_PRIV_FOR(current->domain, d) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, mem_event_setup) (struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(int, mem_event_control) (struct domain *d, int mode, int op)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, mem_event_op) (struct domain *d, int op)
{
    if ( !IS_PRIV_FOR(current->domain, d) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, mem_sharing) (struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(int, mem_sharing_op) (struct domain *d, struct domain *cd, int op)
{
    if ( !IS_PRIV_FOR(current->domain, cd) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, apic) (struct domain *d, int cmd)
{
    if ( !IS_PRIV(d) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, xen_settime) (void)
{
    return 0;
}

static XSM_DEFAULT(int, memtype) (uint32_t access)
{
    return 0;
}

static XSM_DEFAULT(int, microcode) (void)
{
    return 0;
}

static XSM_DEFAULT(int, physinfo) (void)
{
    return 0;
}

static XSM_DEFAULT(int, platform_quirk) (uint32_t quirk)
{
    return 0;
}

static XSM_DEFAULT(int, platform_op) (uint32_t op)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, firmware_info) (void)
{
    return 0;
}

static XSM_DEFAULT(int, efi_call) (void)
{
    return 0;
}

static XSM_DEFAULT(int, acpi_sleep) (void)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, change_freq) (void)
{
    return 0;
}

static XSM_DEFAULT(int, getidletime) (void)
{
    return 0;
}

static XSM_DEFAULT(int, machine_memory_map) (void)
{
    if ( !IS_PRIV(current->domain) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, domain_memory_map) (struct domain *d)
{
    if ( current->domain != d && !IS_PRIV_FOR(current->domain, d) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, mmu_normal_update) (struct domain *d, struct domain *t,
                                            struct domain *f, intpte_t fpte)
{
    return 0;
}

static XSM_DEFAULT(int, mmu_machphys_update) (struct domain *d, struct domain *f,
                                              unsigned long mfn)
{
    return 0;
}

static XSM_DEFAULT(int, update_va_mapping) (struct domain *d, struct domain *f, 
                                                            l1_pgentry_t pte)
{
    return 0;
}

static XSM_DEFAULT(int, add_to_physmap) (struct domain *d1, struct domain *d2)
{
    if ( d1 != d2 && !IS_PRIV_FOR(d1, d2) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, remove_from_physmap) (struct domain *d1, struct domain *d2)
{
    if ( d1 != d2 && !IS_PRIV_FOR(d1, d2) )
        return -EPERM;
    return 0;
}

static XSM_DEFAULT(int, sendtrigger) (struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(int, bind_pt_irq) (struct domain *d, struct xen_domctl_bind_pt_irq *bind)
{
    return 0;
}

static XSM_DEFAULT(int, unbind_pt_irq) (struct domain *d, struct xen_domctl_bind_pt_irq *bind)
{
    return 0;
}

static XSM_DEFAULT(int, pin_mem_cacheattr) (struct domain *d)
{
    return 0;
}

static XSM_DEFAULT(int, ext_vcpucontext) (struct domain *d, uint32_t cmd)
{
    return 0;
}

static XSM_DEFAULT(int, vcpuextstate) (struct domain *d, uint32_t cmd)
{
    return 0;
}

static XSM_DEFAULT(int, ioport_permission) (struct domain *d, uint32_t s, uint32_t e, uint8_t allow)
{
    return 0;
}

static XSM_DEFAULT(int, ioport_mapping) (struct domain *d, uint32_t s, uint32_t e, uint8_t allow)
{
    return 0;
}

#endif
