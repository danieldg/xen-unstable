/*
 *  This file contains the XSM hook definitions for Xen.
 *
 *  This work is based on the LSM implementation in Linux 2.6.13.4.
 *
 *  Author:  George Coker, <gscoker@alpha.ncsc.mil>
 *
 *  Contributors: Michael LeMay, <mdlemay@epoch.ncsc.mil>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 */

#ifndef __XSM_H__
#define __XSM_H__

#include <xen/sched.h>
#include <xen/multiboot.h>

typedef void xsm_op_t;
DEFINE_XEN_GUEST_HANDLE(xsm_op_t);

/* policy magic number (defined by XSM_MAGIC) */
typedef u32 xsm_magic_t;
#ifndef XSM_MAGIC
#define XSM_MAGIC 0x00000000
#endif

extern char *policy_buffer;
extern u32 policy_size;

typedef int (*xsm_initcall_t)(void);

extern xsm_initcall_t __xsm_initcall_start[], __xsm_initcall_end[];

#define xsm_initcall(fn) \
    static xsm_initcall_t __initcall_##fn \
    __used_section(".xsm_initcall.init") = fn

struct xsm_operations {
    void (*populate_security_domaininfo) (struct domain *d,
                                        struct xen_domctl_getdomaininfo *info);
    int (*hook_domain_create) (struct domain *d, u32 ssidref);
    int (*hook_getdomaininfo) (struct domain *d);
    int (*hook_set_target) (struct domain *d, struct domain *e);
    int (*domctl) (struct domain *d, int cmd);
    int (*sysctl) (int cmd);
    int (*hook_readconsole) (uint32_t clear);
    int (*priv_do_mca) (void);

    int (*target_evtchn_unbound) (struct domain *d, struct evtchn *chn, domid_t id2);
    int (*hook_evtchn_interdomain) (struct domain *d1, struct evtchn *chn1,
                                        struct domain *d2, struct evtchn *chn2);
    void (*hook_evtchn_close_post) (struct evtchn *chn);
    int (*hook_evtchn_send) (struct domain *d, struct evtchn *chn);
    int (*target_evtchn_status) (struct domain *d, struct evtchn *chn);
    int (*target_evtchn_reset) (struct domain *d1, struct domain *d2);

    int (*hook_grant_mapref) (struct domain *d1, struct domain *d2, uint32_t flags);
    int (*hook_grant_unmapref) (struct domain *d1, struct domain *d2);
    int (*target_grant_setup) (struct domain *d1, struct domain *d2);
    int (*hook_grant_transfer) (struct domain *d1, struct domain *d2);
    int (*hook_grant_copy) (struct domain *d1, struct domain *d2);
    int (*target_grant_query_size) (struct domain *d1, struct domain *d2);

    int (*alloc_security_domain) (struct domain *d);
    void (*free_security_domain) (struct domain *d);
    int (*alloc_security_evtchn) (struct evtchn *chn);
    void (*free_security_evtchn) (struct evtchn *chn);
    char *(*show_security_evtchn) (struct domain *d, const struct evtchn *chn);

    int (*priv_get_pod_target) (struct domain *d);
    int (*priv_set_pod_target) (struct domain *d);
    int (*target_memory_exchange) (struct domain *d);
    int (*target_memory_adjust_reservation) (struct domain *d1, struct domain *d2);
    int (*target_memory_stat_reservation) (struct domain *d1, struct domain *d2);
    int (*hook_memory_pin_page) (struct domain *d1, struct domain *d2, struct page_info *page);
    int (*target_remove_from_physmap) (struct domain *d1, struct domain *d2);

    int (*priv_console_io) (struct domain *d, int cmd);

    int (*hook_profile) (struct domain *d, int op);

    int (*priv_kexec) (void);
    int (*dm_schedop_shutdown) (struct domain *d1, struct domain *d2);

    char *(*show_irq_sid) (int irq);
    int (*hook_map_domain_pirq) (struct domain *d, int irq, void *data);
    int (*dm_unmap_domain_pirq) (struct domain *d, int irq);
    int (*hook_irq_permission) (struct domain *d, int pirq, uint8_t allow);
    int (*hook_iomem_permission) (struct domain *d, uint64_t s, uint64_t e, uint8_t allow);
    int (*hook_iomem_mapping) (struct domain *d, uint64_t s, uint64_t e, uint8_t allow);
    int (*hook_pci_config_permission) (struct domain *d, uint32_t machine_bdf, uint16_t start, uint16_t end, uint8_t access);

    int (*hook_get_device_group) (uint32_t machine_bdf);
    int (*hook_test_assign_device) (uint32_t machine_bdf);
    int (*hook_assign_device) (struct domain *d, uint32_t machine_bdf);
    int (*hook_deassign_device) (struct domain *d, uint32_t machine_bdf);

    int (*hook_resource_plug_core) (void);
    int (*hook_resource_unplug_core) (void);
    int (*priv_resource_plug_pci) (uint32_t machine_bdf);
    int (*priv_resource_unplug_pci) (uint32_t machine_bdf);
    int (*priv_resource_setup_pci) (uint32_t machine_bdf);
    int (*priv_resource_setup_gsi) (int gsi);
    int (*priv_resource_setup_misc) (void);

    int (*hook_page_offline)(uint32_t cmd);
    int (*hook_tmem_op)(void);
    int (*priv_tmem_control)(void);

    long (*do_xsm_op) (XEN_GUEST_HANDLE_PARAM(xsm_op_t) op);

#ifdef CONFIG_X86
    int (*hook_shadow_control) (struct domain *d, uint32_t op);
    int (*target_hvm_param) (struct domain *d, unsigned long op);
    int (*dm_hvm_set_pci_intx_level) (struct domain *d);
    int (*dm_hvm_set_isa_irq_level) (struct domain *d);
    int (*dm_hvm_set_pci_link_route) (struct domain *d);
    int (*dm_hvm_inject_msi) (struct domain *d);
    int (*dm_mem_event_control) (struct domain *d, int mode, int op);
    int (*dm_mem_event_op) (struct domain *d, int op);
    int (*dm_mem_sharing_op) (struct domain *d, struct domain *cd, int op);
    int (*priv_apic) (struct domain *d, int cmd);
    int (*memtype) (uint32_t access);
    int (*priv_platform_op) (uint32_t cmd);
    int (*priv_machine_memory_map) (void);
    int (*target_domain_memory_map) (struct domain *d);
#define XSM_MMU_UPDATE_READ      1
#define XSM_MMU_UPDATE_WRITE     2
#define XSM_MMU_NORMAL_UPDATE    4
#define XSM_MMU_MACHPHYS_UPDATE  8
    int (*target_mmu_update) (struct domain *d, struct domain *t,
                       struct domain *f, uint32_t flags);
    int (*target_mmuext_op) (struct domain *d, struct domain *f);
    int (*target_update_va_mapping) (struct domain *d, struct domain *f, l1_pgentry_t pte);
    int (*target_add_to_physmap) (struct domain *d1, struct domain *d2);
    int (*hook_bind_pt_irq) (struct domain *d, struct xen_domctl_bind_pt_irq *bind);
    int (*hook_unbind_pt_irq) (struct domain *d, struct xen_domctl_bind_pt_irq *bind);
    int (*hook_ioport_permission) (struct domain *d, uint32_t s, uint32_t e, uint8_t allow);
    int (*hook_ioport_mapping) (struct domain *d, uint32_t s, uint32_t e, uint8_t allow);
#endif
};

#ifdef XSM_ENABLE

extern struct xsm_operations *xsm_ops;

#ifndef XSM_NO_WRAPPERS

static inline void xsm_populate_security_domaininfo (struct domain *d,
                                        struct xen_domctl_getdomaininfo *info)
{
    xsm_ops->populate_security_domaininfo(d, info);
}

static inline int xsm_hook_domain_create (struct domain *d, u32 ssidref)
{
    return xsm_ops->hook_domain_create(d, ssidref);
}

static inline int xsm_hook_getdomaininfo (struct domain *d)
{
    return xsm_ops->hook_getdomaininfo(d);
}

static inline int xsm_hook_set_target (struct domain *d, struct domain *e)
{
    return xsm_ops->hook_set_target(d, e);
}

static inline int xsm_domctl (struct domain *d, int cmd)
{
    return xsm_ops->domctl(d, cmd);
}

static inline int xsm_sysctl (int cmd)
{
    return xsm_ops->sysctl(cmd);
}

static inline int xsm_hook_readconsole (uint32_t clear)
{
    return xsm_ops->hook_readconsole(clear);
}

static inline int xsm_priv_do_mca(void)
{
    return xsm_ops->priv_do_mca();
}

static inline int xsm_target_evtchn_unbound (struct domain *d1, struct evtchn *chn,
                                                                    domid_t id2)
{
    return xsm_ops->target_evtchn_unbound(d1, chn, id2);
}

static inline int xsm_hook_evtchn_interdomain (struct domain *d1, 
                struct evtchn *chan1, struct domain *d2, struct evtchn *chan2)
{
    return xsm_ops->hook_evtchn_interdomain(d1, chan1, d2, chan2);
}

static inline void xsm_hook_evtchn_close_post (struct evtchn *chn)
{
    xsm_ops->hook_evtchn_close_post(chn);
}

static inline int xsm_hook_evtchn_send (struct domain *d, struct evtchn *chn)
{
    return xsm_ops->hook_evtchn_send(d, chn);
}

static inline int xsm_target_evtchn_status (struct domain *d, struct evtchn *chn)
{
    return xsm_ops->target_evtchn_status(d, chn);
}

static inline int xsm_target_evtchn_reset (struct domain *d1, struct domain *d2)
{
    return xsm_ops->target_evtchn_reset(d1, d2);
}

static inline int xsm_hook_grant_mapref (struct domain *d1, struct domain *d2,
                                                                uint32_t flags)
{
    return xsm_ops->hook_grant_mapref(d1, d2, flags);
}

static inline int xsm_hook_grant_unmapref (struct domain *d1, struct domain *d2)
{
    return xsm_ops->hook_grant_unmapref(d1, d2);
}

static inline int xsm_target_grant_setup (struct domain *d1, struct domain *d2)
{
    return xsm_ops->target_grant_setup(d1, d2);
}

static inline int xsm_hook_grant_transfer (struct domain *d1, struct domain *d2)
{
    return xsm_ops->hook_grant_transfer(d1, d2);
}

static inline int xsm_hook_grant_copy (struct domain *d1, struct domain *d2)
{
    return xsm_ops->hook_grant_copy(d1, d2);
}

static inline int xsm_target_grant_query_size (struct domain *d1, struct domain *d2)
{
    return xsm_ops->target_grant_query_size(d1, d2);
}

static inline int xsm_alloc_security_domain (struct domain *d)
{
    return xsm_ops->alloc_security_domain(d);
}

static inline void xsm_free_security_domain (struct domain *d)
{
    xsm_ops->free_security_domain(d);
}

static inline int xsm_alloc_security_evtchn (struct evtchn *chn)
{
    return xsm_ops->alloc_security_evtchn(chn);
}

static inline void xsm_free_security_evtchn (struct evtchn *chn)
{
    (void)xsm_ops->free_security_evtchn(chn);
}

static inline char *xsm_show_security_evtchn (struct domain *d, const struct evtchn *chn)
{
    return xsm_ops->show_security_evtchn(d, chn);
}

static inline int xsm_priv_get_pod_target (struct domain *d)
{
    return xsm_ops->priv_get_pod_target(d);
}

static inline int xsm_priv_set_pod_target (struct domain *d)
{
    return xsm_ops->priv_set_pod_target(d);
}

static inline int xsm_target_memory_exchange (struct domain *d)
{
    return xsm_ops->target_memory_exchange(d);
}

static inline int xsm_target_memory_adjust_reservation (struct domain *d1, struct
                                                                    domain *d2)
{
    return xsm_ops->target_memory_adjust_reservation(d1, d2);
}

static inline int xsm_target_memory_stat_reservation (struct domain *d1,
                                                            struct domain *d2)
{
    return xsm_ops->target_memory_stat_reservation(d1, d2);
}

static inline int xsm_hook_memory_pin_page(struct domain *d1, struct domain *d2,
                                      struct page_info *page)
{
    return xsm_ops->hook_memory_pin_page(d1, d2, page);
}

static inline int xsm_target_remove_from_physmap(struct domain *d1, struct domain *d2)
{
    return xsm_ops->target_remove_from_physmap(d1, d2);
}

static inline int xsm_priv_console_io (struct domain *d, int cmd)
{
    return xsm_ops->priv_console_io(d, cmd);
}

static inline int xsm_hook_profile (struct domain *d, int op)
{
    return xsm_ops->hook_profile(d, op);
}

static inline int xsm_priv_kexec (void)
{
    return xsm_ops->priv_kexec();
}

static inline int xsm_dm_schedop_shutdown (struct domain *d1, struct domain *d2)
{
    return xsm_ops->dm_schedop_shutdown(d1, d2);
}

static inline char *xsm_show_irq_sid (int irq)
{
    return xsm_ops->show_irq_sid(irq);
}

static inline int xsm_hook_map_domain_pirq (struct domain *d, int irq, void *data)
{
    return xsm_ops->hook_map_domain_pirq(d, irq, data);
}

static inline int xsm_dm_unmap_domain_pirq (struct domain *d, int irq)
{
    return xsm_ops->dm_unmap_domain_pirq(d, irq);
}

static inline int xsm_hook_irq_permission (struct domain *d, int pirq, uint8_t allow)
{
    return xsm_ops->hook_irq_permission(d, pirq, allow);
}

static inline int xsm_hook_iomem_permission (struct domain *d, uint64_t s, uint64_t e, uint8_t allow)
{
    return xsm_ops->hook_iomem_permission(d, s, e, allow);
}

static inline int xsm_hook_iomem_mapping (struct domain *d, uint64_t s, uint64_t e, uint8_t allow)
{
    return xsm_ops->hook_iomem_mapping(d, s, e, allow);
}

static inline int xsm_hook_pci_config_permission (struct domain *d, uint32_t machine_bdf, uint16_t start, uint16_t end, uint8_t access)
{
    return xsm_ops->hook_pci_config_permission(d, machine_bdf, start, end, access);
}

static inline int xsm_hook_get_device_group(uint32_t machine_bdf)
{
    return xsm_ops->hook_get_device_group(machine_bdf);
}

static inline int xsm_hook_test_assign_device(uint32_t machine_bdf)
{
    return xsm_ops->hook_test_assign_device(machine_bdf);
}

static inline int xsm_hook_assign_device(struct domain *d, uint32_t machine_bdf)
{
    return xsm_ops->hook_assign_device(d, machine_bdf);
}

static inline int xsm_hook_deassign_device(struct domain *d, uint32_t machine_bdf)
{
    return xsm_ops->hook_deassign_device(d, machine_bdf);
}

static inline int xsm_priv_resource_plug_pci (uint32_t machine_bdf)
{
    return xsm_ops->priv_resource_plug_pci(machine_bdf);
}

static inline int xsm_priv_resource_unplug_pci (uint32_t machine_bdf)
{
    return xsm_ops->priv_resource_unplug_pci(machine_bdf);
}

static inline int xsm_hook_resource_plug_core (void)
{
    return xsm_ops->hook_resource_plug_core();
}

static inline int xsm_hook_resource_unplug_core (void)
{
    return xsm_ops->hook_resource_unplug_core();
}

static inline int xsm_priv_resource_setup_pci (uint32_t machine_bdf)
{
    return xsm_ops->priv_resource_setup_pci(machine_bdf);
}

static inline int xsm_priv_resource_setup_gsi (int gsi)
{
    return xsm_ops->priv_resource_setup_gsi(gsi);
}

static inline int xsm_priv_resource_setup_misc (void)
{
    return xsm_ops->priv_resource_setup_misc();
}

static inline int xsm_hook_page_offline(uint32_t cmd)
{
    return xsm_ops->hook_page_offline(cmd);
}

static inline int xsm_hook_tmem_op(void)
{
    return xsm_ops->hook_tmem_op();
}

static inline int xsm_priv_tmem_control(void)
{
    return xsm_ops->priv_tmem_control();
}

static inline long xsm_do_xsm_op (XEN_GUEST_HANDLE_PARAM(xsm_op_t) op)
{
    return xsm_ops->do_xsm_op(op);
}

#ifdef CONFIG_X86
static inline int xsm_hook_shadow_control (struct domain *d, uint32_t op)
{
    return xsm_ops->hook_shadow_control(d, op);
}

static inline int xsm_target_hvm_param (struct domain *d, unsigned long op)
{
    return xsm_ops->target_hvm_param(d, op);
}

static inline int xsm_dm_hvm_set_pci_intx_level (struct domain *d)
{
    return xsm_ops->dm_hvm_set_pci_intx_level(d);
}

static inline int xsm_dm_hvm_set_isa_irq_level (struct domain *d)
{
    return xsm_ops->dm_hvm_set_isa_irq_level(d);
}

static inline int xsm_dm_hvm_set_pci_link_route (struct domain *d)
{
    return xsm_ops->dm_hvm_set_pci_link_route(d);
}

static inline int xsm_dm_hvm_inject_msi (struct domain *d)
{
    return xsm_ops->dm_hvm_inject_msi(d);
}

static inline int xsm_dm_mem_event_control (struct domain *d, int mode, int op)
{
    return xsm_ops->dm_mem_event_control(d, mode, op);
}

static inline int xsm_dm_mem_event_op (struct domain *d, int op)
{
    return xsm_ops->dm_mem_event_op(d, op);
}

static inline int xsm_dm_mem_sharing_op (struct domain *d, struct domain *cd, int op)
{
    return xsm_ops->dm_mem_sharing_op(d, cd, op);
}

static inline int xsm_priv_apic (struct domain *d, int cmd)
{
    return xsm_ops->priv_apic(d, cmd);
}

static inline int xsm_memtype (uint32_t access)
{
    return xsm_ops->memtype(access);
}

static inline int xsm_priv_platform_op (uint32_t op)
{
    return xsm_ops->priv_platform_op(op);
}

static inline int xsm_priv_machine_memory_map(void)
{
    return xsm_ops->priv_machine_memory_map();
}

static inline int xsm_target_domain_memory_map(struct domain *d)
{
    return xsm_ops->target_domain_memory_map(d);
}

static inline int xsm_target_mmu_update (struct domain *d, struct domain *t,
                                  struct domain *f, uint32_t flags)
{
    return xsm_ops->target_mmu_update(d, t, f, flags);
}

static inline int xsm_target_mmuext_op (struct domain *d, struct domain *f)
{
    return xsm_ops->target_mmuext_op(d, f);
}

static inline int xsm_target_update_va_mapping(struct domain *d, struct domain *f, 
                                                            l1_pgentry_t pte)
{
    return xsm_ops->target_update_va_mapping(d, f, pte);
}

static inline int xsm_target_add_to_physmap(struct domain *d1, struct domain *d2)
{
    return xsm_ops->target_add_to_physmap(d1, d2);
}

static inline int xsm_hook_bind_pt_irq(struct domain *d, 
                                                struct xen_domctl_bind_pt_irq *bind)
{
    return xsm_ops->hook_bind_pt_irq(d, bind);
}

static inline int xsm_hook_unbind_pt_irq(struct domain *d,
                                                struct xen_domctl_bind_pt_irq *bind)
{
    return xsm_ops->hook_unbind_pt_irq(d, bind);
}

static inline int xsm_hook_ioport_permission (struct domain *d, uint32_t s, uint32_t e, uint8_t allow)
{
    return xsm_ops->hook_ioport_permission(d, s, e, allow);
}

static inline int xsm_hook_ioport_mapping (struct domain *d, uint32_t s, uint32_t e, uint8_t allow)
{
    return xsm_ops->hook_ioport_mapping(d, s, e, allow);
}
#endif /* CONFIG_X86 */
#endif /* XSM_NO_WRAPPERS */

extern int xsm_init(unsigned long *module_map, const multiboot_info_t *mbi,
                    void *(*bootstrap_map)(const module_t *));
extern int xsm_policy_init(unsigned long *module_map,
                           const multiboot_info_t *mbi,
                           void *(*bootstrap_map)(const module_t *));
extern int register_xsm(struct xsm_operations *ops);
extern int unregister_xsm(struct xsm_operations *ops);

extern struct xsm_operations dummy_xsm_ops;
extern void xsm_fixup_ops(struct xsm_operations *ops);

#else /* XSM_ENABLE */

#define XSM_INLINE inline
#include <xsm/dummy.h>

static inline int xsm_init (unsigned long *module_map,
                            const multiboot_info_t *mbi,
                            void *(*bootstrap_map)(const module_t *))
{
    return 0;
}
#endif /* XSM_ENABLE */

#endif /* __XSM_H */
