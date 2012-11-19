/*
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

#define XSM_NO_WRAPPERS
#define XSM_INLINE /* */
#include <xsm/dummy.h>

struct xsm_operations dummy_xsm_ops;

#define set_to_dummy_if_null(ops, function)                            \
    do {                                                               \
        if ( !ops->function )                                          \
        {                                                              \
            ops->function = xsm_##function;                            \
            if (ops != &dummy_xsm_ops)                                 \
                dprintk(XENLOG_DEBUG, "Had to override the " #function \
                    " security operation with the dummy one.\n");      \
        }                                                              \
    } while (0)

void xsm_fixup_ops (struct xsm_operations *ops)
{
    set_to_dummy_if_null(ops, populate_security_domaininfo);
    set_to_dummy_if_null(ops, hook_domain_create);
    set_to_dummy_if_null(ops, hook_getdomaininfo);
    set_to_dummy_if_null(ops, hook_set_target);
    set_to_dummy_if_null(ops, domctl);
    set_to_dummy_if_null(ops, sysctl);
    set_to_dummy_if_null(ops, hook_readconsole);
    set_to_dummy_if_null(ops, priv_do_mca);

    set_to_dummy_if_null(ops, target_evtchn_unbound);
    set_to_dummy_if_null(ops, hook_evtchn_interdomain);
    set_to_dummy_if_null(ops, hook_evtchn_close_post);
    set_to_dummy_if_null(ops, hook_evtchn_send);
    set_to_dummy_if_null(ops, target_evtchn_status);
    set_to_dummy_if_null(ops, target_evtchn_reset);

    set_to_dummy_if_null(ops, hook_grant_mapref);
    set_to_dummy_if_null(ops, hook_grant_unmapref);
    set_to_dummy_if_null(ops, target_grant_setup);
    set_to_dummy_if_null(ops, hook_grant_transfer);
    set_to_dummy_if_null(ops, hook_grant_copy);
    set_to_dummy_if_null(ops, target_grant_query_size);

    set_to_dummy_if_null(ops, alloc_security_domain);
    set_to_dummy_if_null(ops, free_security_domain);
    set_to_dummy_if_null(ops, alloc_security_evtchn);
    set_to_dummy_if_null(ops, free_security_evtchn);
    set_to_dummy_if_null(ops, show_security_evtchn);
    set_to_dummy_if_null(ops, priv_get_pod_target);
    set_to_dummy_if_null(ops, priv_set_pod_target);

    set_to_dummy_if_null(ops, target_memory_exchange);
    set_to_dummy_if_null(ops, target_memory_adjust_reservation);
    set_to_dummy_if_null(ops, target_memory_stat_reservation);
    set_to_dummy_if_null(ops, hook_memory_pin_page);

    set_to_dummy_if_null(ops, priv_console_io);

    set_to_dummy_if_null(ops, hook_profile);

    set_to_dummy_if_null(ops, priv_kexec);
    set_to_dummy_if_null(ops, dm_schedop_shutdown);

    set_to_dummy_if_null(ops, show_irq_sid);
    set_to_dummy_if_null(ops, hook_map_domain_pirq);
    set_to_dummy_if_null(ops, dm_unmap_domain_pirq);
    set_to_dummy_if_null(ops, hook_irq_permission);
    set_to_dummy_if_null(ops, hook_iomem_permission);
    set_to_dummy_if_null(ops, hook_iomem_mapping);
    set_to_dummy_if_null(ops, hook_pci_config_permission);

    set_to_dummy_if_null(ops, hook_get_device_group);
    set_to_dummy_if_null(ops, hook_test_assign_device);
    set_to_dummy_if_null(ops, hook_assign_device);
    set_to_dummy_if_null(ops, hook_deassign_device);

    set_to_dummy_if_null(ops, hook_resource_plug_core);
    set_to_dummy_if_null(ops, hook_resource_unplug_core);
    set_to_dummy_if_null(ops, priv_resource_plug_pci);
    set_to_dummy_if_null(ops, priv_resource_unplug_pci);
    set_to_dummy_if_null(ops, priv_resource_setup_pci);
    set_to_dummy_if_null(ops, priv_resource_setup_gsi);
    set_to_dummy_if_null(ops, priv_resource_setup_misc);

    set_to_dummy_if_null(ops, hook_page_offline);
    set_to_dummy_if_null(ops, hook_tmem_op);
    set_to_dummy_if_null(ops, priv_tmem_control);

    set_to_dummy_if_null(ops, do_xsm_op);

#ifdef CONFIG_X86
    set_to_dummy_if_null(ops, hook_shadow_control);
    set_to_dummy_if_null(ops, target_hvm_param);
    set_to_dummy_if_null(ops, dm_hvm_set_pci_intx_level);
    set_to_dummy_if_null(ops, dm_hvm_set_isa_irq_level);
    set_to_dummy_if_null(ops, dm_hvm_set_pci_link_route);
    set_to_dummy_if_null(ops, dm_hvm_inject_msi);
    set_to_dummy_if_null(ops, dm_mem_event_control);
    set_to_dummy_if_null(ops, dm_mem_event_op);
    set_to_dummy_if_null(ops, dm_mem_sharing_op);
    set_to_dummy_if_null(ops, priv_apic);
    set_to_dummy_if_null(ops, priv_platform_op);
    set_to_dummy_if_null(ops, priv_machine_memory_map);
    set_to_dummy_if_null(ops, target_domain_memory_map);
    set_to_dummy_if_null(ops, target_mmu_update);
    set_to_dummy_if_null(ops, target_mmuext_op);
    set_to_dummy_if_null(ops, target_update_va_mapping);
    set_to_dummy_if_null(ops, target_add_to_physmap);
    set_to_dummy_if_null(ops, target_remove_from_physmap);
    set_to_dummy_if_null(ops, hook_bind_pt_irq);
    set_to_dummy_if_null(ops, hook_unbind_pt_irq);
    set_to_dummy_if_null(ops, hook_ioport_permission);
    set_to_dummy_if_null(ops, hook_ioport_mapping);
#endif
}
