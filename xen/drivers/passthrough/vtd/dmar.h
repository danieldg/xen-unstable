/*
 * Copyright (c) 2006, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 * Copyright (C) Ashok Raj <ashok.raj@intel.com>
 * Copyright (C) Shaohua Li <shaohua.li@intel.com>
 */

#ifndef _DMAR_H_
#define _DMAR_H_

#include <xen/list.h>
#include <xen/iommu.h>

extern u8 dmar_host_address_width;

/* This one is for interrupt remapping */
struct acpi_ioapic_unit {
    struct list_head list;
    int apic_id;
    union {
        u16 info;
        struct {
            u16 func: 3,
                dev:  5,
                bus:  8;
        }bdf;
    }ioapic;
};

struct dmar_scope {
    DECLARE_BITMAP(buses, 256);         /* buses owned by this unit */
    u16    *devices;                    /* devices owned by this unit */
    int    devices_cnt;
};

struct acpi_drhd_unit {
    struct dmar_scope scope;            /* must be first member of struct */
    struct list_head list;
    u64    address;                     /* register base address of the unit */
    u8     include_all:1;
    struct iommu *iommu;
    struct list_head ioapic_list;
};

struct acpi_rmrr_unit {
    struct dmar_scope scope;            /* must be first member of struct */
    struct list_head list;
    u64    base_address;
    u64    end_address;
    u8     allow_all:1;
};

struct acpi_atsr_unit {
    struct dmar_scope scope;            /* must be first member of struct */
    struct list_head list;
    u8     all_ports:1;
};


#define for_each_drhd_unit(drhd) \
    list_for_each_entry(drhd, &acpi_drhd_units, list)

#define for_each_rmrr_device(rmrr, bdf, idx)            \
    list_for_each_entry(rmrr, &acpi_rmrr_units, list)   \
        /* assume there never is a bdf == 0 */          \
        for (idx = 0; (bdf = rmrr->scope.devices[i]) && \
                 idx < rmrr->scope.devices_cnt; idx++)

struct acpi_drhd_unit * acpi_find_matched_drhd_unit(u8 bus, u8 devfn);
void dmar_scope_add_buses(struct dmar_scope *scope, u16 sec, u16 sub);
void dmar_scope_remove_buses(struct dmar_scope *scope, u16 sec, u16 sub);

#define DMAR_TYPE 1
#define RMRR_TYPE 2
#define ATSR_TYPE 3

#define DMAR_OPERATION_TIMEOUT MILLISECS(1000)

int vtd_hw_check(void);
void disable_pmr(struct iommu *iommu);
int is_usb_device(u8 bus, u8 devfn);

#endif /* _DMAR_H_ */
