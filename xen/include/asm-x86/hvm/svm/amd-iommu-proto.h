/*
 * Copyright (C) 2007 Advanced Micro Devices, Inc.
 * Author: Leo Duran <leo.duran@amd.com>
 * Author: Wei Wang <wei.wang2@amd.com> - adapted to xen
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#ifndef _ASM_X86_64_AMD_IOMMU_PROTO_H
#define _ASM_X86_64_AMD_IOMMU_PROTO_H

#include <xen/sched.h>
#include <asm/amd-iommu.h>
#include <xen/domain_page.h>

#define for_each_amd_iommu(amd_iommu) \
    list_for_each_entry(amd_iommu, \
        &amd_iommu_head, list)

#define DMA_32BIT_MASK  0x00000000ffffffffULL
#define PAGE_ALIGN(addr)    (((addr) + PAGE_SIZE - 1) & PAGE_MASK)

#ifdef AMD_IOV_DEBUG
#define amd_iov_info(fmt, args...) \
    printk(XENLOG_INFO "AMD_IOV: " fmt, ## args)
#define amd_iov_warning(fmt, args...) \
    printk(XENLOG_WARNING "AMD_IOV: " fmt, ## args)
#define amd_iov_error(fmt, args...) \
    printk(XENLOG_ERR "AMD_IOV: %s:%d: " fmt, __FILE__ , __LINE__ , ## args)
#else
#define amd_iov_info(fmt, args...)
#define amd_iov_warning(fmt, args...)
#define amd_iov_error(fmt, args...)
#endif

/* amd-iommu-detect functions */
int __init amd_iommu_get_ivrs_dev_entries(void);
int __init amd_iommu_detect_one_acpi(void *ivhd);
int __init amd_iommu_detect_acpi(void);

/* amd-iommu-init functions */
int __init amd_iommu_init(void);
int __init amd_iommu_update_ivrs_mapping_acpi(void);

/* mapping functions */
int amd_iommu_map_page(struct domain *d, unsigned long gfn, unsigned long mfn);
int amd_iommu_unmap_page(struct domain *d, unsigned long gfn);
u64 amd_iommu_get_next_table_from_pte(u32 *entry);
int amd_iommu_reserve_domain_unity_map(struct domain *domain,
        unsigned long phys_addr, unsigned long size, int iw, int ir);
void invalidate_all_iommu_pages(struct domain *d);

/* device table functions */
void amd_iommu_set_dev_table_entry(u32 *dte, u64 root_ptr, u64 intremap_ptr,
        u16 domain_id, u8 sys_mgt, u8 dev_ex, u8 paging_mode,
        u8 valid, u8 int_valid);
int amd_iommu_is_dte_page_translation_valid(u32 *entry);
void invalidate_dev_table_entry(struct amd_iommu *iommu, u16 devic_id);

/* send cmd to iommu */
int send_iommu_command(struct amd_iommu *iommu, u32 cmd[]);
void flush_command_buffer(struct amd_iommu *iommu);

/* find iommu for bdf */
struct amd_iommu *find_iommu_for_device(int bus, int devfn);

/*interrupt remapping */
int __init amd_iommu_setup_intremap_table(void);
int __init deallocate_intremap_table(void);
void invalidate_interrupt_table(struct amd_iommu *iommu, u16 device_id);
void amd_iommu_ioapic_update_ire(
    unsigned int apic, unsigned int reg, unsigned int value);
void amd_iommu_msi_msg_update_ire(
    struct msi_desc *msi_desc, struct msi_msg *msg);
void amd_iommu_read_msi_from_ire(
    struct msi_desc *msi_desc, struct msi_msg *msg);
unsigned int amd_iommu_read_ioapic_from_ire(
    unsigned int apic, unsigned int reg);

/* power management support */
void amd_iommu_resume(void);
void amd_iommu_suspend(void);

static inline u32 get_field_from_reg_u32(u32 reg_value, u32 mask, u32 shift)
{
    u32 field;
    field = (reg_value & mask) >> shift;
    return field;
}

static inline u32 set_field_in_reg_u32(u32 field, u32 reg_value,
        u32 mask, u32 shift, u32 *reg)
{
    reg_value &= ~mask;
    reg_value |= (field << shift) & mask;
    if (reg)
        *reg = reg_value;
    return reg_value;
}

static inline u8 get_field_from_byte(u8 value, u8 mask, u8 shift)
{
    u8 field;
    field = (value & mask) >> shift;
    return field;
}

static inline unsigned long region_to_pages(unsigned long addr, unsigned long size)
{
    return (PAGE_ALIGN(addr + size) - (addr & PAGE_MASK)) >> PAGE_SHIFT;
}

static inline struct page_info* alloc_amd_iommu_pgtable(void)
{
    struct page_info *pg;
    void *vaddr;

    pg = alloc_domheap_page(NULL, 0);
    if ( pg == NULL )
        return 0;
    vaddr = map_domain_page(page_to_mfn(pg));
    if ( vaddr == NULL )
        return 0;
    memset(vaddr, 0, PAGE_SIZE);
    unmap_domain_page(vaddr);
    return pg;
}

static inline void free_amd_iommu_pgtable(struct page_info *pg)
{
    if ( pg != 0 )
        free_domheap_page(pg);
}

static inline void* __alloc_amd_iommu_tables(int order)
{
    void *buf;
    buf = alloc_xenheap_pages(order, 0);
    return buf;
}

static inline void __free_amd_iommu_tables(void *table, int order)
{
    free_xenheap_pages(table, order);
}

#endif /* _ASM_X86_64_AMD_IOMMU_PROTO_H */
