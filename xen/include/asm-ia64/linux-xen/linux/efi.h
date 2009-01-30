#ifndef _LINUX_EFI_H
#define _LINUX_EFI_H

#ifndef __ASSEMBLY__

/*
 * Extensible Firmware Interface
 * Based on 'Extensible Firmware Interface Specification' version 0.9, April 30, 1999
 *
 * Copyright (C) 1999 VA Linux Systems
 * Copyright (C) 1999 Walt Drummond <drummond@valinux.com>
 * Copyright (C) 1999, 2002-2003 Hewlett-Packard Co.
 *	David Mosberger-Tang <davidm@hpl.hp.com>
 *	Stephane Eranian <eranian@hpl.hp.com>
 */
#include <linux/init.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/rtc.h>
#include <linux/ioport.h>

#include <asm/page.h>
#include <asm/system.h>
#ifdef XEN
#include <asm/pgtable.h>
#endif

#define EFI_SUCCESS		0
#define EFI_LOAD_ERROR          ( 1 | (1UL << (BITS_PER_LONG-1)))
#define EFI_INVALID_PARAMETER	( 2 | (1UL << (BITS_PER_LONG-1)))
#define EFI_UNSUPPORTED		( 3 | (1UL << (BITS_PER_LONG-1)))
#define EFI_BAD_BUFFER_SIZE     ( 4 | (1UL << (BITS_PER_LONG-1)))
#define EFI_BUFFER_TOO_SMALL	( 5 | (1UL << (BITS_PER_LONG-1)))
#define EFI_NOT_FOUND		(14 | (1UL << (BITS_PER_LONG-1)))

typedef unsigned long efi_status_t;
typedef u8 efi_bool_t;
typedef u16 efi_char16_t;		/* UNICODE character */


typedef struct {
	u8 b[16];
} efi_guid_t;

#define EFI_GUID(a,b,c,d0,d1,d2,d3,d4,d5,d6,d7) \
((efi_guid_t) \
{{ (a) & 0xff, ((a) >> 8) & 0xff, ((a) >> 16) & 0xff, ((a) >> 24) & 0xff, \
  (b) & 0xff, ((b) >> 8) & 0xff, \
  (c) & 0xff, ((c) >> 8) & 0xff, \
  (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) }})

/*
 * Generic EFI table header
 */
typedef	struct {
	u64 signature;
	u32 revision;
	u32 headersize;
	u32 crc32;
	u32 reserved;
} efi_table_hdr_t;

/*
 * Memory map descriptor:
 */

/* Memory types: */
#define EFI_RESERVED_TYPE		 0
#define EFI_LOADER_CODE			 1
#define EFI_LOADER_DATA			 2
#define EFI_BOOT_SERVICES_CODE		 3
#define EFI_BOOT_SERVICES_DATA		 4
#define EFI_RUNTIME_SERVICES_CODE	 5
#define EFI_RUNTIME_SERVICES_DATA	 6
#define EFI_CONVENTIONAL_MEMORY		 7
#define EFI_UNUSABLE_MEMORY		 8
#define EFI_ACPI_RECLAIM_MEMORY		 9
#define EFI_ACPI_MEMORY_NVS		10
#define EFI_MEMORY_MAPPED_IO		11
#define EFI_MEMORY_MAPPED_IO_PORT_SPACE	12
#define EFI_PAL_CODE			13
#define EFI_MAX_MEMORY_TYPE		14

/* Attribute values: */
#define EFI_MEMORY_UC		((u64)0x0000000000000001ULL)	/* uncached */
#define EFI_MEMORY_WC		((u64)0x0000000000000002ULL)	/* write-coalescing */
#define EFI_MEMORY_WT		((u64)0x0000000000000004ULL)	/* write-through */
#define EFI_MEMORY_WB		((u64)0x0000000000000008ULL)	/* write-back */
#define EFI_MEMORY_WP		((u64)0x0000000000001000ULL)	/* write-protect */
#define EFI_MEMORY_RP		((u64)0x0000000000002000ULL)	/* read-protect */
#define EFI_MEMORY_XP		((u64)0x0000000000004000ULL)	/* execute-protect */
#define EFI_MEMORY_RUNTIME	((u64)0x8000000000000000ULL)	/* range requires runtime mapping */
#define EFI_MEMORY_DESCRIPTOR_VERSION	1

#define EFI_PAGE_SHIFT		12

typedef struct {
	u32 type;
	u32 pad;
	u64 phys_addr;
	u64 virt_addr;
	u64 num_pages;
	u64 attribute;
} efi_memory_desc_t;

typedef int (*efi_freemem_callback_t) (unsigned long start, unsigned long end, void *arg);

/*
 * Types and defines for Time Services
 */
#define EFI_TIME_ADJUST_DAYLIGHT 0x1
#define EFI_TIME_IN_DAYLIGHT     0x2
#define EFI_UNSPECIFIED_TIMEZONE 0x07ff

typedef struct {
	u16 year;
	u8 month;
	u8 day;
	u8 hour;
	u8 minute;
	u8 second;
	u8 pad1;
	u32 nanosecond;
	s16 timezone;
	u8 daylight;
	u8 pad2;
} efi_time_t;

typedef struct {
	u32 resolution;
	u32 accuracy;
	u8 sets_to_zero;
} efi_time_cap_t;

/*
 * Types and defines for EFI ResetSystem
 */
#define EFI_RESET_COLD 0
#define EFI_RESET_WARM 1
#define EFI_RESET_SHUTDOWN 2

/*
 * EFI Runtime Services table
 */
#define EFI_RUNTIME_SERVICES_SIGNATURE ((u64)0x5652453544e5552ULL)
#define EFI_RUNTIME_SERVICES_REVISION  0x00010000

typedef struct {
	efi_table_hdr_t hdr;
	unsigned long get_time;
	unsigned long set_time;
	unsigned long get_wakeup_time;
	unsigned long set_wakeup_time;
	unsigned long set_virtual_address_map;
	unsigned long convert_pointer;
	unsigned long get_variable;
	unsigned long get_next_variable;
	unsigned long set_variable;
	unsigned long get_next_high_mono_count;
	unsigned long reset_system;
} efi_runtime_services_t;

typedef efi_status_t efi_get_time_t (efi_time_t *tm, efi_time_cap_t *tc);
typedef efi_status_t efi_set_time_t (efi_time_t *tm);
typedef efi_status_t efi_get_wakeup_time_t (efi_bool_t *enabled, efi_bool_t *pending,
					    efi_time_t *tm);
typedef efi_status_t efi_set_wakeup_time_t (efi_bool_t enabled, efi_time_t *tm);
typedef efi_status_t efi_get_variable_t (efi_char16_t *name, efi_guid_t *vendor, u32 *attr,
					 unsigned long *data_size, void *data);
typedef efi_status_t efi_get_next_variable_t (unsigned long *name_size, efi_char16_t *name,
					      efi_guid_t *vendor);
typedef efi_status_t efi_set_variable_t (efi_char16_t *name, efi_guid_t *vendor, 
					 unsigned long attr, unsigned long data_size, 
					 void *data);
typedef efi_status_t efi_get_next_high_mono_count_t (u32 *count);
typedef void efi_reset_system_t (int reset_type, efi_status_t status,
				 unsigned long data_size, efi_char16_t *data);
typedef efi_status_t efi_set_virtual_address_map_t (unsigned long memory_map_size,
						unsigned long descriptor_size,
						u32 descriptor_version,
						efi_memory_desc_t *virtual_map);

/*
 *  EFI Configuration Table and GUID definitions
 */
#define NULL_GUID \
    EFI_GUID(  0x00000000, 0x0000, 0x0000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 )

#define MPS_TABLE_GUID    \
    EFI_GUID(  0xeb9d2d2f, 0x2d88, 0x11d3, 0x9a, 0x16, 0x0, 0x90, 0x27, 0x3f, 0xc1, 0x4d )

#define ACPI_TABLE_GUID    \
    EFI_GUID(  0xeb9d2d30, 0x2d88, 0x11d3, 0x9a, 0x16, 0x0, 0x90, 0x27, 0x3f, 0xc1, 0x4d )

#define ACPI_20_TABLE_GUID    \
    EFI_GUID(  0x8868e871, 0xe4f1, 0x11d3, 0xbc, 0x22, 0x0, 0x80, 0xc7, 0x3c, 0x88, 0x81 )

#define SMBIOS_TABLE_GUID    \
    EFI_GUID(  0xeb9d2d31, 0x2d88, 0x11d3, 0x9a, 0x16, 0x0, 0x90, 0x27, 0x3f, 0xc1, 0x4d )

#define SAL_SYSTEM_TABLE_GUID    \
    EFI_GUID(  0xeb9d2d32, 0x2d88, 0x11d3, 0x9a, 0x16, 0x0, 0x90, 0x27, 0x3f, 0xc1, 0x4d )

#define HCDP_TABLE_GUID	\
    EFI_GUID(  0xf951938d, 0x620b, 0x42ef, 0x82, 0x79, 0xa8, 0x4b, 0x79, 0x61, 0x78, 0x98 )

#define UGA_IO_PROTOCOL_GUID \
    EFI_GUID(  0x61a4d49e, 0x6f68, 0x4f1b, 0xb9, 0x22, 0xa8, 0x6e, 0xed, 0xb, 0x7, 0xa2 )

#define EFI_GLOBAL_VARIABLE_GUID \
    EFI_GUID(  0x8be4df61, 0x93ca, 0x11d2, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c )

typedef struct {
	efi_guid_t guid;
	unsigned long table;
} efi_config_table_t;

#define EFI_SYSTEM_TABLE_SIGNATURE ((u64)0x5453595320494249ULL)

typedef struct {
	efi_table_hdr_t hdr;
	unsigned long fw_vendor;	/* physical addr of CHAR16 vendor string */
	u32 fw_revision;
	unsigned long con_in_handle;
	unsigned long con_in;
	unsigned long con_out_handle;
	unsigned long con_out;
	unsigned long stderr_handle;
	unsigned long stderr;
	efi_runtime_services_t *runtime;
	unsigned long boottime;
	unsigned long nr_tables;
	unsigned long tables;
} efi_system_table_t;

struct efi_memory_map {
#ifndef XEN
	void *phys_map;
	void *map;
#else
	efi_memory_desc_t *phys_map;
	efi_memory_desc_t *map;
#endif
	void *map_end;
	int nr_map;
	unsigned long desc_version;
	unsigned long desc_size;
};

#define EFI_INVALID_TABLE_ADDR		(~0UL)

/*
 * All runtime access to EFI goes through this structure:
 */
extern struct efi {
	efi_system_table_t *systab;	/* EFI system table */
	unsigned long mps;		/* MPS table */
	unsigned long acpi;		/* ACPI table  (IA64 ext 0.71) */
	unsigned long acpi20;		/* ACPI table  (ACPI 2.0) */
	unsigned long smbios;		/* SM BIOS table */
	unsigned long sal_systab;	/* SAL system table */
	unsigned long boot_info;	/* boot info table */
	unsigned long hcdp;		/* HCDP table */
	unsigned long uga;		/* UGA table */
	efi_get_time_t *get_time;
	efi_set_time_t *set_time;
	efi_get_wakeup_time_t *get_wakeup_time;
	efi_set_wakeup_time_t *set_wakeup_time;
	efi_get_variable_t *get_variable;
	efi_get_next_variable_t *get_next_variable;
	efi_set_variable_t *set_variable;
	efi_get_next_high_mono_count_t *get_next_high_mono_count;
	efi_reset_system_t *reset_system;
	efi_set_virtual_address_map_t *set_virtual_address_map;
} efi;

static inline int
efi_guidcmp (efi_guid_t left, efi_guid_t right)
{
	return memcmp(&left, &right, sizeof (efi_guid_t));
}

static inline char *
efi_guid_unparse(efi_guid_t *guid, char *out)
{
#ifndef XEN
	sprintf(out, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
#else
	snprintf(out, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
#endif
		guid->b[3], guid->b[2], guid->b[1], guid->b[0],
		guid->b[5], guid->b[4], guid->b[7], guid->b[6],
		guid->b[8], guid->b[9], guid->b[10], guid->b[11],
		guid->b[12], guid->b[13], guid->b[14], guid->b[15]);
        return out;
}

extern void efi_init (void);
extern void *efi_get_pal_addr (void);
extern void efi_map_pal_code (void);
#ifdef XEN
extern void efi_unmap_pal_code (void);
#endif
extern void efi_map_memmap(void);
extern void efi_memmap_walk (efi_freemem_callback_t callback, void *arg);
extern void efi_gettimeofday (struct timespec *ts);
extern void efi_enter_virtual_mode (void);	/* switch EFI to virtual mode, if possible */
extern u64 efi_get_iobase (void);
extern u32 efi_mem_type (unsigned long phys_addr);
extern u64 efi_mem_attributes (unsigned long phys_addr);
extern u64 efi_mem_attribute (unsigned long phys_addr, unsigned long size);
extern int efi_mem_attribute_range (unsigned long phys_addr, unsigned long size,
				    u64 attr);
extern int __init efi_uart_console_only (void);
extern void efi_initialize_iomem_resources(struct resource *code_resource,
					struct resource *data_resource);
extern unsigned long efi_get_time(void);
extern int efi_set_rtc_mmss(unsigned long nowtime);
extern int is_available_memory(efi_memory_desc_t * md);
extern struct efi_memory_map memmap;

/**
 * efi_range_is_wc - check the WC bit on an address range
 * @start: starting kvirt address
 * @len: length of range
 *
 * Consult the EFI memory map and make sure it's ok to set this range WC.
 * Returns true or false.
 */
static inline int efi_range_is_wc(unsigned long start, unsigned long len)
{
	unsigned long i;

	for (i = 0; i < len; i += (1UL << EFI_PAGE_SHIFT)) {
		unsigned long paddr = __pa(start + i);
		if (!(efi_mem_attributes(paddr) & EFI_MEMORY_WC))
			return 0;
	}
	/* The range checked out */
	return 1;
}

#ifdef CONFIG_EFI_PCDP
extern int __init efi_setup_pcdp_console(char *);
#endif

/*
 * We play games with efi_enabled so that the compiler will, if possible, remove
 * EFI-related code altogether.
 */
#ifdef CONFIG_EFI
# ifdef CONFIG_X86
   extern int efi_enabled;
# else
#  define efi_enabled 1
# endif
#else
# define efi_enabled 0
#endif

/*
 * Variable Attributes
 */
#define EFI_VARIABLE_NON_VOLATILE       0x0000000000000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS 0x0000000000000002
#define EFI_VARIABLE_RUNTIME_ACCESS     0x0000000000000004

/*
 * EFI Device Path information
 */
#define EFI_DEV_HW			0x01
#define  EFI_DEV_PCI				 1
#define  EFI_DEV_PCCARD				 2
#define  EFI_DEV_MEM_MAPPED			 3
#define  EFI_DEV_VENDOR				 4
#define  EFI_DEV_CONTROLLER			 5
#define EFI_DEV_ACPI			0x02
#define   EFI_DEV_BASIC_ACPI			 1
#define   EFI_DEV_EXPANDED_ACPI			 2
#define EFI_DEV_MSG			0x03
#define   EFI_DEV_MSG_ATAPI			 1
#define   EFI_DEV_MSG_SCSI			 2
#define   EFI_DEV_MSG_FC			 3
#define   EFI_DEV_MSG_1394			 4
#define   EFI_DEV_MSG_USB			 5
#define   EFI_DEV_MSG_USB_CLASS			15
#define   EFI_DEV_MSG_I20			 6
#define   EFI_DEV_MSG_MAC			11
#define   EFI_DEV_MSG_IPV4			12
#define   EFI_DEV_MSG_IPV6			13
#define   EFI_DEV_MSG_INFINIBAND		 9
#define   EFI_DEV_MSG_UART			14
#define   EFI_DEV_MSG_VENDOR			10
#define EFI_DEV_MEDIA			0x04
#define   EFI_DEV_MEDIA_HARD_DRIVE		 1
#define   EFI_DEV_MEDIA_CDROM			 2
#define   EFI_DEV_MEDIA_VENDOR			 3
#define   EFI_DEV_MEDIA_FILE			 4
#define   EFI_DEV_MEDIA_PROTOCOL		 5
#define EFI_DEV_BIOS_BOOT		0x05
#define EFI_DEV_END_PATH		0x7F
#define EFI_DEV_END_PATH2		0xFF
#define   EFI_DEV_END_INSTANCE			0x01
#define   EFI_DEV_END_ENTIRE			0xFF

struct efi_generic_dev_path {
	u8 type;
	u8 sub_type;
	u16 length;
} __attribute ((packed));

#ifdef XEN
/*
 * According to xen/arch/ia64/xen/regionreg.c the RID space is broken up
 * into large-blocks. Each block belongs to a domain, except 0th block,
 * which is broken up into small-blocks. The small-blocks are used for
 * metaphysical mappings, again one per domain, except for the 0th
 * small-block which is unused other than very early on in the
 * hypervisor boot.
 *
 * By default each large-block is 18 bits wide, which is also the minimum
 * allowed width for a block. Each small-block is by default 1/64 the width
 * of a large-block, which is the maximum division allowed. In other words
 * each small-block is at least 12 bits wide.
 *
 * The portion of the 0th small-block that is used early on during
 * the hypervisor boot relates to IA64_REGION_ID_KERNEL, which is
 * used to form an RID using the following scheme which seems to be
 * have been inherited from Linux:
 *
 * a: bits 0-2: Region Number (0-7)
 * b: 3-N:      IA64_REGION_ID_KERNEL (0)
 * c: N-23:     reserved (0)
 *
 * N is defined by the platform.
 *
 * For EFI we use the following RID:
 *
 * a: bits 0-2:  Region Number (0-7)
 * e: bits 3-N:  IA64_REGION_ID_KERNEL (1)
 * f: bits N-53: reserved (0)
 *
 * + Only 6 and 7 are used as we only need two RIDs. Its not really important
 *   what this number is, so long as its between 0 and 7.
 *
 * The nice thing about this is that we are only using 4 bits of RID
 * space, so it shouldn't have any chance of running into an adjacent
 * small-block since small-blocks are at least 12 bits wide.
 *
 * It would actually be possible to just use a IA64_REGION_ID_KERNEL
 * based RID for EFI use. The important thing is that it is in the 0th
 * small block, and thus not available to domains. But as we have
 * lots of space, its seems to be nice and clean to just use a separate
 * RID for EFI.
 *
 * This can be trivially changed by updating the definition of XEN_EFI_RR.
 *
 * For reference, the RID is used to produce the value inserted
 * in to a region register in the following way:
 *
 * A: bit 0:     VHPT (0 = off, 1 = on)
 * B: bit 1:     reserved (0)
 * C: bits 2-7:  log 2 page_size
 * D: bits 8-N:  RID
 * E: bits N-53: reserved (0)
 */

/* rr7 (and rr6) may already be set to XEN_EFI_RR7 (and XEN_EFI_RR6), which
 * would indicate a nested EFI, SAL or PAL call, such
 * as from an MCA. This may have occured during a call
 * to set_one_rr_efi(). To be safe, repin everything anyway.
 */

#define XEN_EFI_RR_ENTER(rr6, rr7) do {			\
	rr6 = ia64_get_rr(6UL << 61);			\
	rr7 = ia64_get_rr(7UL << 61);			\
	set_one_rr_efi(6UL << 61, XEN_EFI_RR6);		\
	set_one_rr_efi(7UL << 61, XEN_EFI_RR7);		\
	efi_map_pal_code();				\
} while (0)

/* There is no need to do anything if the saved rr7 (and rr6)
 * is XEN_EFI_RR, as it would just switch them from XEN_EFI_RR to XEN_EFI_RR
 * Furthermore, if this is a nested call it is important not
 * to unpin efi_unmap_pal_code() until the outermost call is finished
 */

#define XEN_EFI_RR_LEAVE(rr6, rr7) do {			\
	if (rr7 != XEN_EFI_RR7) {			\
		efi_unmap_pal_code();			\
		set_one_rr_efi_restore(6UL << 61, rr6);	\
		set_one_rr_efi_restore(7UL << 61, rr7);	\
	}						\
} while (0)

#else
/* Just use rr6 and rr7 in a dummy fashion here to get
 * rid of compiler warnings - a better solution should
 * be found if this code is ever actually used */
#define XEN_EFI_RR_ENTER(rr6, rr7)	do { rr6 = 0; rr7 = 0; } while (0)
#define XEN_EFI_RR_LEAVE(rr6, rr7)	do {} while (0)
#endif /* XEN */

#define XEN_EFI_RR_DECLARE(rr6, rr7)	unsigned long rr6, rr7;

#endif /* !__ASSEMBLY__ */

#ifdef XEN
#include <asm/mmu_context.h> /* For IA64_REGION_ID_EFI and ia64_rid() */
#include <asm/pgtable.h>     /* IA64_GRANULE_SHIFT */

/* macro version of vmMangleRID() */
#define XEN_EFI_VM_MANGLE_RRVAL(rrval)		\
	((((rrval) & 0xff000000) >> 16) |	\
	 ((rrval) & 0x00ff0000) |		\
	 (((rrval) & 0x0000ff00) << 16 ) |	\
	 ((rrval) & 0x000000ff))

#define XEN_EFI_REGION6 __IA64_UL_CONST(6)
#define XEN_EFI_REGION7 __IA64_UL_CONST(7)
#define _XEN_EFI_RR6 ((ia64_rid(XEN_IA64_REGION_ID_EFI,			\
				XEN_EFI_REGION6) << 8) |		\
		      (IA64_GRANULE_SHIFT << 2))
#define _XEN_EFI_RR7 ((ia64_rid(XEN_IA64_REGION_ID_EFI,			\
				XEN_EFI_REGION7) << 8) |		\
		      (IA64_GRANULE_SHIFT << 2))
#define XEN_EFI_RR6 XEN_EFI_VM_MANGLE_RRVAL(_XEN_EFI_RR6)
#define XEN_EFI_RR7 XEN_EFI_VM_MANGLE_RRVAL(_XEN_EFI_RR7)

#endif /* XEN */

#endif /* _LINUX_EFI_H */
