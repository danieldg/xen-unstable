/*
 * hvmloader.c: HVM ROMBIOS/VGABIOS/ACPI/VMXAssist image loader.
 *
 * Leendert van Doorn, leendert@watson.ibm.com
 * Copyright (c) 2005, International Business Machines Corporation.
 *
 * Copyright (c) 2006, Keir Fraser, XenSource Inc.
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
 */
#include "roms.h"
#include "acpi/acpi2_0.h"  /* for ACPI_PHYSICAL_ADDRESS */
#include "hypercall.h"
#include "util.h"
#include "acpi_utils.h"
#include "smbios.h"
#include "config.h"
#include "apic_regs.h"
#include "pci_regs.h"
#include <xen/version.h>
#include <xen/hvm/params.h>
#include <xen/hvm/e820.h>

/* memory map */
#define HYPERCALL_PHYSICAL_ADDRESS    0x00080000
#define VGABIOS_PHYSICAL_ADDRESS      0x000C0000
#define VMXASSIST_PHYSICAL_ADDRESS    0x000D0000
#define ROMBIOS_PHYSICAL_ADDRESS      0x000F0000

/* invoke SVM's paged realmode support */
#define SVM_VMMCALL_RESET_TO_REALMODE 0x80000001

/*
 * C runtime start off
 */
asm(
    "    .text                       \n"
    "    .globl _start               \n"
    "_start:                         \n"
    "    cld                         \n"
    "    cli                         \n"
    "    lgdt gdt_desr               \n"
    "    movl $stack_top, %esp       \n"
    "    movl %esp, %ebp             \n"
    "    call main                   \n"
    "    ud2                         \n"
    "                                \n"
    "gdt_desr:                       \n"
    "    .word gdt_end - gdt - 1     \n"
    "    .long gdt                   \n"
    "                                \n"
    "    .align 8                    \n"
    "gdt:                            \n"
    "    .quad 0x0000000000000000    \n"
    "    .quad 0x00CF92000000FFFF    \n"
    "    .quad 0x00CF9A000000FFFF    \n"
    "gdt_end:                        \n"
    "                                \n"
    "    .bss                        \n"
    "    .align    8                 \n"
    "stack:                          \n"
    "    .skip    0x4000             \n"
    "stack_top:                      \n"
    );

extern void create_mp_tables(void);

static int
cirrus_check(void)
{
    outw(0x3C4, 0x9206);
    return inb(0x3C5) == 0x12;
}

static int
vmmcall(int function, int edi, int esi, int edx, int ecx, int ebx)
{
    int eax;

    __asm__ __volatile__ (
        ".byte 0x0F,0x01,0xD9"
        : "=a" (eax)
        : "a"(function),
        "b"(ebx), "c"(ecx), "d"(edx), "D"(edi), "S"(esi) );
    return eax;
}

static int
check_amd(void)
{
    char id[12];

    __asm__ __volatile__ (
        "cpuid" 
        : "=b" (*(int *)(&id[0])),
        "=c" (*(int *)(&id[8])),
        "=d" (*(int *)(&id[4]))
        : "a" (0) );
    return __builtin_memcmp(id, "AuthenticAMD", 12) == 0;
}

static void
wrmsr(uint32_t idx, uint64_t v)
{
    __asm__ __volatile__ (
        "wrmsr"
        : : "c" (idx), "a" ((uint32_t)v), "d" ((uint32_t)(v>>32)) );
}

static void
init_hypercalls(void)
{
    uint32_t eax, ebx, ecx, edx;
    unsigned long i;
    char signature[13];
    xen_extraversion_t extraversion;

    cpuid(0x40000000, &eax, &ebx, &ecx, &edx);

    *(uint32_t *)(signature + 0) = ebx;
    *(uint32_t *)(signature + 4) = ecx;
    *(uint32_t *)(signature + 8) = edx;
    signature[12] = '\0';

    if ( strcmp("XenVMMXenVMM", signature) || (eax < 0x40000002) )
    {
        printf("FATAL: Xen hypervisor not detected\n");
        __asm__ __volatile__( "ud2" );
    }

    /* Fill in hypercall transfer pages. */
    cpuid(0x40000002, &eax, &ebx, &ecx, &edx);
    for ( i = 0; i < eax; i++ )
        wrmsr(ebx, HYPERCALL_PHYSICAL_ADDRESS + (i << 12) + i);

    /* Print version information. */
    cpuid(0x40000001, &eax, &ebx, &ecx, &edx);
    hypercall_xen_version(XENVER_extraversion, extraversion);
    printf("Detected Xen v%u.%u%s\n", eax >> 16, eax & 0xffff, extraversion);
}

static void apic_setup(void)
{
    /* Set the IOAPIC ID to tha static value used in the MP/ACPI tables. */
    ioapic_write(0x00, IOAPIC_ID);

    /* Set up Virtual Wire mode. */
    lapic_write(APIC_SPIV, APIC_SPIV_APIC_ENABLED | 0xFF);
    lapic_write(APIC_LVT0, APIC_MODE_EXTINT << 8);
    lapic_write(APIC_LVT1, APIC_MODE_NMI    << 8);
}

static void pci_setup(void)
{
    uint32_t devfn, bar_reg, bar_data, bar_sz, cmd;
    uint32_t *base, io_base = 0xc000, mem_base = HVM_BELOW_4G_MMIO_START;
    uint16_t class, vendor_id, device_id;
    unsigned int bar, pin, link, isa_irq;

    /* Program PCI-ISA bridge with appropriate link routes. */
    link = 0;
    for ( isa_irq = 0; isa_irq < 15; isa_irq++ )
    {
        if ( !(PCI_ISA_IRQ_MASK & (1U << isa_irq)) )
            continue;
        pci_writeb(PCI_ISA_DEVFN, 0x60 + link, isa_irq);
        printf("PCI-ISA link %u routed to IRQ%u\n", link, isa_irq);
        if ( link++ == 4 )
            break;
    }

    /* Program ELCR to match PCI-wired IRQs. */
    outb(0x4d0, (uint8_t)(PCI_ISA_IRQ_MASK >> 0));
    outb(0x4d1, (uint8_t)(PCI_ISA_IRQ_MASK >> 8));

    /* Scan the PCI bus and map resources. */
    for ( devfn = 0; devfn < 128; devfn++ )
    {
        class     = pci_readw(devfn, PCI_CLASS_DEVICE);
        vendor_id = pci_readw(devfn, PCI_VENDOR_ID);
        device_id = pci_readw(devfn, PCI_DEVICE_ID);
        if ( (vendor_id == 0xffff) && (device_id == 0xffff) )
            continue;

        ASSERT((devfn != PCI_ISA_DEVFN) ||
               ((vendor_id == 0x8086) && (device_id == 0x7000)));

        switch ( class )
        {
        case 0x0680:
            ASSERT((vendor_id == 0x8086) && (device_id == 0x7113));
            /*
             * PIIX4 ACPI PM. Special device with special PCI config space.
             * No ordinary BARs.
             */
            pci_writew(devfn, 0x20, 0x0000); /* No smb bus IO enable */
            pci_writew(devfn, 0x22, 0x0000);
            pci_writew(devfn, 0x3c, 0x0009); /* Hardcoded IRQ9 */
            pci_writew(devfn, 0x3d, 0x0001);
            break;
        case 0x0101:
            /* PIIX3 IDE */
            ASSERT((vendor_id == 0x8086) && (device_id == 0x7010));
            pci_writew(devfn, 0x40, 0x8000); /* enable IDE0 */
            pci_writew(devfn, 0x42, 0x8000); /* enable IDE1 */
            /* fall through */
        default:
            /* Default memory mappings. */
            for ( bar = 0; bar < 7; bar++ )
            {
                bar_reg = PCI_BASE_ADDRESS_0 + 4*bar;
                if ( bar == 6 )
                    bar_reg = PCI_ROM_ADDRESS;

                bar_data = pci_readl(devfn, bar_reg);

                pci_writel(devfn, bar_reg, ~0);
                bar_sz = pci_readl(devfn, bar_reg);
                if ( bar_sz == 0 )
                    continue;

                if ( (bar_data & PCI_BASE_ADDRESS_SPACE) ==
                     PCI_BASE_ADDRESS_SPACE_MEMORY )
                {
                    base = &mem_base;
                    bar_sz &= PCI_BASE_ADDRESS_MEM_MASK;
                    bar_data &= ~PCI_BASE_ADDRESS_MEM_MASK;
                }
                else
                {
                    base = &io_base;
                    bar_sz &= PCI_BASE_ADDRESS_IO_MASK & 0xffff;
                    bar_data &= ~PCI_BASE_ADDRESS_IO_MASK;
                }
                bar_sz &= ~(bar_sz - 1);

                *base = (*base + bar_sz - 1) & ~(bar_sz - 1);
                bar_data |= *base;
                *base += bar_sz;

                pci_writel(devfn, bar_reg, bar_data);
                printf("pci dev %02x:%x bar %02x size %08x: %08x\n",
                       devfn>>3, devfn&7, bar_reg, bar_sz, bar_data);

                /* Now enable the memory or I/O mapping. */
                cmd = pci_readw(devfn, PCI_COMMAND);
                if ( (bar_reg == PCI_ROM_ADDRESS) ||
                     ((bar_data & PCI_BASE_ADDRESS_SPACE) ==
                      PCI_BASE_ADDRESS_SPACE_MEMORY) )
                    cmd |= PCI_COMMAND_MEMORY;
                else
                    cmd |= PCI_COMMAND_IO;
                pci_writew(devfn, PCI_COMMAND, cmd);
            }
            break;
        }

        /* Map the interrupt. */
        pin = pci_readb(devfn, PCI_INTERRUPT_PIN);
        if ( pin != 0 )
        {
            /* This is the barber's pole mapping used by Xen. */
            link = ((pin - 1) + (devfn >> 3)) & 3;
            isa_irq = pci_readb(PCI_ISA_DEVFN, 0x60 + link);
            pci_writeb(devfn, PCI_INTERRUPT_LINE, isa_irq);
            printf("pci dev %02x:%x INT%c->IRQ%u\n",
                   devfn>>3, devfn&7, 'A'+pin-1, isa_irq);
        }
    }
}

int main(void)
{
    int acpi_sz;
    uint8_t *freemem;

    printf("HVM Loader\n");

    init_hypercalls();

    printf("Writing SMBIOS tables ...\n");
    hvm_write_smbios_tables();

    printf("Loading ROMBIOS ...\n");
    memcpy((void *)ROMBIOS_PHYSICAL_ADDRESS, rombios, sizeof(rombios));

    apic_setup();
    pci_setup();

    if ( (get_vcpu_nr() > 1) || get_apic_mode() )
        create_mp_tables();

    if ( cirrus_check() )
    {
        printf("Loading Cirrus VGABIOS ...\n");
        memcpy((void *)VGABIOS_PHYSICAL_ADDRESS,
               vgabios_cirrusvga, sizeof(vgabios_cirrusvga));
    }
    else
    {
        printf("Loading Standard VGABIOS ...\n");
        memcpy((void *)VGABIOS_PHYSICAL_ADDRESS,
               vgabios_stdvga, sizeof(vgabios_stdvga));
    }

    if ( get_acpi_enabled() != 0 )
    {
        printf("Loading ACPI ...\n");
        acpi_sz = acpi_build_tables((uint8_t *)ACPI_PHYSICAL_ADDRESS);
        freemem = (uint8_t *)ACPI_PHYSICAL_ADDRESS + acpi_sz;
        ASSERT(freemem <= (uint8_t *)0xF0000);
        acpi_update((unsigned char *)ACPI_PHYSICAL_ADDRESS,
                    freemem - (uint8_t *)ACPI_PHYSICAL_ADDRESS,
                    (unsigned char *)0xF0000,
                    &freemem);
    }

    if ( check_amd() )
    {
        /* AMD implies this is SVM */
        printf("SVM go ...\n");
        vmmcall(SVM_VMMCALL_RESET_TO_REALMODE, 0, 0, 0, 0, 0);
    }
    else
    {
        printf("Loading VMXAssist ...\n");
        memcpy((void *)VMXASSIST_PHYSICAL_ADDRESS,
               vmxassist, sizeof(vmxassist));

        printf("VMX go ...\n");
        __asm__ __volatile__(
            "jmp *%%eax"
            : : "a" (VMXASSIST_PHYSICAL_ADDRESS), "d" (0)
            );
    }

    printf("Failed to invoke ROMBIOS\n");
    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
