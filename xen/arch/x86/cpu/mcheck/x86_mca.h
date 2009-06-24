/*
 * MCA implementation for AMD K7/K8 CPUs
 * Copyright (c) 2007 Advanced Micro Devices, Inc. 
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef X86_MCA_H
#define X86_MCA_H

#include <public/arch-x86/xen-mca.h>

/* The MCA/MCE MSRs should not be used anywhere else.
 * They are cpu family/model specific and are only for use
 * in terms of machine check handling.
 * So we define them here rather in <asm/msr.h>.
 */


/* Bitfield of the MSR_IA32_MCG_CAP register */
#define MCG_SER_P               (1UL<<24)
#define MCG_CAP_COUNT           0x00000000000000ffULL
#define MCG_CTL_P               0x0000000000000100ULL
#define MCG_EXT_P		(1UL<<9)
#define MCG_EXT_CNT		(16)
#define MCG_CMCI_P		(1UL<<10)
/* Other bits are reserved */

/* Bitfield of the MSR_IA32_MCG_STATUS register */
#define MCG_STATUS_RIPV         0x0000000000000001ULL
#define MCG_STATUS_EIPV         0x0000000000000002ULL
#define MCG_STATUS_MCIP         0x0000000000000004ULL
/* Bits 3-63 are reserved */

/* Bitfield of MSR_K8_MCi_STATUS registers */
/* MCA error code */
#define MCi_STATUS_MCA          0x000000000000ffffULL
/* model-specific error code */
#define MCi_STATUS_MSEC         0x00000000ffff0000ULL
/* Other information */
#define MCi_STATUS_OTHER        0x01ffffff00000000ULL
/* Action Required flag */
#define MCi_STATUS_AR           0x0080000000000000ULL
/* Signaling flag */
#define MCi_STATUS_S            0x0100000000000000ULL
/* processor context corrupt */
#define MCi_STATUS_PCC          0x0200000000000000ULL
/* MSR_K8_MCi_ADDR register valid */
#define MCi_STATUS_ADDRV        0x0400000000000000ULL
/* MSR_K8_MCi_MISC register valid */
#define MCi_STATUS_MISCV        0x0800000000000000ULL
/* error condition enabled */
#define MCi_STATUS_EN           0x1000000000000000ULL
/* uncorrected error */
#define MCi_STATUS_UC           0x2000000000000000ULL
/* status register overflow */
#define MCi_STATUS_OVER         0x4000000000000000ULL
/* valid */
#define MCi_STATUS_VAL          0x8000000000000000ULL

/* Bitfield of MSi_STATUS_OTHER field */
/* reserved bits */
#define MCi_STATUS_OTHER_RESERVED1      0x00001fff00000000ULL
/* uncorrectable ECC error */
#define MCi_STATUS_OTEHR_UC_ECC         0x0000200000000000ULL
/* correctable ECC error */
#define MCi_STATUS_OTHER_C_ECC          0x0000400000000000ULL
/* ECC syndrome of an ECC error */
#define MCi_STATUS_OTHER_ECC_SYNDROME   0x007f800000000000ULL
/* reserved bits */
#define MCi_STATUS_OTHER_RESERVED2      0x0180000000000000ULL

/* Bitfield of MSR_K8_HWCR register */
#define K8_HWCR_MCi_STATUS_WREN		(1ULL << 18)

/*Intel Specific bitfield*/
#define CMCI_THRESHOLD			0x2

#include <asm/domain.h>
typedef DECLARE_BITMAP(cpu_banks_t, MAX_NR_BANKS);
DECLARE_PER_CPU(cpu_banks_t, mce_banks_owned);

/* Below interfaces are defined for MCA internal processing:
 * a. pre_handler will be called early in MCA ISR context, mainly for early
 *    need_reset detection for avoiding log missing. Also, it is used to judge
 *    impacted DOMAIN if possible.
 * b. mca_error_handler is actually a (error_action_index,
 *    recovery_hanlder pointer) pair. The defined recovery_handler
 *    performs the actual recovery operations such as page_offline, cpu_offline
 *    in softIRQ context when the per_bank MCA error matching the corresponding
 *    mca_code index. If pre_handler can't judge the impacted domain,
 *    recovery_handler must figure it out.
*/

/* MCA error has been recovered successfully by the recovery action*/
#define MCA_RECOVERED (0x1 << 0)
/* MCA error impact the specified DOMAIN in owner field below */
#define MCA_OWNER (0x1 << 1)
/* MCA error can't be recovered and need reset */
#define MCA_NEED_RESET (0x1 << 2)
/* MCA error did not have any action yet */
#define MCA_NO_ACTION (0x1 << 3)

struct mca_handle_result
{
    uint32_t result;
    /* Used one result & MCA_OWNER */
    domid_t owner;
    /* Used by mca_error_handler, result & MCA_RECOVRED */
    struct recovery_action *action;
};

extern void (*mca_prehandler)( struct cpu_user_regs *regs,
                        struct mca_handle_result *result);

struct mca_error_handler
{
    /* Assume corresponding recovery action could be uniquely
     * identified by mca_code. Otherwise, we might need to have
     * a seperate function to decode the corresponding actions
     * for the particular mca error later.
    */
    uint16_t mca_code;
    void (*recovery_handler)( struct mcinfo_bank *bank,
                    struct mcinfo_global *global,
                    struct mcinfo_extended *extension,
                    struct mca_handle_result *result);
};

/* Global variables */
extern int mce_disabled;
extern unsigned int nr_mce_banks;

#endif /* X86_MCA_H */
