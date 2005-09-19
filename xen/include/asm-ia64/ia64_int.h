#ifndef _ASM_IA64_INT_H
#define _ASM_IA64_INT_H

//#include "ia64.h"

#define	IA64_VHPT_TRANS_VECTOR			0x0000
#define IA64_INST_TLB_VECTOR			0x0400
#define IA64_DATA_TLB_VECTOR			0x0800
#define IA64_ALT_INST_TLB_VECTOR		0x0c00
#define IA64_ALT_DATA_TLB_VECTOR		0x1000
#define IA64_DATA_NESTED_TLB_VECTOR		0x1400
#define IA64_INST_KEY_MISS_VECTOR		0x1800
#define IA64_DATA_KEY_MISS_VECTOR		0x1c00
#define IA64_DIRTY_BIT_VECTOR			0x2000
#define IA64_INST_ACCESS_BIT_VECTOR		0x2400
#define IA64_DATA_ACCESS_BIT_VECTOR		0x2800
#define IA64_BREAK_VECTOR			0x2c00
#define IA64_EXTINT_VECTOR			0x3000
#define IA64_PAGE_NOT_PRESENT_VECTOR		0x5000
#define IA64_KEY_PERMISSION_VECTOR		0x5100
#define IA64_INST_ACCESS_RIGHTS_VECTOR		0x5200
#define IA64_DATA_ACCESS_RIGHTS_VECTOR		0x5300
#define IA64_GENEX_VECTOR			0x5400
#define IA64_DISABLED_FPREG_VECTOR		0x5500
#define IA64_NAT_CONSUMPTION_VECTOR		0x5600
#define IA64_SPECULATION_VECTOR			0x5700 /* UNUSED */
#define IA64_DEBUG_VECTOR			0x5900
#define IA64_UNALIGNED_REF_VECTOR		0x5a00
#define IA64_UNSUPPORTED_DATA_REF_VECTOR	0x5b00
#define IA64_FP_FAULT_VECTOR			0x5c00
#define IA64_FP_TRAP_VECTOR			0x5d00
#define IA64_LOWERPRIV_TRANSFER_TRAP_VECTOR	0x5e00
#define IA64_TAKEN_BRANCH_TRAP_VECTOR		0x5f00
#define IA64_SINGLE_STEP_TRAP_VECTOR		0x6000

#define	IA64_NO_FAULT		0x0000
#define IA64_FAULT		        0x0001
#define	IA64_RFI_IN_PROGRESS	0x0002
#define IA64_RETRY              0x0003
#define IA64_FORCED_IFA         0x0004
#define	IA64_ILLOP_FAULT	(IA64_GENEX_VECTOR | 0x00)
#define	IA64_PRIVOP_FAULT	(IA64_GENEX_VECTOR | 0x10)
#define	IA64_PRIVREG_FAULT	(IA64_GENEX_VECTOR | 0x20)
#define	IA64_RSVDREG_FAULT	(IA64_GENEX_VECTOR | 0x30)
#define	IA64_DISIST_FAULT	(IA64_GENEX_VECTOR | 0x40)
#define	IA64_ILLDEP_FAULT	(IA64_GENEX_VECTOR | 0x80)
#define	IA64_DTLB_FAULT		(IA64_DATA_TLB_VECTOR)
#define IA64_VHPT_FAULT     (IA64_VHPT_TRANS_VECTOR | 0x10)
#if !defined(__ASSEMBLY__)
typedef unsigned long IA64FAULT;
typedef unsigned long IA64INTVECTOR;
#endif /* !ASSEMBLY */
#endif
