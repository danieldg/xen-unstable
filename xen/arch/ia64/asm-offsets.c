/*
 * Generate definitions needed by assembly language modules.
 * This code generates raw asm output which is post-processed
 * to extract and format the required data.
 */

#include <xen/config.h>
#include <xen/sched.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <public/xen.h>
#include <asm/tlb.h>
#include <asm/regs.h>

#define task_struct vcpu

#define DEFINE(sym, val) \
        asm volatile("\n->" #sym " (%0) " #val : : "i" (val))

#define BLANK() asm volatile("\n->" : : )

#define OFFSET(_sym, _str, _mem) \
    DEFINE(_sym, offsetof(_str, _mem));

void foo(void)
{
	DEFINE(IA64_TASK_SIZE, sizeof (struct task_struct));
	DEFINE(IA64_THREAD_INFO_SIZE, sizeof (struct thread_info));
	DEFINE(IA64_PT_REGS_SIZE, sizeof (struct pt_regs));
	DEFINE(IA64_SWITCH_STACK_SIZE, sizeof (struct switch_stack));
	//DEFINE(IA64_SIGINFO_SIZE, sizeof (struct siginfo));
	DEFINE(IA64_CPU_SIZE, sizeof (struct cpuinfo_ia64));
	//DEFINE(SIGFRAME_SIZE, sizeof (struct sigframe));
	DEFINE(UNW_FRAME_INFO_SIZE, sizeof (struct unw_frame_info));

	BLANK();
#ifdef   VTI_DEBUG
	DEFINE(IVT_CUR_OFS, offsetof(struct vcpu, arch.arch_vmx.ivt_current));
	DEFINE(IVT_DBG_OFS, offsetof(struct vcpu, arch.arch_vmx.ivt_debug));
#endif
	DEFINE(TI_FLAGS, offsetof(struct thread_info, flags));
	DEFINE(TI_PRE_COUNT, offsetof(struct thread_info, preempt_count));

	BLANK();

	DEFINE(XSI_PSR_IC_OFS, offsetof(mapped_regs_t, interrupt_collection_enabled));
	DEFINE(XSI_PSR_IC, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, interrupt_collection_enabled)));
	DEFINE(XSI_PSR_I_OFS, offsetof(mapped_regs_t, interrupt_delivery_enabled));
	DEFINE(XSI_IIP_OFS, offsetof(mapped_regs_t, iip));
	DEFINE(XSI_IIP, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, iip)));
	DEFINE(XSI_IFA_OFS, offsetof(mapped_regs_t, ifa));
	DEFINE(XSI_IFA, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, ifa)));
	DEFINE(XSI_ITIR_OFS, offsetof(mapped_regs_t, itir));
	DEFINE(XSI_ITIR, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, itir)));

	DEFINE(XSI_IPSR, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, ipsr)));
	DEFINE(XSI_IPSR_OFS, offsetof(mapped_regs_t, ipsr));
	DEFINE(XSI_IFS_OFS, offsetof(mapped_regs_t, ifs));
	DEFINE(XSI_IFS, (SHARED_ARCHINFO_ADDR+offsetof(mapped_regs_t, ifs)));
	DEFINE(XSI_ISR_OFS, offsetof(mapped_regs_t, isr));
	DEFINE(XSI_IIM_OFS, offsetof(mapped_regs_t, iim));
	DEFINE(XSI_BANKNUM_OFS, offsetof(mapped_regs_t, banknum));
	DEFINE(XSI_BANK0_OFS, offsetof(mapped_regs_t, bank0_regs[0]));
	DEFINE(XSI_BANK1_OFS, offsetof(mapped_regs_t, bank1_regs[0]));
	DEFINE(XSI_B0NATS_OFS, offsetof(mapped_regs_t, vbnat));
	DEFINE(XSI_B1NATS_OFS, offsetof(mapped_regs_t, vnat));
	DEFINE(XSI_RR0_OFS, offsetof(mapped_regs_t, rrs[0]));
	DEFINE(XSI_METAPHYS_OFS, offsetof(mapped_regs_t, metaphysical_mode));
	DEFINE(XSI_PRECOVER_IFS_OFS, offsetof(mapped_regs_t, precover_ifs));
	DEFINE(XSI_INCOMPL_REG_OFS, offsetof(mapped_regs_t, incomplete_regframe));
	DEFINE(XSI_PEND_OFS, offsetof(mapped_regs_t, pending_interruption));
	DEFINE(XSI_RR0_OFS, offsetof(mapped_regs_t, rrs[0]));
	DEFINE(XSI_IHA_OFS, offsetof(mapped_regs_t, iha));
	DEFINE(XSI_TPR_OFS, offsetof(mapped_regs_t, tpr));
	DEFINE(XSI_PTA_OFS, offsetof(mapped_regs_t, pta));
	DEFINE(XSI_ITV_OFS, offsetof(mapped_regs_t, itv));
	DEFINE(XSI_KR0_OFS, offsetof(mapped_regs_t, krs[0]));
	//DEFINE(IA64_TASK_BLOCKED_OFFSET,offsetof (struct task_struct, blocked));
	//DEFINE(IA64_TASK_CLEAR_CHILD_TID_OFFSET,offsetof (struct task_struct, clear_child_tid));
	//DEFINE(IA64_TASK_GROUP_LEADER_OFFSET, offsetof (struct task_struct, group_leader));
	//DEFINE(IA64_TASK_PENDING_OFFSET,offsetof (struct task_struct, pending));
	//DEFINE(IA64_TASK_PID_OFFSET, offsetof (struct task_struct, pid));
	//DEFINE(IA64_TASK_REAL_PARENT_OFFSET, offsetof (struct task_struct, real_parent));
	//DEFINE(IA64_TASK_SIGHAND_OFFSET,offsetof (struct task_struct, sighand));
	//DEFINE(IA64_TASK_SIGNAL_OFFSET,offsetof (struct task_struct, signal));
	//DEFINE(IA64_TASK_TGID_OFFSET, offsetof (struct task_struct, tgid));
	DEFINE(IA64_TASK_THREAD_KSP_OFFSET, offsetof (struct vcpu, arch._thread.ksp));
	DEFINE(IA64_TASK_THREAD_ON_USTACK_OFFSET, offsetof (struct vcpu, arch._thread.on_ustack));

	DEFINE(IA64_VCPU_DOMAIN_OFFSET, offsetof (struct vcpu, domain));
	DEFINE(IA64_VCPU_META_RR0_OFFSET, offsetof (struct vcpu, arch.metaphysical_rr0));
	DEFINE(IA64_VCPU_META_SAVED_RR0_OFFSET, offsetof (struct vcpu, arch.metaphysical_saved_rr0));
	DEFINE(IA64_VCPU_BREAKIMM_OFFSET, offsetof (struct vcpu, arch.breakimm));
	DEFINE(IA64_VCPU_IVA_OFFSET, offsetof (struct vcpu, arch.iva));
	DEFINE(IA64_VCPU_DTLB_PTE_OFFSET, offsetof (struct vcpu, arch.dtlb_pte));
	DEFINE(IA64_VCPU_ITLB_PTE_OFFSET, offsetof (struct vcpu, arch.itlb_pte));
	DEFINE(IA64_VCPU_IRR0_OFFSET, offsetof (struct vcpu, arch.irr[0]));
	DEFINE(IA64_VCPU_IRR3_OFFSET, offsetof (struct vcpu, arch.irr[3]));
	DEFINE(IA64_VCPU_INSVC3_OFFSET, offsetof (struct vcpu, arch.insvc[3]));
	DEFINE(IA64_VCPU_STARTING_RID_OFFSET, offsetof (struct vcpu, arch.starting_rid));
	DEFINE(IA64_VCPU_ENDING_RID_OFFSET, offsetof (struct vcpu, arch.ending_rid));
	DEFINE(IA64_VCPU_DOMAIN_ITM_OFFSET, offsetof (struct vcpu, arch.domain_itm));
	DEFINE(IA64_VCPU_DOMAIN_ITM_LAST_OFFSET, offsetof (struct vcpu, arch.domain_itm_last));
	DEFINE(IA64_VCPU_ITLB_OFFSET, offsetof (struct vcpu, arch.itlb));
	DEFINE(IA64_VCPU_DTLB_OFFSET, offsetof (struct vcpu, arch.dtlb));

	BLANK();
	DEFINE(IA64_CPUINFO_ITM_NEXT_OFFSET, offsetof (struct cpuinfo_ia64, itm_next));
	DEFINE(IA64_CPUINFO_KSOFTIRQD_OFFSET, offsetof (struct cpuinfo_ia64, ksoftirqd));

	//DEFINE(IA64_SIGHAND_SIGLOCK_OFFSET,offsetof (struct sighand_struct, siglock));

	BLANK();

	//DEFINE(IA64_SIGNAL_GROUP_STOP_COUNT_OFFSET,offsetof (struct signal_struct,
							     //group_stop_count));
	//DEFINE(IA64_SIGNAL_SHARED_PENDING_OFFSET,offsetof (struct signal_struct, shared_pending));

	BLANK();

	DEFINE(IA64_PT_REGS_B6_OFFSET, offsetof (struct pt_regs, b6));
	DEFINE(IA64_PT_REGS_B7_OFFSET, offsetof (struct pt_regs, b7));
	DEFINE(IA64_PT_REGS_AR_CSD_OFFSET, offsetof (struct pt_regs, ar_csd));
	DEFINE(IA64_PT_REGS_AR_SSD_OFFSET, offsetof (struct pt_regs, ar_ssd));
	DEFINE(IA64_PT_REGS_R8_OFFSET, offsetof (struct pt_regs, r8));
	DEFINE(IA64_PT_REGS_R9_OFFSET, offsetof (struct pt_regs, r9));
	DEFINE(IA64_PT_REGS_R10_OFFSET, offsetof (struct pt_regs, r10));
	DEFINE(IA64_PT_REGS_R11_OFFSET, offsetof (struct pt_regs, r11));
	DEFINE(IA64_PT_REGS_CR_IPSR_OFFSET, offsetof (struct pt_regs, cr_ipsr));
	DEFINE(IA64_PT_REGS_CR_IIP_OFFSET, offsetof (struct pt_regs, cr_iip));
	DEFINE(IA64_PT_REGS_CR_IFS_OFFSET, offsetof (struct pt_regs, cr_ifs));
	DEFINE(IA64_PT_REGS_AR_UNAT_OFFSET, offsetof (struct pt_regs, ar_unat));
	DEFINE(IA64_PT_REGS_AR_PFS_OFFSET, offsetof (struct pt_regs, ar_pfs));
	DEFINE(IA64_PT_REGS_AR_RSC_OFFSET, offsetof (struct pt_regs, ar_rsc));
	DEFINE(IA64_PT_REGS_AR_RNAT_OFFSET, offsetof (struct pt_regs, ar_rnat));

	DEFINE(IA64_PT_REGS_AR_BSPSTORE_OFFSET, offsetof (struct pt_regs, ar_bspstore));
	DEFINE(IA64_PT_REGS_PR_OFFSET, offsetof (struct pt_regs, pr));
	DEFINE(IA64_PT_REGS_B0_OFFSET, offsetof (struct pt_regs, b0));
	DEFINE(IA64_PT_REGS_LOADRS_OFFSET, offsetof (struct pt_regs, loadrs));
	DEFINE(IA64_PT_REGS_R1_OFFSET, offsetof (struct pt_regs, r1));
	DEFINE(IA64_PT_REGS_R12_OFFSET, offsetof (struct pt_regs, r12));
	DEFINE(IA64_PT_REGS_R13_OFFSET, offsetof (struct pt_regs, r13));
	DEFINE(IA64_PT_REGS_AR_FPSR_OFFSET, offsetof (struct pt_regs, ar_fpsr));
	DEFINE(IA64_PT_REGS_R15_OFFSET, offsetof (struct pt_regs, r15));
	DEFINE(IA64_PT_REGS_R14_OFFSET, offsetof (struct pt_regs, r14));
	DEFINE(IA64_PT_REGS_R2_OFFSET, offsetof (struct pt_regs, r2));
	DEFINE(IA64_PT_REGS_R3_OFFSET, offsetof (struct pt_regs, r3));
	DEFINE(IA64_PT_REGS_R16_OFFSET, offsetof (struct pt_regs, r16));
	DEFINE(IA64_PT_REGS_R17_OFFSET, offsetof (struct pt_regs, r17));
	DEFINE(IA64_PT_REGS_R18_OFFSET, offsetof (struct pt_regs, r18));
	DEFINE(IA64_PT_REGS_R19_OFFSET, offsetof (struct pt_regs, r19));
	DEFINE(IA64_PT_REGS_R20_OFFSET, offsetof (struct pt_regs, r20));
	DEFINE(IA64_PT_REGS_R21_OFFSET, offsetof (struct pt_regs, r21));
	DEFINE(IA64_PT_REGS_R22_OFFSET, offsetof (struct pt_regs, r22));
	DEFINE(IA64_PT_REGS_R23_OFFSET, offsetof (struct pt_regs, r23));
	DEFINE(IA64_PT_REGS_R24_OFFSET, offsetof (struct pt_regs, r24));
	DEFINE(IA64_PT_REGS_R25_OFFSET, offsetof (struct pt_regs, r25));
	DEFINE(IA64_PT_REGS_R26_OFFSET, offsetof (struct pt_regs, r26));
	DEFINE(IA64_PT_REGS_R27_OFFSET, offsetof (struct pt_regs, r27));
	DEFINE(IA64_PT_REGS_R28_OFFSET, offsetof (struct pt_regs, r28));
	DEFINE(IA64_PT_REGS_R29_OFFSET, offsetof (struct pt_regs, r29));
	DEFINE(IA64_PT_REGS_R30_OFFSET, offsetof (struct pt_regs, r30));
	DEFINE(IA64_PT_REGS_R31_OFFSET, offsetof (struct pt_regs, r31));
	DEFINE(IA64_PT_REGS_AR_CCV_OFFSET, offsetof (struct pt_regs, ar_ccv));
	DEFINE(IA64_PT_REGS_F6_OFFSET, offsetof (struct pt_regs, f6));
	DEFINE(IA64_PT_REGS_F7_OFFSET, offsetof (struct pt_regs, f7));
	DEFINE(IA64_PT_REGS_F8_OFFSET, offsetof (struct pt_regs, f8));
	DEFINE(IA64_PT_REGS_F9_OFFSET, offsetof (struct pt_regs, f9));
	DEFINE(IA64_PT_REGS_F10_OFFSET, offsetof (struct pt_regs, f10));
	DEFINE(IA64_PT_REGS_F11_OFFSET, offsetof (struct pt_regs, f11));
	DEFINE(IA64_PT_REGS_R4_OFFSET, offsetof (struct pt_regs, r4));
	DEFINE(IA64_PT_REGS_R5_OFFSET, offsetof (struct pt_regs, r5));
	DEFINE(IA64_PT_REGS_R6_OFFSET, offsetof (struct pt_regs, r6));
	DEFINE(IA64_PT_REGS_R7_OFFSET, offsetof (struct pt_regs, r7));
	DEFINE(IA64_PT_REGS_EML_UNAT_OFFSET, offsetof (struct pt_regs, eml_unat));
	DEFINE(IA64_PT_REGS_RFI_PFS_OFFSET, offsetof (struct pt_regs, rfi_pfs));
    DEFINE(IA64_VCPU_IIPA_OFFSET, offsetof (struct vcpu, arch.arch_vmx.cr_iipa));
    DEFINE(IA64_VCPU_ISR_OFFSET, offsetof (struct vcpu, arch.arch_vmx.cr_isr));
    DEFINE(IA64_VCPU_CAUSE_OFFSET, offsetof (struct vcpu, arch.arch_vmx.cause));
    DEFINE(IA64_VCPU_OPCODE_OFFSET, offsetof (struct vcpu, arch.arch_vmx.opcode));
	DEFINE(SWITCH_MPTA_OFFSET,offsetof(struct vcpu ,arch.arch_vmx.mpta));
    DEFINE(IA64_PT_REGS_R16_SLOT, (((offsetof(struct pt_regs, r16)-sizeof(struct pt_regs))>>3)&0x3f));
	DEFINE(IA64_VCPU_FLAGS_OFFSET,offsetof(struct vcpu ,arch.arch_vmx.flags));

	BLANK();

	DEFINE(IA64_SWITCH_STACK_CALLER_UNAT_OFFSET, offsetof (struct switch_stack, caller_unat));
	DEFINE(IA64_SWITCH_STACK_AR_FPSR_OFFSET, offsetof (struct switch_stack, ar_fpsr));
	DEFINE(IA64_SWITCH_STACK_F2_OFFSET, offsetof (struct switch_stack, f2));
	DEFINE(IA64_SWITCH_STACK_F3_OFFSET, offsetof (struct switch_stack, f3));
	DEFINE(IA64_SWITCH_STACK_F4_OFFSET, offsetof (struct switch_stack, f4));
	DEFINE(IA64_SWITCH_STACK_F5_OFFSET, offsetof (struct switch_stack, f5));
	DEFINE(IA64_SWITCH_STACK_F12_OFFSET, offsetof (struct switch_stack, f12));
	DEFINE(IA64_SWITCH_STACK_F13_OFFSET, offsetof (struct switch_stack, f13));
	DEFINE(IA64_SWITCH_STACK_F14_OFFSET, offsetof (struct switch_stack, f14));
	DEFINE(IA64_SWITCH_STACK_F15_OFFSET, offsetof (struct switch_stack, f15));
	DEFINE(IA64_SWITCH_STACK_F16_OFFSET, offsetof (struct switch_stack, f16));
	DEFINE(IA64_SWITCH_STACK_F17_OFFSET, offsetof (struct switch_stack, f17));
	DEFINE(IA64_SWITCH_STACK_F18_OFFSET, offsetof (struct switch_stack, f18));
	DEFINE(IA64_SWITCH_STACK_F19_OFFSET, offsetof (struct switch_stack, f19));
	DEFINE(IA64_SWITCH_STACK_F20_OFFSET, offsetof (struct switch_stack, f20));
	DEFINE(IA64_SWITCH_STACK_F21_OFFSET, offsetof (struct switch_stack, f21));
	DEFINE(IA64_SWITCH_STACK_F22_OFFSET, offsetof (struct switch_stack, f22));
	DEFINE(IA64_SWITCH_STACK_F23_OFFSET, offsetof (struct switch_stack, f23));
	DEFINE(IA64_SWITCH_STACK_F24_OFFSET, offsetof (struct switch_stack, f24));
	DEFINE(IA64_SWITCH_STACK_F25_OFFSET, offsetof (struct switch_stack, f25));
	DEFINE(IA64_SWITCH_STACK_F26_OFFSET, offsetof (struct switch_stack, f26));
	DEFINE(IA64_SWITCH_STACK_F27_OFFSET, offsetof (struct switch_stack, f27));
	DEFINE(IA64_SWITCH_STACK_F28_OFFSET, offsetof (struct switch_stack, f28));
	DEFINE(IA64_SWITCH_STACK_F29_OFFSET, offsetof (struct switch_stack, f29));
	DEFINE(IA64_SWITCH_STACK_F30_OFFSET, offsetof (struct switch_stack, f30));
	DEFINE(IA64_SWITCH_STACK_F31_OFFSET, offsetof (struct switch_stack, f31));
	DEFINE(IA64_SWITCH_STACK_R4_OFFSET, offsetof (struct switch_stack, r4));
	DEFINE(IA64_SWITCH_STACK_R5_OFFSET, offsetof (struct switch_stack, r5));
	DEFINE(IA64_SWITCH_STACK_R6_OFFSET, offsetof (struct switch_stack, r6));
	DEFINE(IA64_SWITCH_STACK_R7_OFFSET, offsetof (struct switch_stack, r7));
	DEFINE(IA64_SWITCH_STACK_B0_OFFSET, offsetof (struct switch_stack, b0));
	DEFINE(IA64_SWITCH_STACK_B1_OFFSET, offsetof (struct switch_stack, b1));
	DEFINE(IA64_SWITCH_STACK_B2_OFFSET, offsetof (struct switch_stack, b2));
	DEFINE(IA64_SWITCH_STACK_B3_OFFSET, offsetof (struct switch_stack, b3));
	DEFINE(IA64_SWITCH_STACK_B4_OFFSET, offsetof (struct switch_stack, b4));
	DEFINE(IA64_SWITCH_STACK_B5_OFFSET, offsetof (struct switch_stack, b5));
	DEFINE(IA64_SWITCH_STACK_AR_PFS_OFFSET, offsetof (struct switch_stack, ar_pfs));
	DEFINE(IA64_SWITCH_STACK_AR_LC_OFFSET, offsetof (struct switch_stack, ar_lc));
	DEFINE(IA64_SWITCH_STACK_AR_UNAT_OFFSET, offsetof (struct switch_stack, ar_unat));
	DEFINE(IA64_SWITCH_STACK_AR_RNAT_OFFSET, offsetof (struct switch_stack, ar_rnat));
	DEFINE(IA64_SWITCH_STACK_AR_BSPSTORE_OFFSET, offsetof (struct switch_stack, ar_bspstore));
	DEFINE(IA64_SWITCH_STACK_PR_OFFSET, offsetof (struct switch_stack, pr));

	BLANK();

	DEFINE(IA64_VPD_BASE_OFFSET, offsetof (struct vcpu, arch.privregs));
 	DEFINE(IA64_VLSAPIC_INSVC_BASE_OFFSET, offsetof (struct vcpu, arch.insvc[0]));
	DEFINE(IA64_VPD_CR_VPTA_OFFSET, offsetof (cr_t, pta));
	DEFINE(XXX_THASH_SIZE, sizeof (thash_data_t));

	BLANK();
	//DEFINE(IA64_SIGCONTEXT_IP_OFFSET, offsetof (struct sigcontext, sc_ip));
	//DEFINE(IA64_SIGCONTEXT_AR_BSP_OFFSET, offsetof (struct sigcontext, sc_ar_bsp));
	//DEFINE(IA64_SIGCONTEXT_AR_FPSR_OFFSET, offsetof (struct sigcontext, sc_ar_fpsr));
	//DEFINE(IA64_SIGCONTEXT_AR_RNAT_OFFSET, offsetof (struct sigcontext, sc_ar_rnat));
	//DEFINE(IA64_SIGCONTEXT_AR_UNAT_OFFSET, offsetof (struct sigcontext, sc_ar_unat));
	//DEFINE(IA64_SIGCONTEXT_B0_OFFSET, offsetof (struct sigcontext, sc_br[0]));
	//DEFINE(IA64_SIGCONTEXT_CFM_OFFSET, offsetof (struct sigcontext, sc_cfm));
	//DEFINE(IA64_SIGCONTEXT_FLAGS_OFFSET, offsetof (struct sigcontext, sc_flags));
	//DEFINE(IA64_SIGCONTEXT_FR6_OFFSET, offsetof (struct sigcontext, sc_fr[6]));
	//DEFINE(IA64_SIGCONTEXT_PR_OFFSET, offsetof (struct sigcontext, sc_pr));
	//DEFINE(IA64_SIGCONTEXT_R12_OFFSET, offsetof (struct sigcontext, sc_gr[12]));
	//DEFINE(IA64_SIGCONTEXT_RBS_BASE_OFFSET,offsetof (struct sigcontext, sc_rbs_base));
	//DEFINE(IA64_SIGCONTEXT_LOADRS_OFFSET, offsetof (struct sigcontext, sc_loadrs));

	//BLANK();

	//DEFINE(IA64_SIGPENDING_SIGNAL_OFFSET, offsetof (struct sigpending, signal));

	//BLANK();

	//DEFINE(IA64_SIGFRAME_ARG0_OFFSET, offsetof (struct sigframe, arg0));
	//DEFINE(IA64_SIGFRAME_ARG1_OFFSET, offsetof (struct sigframe, arg1));
	//DEFINE(IA64_SIGFRAME_ARG2_OFFSET, offsetof (struct sigframe, arg2));
	//DEFINE(IA64_SIGFRAME_HANDLER_OFFSET, offsetof (struct sigframe, handler));
	//DEFINE(IA64_SIGFRAME_SIGCONTEXT_OFFSET, offsetof (struct sigframe, sc));
	//BLANK();
    /* for assembly files which can't include sched.h: */
	//DEFINE(IA64_CLONE_VFORK, CLONE_VFORK);
	//DEFINE(IA64_CLONE_VM, CLONE_VM);

	BLANK();
	DEFINE(IA64_CPUINFO_NSEC_PER_CYC_OFFSET, offsetof (struct cpuinfo_ia64, nsec_per_cyc));
	DEFINE(IA64_TIMESPEC_TV_NSEC_OFFSET, offsetof (struct timespec, tv_nsec));


	DEFINE(CLONE_IDLETASK_BIT, 12);
	DEFINE(CLONE_SETTLS_BIT, 19);
//#if CLONE_SETTLS != (1<<19)
//# error "CLONE_SETTLS_BIT incorrect, please fix"
//#endif

	//BLANK();
	//DEFINE(IA64_MCA_TLB_INFO_SIZE, sizeof (struct ia64_mca_tlb_info));
	/* used by head.S */
	DEFINE(IA64_CPUINFO_NSEC_PER_CYC_OFFSET, offsetof (struct cpuinfo_ia64, nsec_per_cyc));

	BLANK();
	/* used by fsys_gettimeofday in arch/ia64/kernel/fsys.S */
	//DEFINE(IA64_TIME_INTERPOLATOR_ADDRESS_OFFSET, offsetof (struct time_interpolator, addr));
	//DEFINE(IA64_TIME_INTERPOLATOR_SOURCE_OFFSET, offsetof (struct time_interpolator, source));
	//DEFINE(IA64_TIME_INTERPOLATOR_SHIFT_OFFSET, offsetof (struct time_interpolator, shift));
	//DEFINE(IA64_TIME_INTERPOLATOR_NSEC_OFFSET, offsetof (struct time_interpolator, nsec_per_cyc));
	//DEFINE(IA64_TIME_INTERPOLATOR_OFFSET_OFFSET, offsetof (struct time_interpolator, offset));
	//DEFINE(IA64_TIME_INTERPOLATOR_LAST_CYCLE_OFFSET, offsetof (struct time_interpolator, last_cycle));
	//DEFINE(IA64_TIME_INTERPOLATOR_LAST_COUNTER_OFFSET, offsetof (struct time_interpolator, last_counter));
	//DEFINE(IA64_TIME_INTERPOLATOR_JITTER_OFFSET, offsetof (struct time_interpolator, jitter));
	//DEFINE(IA64_TIME_INTERPOLATOR_MASK_OFFSET, offsetof (struct time_interpolator, mask));
	//DEFINE(IA64_TIME_SOURCE_CPU, TIME_SOURCE_CPU);
	//DEFINE(IA64_TIME_SOURCE_MMIO64, TIME_SOURCE_MMIO64);
	//DEFINE(IA64_TIME_SOURCE_MMIO32, TIME_SOURCE_MMIO32);
	//DEFINE(IA64_TIMESPEC_TV_NSEC_OFFSET, offsetof (struct timespec, tv_nsec));
	DEFINE(IA64_KR_CURRENT_OFFSET, offsetof (cpu_kr_ia64_t, _kr[IA64_KR_CURRENT]));
	DEFINE(IA64_KR_PT_BASE_OFFSET, offsetof (cpu_kr_ia64_t, _kr[IA64_KR_PT_BASE]));
	DEFINE(IA64_KR_IO_BASE_OFFSET, offsetof (cpu_kr_ia64_t, _kr[IA64_KR_IO_BASE]));
	DEFINE(IA64_KR_PERCPU_DATA_OFFSET, offsetof (cpu_kr_ia64_t, _kr[IA64_KR_PER_CPU_DATA]));
	DEFINE(IA64_KR_IO_BASE_OFFSET, offsetof (cpu_kr_ia64_t, _kr[IA64_KR_IO_BASE]));
	DEFINE(IA64_KR_CURRENT_STACK_OFFSET, offsetof (cpu_kr_ia64_t, _kr[IA64_KR_CURRENT_STACK]));

}
