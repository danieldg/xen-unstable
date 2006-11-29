
/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vlsapic.c: virtual lsapic model including ITC timer.
 * Copyright (c) 2005, Intel Corporation.
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
 *  Yaozu Dong (Eddie Dong) (Eddie.dong@intel.com)
 */

#include <linux/sched.h>
#include <public/xen.h>
#include <asm/ia64_int.h>
#include <asm/vcpu.h>
#include <asm/regionreg.h>
#include <asm/tlb.h>
#include <asm/processor.h>
#include <asm/delay.h>
#include <asm/vmx_vcpu.h>
#include <asm/vmx_vcpu.h>
#include <asm/regs.h>
#include <asm/gcc_intrin.h>
#include <asm/vmx_mm_def.h>
#include <asm/vmx.h>
#include <asm/hw_irq.h>
#include <asm/vmx_pal_vsa.h>
#include <asm/kregs.h>
#include <asm/vmx_platform.h>
#include <asm/viosapic.h>
#include <asm/linux/jiffies.h>

//u64  fire_itc;
//u64  fire_itc2;
//u64  fire_itm;
//u64  fire_itm2;
/*
 * Update the checked last_itc.
 */

extern void vmx_reflect_interruption(u64 ifa, u64 isr, u64 iim,
                                     u64 vector, REGS *regs);
static void update_last_itc(vtime_t *vtm, uint64_t cur_itc)
{
    vtm->last_itc = cur_itc;
}

/*
 * Next for vLSapic
 */

#define NMI_VECTOR		2
#define ExtINT_VECTOR		0
#define NULL_VECTOR		-1

static void update_vhpi(VCPU *vcpu, int vec)
{
    u64 vhpi;

    if (vec == NULL_VECTOR)
        vhpi = 0;
    else if (vec == NMI_VECTOR)
        vhpi = 32;
    else if (vec == ExtINT_VECTOR)
        vhpi = 16;
    else
        vhpi = vec >> 4;

    VCPU(vcpu,vhpi) = vhpi;
    // TODO: Add support for XENO
    if (VCPU(vcpu,vac).a_int)
        ia64_call_vsa(PAL_VPS_SET_PENDING_INTERRUPT, 
                      (uint64_t)vcpu->arch.privregs, 0, 0, 0, 0, 0, 0);
}


/*
 * May come from virtualization fault or
 * nested host interrupt.
 */
static int vmx_vcpu_unpend_interrupt(VCPU *vcpu, uint8_t vector)
{
    uint64_t spsr;
    int ret;

    if (vector & ~0xff) {
        dprintk(XENLOG_WARNING, "vmx_vcpu_pend_interrupt: bad vector\n");
        return -1;
    }

    local_irq_save(spsr);
    ret = test_and_clear_bit(vector, &VCPU(vcpu, irr[0]));
    local_irq_restore(spsr);

    if (ret)
        vcpu->arch.irq_new_pending = 1;

    return ret;
}

/*
 * ITC value saw in guest (host+offset+drift).
 */
static uint64_t now_itc(vtime_t *vtm)
{
        uint64_t guest_itc=vtm->vtm_offset+ia64_get_itc();
        
        if ( vtm->vtm_local_drift ) {
//          guest_itc -= vtm->vtm_local_drift;
        }       
        if (guest_itc >= vtm->last_itc)
            return guest_itc;
        else
            /* guest ITC backwarded due after LP switch */
            return vtm->last_itc;
}

/*
 * Interval time components reset.
 */
static void vtm_reset(VCPU *vcpu)
{
    int i;
    u64 vtm_offset;
    VCPU *v;
    struct domain *d = vcpu->domain;
    vtime_t *vtm = &VMX(vcpu, vtm);

    if (vcpu->vcpu_id == 0) {
        vtm_offset = 0UL - ia64_get_itc();
        for (i = MAX_VIRT_CPUS - 1; i >= 0; i--) {
            if ((v = d->vcpu[i]) != NULL) {
                VMX(v, vtm).vtm_offset = vtm_offset;
                VMX(v, vtm).last_itc = 0;
            }
        }
    }
    vtm->vtm_local_drift = 0;
    VCPU(vcpu, itm) = 0;
    VCPU(vcpu, itv) = 0x10000;
    vtm->last_itc = 0;
}

/* callback function when vtm_timer expires */
static void vtm_timer_fn(void *data)
{
    VCPU *vcpu = data;
    vtime_t *vtm = &VMX(vcpu, vtm);
    u64 vitv;

    vitv = VCPU(vcpu, itv);
    if (!ITV_IRQ_MASK(vitv)) {
        vmx_vcpu_pend_interrupt(vcpu, ITV_VECTOR(vitv));
        vcpu_unblock(vcpu);
    } else
        vtm->pending = 1;

    update_last_itc(vtm, VCPU(vcpu, itm));  // update vITC
}

void vtm_init(VCPU *vcpu)
{
    vtime_t     *vtm;
    uint64_t    itc_freq;
    
    vtm = &VMX(vcpu, vtm);

    itc_freq = local_cpu_data->itc_freq;
    vtm->cfg_max_jump=itc_freq*MAX_JUMP_STEP/1000;
    vtm->cfg_min_grun=itc_freq*MIN_GUEST_RUNNING_TIME/1000;
    init_timer(&vtm->vtm_timer, vtm_timer_fn, vcpu, vcpu->processor);
    vtm_reset(vcpu);
}

/*
 * Action when guest read ITC.
 */
uint64_t vtm_get_itc(VCPU *vcpu)
{
    uint64_t guest_itc;
    vtime_t *vtm = &VMX(vcpu, vtm);

    guest_itc = now_itc(vtm);
    return guest_itc;
}


void vtm_set_itc(VCPU *vcpu, uint64_t new_itc)
{
    int i;
    uint64_t vitm, vtm_offset;
    vtime_t *vtm;
    VCPU *v;
    struct domain *d = vcpu->domain;

    vitm = VCPU(vcpu, itm);
    vtm = &VMX(vcpu, vtm);
    if (vcpu->vcpu_id == 0) {
        vtm_offset = new_itc - ia64_get_itc();
        for (i = MAX_VIRT_CPUS - 1; i >= 0; i--) {
            if ((v = d->vcpu[i]) != NULL) {
                VMX(v, vtm).vtm_offset = vtm_offset;
                VMX(v, vtm).last_itc = 0;
            }
        }
    }
    vtm->last_itc = 0;
    if (vitm <= new_itc)
        stop_timer(&vtm->vtm_timer);
    else
        vtm_set_itm(vcpu, vitm);
}


#define TIMER_SLOP (50*1000) /* ns */  /* copy from timer.c */
extern u64 cycle_to_ns(u64 cyle);


void vtm_set_itm(VCPU *vcpu, uint64_t val)
{
    vtime_t *vtm;
    uint64_t   vitv, cur_itc, expires;

    vitv = VCPU(vcpu, itv);
    vtm = &VMX(vcpu, vtm);
    VCPU(vcpu, itm) = val;
    if (val > vtm->last_itc) {
        cur_itc = now_itc(vtm);
        if (time_before(val, cur_itc))
            val = cur_itc;
        expires = NOW() + cycle_to_ns(val-cur_itc) + TIMER_SLOP;
        vmx_vcpu_unpend_interrupt(vcpu, ITV_VECTOR(vitv));
        set_timer(&vtm->vtm_timer, expires);
    }else{
        stop_timer(&vtm->vtm_timer);
    }
}


void vtm_set_itv(VCPU *vcpu, uint64_t val)
{
    vtime_t *vtm = &VMX(vcpu, vtm);

    VCPU(vcpu, itv) = val;

    if (!ITV_IRQ_MASK(val) && vtm->pending) {
        vmx_vcpu_pend_interrupt(vcpu, ITV_VECTOR(val));
        vtm->pending = 0;
    }
}


/*
 * Update interrupt or hook the vtm timer for fire
 * At this point vtm_timer should be removed if itv is masked.
 */
/* Interrupt must be disabled at this point */
/*
void vtm_interruption_update(VCPU *vcpu, vtime_t* vtm)
{
    uint64_t    cur_itc,vitm,vitv;
    uint64_t    expires;
    long        diff_now, diff_last;
    uint64_t    spsr;
    
    vitv = VCPU(vcpu, itv);
    if ( ITV_IRQ_MASK(vitv) ) {
        return;
    }
    
    vitm =VCPU(vcpu, itm);
    local_irq_save(spsr);
    cur_itc =now_itc(vtm);
    diff_last = vtm->last_itc - vitm;
    diff_now = cur_itc - vitm;

    if ( diff_last >= 0 ) {
        // interrupt already fired.
        stop_timer(&vtm->vtm_timer);
    }
    else if ( diff_now >= 0 ) {
        // ITV is fired.
        vmx_vcpu_pend_interrupt(vcpu, vitv&0xff);
    }
*/
    /* Both last_itc & cur_itc < itm, wait for fire condition */
/*    else {
        expires = NOW() + cycle_to_ns(0-diff_now) + TIMER_SLOP;
        set_timer(&vtm->vtm_timer, expires);
    }
    local_irq_restore(spsr);
}
 */

/*
 * Action for vtm when the domain is scheduled out.
 * Remove the timer for vtm.
 */
/*
void vtm_domain_out(VCPU *vcpu)
{
    if(!is_idle_domain(vcpu->domain))
	stop_timer(&vcpu->arch.arch_vmx.vtm.vtm_timer);
}
 */
/*
 * Action for vtm when the domain is scheduled in.
 * Fire vtm IRQ or add the timer for vtm.
 */
/*
void vtm_domain_in(VCPU *vcpu)
{
    vtime_t     *vtm;

    if(!is_idle_domain(vcpu->domain)) {
	vtm=&(vcpu->arch.arch_vmx.vtm);
	vtm_interruption_update(vcpu, vtm);
    }
}
 */


void vlsapic_reset(VCPU *vcpu)
{
    int     i;

    VCPU(vcpu, lid) = VCPU_LID(vcpu);
    VCPU(vcpu, ivr) = 0;
    VCPU(vcpu,tpr) = 0x10000;
    VCPU(vcpu, eoi) = 0;
    VCPU(vcpu, irr[0]) = 0;
    VCPU(vcpu, irr[1]) = 0;
    VCPU(vcpu, irr[2]) = 0;
    VCPU(vcpu, irr[3]) = 0;
    VCPU(vcpu, pmv) = 0x10000;
    VCPU(vcpu, cmcv) = 0x10000;
    VCPU(vcpu, lrr0) = 0x10000;   // default reset value?
    VCPU(vcpu, lrr1) = 0x10000;   // default reset value?
    update_vhpi(vcpu, NULL_VECTOR);
    for ( i=0; i<4; i++) {
        VLSAPIC_INSVC(vcpu,i) = 0;
    }

    dprintk(XENLOG_INFO, "VLSAPIC inservice base=%p\n", &VLSAPIC_INSVC(vcpu,0) );
}

/*
 *  Find highest signaled bits in 4 words (long). 
 *
 *  return 0-255: highest bits.
 *          -1 : Not found.
 */
static __inline__ int highest_bits(uint64_t *dat)
{
    uint64_t  bits, bitnum;
    int i;
    
    /* loop for all 256 bits */
    for ( i=3; i >= 0 ; i -- ) {
        bits = dat[i];
        if ( bits ) {
            bitnum = ia64_fls(bits);
            return i*64+bitnum;
        }
    }
   return NULL_VECTOR;
}

/*
 * Return 0-255 for pending irq.
 *        NULL_VECTOR: when no pending.
 */
static int highest_pending_irq(VCPU *vcpu)
{
    if ( VCPU(vcpu, irr[0]) & (1UL<<NMI_VECTOR) ) return NMI_VECTOR;
    if ( VCPU(vcpu, irr[0]) & (1UL<<ExtINT_VECTOR) ) return ExtINT_VECTOR;
    return highest_bits(&VCPU(vcpu, irr[0]));
}

static int highest_inservice_irq(VCPU *vcpu)
{
    if ( VLSAPIC_INSVC(vcpu, 0) & (1UL<<NMI_VECTOR) ) return NMI_VECTOR;
    if ( VLSAPIC_INSVC(vcpu, 0) & (1UL<<ExtINT_VECTOR) ) return ExtINT_VECTOR;
    return highest_bits(&(VLSAPIC_INSVC(vcpu, 0)));
}

/*
 * The pending irq is higher than the inservice one.
 *
 */
static int is_higher_irq(int pending, int inservice)
{
    return ( (pending > inservice) || 
                ((pending != NULL_VECTOR) && (inservice == NULL_VECTOR)) );
}

static int is_higher_class(int pending, int mic)
{
    return ( (pending >> 4) > mic );
}
#if 0
static int is_invalid_irq(int vec)
{
    return (vec == 1 || ((vec <= 14 && vec >= 3)));
}
#endif //shadow it due to no use currently

#define   IRQ_NO_MASKED         0
#define   IRQ_MASKED_BY_VTPR    1
#define   IRQ_MASKED_BY_INSVC   2   // masked by inservice IRQ

/* See Table 5-8 in SDM vol2 for the definition */
static int
_xirq_masked(VCPU *vcpu, int h_pending, int h_inservice)
{
    tpr_t    vtpr;
    
    vtpr.val = VCPU(vcpu, tpr);

    if ( h_inservice == NMI_VECTOR ) {
        return IRQ_MASKED_BY_INSVC;
    }
    if ( h_pending == NMI_VECTOR ) {
        // Non Maskable Interrupt
        return IRQ_NO_MASKED;
    }
    if ( h_inservice == ExtINT_VECTOR ) {
        return IRQ_MASKED_BY_INSVC;
    }

    if ( h_pending == ExtINT_VECTOR ) {
        if ( vtpr.mmi ) {
            // mask all external IRQ
            return IRQ_MASKED_BY_VTPR;
        }
        else {
            return IRQ_NO_MASKED;
        }
    }

    if ( is_higher_irq(h_pending, h_inservice) ) {
        if ( is_higher_class(h_pending, vtpr.mic + (vtpr.mmi << 4)) ) {
            return IRQ_NO_MASKED;
        }
        else {
            return IRQ_MASKED_BY_VTPR;
        }
    }
    else {
        return IRQ_MASKED_BY_INSVC;
    }
}

static int irq_masked(VCPU *vcpu, int h_pending, int h_inservice)
{
    int mask;
    
    mask = _xirq_masked(vcpu, h_pending, h_inservice);
    return mask;
}


/*
 * May come from virtualization fault or
 * nested host interrupt.
 */
int vmx_vcpu_pend_interrupt(VCPU *vcpu, uint8_t vector)
{
    uint64_t    spsr;
    int ret;

    if (vector & ~0xff) {
        gdprintk(XENLOG_INFO, "vmx_vcpu_pend_interrupt: bad vector\n");
        return -1;
    }
    local_irq_save(spsr);
    ret = test_and_set_bit(vector, &VCPU(vcpu, irr[0]));
    local_irq_restore(spsr);

    if (!ret)
        vcpu->arch.irq_new_pending = 1;

    return ret;
}


/*
 * Add batch of pending interrupt.
 * The interrupt source is contained in pend_irr[0-3] with
 * each bits stand for one interrupt.
 */
void vmx_vcpu_pend_batch_interrupt(VCPU *vcpu, u64 *pend_irr)
{
    uint64_t    spsr;
    int     i;

    local_irq_save(spsr);
    for (i=0 ; i<4; i++ ) {
        VCPU(vcpu,irr[i]) |= pend_irr[i];
    }
    local_irq_restore(spsr);
    vcpu->arch.irq_new_pending = 1;
}

/*
 * If the new pending interrupt is enabled and not masked, we directly inject 
 * it into the guest. Otherwise, we set the VHPI if vac.a_int=1 so that when 
 * the interrupt becomes unmasked, it gets injected.
 * RETURN:
 *    the highest unmasked interrupt.
 *
 * Optimization: We defer setting the VHPI until the EOI time, if a higher 
 *               priority interrupt is in-service. The idea is to reduce the 
 *               number of unnecessary calls to inject_vhpi.
 */
int vmx_check_pending_irq(VCPU *vcpu)
{
    int  mask, h_pending, h_inservice;
    uint64_t isr;
    IA64_PSR vpsr;
    REGS *regs=vcpu_regs(vcpu);
    h_pending = highest_pending_irq(vcpu);
    if ( h_pending == NULL_VECTOR ) {
        update_vhpi(vcpu, NULL_VECTOR);
        h_pending = SPURIOUS_VECTOR;
        goto chk_irq_exit;
    }
    h_inservice = highest_inservice_irq(vcpu);

    vpsr.val = VCPU(vcpu, vpsr);
    mask = irq_masked(vcpu, h_pending, h_inservice);
    if (  vpsr.i && IRQ_NO_MASKED == mask ) {
        isr = vpsr.val & IA64_PSR_RI;
        if ( !vpsr.ic )
            panic_domain(regs,"Interrupt when IC=0\n");
        update_vhpi(vcpu, h_pending);
        vmx_reflect_interruption(0, isr, 0, 12, regs); // EXT IRQ
    } else if (mask == IRQ_MASKED_BY_INSVC) {
        if (VCPU(vcpu, vhpi))
            update_vhpi(vcpu, NULL_VECTOR);
    }
    else {
        // masked by vpsr.i or vtpr.
        update_vhpi(vcpu,h_pending);
    }

chk_irq_exit:
    return h_pending;
}

/*
 * Only coming from virtualization fault.
 */
void guest_write_eoi(VCPU *vcpu)
{
    int vec;

    vec = highest_inservice_irq(vcpu);
    if ( vec == NULL_VECTOR ) 
        panic_domain(vcpu_regs(vcpu), "Wrong vector to EOI\n");
    VLSAPIC_INSVC(vcpu,vec>>6) &= ~(1UL <<(vec&63));
    VCPU(vcpu, eoi)=0;    // overwrite the data
    vcpu->arch.irq_new_pending=1;
}

int is_unmasked_irq(VCPU *vcpu)
{
    int h_pending, h_inservice;

    h_pending = highest_pending_irq(vcpu);
    h_inservice = highest_inservice_irq(vcpu);
    if ( h_pending == NULL_VECTOR || 
        irq_masked(vcpu, h_pending, h_inservice) != IRQ_NO_MASKED ) {
        return 0;
    }
    else
        return 1;
}

uint64_t guest_read_vivr(VCPU *vcpu)
{
    int vec, h_inservice, mask;
    vec = highest_pending_irq(vcpu);
    h_inservice = highest_inservice_irq(vcpu);
    mask = irq_masked(vcpu, vec, h_inservice);
    if (vec == NULL_VECTOR || mask == IRQ_MASKED_BY_INSVC) {
        if (VCPU(vcpu, vhpi))
            update_vhpi(vcpu, NULL_VECTOR);
        return IA64_SPURIOUS_INT_VECTOR;
    }
    if (mask == IRQ_MASKED_BY_VTPR) {
        update_vhpi(vcpu, vec);
        return IA64_SPURIOUS_INT_VECTOR;
    }
    VLSAPIC_INSVC(vcpu,vec>>6) |= (1UL <<(vec&63));
    vmx_vcpu_unpend_interrupt(vcpu, vec);
    return (uint64_t)vec;
}

static void generate_exirq(VCPU *vcpu)
{
    IA64_PSR    vpsr;
    uint64_t    isr;
    REGS *regs=vcpu_regs(vcpu);
    vpsr.val = VCPU(vcpu, vpsr);
    isr = vpsr.val & IA64_PSR_RI;
    if ( !vpsr.ic )
        panic_domain(regs,"Interrupt when IC=0\n");
    vmx_reflect_interruption(0,isr,0, 12, regs); // EXT IRQ
}

void vhpi_detection(VCPU *vcpu)
{
    uint64_t    threshold,vhpi;
    tpr_t       vtpr;
    IA64_PSR    vpsr;
    vpsr.val = VCPU(vcpu, vpsr);
    vtpr.val = VCPU(vcpu, tpr);

    threshold = ((!vpsr.i) << 5) | (vtpr.mmi << 4) | vtpr.mic;
    vhpi = VCPU(vcpu,vhpi);
    if ( vhpi > threshold ) {
        // interrupt actived
        generate_exirq (vcpu);
    }
}

void vmx_vexirq(VCPU *vcpu)
{
    generate_exirq (vcpu);
}

struct vcpu * vlsapic_lid_to_vcpu(struct domain *d, uint16_t dest)
{
    struct vcpu * v;
    for_each_vcpu ( d, v ) {
        if ( (v->arch.privregs->lid >> 16) == dest )
            return v;
    }
    return NULL;
}                                     
