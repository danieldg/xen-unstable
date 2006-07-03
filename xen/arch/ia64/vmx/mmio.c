
/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * mmio.c: MMIO emulation components.
 * Copyright (c) 2004, Intel Corporation.
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
 *  Kun Tian (Kevin Tian) (Kevin.tian@intel.com)
 */

#include <linux/sched.h>
#include <asm/tlb.h>
#include <asm/vmx_mm_def.h>
#include <asm/gcc_intrin.h>
#include <linux/interrupt.h>
#include <asm/vmx_vcpu.h>
#include <asm/bundle.h>
#include <asm/types.h>
#include <public/hvm/ioreq.h>
#include <asm/mm.h>
#include <asm/vmx.h>
#include <public/event_channel.h>
#include <public/arch-ia64.h>
#include <linux/event.h>
#include <xen/domain.h>
/*
struct mmio_list *lookup_mmio(u64 gpa, struct mmio_list *mio_base)
{
    int     i;
    for (i=0; mio_base[i].iot != NOT_IO; i++ ) {
        if ( gpa >= mio_base[i].start && gpa <= mio_base[i].end )
            return &mio_base[i];
    }
    return NULL;
}
*/

#define	PIB_LOW_HALF(ofst)	!(ofst&(1<<20))
#define PIB_OFST_INTA           0x1E0000
#define PIB_OFST_XTP            0x1E0008

static void write_ipi (VCPU *vcpu, uint64_t addr, uint64_t value);

static void pib_write(VCPU *vcpu, void *src, uint64_t pib_off, size_t s, int ma)
{
    switch (pib_off) {
    case PIB_OFST_INTA:
        panic_domain(NULL,"Undefined write on PIB INTA\n");
        break;
    case PIB_OFST_XTP:
        if ( s == 1 && ma == 4 /* UC */) {
            vmx_vcpu_get_plat(vcpu)->xtp = *(uint8_t *)src;
        }
        else {
            panic_domain(NULL,"Undefined write on PIB XTP\n");
        }
        break;
    default:
        if ( PIB_LOW_HALF(pib_off) ) {   // lower half
            if ( s != 8 || ma != 0x4 /* UC */ ) {
                panic_domain
		  (NULL,"Undefined IPI-LHF write with s %ld, ma %d!\n", s, ma);
            }
            else {
                write_ipi(vcpu, pib_off, *(uint64_t *)src);
                // TODO for SM-VP
            }
        }
        else {      // upper half
            printf("IPI-UHF write %lx\n",pib_off);
            panic_domain(NULL,"Not support yet for SM-VP\n");
        }
        break;
    }
}

static void pib_read(VCPU *vcpu, uint64_t pib_off, void *dest, size_t s, int ma)
{
    switch (pib_off) {
    case PIB_OFST_INTA:
        // todo --- emit on processor system bus.
        if ( s == 1 && ma == 4) { // 1 byte load
            // TODO: INTA read from IOSAPIC
        }
        else {
            panic_domain(NULL,"Undefined read on PIB INTA\n");
        }
        break;
    case PIB_OFST_XTP:
        if ( s == 1 && ma == 4) {
            *((uint8_t*)dest) = vmx_vcpu_get_plat(vcpu)->xtp;
        }
        else {
            panic_domain(NULL,"Undefined read on PIB XTP\n");
        }
        break;
    default:
        if ( PIB_LOW_HALF(pib_off) ) {   // lower half
            if ( s != 8 || ma != 4 ) {
                panic_domain(NULL,"Undefined IPI-LHF read!\n");
            }
            else {
#ifdef  IPI_DEBUG
                printf("IPI-LHF read %lx\n",pib_off);
#endif
                *(uint64_t *)dest = 0;  // TODO for SM-VP
            }
        }
        else {      // upper half
            if ( s != 1 || ma != 4 ) {
                panic_domain(NULL,"Undefined PIB-UHF read!\n");
            }
            else {
#ifdef  IPI_DEBUG
                printf("IPI-UHF read %lx\n",pib_off);
#endif
                *(uint8_t *)dest = 0;   // TODO for SM-VP
            }
        }
        break;
    }
}

static void low_mmio_access(VCPU *vcpu, u64 pa, u64 *val, size_t s, int dir)
{
    struct vcpu *v = current;
    vcpu_iodata_t *vio;
    ioreq_t *p;

    vio = get_vio(v->domain, v->vcpu_id);
    if (vio == 0) {
        panic_domain(NULL,"bad shared page: %lx", (unsigned long)vio);
    }
    p = &vio->vp_ioreq;
    p->addr = pa;
    p->size = s;
    p->count = 1;
    p->dir = dir;
    if(dir==IOREQ_WRITE)     //write;
        p->u.data = *val;
    p->pdata_valid = 0;
    p->type = 1;
    p->df = 0;

    set_bit(ARCH_VMX_IO_WAIT, &v->arch.arch_vmx.flags);
    p->state = STATE_IOREQ_READY;
    evtchn_send(iopacket_port(v));
    vmx_wait_io();
    if(dir==IOREQ_READ){ //read
        *val=p->u.data;
    }
    return;
}
#define TO_LEGACY_IO(pa)  (((pa)>>12<<2)|((pa)&0x3))

static void legacy_io_access(VCPU *vcpu, u64 pa, u64 *val, size_t s, int dir)
{
    struct vcpu *v = current;
    vcpu_iodata_t *vio;
    ioreq_t *p;

    vio = get_vio(v->domain, v->vcpu_id);
    if (vio == 0) {
        panic_domain(NULL,"bad shared page\n");
    }
    p = &vio->vp_ioreq;
    p->addr = TO_LEGACY_IO(pa&0x3ffffffUL);
    p->size = s;
    p->count = 1;
    p->dir = dir;
    if(dir==IOREQ_WRITE)     //write;
        p->u.data = *val;
    p->pdata_valid = 0;
    p->type = 0;
    p->df = 0;

    set_bit(ARCH_VMX_IO_WAIT, &v->arch.arch_vmx.flags);
    p->state = STATE_IOREQ_READY;
    evtchn_send(iopacket_port(v));

    vmx_wait_io();
    if(dir==IOREQ_READ){ //read
        *val=p->u.data;
    }
#ifdef DEBUG_PCI
    if(dir==IOREQ_WRITE)
        if(p->addr == 0xcf8UL)
            printk("Write 0xcf8, with val [0x%lx]\n", p->u.data);
    else
        if(p->addr == 0xcfcUL)
            printk("Read 0xcfc, with val [0x%lx]\n", p->u.data);
#endif //DEBUG_PCI
    return;
}

extern struct vmx_mmio_handler vioapic_mmio_handler;
static void mmio_access(VCPU *vcpu, u64 src_pa, u64 *dest, size_t s, int ma, int dir)
{
    struct virtual_platform_def *v_plat;
    //mmio_type_t iot;
    unsigned long iot;
    struct vmx_mmio_handler *vioapic_handler = &vioapic_mmio_handler;
    iot=__gpfn_is_io(vcpu->domain, src_pa>>PAGE_SHIFT);
    v_plat = vmx_vcpu_get_plat(vcpu);

    switch (iot) {
    case GPFN_PIB:
        if(!dir)
            pib_write(vcpu, dest, src_pa - v_plat->pib_base, s, ma);
        else
            pib_read(vcpu, src_pa - v_plat->pib_base, dest, s, ma);
        break;
    case GPFN_GFW:
        break;
    case GPFN_IOSAPIC:
	if (!dir)
	    vioapic_handler->write_handler(vcpu, src_pa, s, *dest);
	else
	    *dest = vioapic_handler->read_handler(vcpu, src_pa, s);
	break;
    case GPFN_FRAME_BUFFER:
    case GPFN_LOW_MMIO:
        low_mmio_access(vcpu, src_pa, dest, s, dir);
        break;
    case GPFN_LEGACY_IO:
        legacy_io_access(vcpu, src_pa, dest, s, dir);
        break;
    default:
        panic_domain(NULL,"Bad I/O access\n");
        break;
    }
    return;
}

/*
 * Read or write data in guest virtual address mode.
 */
/*
void
memwrite_v(VCPU *vcpu, thash_data_t *vtlb, u64 *src, u64 *dest, size_t s)
{
    uint64_t pa;

    if (!vtlb->nomap)
        panic("Normal memory write shouldn't go to this point!");
    pa = PPN_2_PA(vtlb->ppn);
    pa += POFFSET((u64)dest, vtlb->ps);
    mmio_write (vcpu, src, pa, s, vtlb->ma);
}


void
memwrite_p(VCPU *vcpu, u64 *src, u64 *dest, size_t s)
{
    uint64_t pa = (uint64_t)dest;
    int    ma;

    if ( pa & (1UL <<63) ) {
        // UC
        ma = 4;
        pa <<=1;
        pa >>=1;
    }
    else {
        // WBL
        ma = 0;     // using WB for WBL
    }
    mmio_write (vcpu, src, pa, s, ma);
}

void
memread_v(VCPU *vcpu, thash_data_t *vtlb, u64 *src, u64 *dest, size_t s)
{
    uint64_t pa;

    if (!vtlb->nomap)
        panic_domain(NULL,"Normal memory write shouldn't go to this point!");
    pa = PPN_2_PA(vtlb->ppn);
    pa += POFFSET((u64)src, vtlb->ps);

    mmio_read(vcpu, pa, dest, s, vtlb->ma);
}

void
memread_p(VCPU *vcpu, u64 *src, u64 *dest, size_t s)
{
    uint64_t pa = (uint64_t)src;
    int    ma;

    if ( pa & (1UL <<63) ) {
        // UC
        ma = 4;
        pa <<=1;
        pa >>=1;
    }
    else {
        // WBL
        ma = 0;     // using WB for WBL
    }
    mmio_read(vcpu, pa, dest, s, ma);
}
*/


/*
 * Deliver IPI message. (Only U-VP is supported now)
 *  offset: address offset to IPI space.
 *  value:  deliver value.
 */
static void deliver_ipi (VCPU *vcpu, uint64_t dm, uint64_t vector)
{
#ifdef  IPI_DEBUG
  printf ("deliver_ipi %lx %lx\n",dm,vector);
#endif
    switch ( dm ) {
    case 0:     // INT
        vmx_vcpu_pend_interrupt (vcpu, vector);
        break;
    case 2:     // PMI
        // TODO -- inject guest PMI
        panic_domain (NULL, "Inject guest PMI!\n");
        break;
    case 4:     // NMI
        vmx_vcpu_pend_interrupt (vcpu, 2);
        break;
    case 5:     // INIT
        // TODO -- inject guest INIT
        panic_domain (NULL, "Inject guest INIT!\n");
        break;
    case 7:     // ExtINT
        vmx_vcpu_pend_interrupt (vcpu, 0);
        break;
    case 1:
    case 3:
    case 6:
    default:
        panic_domain (NULL, "Deliver reserved IPI!\n");
        break;
    }
}

/*
 * TODO: Use hash table for the lookup.
 */
static inline VCPU *lid_2_vcpu (struct domain *d, u64 id, u64 eid)
{
    int   i;
    VCPU  *vcpu;
    LID   lid;
    for (i=0; i<MAX_VIRT_CPUS; i++) {
        vcpu = d->vcpu[i];
        if (!vcpu)
            continue;
        lid.val = VCPU_LID(vcpu);
        if ( lid.id == id && lid.eid == eid )
            return vcpu;
    }
    return NULL;
}

/*
 * execute write IPI op.
 */
static void write_ipi (VCPU *vcpu, uint64_t addr, uint64_t value)
{
    VCPU   *targ;
    struct domain *d=vcpu->domain; 
    targ = lid_2_vcpu(vcpu->domain, 
           ((ipi_a_t)addr).id, ((ipi_a_t)addr).eid);
    if ( targ == NULL ) panic_domain (NULL,"Unknown IPI cpu\n");

    if (!test_bit(_VCPUF_initialised, &targ->vcpu_flags)) {
        struct pt_regs *targ_regs = vcpu_regs (targ);
        struct vcpu_guest_context c;

        printf ("arch_boot_vcpu: %p %p\n",
                (void *)d->arch.boot_rdv_ip,
                (void *)d->arch.boot_rdv_r1);
        memset (&c, 0, sizeof (c));

        c.flags = VGCF_VMX_GUEST;
        if (arch_set_info_guest (targ, &c) != 0) {
            printf ("arch_boot_vcpu: failure\n");
            return;
        }
        /* First or next rendez-vous: set registers.  */
        vcpu_init_regs (targ);
        targ_regs->cr_iip = d->arch.boot_rdv_ip;
        targ_regs->r1 = d->arch.boot_rdv_r1;

        if (test_and_clear_bit(_VCPUF_down,&targ->vcpu_flags)) {
            vcpu_wake(targ);
            printf ("arch_boot_vcpu: vcpu %d awaken %016lx!\n",
                    targ->vcpu_id, targ_regs->cr_iip);
        }
        else
            printf ("arch_boot_vcpu: huu, already awaken!");
    }
    else {
        int running = test_bit(_VCPUF_running,&targ->vcpu_flags);
        deliver_ipi (targ, ((ipi_d_t)value).dm, 
                    ((ipi_d_t)value).vector);
        vcpu_unblock(targ);
        if (running)
            smp_send_event_check_cpu(targ->processor);
    }
    return;
}


/*
   dir 1: read 0:write
    inst_type 0:integer 1:floating point
 */
extern IA64_BUNDLE __vmx_get_domain_bundle(u64 iip);
#define SL_INTEGER  0        // store/load interger
#define SL_FLOATING    1       // store/load floating

void emulate_io_inst(VCPU *vcpu, u64 padr, u64 ma)
{
    REGS *regs;
    IA64_BUNDLE bundle;
    int slot, dir=0, inst_type;
    size_t size;
    u64 data, value,post_update, slot1a, slot1b, temp;
    INST64 inst;
    regs=vcpu_regs(vcpu);
    bundle = __vmx_get_domain_bundle(regs->cr_iip);
    slot = ((struct ia64_psr *)&(regs->cr_ipsr))->ri;
    if (!slot) inst.inst = bundle.slot0;
    else if (slot == 1){
        slot1a=bundle.slot1a;
        slot1b=bundle.slot1b;
        inst.inst =slot1a + (slot1b<<18);
    }
    else if (slot == 2) inst.inst = bundle.slot2;


    // Integer Load/Store
    if(inst.M1.major==4&&inst.M1.m==0&&inst.M1.x==0){
        inst_type = SL_INTEGER;  //
        size=(inst.M1.x6&0x3);
        if((inst.M1.x6>>2)>0xb){      // write
            dir=IOREQ_WRITE;     //write
            vcpu_get_gr_nat(vcpu,inst.M4.r2,&data);
        }else if((inst.M1.x6>>2)<0xb){   //  read
            dir=IOREQ_READ;
            vcpu_get_gr_nat(vcpu,inst.M1.r1,&value);
        }
    }
    // Integer Load + Reg update
    else if(inst.M2.major==4&&inst.M2.m==1&&inst.M2.x==0){
        inst_type = SL_INTEGER;
        dir = IOREQ_READ;     //write
        size = (inst.M2.x6&0x3);
        vcpu_get_gr_nat(vcpu,inst.M2.r1,&value);
        vcpu_get_gr_nat(vcpu,inst.M2.r3,&temp);
        vcpu_get_gr_nat(vcpu,inst.M2.r2,&post_update);
        temp += post_update;
        vcpu_set_gr(vcpu,inst.M2.r3,temp,0);
    }
    // Integer Load/Store + Imm update
    else if(inst.M3.major==5){
        inst_type = SL_INTEGER;  //
        size=(inst.M3.x6&0x3);
        if((inst.M5.x6>>2)>0xb){      // write
            dir=IOREQ_WRITE;     //write
            vcpu_get_gr_nat(vcpu,inst.M5.r2,&data);
            vcpu_get_gr_nat(vcpu,inst.M5.r3,&temp);
            post_update = (inst.M5.i<<7)+inst.M5.imm7;
            if(inst.M5.s)
                temp -= post_update;
            else
                temp += post_update;
            vcpu_set_gr(vcpu,inst.M5.r3,temp,0);

        }else if((inst.M3.x6>>2)<0xb){   //  read
            dir=IOREQ_READ;
            vcpu_get_gr_nat(vcpu,inst.M3.r1,&value);
            vcpu_get_gr_nat(vcpu,inst.M3.r3,&temp);
            post_update = (inst.M3.i<<7)+inst.M3.imm7;
            if(inst.M3.s)
                temp -= post_update;
            else
                temp += post_update;
            vcpu_set_gr(vcpu,inst.M3.r3,temp,0);

        }
    }
    // Floating-point spill + Imm update
    else if(inst.M10.major==7&&inst.M10.x6==0x3B){
        struct ia64_fpreg v;
	inst_type=SL_FLOATING;
	dir=IOREQ_WRITE;
	vcpu_get_fpreg(vcpu,inst.M10.f2,&v);
	vcpu_get_gr_nat(vcpu,inst.M10.r3,&temp);
	post_update = (inst.M10.i<<7)+inst.M10.imm7;
	if(inst.M10.s)
            temp -= post_update;
	else
            temp += post_update;
	vcpu_set_gr(vcpu,inst.M10.r3,temp,0);

	/* Write high word.
	   FIXME: this is a kludge!  */
	v.u.bits[1] &= 0x3ffff;
	mmio_access(vcpu, padr + 8, &v.u.bits[1], 8, ma, IOREQ_WRITE);
	data = v.u.bits[0];
	size = 3;
    }
    // Floating-point stf8 + Imm update
    else if(inst.M10.major==7&&inst.M10.x6==0x31){
        struct ia64_fpreg v;
	inst_type=SL_FLOATING;
	dir=IOREQ_WRITE;
	size=3;
	vcpu_get_fpreg(vcpu,inst.M10.f2,&v);
	data = v.u.bits[0]; /* Significand.  */
	vcpu_get_gr_nat(vcpu,inst.M10.r3,&temp);
	post_update = (inst.M10.i<<7)+inst.M10.imm7;
	if(inst.M10.s)
            temp -= post_update;
	else
            temp += post_update;
	vcpu_set_gr(vcpu,inst.M10.r3,temp,0);
    }
//    else if(inst.M6.major==6&&inst.M6.m==0&&inst.M6.x==0&&inst.M6.x6==3){
//        inst_type=SL_FLOATING;  //fp
//        dir=IOREQ_READ;
//        size=3;     //ldfd
//    }
    //  lfetch - do not perform accesses.
    else if(inst.M15.major==7&&inst.M15.x6>=0x2c&&inst.M15.x6<=0x2f){
	vcpu_get_gr_nat(vcpu,inst.M15.r3,&temp);
	post_update = (inst.M15.i<<7)+inst.M15.imm7;
	if(inst.M15.s)
            temp -= post_update;
	else
            temp += post_update;
	vcpu_set_gr(vcpu,inst.M15.r3,temp,0);

	vmx_vcpu_increment_iip(vcpu);
	return;
    }
    // Floating-point Load Pair + Imm ldfp8 M12
    else if(inst.M12.major==6&&inst.M12.m==1&&inst.M12.x==1&&inst.M12.x6==1){
        struct ia64_fpreg v;
        inst_type=SL_FLOATING;
        dir = IOREQ_READ;
        size = 8;     //ldfd
        mmio_access(vcpu, padr, &data, size, ma, dir);
        v.u.bits[0]=data;
        v.u.bits[1]=0x1003E;
        vcpu_set_fpreg(vcpu,inst.M12.f1,&v);
        padr += 8;
        mmio_access(vcpu, padr, &data, size, ma, dir);
        v.u.bits[0]=data;
        v.u.bits[1]=0x1003E;
        vcpu_set_fpreg(vcpu,inst.M12.f2,&v);
        padr += 8;
        vcpu_set_gr(vcpu,inst.M12.r3,padr,0);
        vmx_vcpu_increment_iip(vcpu);
        return;
    }					
    else{
        panic_domain
	  (NULL,"This memory access instr can't be emulated: %lx pc=%lx\n ",
	   inst.inst, regs->cr_iip);
    }

    size = 1 << size;
    if(dir==IOREQ_WRITE){
        mmio_access(vcpu, padr, &data, size, ma, dir);
    }else{
        mmio_access(vcpu, padr, &data, size, ma, dir);
        if(size==1)
            data = (value & 0xffffffffffffff00U) | (data & 0xffU);
        else if(size==2)
            data = (value & 0xffffffffffff0000U) | (data & 0xffffU);
        else if(size==4)
            data = (value & 0xffffffff00000000U) | (data & 0xffffffffU);

        if(inst_type==SL_INTEGER){       //gp
            vcpu_set_gr(vcpu,inst.M1.r1,data,0);
        }else{
            panic_domain(NULL, "Don't support ldfd now !");
/*            switch(inst.M6.f1){

            case 6:
                regs->f6=(struct ia64_fpreg)data;
            case 7:
                regs->f7=(struct ia64_fpreg)data;
            case 8:
                regs->f8=(struct ia64_fpreg)data;
            case 9:
                regs->f9=(struct ia64_fpreg)data;
            case 10:
                regs->f10=(struct ia64_fpreg)data;
            case 11:
                regs->f11=(struct ia64_fpreg)data;
            default :
                ia64_ldfs(inst.M6.f1,&data);
            }
*/
        }
    }
    vmx_vcpu_increment_iip(vcpu);
}
