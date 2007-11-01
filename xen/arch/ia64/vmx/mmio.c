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
#include <xen/mm.h>
#include <asm/vmx_mm_def.h>
#include <asm/gcc_intrin.h>
#include <linux/interrupt.h>
#include <asm/vmx_vcpu.h>
#include <asm/bundle.h>
#include <asm/types.h>
#include <public/hvm/ioreq.h>
#include <asm/vmx.h>
#include <public/event_channel.h>
#include <public/xen.h>
#include <linux/event.h>
#include <xen/domain.h>
#include <asm/viosapic.h>
#include <asm/vlsapic.h>
#include <asm/hvm/vacpi.h>

#define HVM_BUFFERED_IO_RANGE_NR 1

struct hvm_buffered_io_range {
    unsigned long start_addr;
    unsigned long length;
};

static struct hvm_buffered_io_range buffered_stdvga_range = {0xA0000, 0x20000};
static struct hvm_buffered_io_range
*hvm_buffered_io_ranges[HVM_BUFFERED_IO_RANGE_NR] =
{
    &buffered_stdvga_range
};

static int hvm_buffered_io_intercept(ioreq_t *p)
{
    struct vcpu *v = current;
    buffered_iopage_t *pg =
        (buffered_iopage_t *)(v->domain->arch.hvm_domain.buffered_io_va);
    buf_ioreq_t bp;
    int i, qw = 0;

    /* Ensure buffered_iopage fits in a page */
    BUILD_BUG_ON(sizeof(buffered_iopage_t) > PAGE_SIZE);

    /* ignore READ ioreq_t and anything buffered io can't deal with */
    if (p->dir == IOREQ_READ || p->addr > 0xFFFFFUL ||
        p->data_is_ptr || p->df || p->count != 1)
        return 0;

    for (i = 0; i < HVM_BUFFERED_IO_RANGE_NR; i++) {
        if (p->addr >= hvm_buffered_io_ranges[i]->start_addr &&
            p->addr + p->size - 1 < hvm_buffered_io_ranges[i]->start_addr +
                                    hvm_buffered_io_ranges[i]->length)
            break;
    }

    if (i == HVM_BUFFERED_IO_RANGE_NR)
        return 0;

    bp.type = p->type;
    bp.dir = p->dir;
    switch (p->size) {
    case 1:
        bp.size = 0;
        break;
    case 2:
        bp.size = 1;
        break;
    case 4:
        bp.size = 2;
        break;
    case 8:
        bp.size = 3;
        qw = 1;
        break;
    default:
        gdprintk(XENLOG_WARNING, "unexpected ioreq size:%"PRId64"\n", p->size);
        return 0;
    }
    bp.data = p->data;
    bp.addr = p->addr;

    spin_lock(&v->domain->arch.hvm_domain.buffered_io_lock);

    if (pg->write_pointer - pg->read_pointer >= IOREQ_BUFFER_SLOT_NUM - qw) {
        /* the queue is full.
         * send the iopacket through the normal path.
         * NOTE: The arithimetic operation could handle the situation for
         * write_pointer overflow.
         */
        spin_unlock(&v->domain->arch.hvm_domain.buffered_io_lock);
        return 0;
    }

    memcpy(&pg->buf_ioreq[pg->write_pointer % IOREQ_BUFFER_SLOT_NUM],
           &bp, sizeof(bp));

    if (qw) {
        bp.data = p->data >> 32;
        memcpy(&pg->buf_ioreq[(pg->write_pointer + 1) % IOREQ_BUFFER_SLOT_NUM],
               &bp, sizeof(bp));
    }

    /* Make the ioreq_t visible before write_pointer */
    wmb();
    pg->write_pointer += qw ? 2 : 1;

    spin_unlock(&v->domain->arch.hvm_domain.buffered_io_lock);

    return 1;
}

static void low_mmio_access(VCPU *vcpu, u64 pa, u64 *val, size_t s, int dir)
{
    struct vcpu *v = current;
    vcpu_iodata_t *vio;
    ioreq_t *p;

    vio = get_vio(v->domain, v->vcpu_id);
    if (!vio)
        panic_domain(NULL, "bad shared page");

    p = &vio->vp_ioreq;

    p->addr = pa;
    p->size = s;
    p->count = 1;
    if (dir == IOREQ_WRITE)
        p->data = *val;
    else
        p->data = 0;
    p->data_is_ptr = 0;
    p->dir = dir;
    p->df = 0;
    p->type = 1;

    p->io_count++;

    if (hvm_buffered_io_intercept(p)) {
        p->state = STATE_IORESP_READY;
        vmx_io_assist(v);
        if (dir != IOREQ_READ)
            return;
    }

    vmx_send_assist_req(v);
    if (dir == IOREQ_READ)
        *val = p->data;

    return;
}

static int vmx_ide_pio_intercept(ioreq_t *p, u64 *val)
{
    struct buffered_piopage *pio_page =
        (void *)(current->domain->arch.hvm_domain.buffered_pio_va);
    struct pio_buffer *piobuf;
    uint32_t pointer, page_offset;

    if (p->addr == 0x1F0)
        piobuf = &pio_page->pio[PIO_BUFFER_IDE_PRIMARY];
    else if (p->addr == 0x170)
        piobuf = &pio_page->pio[PIO_BUFFER_IDE_SECONDARY];
    else
        return 0;

    if (p->size != 2 && p->size != 4)
        return 0;

    pointer = piobuf->pointer;
    page_offset = piobuf->page_offset;

    /* sanity check */
    if (page_offset + pointer < offsetof(struct buffered_piopage, buffer))
        return 0;
    if (page_offset + piobuf->data_end > PAGE_SIZE)
        return 0;

    if (pointer + p->size < piobuf->data_end) {
        uint8_t *bufp = (uint8_t *)pio_page + page_offset + pointer;
        if (p->dir == IOREQ_WRITE) {
            if (likely(p->size == 4 && (((long)bufp & 3) == 0)))
                *(uint32_t *)bufp = *val;
            else
                memcpy(bufp, val, p->size);
        } else {
            if (likely(p->size == 4 && (((long)bufp & 3) == 0))) {
                *val = *(uint32_t *)bufp;
            } else {
                *val = 0;
                memcpy(val, bufp, p->size);
            }
        }
        piobuf->pointer += p->size;
        p->state = STATE_IORESP_READY;
        vmx_io_assist(current);
        return 1;
    }
    return 0;
}

#define TO_LEGACY_IO(pa)  (((pa)>>12<<2)|((pa)&0x3))

static const char * const guest_os_name[] = {
    "Unknown",
    "Windows 2003 server",
    "Linux",
};

static inline void set_os_type(VCPU *v, u64 type)
{
    if (type > OS_BASE && type < OS_END) {
        v->domain->arch.vmx_platform.gos_type = type;
        gdprintk(XENLOG_INFO, "Guest OS : %s\n", guest_os_name[type - OS_BASE]);

        if (GOS_WINDOWS(v)) {
            struct xen_ia64_opt_feature optf;

            /* Windows identity maps regions 4 & 5 */
            optf.cmd = XEN_IA64_OPTF_IDENT_MAP_REG4;
            optf.on = XEN_IA64_OPTF_ON;
            optf.pgprot = (_PAGE_P|_PAGE_A|_PAGE_D|_PAGE_MA_WB|_PAGE_AR_RW);
            optf.key = 0;
            domain_opt_feature(&optf);

            optf.cmd = XEN_IA64_OPTF_IDENT_MAP_REG5;
            optf.pgprot = (_PAGE_P|_PAGE_A|_PAGE_D|_PAGE_MA_UC|_PAGE_AR_RW);
            domain_opt_feature(&optf);
        }
    }
}


static void legacy_io_access(VCPU *vcpu, u64 pa, u64 *val, size_t s, int dir)
{
    struct vcpu *v = current;
    vcpu_iodata_t *vio;
    ioreq_t *p;

    vio = get_vio(v->domain, v->vcpu_id);
    if (!vio)
        panic_domain(NULL, "bad shared page\n");

    p = &vio->vp_ioreq;
    p->addr = TO_LEGACY_IO(pa & 0x3ffffffUL);
    p->size = s;
    p->count = 1;
    p->dir = dir;
    if (dir == IOREQ_WRITE)
        p->data = *val;
    else
        p->data = 0;
    p->data_is_ptr = 0;
    p->type = 0;
    p->df = 0;

    p->io_count++;
    
    if (dir == IOREQ_WRITE && p->addr == OS_TYPE_PORT) {
        set_os_type(v, *val);
        return;
    }

    if (vmx_ide_pio_intercept(p, val))
        return;

    if (IS_ACPI_ADDR(p->addr) && vacpi_intercept(p, val))
        return;

    vmx_send_assist_req(v);
    if (dir == IOREQ_READ) { // read
        *val=p->data;
    }
#ifdef DEBUG_PCI
    if (dir == IOREQ_WRITE)
        if (p->addr == 0xcf8UL)
            printk("Write 0xcf8, with val [0x%lx]\n", p->data);
    else
        if (p->addr == 0xcfcUL)
            printk("Read 0xcfc, with val [0x%lx]\n", p->data);
#endif //DEBUG_PCI
    return;
}

static void mmio_access(VCPU *vcpu, u64 src_pa, u64 *dest, size_t s, int ma, int dir)
{
    unsigned long iot;
    iot = __gpfn_is_io(vcpu->domain, src_pa >> PAGE_SHIFT);

    perfc_incra(vmx_mmio_access, iot >> 56);
    switch (iot) {
    case GPFN_PIB:       
        if (ma != 4)
            panic_domain(NULL, "Access PIB not with UC attribute\n");

        if (!dir)
            vlsapic_write(vcpu, src_pa, s, *dest);
        else
            *dest = vlsapic_read(vcpu, src_pa, s);
        break;
    case GPFN_GFW:
        break;
    case GPFN_IOSAPIC:
        if (!dir)
            viosapic_write(vcpu, src_pa, s, *dest);
        else
            *dest = viosapic_read(vcpu, src_pa, s);
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
   dir 1: read 0:write
 */
void emulate_io_inst(VCPU *vcpu, u64 padr, u64 ma)
{
    REGS *regs;
    IA64_BUNDLE bundle;
    int slot, dir=0;
    enum { SL_INTEGER, SL_FLOATING, SL_FLOATING_FP8 } inst_type;
    size_t size;
    u64 data, data1, temp, update_reg;
    s32 imm;
    INST64 inst;

    regs = vcpu_regs(vcpu);
    if (IA64_RETRY == __vmx_get_domain_bundle(regs->cr_iip, &bundle)) {
        /* if fetch code fail, return and try again */
        return;
    }
    slot = ((struct ia64_psr *)&(regs->cr_ipsr))->ri;
    if (!slot)
        inst.inst = bundle.slot0;
    else if (slot == 1) {
        u64 slot1b = bundle.slot1b;
        inst.inst = bundle.slot1a + (slot1b << 18);
    }
    else if (slot == 2)
        inst.inst = bundle.slot2;


    // Integer Load/Store
    if (inst.M1.major == 4 && inst.M1.m == 0 && inst.M1.x == 0) {
        inst_type = SL_INTEGER;
        size = (inst.M1.x6 & 0x3);
        if ((inst.M1.x6 >> 2) > 0xb) {
            dir = IOREQ_WRITE;
            vcpu_get_gr_nat(vcpu, inst.M4.r2, &data);
        } else if ((inst.M1.x6 >> 2) < 0xb) {
            dir = IOREQ_READ;
        }
    }
    // Integer Load + Reg update
    else if (inst.M2.major == 4 && inst.M2.m == 1 && inst.M2.x == 0) {
        inst_type = SL_INTEGER;
        dir = IOREQ_READ;
        size = (inst.M2.x6 & 0x3);
        vcpu_get_gr_nat(vcpu, inst.M2.r3, &temp);
        vcpu_get_gr_nat(vcpu, inst.M2.r2, &update_reg);
        temp += update_reg;
        vcpu_set_gr(vcpu, inst.M2.r3, temp, 0);
    }
    // Integer Load/Store + Imm update
    else if (inst.M3.major == 5) {
        inst_type = SL_INTEGER;
        size = (inst.M3.x6 & 0x3);
        if ((inst.M5.x6 >> 2) > 0xb) {
            dir = IOREQ_WRITE;
            vcpu_get_gr_nat(vcpu, inst.M5.r2, &data);
            vcpu_get_gr_nat(vcpu, inst.M5.r3, &temp);
            imm = (inst.M5.s << 31) | (inst.M5.i << 30) | (inst.M5.imm7 << 23);
            temp += imm >> 23;
            vcpu_set_gr(vcpu, inst.M5.r3, temp, 0);
        } else if ((inst.M3.x6 >> 2) < 0xb) {
            dir = IOREQ_READ;
            vcpu_get_gr_nat(vcpu, inst.M3.r3, &temp);
            imm = (inst.M3.s << 31) | (inst.M3.i << 30) | (inst.M3.imm7 << 23);
            temp += imm >> 23;
            vcpu_set_gr(vcpu, inst.M3.r3, temp, 0);
        }
    }
    // Floating-point spill
    else if (inst.M9.major == 6 && inst.M9.x6 == 0x3B &&
             inst.M9.m == 0 && inst.M9.x == 0) {
        struct ia64_fpreg v;

        inst_type = SL_FLOATING;
        dir = IOREQ_WRITE;
        vcpu_get_fpreg(vcpu, inst.M9.f2, &v);
        data1 = v.u.bits[1] & 0x3ffff;
        data = v.u.bits[0];
        size = 4;
    }
    // Floating-point spill + Imm update
    else if (inst.M10.major == 7 && inst.M10.x6 == 0x3B) {
        struct ia64_fpreg v;

        inst_type = SL_FLOATING;
        dir = IOREQ_WRITE;
        vcpu_get_fpreg(vcpu, inst.M10.f2, &v);
        vcpu_get_gr_nat(vcpu, inst.M10.r3, &temp);
        imm = (inst.M10.s << 31) | (inst.M10.i << 30) | (inst.M10.imm7 << 23);
        temp += imm >> 23;
        vcpu_set_gr(vcpu, inst.M10.r3, temp, 0);
        data1 = v.u.bits[1] & 0x3ffff;
        data = v.u.bits[0];
        size = 4;
    }
    // Floating-point stf8 + Imm update
    else if (inst.M10.major == 7 && inst.M10.x6 == 0x31) {
        struct ia64_fpreg v;

        inst_type = SL_FLOATING;
        dir = IOREQ_WRITE;
        size = 3;
        vcpu_get_fpreg(vcpu, inst.M10.f2, &v);
        data = v.u.bits[0]; /* Significand.  */
        vcpu_get_gr_nat(vcpu, inst.M10.r3, &temp);
        imm = (inst.M10.s << 31) | (inst.M10.i << 30) | (inst.M10.imm7 << 23);
        temp += imm >> 23;
        vcpu_set_gr(vcpu, inst.M10.r3, temp, 0);
    }
    //  lfetch - do not perform accesses.
    else if (inst.M15.major== 7 && inst.M15.x6 >=0x2c && inst.M15.x6 <= 0x2f) {
        vcpu_get_gr_nat(vcpu, inst.M15.r3, &temp);
        imm = (inst.M15.s << 31) | (inst.M15.i << 30) | (inst.M15.imm7 << 23);
        temp += imm >> 23;
        vcpu_set_gr(vcpu, inst.M15.r3, temp, 0);

        vcpu_increment_iip(vcpu);
        return;
    }
    // Floating-point Load Pair + Imm ldfp8 M12
    else if (inst.M12.major == 6 && inst.M12.m == 1
             && inst.M12.x == 1 && inst.M12.x6 == 1) {
        inst_type = SL_FLOATING_FP8;
        dir = IOREQ_READ;
        size = 4;     //ldfd
        vcpu_set_gr(vcpu,inst.M12.r3,padr + 16, 0);
    }
    else {
        panic_domain
            (NULL, "This memory access instr can't be emulated: %lx pc=%lx\n",
             inst.inst, regs->cr_iip);
    }

    if (size == 4) {
        mmio_access(vcpu, padr + 8, &data1, 1 << 3, ma, dir);
        size = 3;
    }
    mmio_access(vcpu, padr, &data, 1 << size, ma, dir);

    if (dir == IOREQ_READ) {
        if (inst_type == SL_INTEGER) {
            vcpu_set_gr(vcpu, inst.M1.r1, data, 0);
        } else if (inst_type == SL_FLOATING_FP8) {
            struct ia64_fpreg v;

            v.u.bits[0] = data;
            v.u.bits[1] = 0x1003E;
            vcpu_set_fpreg(vcpu, inst.M12.f1, &v);
            v.u.bits[0] = data1;
            v.u.bits[1] = 0x1003E;
            vcpu_set_fpreg(vcpu, inst.M12.f2, &v);
        } else {
            panic_domain(NULL, "Don't support ldfd now !");
        }
    }
    vcpu_increment_iip(vcpu);
}
