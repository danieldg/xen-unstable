/******************************************************************************
 * arch/xen/drivers/netif/backend/main.c
 * 
 * Back-end of the driver for virtual block devices. This portion of the
 * driver exports a 'unified' block-device interface that can be accessed
 * by any operating system that implements a compatible front end. A 
 * reference front-end implementation can be found in:
 *  arch/xen/drivers/netif/frontend
 * 
 * Copyright (c) 2002-2004, K A Fraser
 */

#include "common.h"
#include <asm/hypervisor-ifs/dom_mem_ops.h>

static void netif_page_release(struct page *page);
static void make_tx_response(netif_t *netif, 
                             u16      id,
                             s8       st);
static int  make_rx_response(netif_t     *netif, 
                             u16          id, 
                             s8           st,
                             netif_addr_t addr,
                             u16          size);

static void net_tx_action(unsigned long unused);
static DECLARE_TASKLET(net_tx_tasklet, net_tx_action, 0);

static void net_rx_action(unsigned long unused);
static DECLARE_TASKLET(net_rx_tasklet, net_rx_action, 0);

typedef struct {
    u16 id;
    unsigned long old_mach_ptr;
    unsigned long new_mach_pfn;
    netif_t *netif;
} rx_info_t;
static struct sk_buff_head rx_queue;
static multicall_entry_t rx_mcl[NETIF_RX_RING_SIZE*2];
static mmu_update_t rx_mmu[NETIF_RX_RING_SIZE*4];
static unsigned char rx_notify[NR_EVENT_CHANNELS];

/* Don't currently gate addition of an interface to the tx scheduling list. */
#define tx_work_exists(_if) (1)

#define MAX_PENDING_REQS 256
static unsigned long mmap_vstart;
#define MMAP_VADDR(_req) (mmap_vstart + ((_req) * PAGE_SIZE))

#define PKT_PROT_LEN (ETH_HLEN + 20)

static u16 pending_id[MAX_PENDING_REQS];
static netif_t *pending_netif[MAX_PENDING_REQS];
static u16 pending_ring[MAX_PENDING_REQS];
typedef unsigned int PEND_RING_IDX;
#define MASK_PEND_IDX(_i) ((_i)&(MAX_PENDING_REQS-1))
static PEND_RING_IDX pending_prod, pending_cons;
#define NR_PENDING_REQS (MAX_PENDING_REQS - pending_prod + pending_cons)

/* Freed TX SKBs get batched on this ring before return to pending_ring. */
static u16 dealloc_ring[MAX_PENDING_REQS];
static spinlock_t dealloc_lock = SPIN_LOCK_UNLOCKED;
static PEND_RING_IDX dealloc_prod, dealloc_cons;

typedef struct {
    u16 idx;
    netif_tx_request_t req;
    netif_t *netif;
} tx_info_t;
static struct sk_buff_head tx_queue;
static multicall_entry_t tx_mcl[MAX_PENDING_REQS];

static struct list_head net_schedule_list;
static spinlock_t net_schedule_list_lock;

#define MAX_MFN_ALLOC 64
static unsigned long mfn_list[MAX_MFN_ALLOC];
static unsigned int alloc_index = 0;
static spinlock_t mfn_lock = SPIN_LOCK_UNLOCKED;

static void __refresh_mfn_list(void)
{
    int ret;
    dom_mem_op_t op;
    op.op = MEMOP_RESERVATION_INCREASE;
    op.u.increase.size  = MAX_MFN_ALLOC;
    op.u.increase.pages = mfn_list;
    if ( (ret = HYPERVISOR_dom_mem_op(&op)) != MAX_MFN_ALLOC )
    {
        printk(KERN_ALERT "Unable to increase memory reservation (%d)\n", ret);
        BUG();
    }
    alloc_index = MAX_MFN_ALLOC;
}

static unsigned long get_new_mfn(void)
{
    unsigned long mfn, flags;
    spin_lock_irqsave(&mfn_lock, flags);
    if ( alloc_index == 0 )
        __refresh_mfn_list();
    mfn = mfn_list[--alloc_index];
    spin_unlock_irqrestore(&mfn_lock, flags);
    return mfn;
}

static void dealloc_mfn(unsigned long mfn)
{
    unsigned long flags;
    dom_mem_op_t  op;

    spin_lock_irqsave(&mfn_lock, flags);
    if ( alloc_index != MAX_MFN_ALLOC )
    {
        /* Usually we can put the MFN back on the quicklist. */
        mfn_list[alloc_index++] = mfn;
    }
    else
    {
        op.op = MEMOP_RESERVATION_INCREASE;
        op.u.decrease.size  = 1;
        op.u.decrease.pages = &mfn;
        (void)HYPERVISOR_dom_mem_op(&op);
    }
    spin_unlock_irqrestore(&mfn_lock, flags);
}

static inline void maybe_schedule_tx_action(void)
{
    smp_mb();
    if ( (NR_PENDING_REQS < (MAX_PENDING_REQS/2)) &&
         !list_empty(&net_schedule_list) )
        tasklet_schedule(&net_tx_tasklet);
}

/*
 * This is the primary RECEIVE function for a network interface.
 * Note that, from the p.o.v. of /this/ OS it looks like a transmit.
 */
int netif_be_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    netif_t *netif = (netif_t *)dev->priv;

    /* Drop the packet if the target domain has no receive buffers. */
    if ( (netif->rx_req_cons == netif->rx->req_prod) ||
         ((netif->rx_req_cons-netif->rx_resp_prod) == NETIF_RX_RING_SIZE) )
        goto drop;

    /*
     * We do not copy the packet unless:
     *  1. The data is shared; or
     *  2. It spans a page boundary; or
     *  3. We cannot be sure the whole data page is allocated.
     * The copying method is taken from skb_copy().
     * NB. We also couldn't cope with fragmented packets, but we won't get
     *     any because we not advertise the NETIF_F_SG feature.
     */
    if ( skb_shared(skb) || skb_cloned(skb) || 
         (((unsigned long)skb->end ^ (unsigned long)skb->head) & PAGE_MASK) ||
         ((skb->end - skb->head) < (PAGE_SIZE/2)) )
    {
        struct sk_buff *nskb = alloc_skb(PAGE_SIZE-1024, GFP_ATOMIC);
        int hlen = skb->data - skb->head;
        if ( unlikely(nskb == NULL) )
            goto drop;
        skb_reserve(nskb, hlen);
        __skb_put(nskb, skb->len);
        (void)skb_copy_bits(skb, -hlen, nskb->head, hlen + skb->len);
        dev_kfree_skb(skb);
        skb = nskb;
    }

    ((rx_info_t *)&skb->cb[0])->id    =
        netif->rx->ring[MASK_NETIF_RX_IDX(netif->rx_req_cons++)].req.id;
    ((rx_info_t *)&skb->cb[0])->netif = netif;
        
    __skb_queue_tail(&rx_queue, skb);
    tasklet_schedule(&net_rx_tasklet);

    return 0;

 drop:
    netif->stats.rx_dropped++;
    dev_kfree_skb(skb);
    return 0;
}

#if 0
static void xen_network_done_notify(void)
{
    static struct net_device *eth0_dev = NULL;
    if ( unlikely(eth0_dev == NULL) )
        eth0_dev = __dev_get_by_name("eth0");
    netif_rx_schedule(eth0_dev);
}
/* 
 * Add following to poll() function in NAPI driver (Tigon3 is example):
 *  if ( xen_network_done() )
 *      tg3_enable_ints(tp); 
 */
int xen_network_done(void)
{
    return skb_queue_empty(&rx_queue);
}
#endif

static void net_rx_action(unsigned long unused)
{
    netif_t *netif;
    s8 status;
    u16 size, id, evtchn;
    mmu_update_t *mmu = rx_mmu;
    multicall_entry_t *mcl;
    unsigned long vdata, mdata, new_mfn;
    struct sk_buff_head rxq;
    struct sk_buff *skb;
    u16 notify_list[NETIF_RX_RING_SIZE];
    int notify_nr = 0;

    skb_queue_head_init(&rxq);

    mcl = rx_mcl;
    while ( (skb = __skb_dequeue(&rx_queue)) != NULL )
    {
        netif   = ((rx_info_t *)&skb->cb[0])->netif;
        vdata   = (unsigned long)skb->data;
        mdata   = virt_to_machine(vdata);
        new_mfn = get_new_mfn();
        
        mmu[0].ptr  = (new_mfn << PAGE_SHIFT) | MMU_MACHPHYS_UPDATE;
        mmu[0].val  = __pa(vdata) >> PAGE_SHIFT;        
        mmu[1].val  = (unsigned long)(netif->domid<<16) & ~0xFFFFUL;
        mmu[1].ptr  = (unsigned long)(netif->domid<< 0) & ~0xFFFFUL;
        mmu[2].val  = (unsigned long)(netif->domid>>16) & ~0xFFFFUL;
        mmu[2].ptr  = (unsigned long)(netif->domid>>32) & ~0xFFFFUL;
        mmu[1].ptr |= MMU_EXTENDED_COMMAND;
        mmu[1].val |= MMUEXT_SET_SUBJECTDOM_L;
        mmu[2].ptr |= MMU_EXTENDED_COMMAND;
        mmu[2].val |= MMUEXT_SET_SUBJECTDOM_H;
        mmu[3].ptr  = (mdata & PAGE_MASK) | MMU_EXTENDED_COMMAND;
        mmu[3].val  = MMUEXT_REASSIGN_PAGE;

        mcl[0].op = __HYPERVISOR_update_va_mapping;
        mcl[0].args[0] = vdata >> PAGE_SHIFT;
        mcl[0].args[1] = (new_mfn << PAGE_SHIFT) | __PAGE_KERNEL;
        mcl[0].args[2] = 0;
        mcl[1].op = __HYPERVISOR_mmu_update;
        mcl[1].args[0] = (unsigned long)mmu;
        mcl[1].args[1] = 4;
        mcl[1].args[2] = 0;

        mmu += 4;
        mcl += 2;

        ((rx_info_t *)&skb->cb[0])->old_mach_ptr = mdata;
        ((rx_info_t *)&skb->cb[0])->new_mach_pfn = new_mfn;
        __skb_queue_tail(&rxq, skb);

        /* Filled the batch queue? */
        if ( (mcl - rx_mcl) == ARRAY_SIZE(rx_mcl) )
            break;
    }

    if ( mcl == rx_mcl )
        return;

    mcl[-2].args[2] = UVMF_FLUSH_TLB;
    (void)HYPERVISOR_multicall(rx_mcl, mcl - rx_mcl);

    mcl = rx_mcl;
    while ( (skb = __skb_dequeue(&rxq)) != NULL )
    {
        netif   = ((rx_info_t *)&skb->cb[0])->netif;
        size    = skb->tail - skb->data;
        id      = ((rx_info_t *)&skb->cb[0])->id;
        new_mfn = ((rx_info_t *)&skb->cb[0])->new_mach_pfn;
        mdata   = ((rx_info_t *)&skb->cb[0])->old_mach_ptr;

        /* Check the reassignment error code. */
        if ( unlikely(mcl[1].args[5] != 0) )
        {
            DPRINTK("Failed MMU update transferring to DOM%llu\n",
                    netif->domid);
            (void)HYPERVISOR_update_va_mapping(
                (unsigned long)skb->head >> PAGE_SHIFT,
                (pte_t) { (mdata & PAGE_MASK) | __PAGE_KERNEL },
                UVMF_INVLPG);
            dealloc_mfn(new_mfn);
            status = NETIF_RSP_ERROR;
        }
        else
        {
            phys_to_machine_mapping[__pa(skb->data) >> PAGE_SHIFT] = new_mfn;

            atomic_set(&(skb_shinfo(skb)->dataref), 1);
            skb_shinfo(skb)->nr_frags = 0;
            skb_shinfo(skb)->frag_list = NULL;

            netif->stats.rx_bytes += size;
            netif->stats.rx_packets++;

            status = NETIF_RSP_OKAY;
        }

        evtchn = netif->evtchn;
        if ( make_rx_response(netif, id, status, mdata, size) &&
             (rx_notify[evtchn] == 0) )
        {
            rx_notify[evtchn] = 1;
            notify_list[notify_nr++] = evtchn;
        }

        dev_kfree_skb(skb);

        mcl += 2;
    }

    while ( notify_nr != 0 )
    {
        evtchn = notify_list[--notify_nr];
        rx_notify[evtchn] = 0;
        notify_via_evtchn(evtchn);
    }

    /* More work to do? */
    if ( !skb_queue_empty(&rx_queue) )
        tasklet_schedule(&net_rx_tasklet);
#if 0
    else
        xen_network_done_notify();
#endif
}

struct net_device_stats *netif_be_get_stats(struct net_device *dev)
{
    netif_t *netif = dev->priv;
    return &netif->stats;
}

static int __on_net_schedule_list(netif_t *netif)
{
    return netif->list.next != NULL;
}

static void remove_from_net_schedule_list(netif_t *netif)
{
    spin_lock_irq(&net_schedule_list_lock);
    if ( likely(__on_net_schedule_list(netif)) )
    {
        list_del(&netif->list);
        netif->list.next = NULL;
        netif_put(netif);
    }
    spin_unlock_irq(&net_schedule_list_lock);
}

static void add_to_net_schedule_list_tail(netif_t *netif)
{
    if ( __on_net_schedule_list(netif) )
        return;

    spin_lock_irq(&net_schedule_list_lock);
    if ( !__on_net_schedule_list(netif) && (netif->status == CONNECTED) )
    {
        list_add_tail(&netif->list, &net_schedule_list);
        netif_get(netif);
    }
    spin_unlock_irq(&net_schedule_list_lock);
}

static inline void netif_schedule_work(netif_t *netif)
{
    if ( (netif->tx_req_cons != netif->tx->req_prod) &&
         ((netif->tx_req_cons-netif->tx_resp_prod) != NETIF_TX_RING_SIZE) )
    {
        add_to_net_schedule_list_tail(netif);
        maybe_schedule_tx_action();
    }
}

void netif_deschedule(netif_t *netif)
{
    remove_from_net_schedule_list(netif);
}

#if 0
static void tx_credit_callback(unsigned long data)
{
    netif_t *netif = (netif_t *)data;
    netif->remaining_credit = netif->credit_bytes;
    netif_schedule_work(netif);
}
#endif

static void net_tx_action(unsigned long unused)
{
    struct list_head *ent;
    struct sk_buff *skb;
    netif_t *netif;
    netif_tx_request_t txreq;
    u16 pending_idx;
    NETIF_RING_IDX i;
    struct page *page;
    multicall_entry_t *mcl;

    if ( (i = dealloc_cons) == dealloc_prod )
        goto skip_dealloc;

    mcl = tx_mcl;
    while ( i != dealloc_prod )
    {
        pending_idx = dealloc_ring[MASK_PEND_IDX(i++)];
        mcl[0].op = __HYPERVISOR_update_va_mapping;
        mcl[0].args[0] = MMAP_VADDR(pending_idx) >> PAGE_SHIFT;
        mcl[0].args[1] = 0;
        mcl[0].args[2] = 0;
        mcl++;        
    }

    mcl[-1].args[2] = UVMF_FLUSH_TLB;
    (void)HYPERVISOR_multicall(tx_mcl, mcl - tx_mcl);

    while ( dealloc_cons != dealloc_prod )
    {
        pending_idx = dealloc_ring[MASK_PEND_IDX(dealloc_cons++)];

        netif = pending_netif[pending_idx];

        spin_lock(&netif->tx_lock);
        make_tx_response(netif, pending_id[pending_idx], NETIF_RSP_OKAY);
        spin_unlock(&netif->tx_lock);
        
        pending_ring[MASK_PEND_IDX(pending_prod++)] = pending_idx;
        
        /*
         * Scheduling checks must happen after the above response is posted.
         * This avoids a possible race with a guest OS on another CPU.
         */
        mb();
        if ( (netif->tx_req_cons != netif->tx->req_prod) &&
             ((netif->tx_req_cons-netif->tx_resp_prod) != NETIF_TX_RING_SIZE) )
            add_to_net_schedule_list_tail(netif);
        
        netif_put(netif);
    }

 skip_dealloc:
    mcl = tx_mcl;
    while ( (NR_PENDING_REQS < MAX_PENDING_REQS) &&
            !list_empty(&net_schedule_list) )
    {
        /* Get a netif from the list with work to do. */
        ent = net_schedule_list.next;
        netif = list_entry(ent, netif_t, list);
        netif_get(netif);
        remove_from_net_schedule_list(netif);

        /* Work to do? */
        i = netif->tx_req_cons;
        if ( (i == netif->tx->req_prod) ||
             ((i-netif->tx_resp_prod) == NETIF_TX_RING_SIZE) )
        {
            netif_put(netif);
            continue;
        }
        memcpy(&txreq, &netif->tx->ring[MASK_NETIF_TX_IDX(i)].req, 
               sizeof(txreq));
        netif->tx_req_cons++;

#if 0
        /* Credit-based scheduling. */
        if ( tx.size > netif->remaining_credit )
        {
            s_time_t now = NOW(), next_credit = 
                netif->credit_timeout.expires + MICROSECS(netif->credit_usec);
            if ( next_credit <= now )
            {
                netif->credit_timeout.expires = now;
                netif->remaining_credit = netif->credit_bytes;
            }
            else
            {
                netif->remaining_credit = 0;
                netif->credit_timeout.expires  = next_credit;
                netif->credit_timeout.data     = (unsigned long)netif;
                netif->credit_timeout.function = tx_credit_callback;
                netif->credit_timeout.cpu      = smp_processor_id();
                add_ac_timer(&netif->credit_timeout);
                break;
            }
        }
        netif->remaining_credit -= tx.size;
#endif

        netif_schedule_work(netif);

        if ( unlikely(txreq.size <= PKT_PROT_LEN) || 
             unlikely(txreq.size > ETH_FRAME_LEN) )
        {
            DPRINTK("Bad packet size: %d\n", txreq.size);
            make_tx_response(netif, txreq.id, NETIF_RSP_ERROR);
            netif_put(netif);
            continue; 
        }

        /* No crossing a page boundary as the payload mustn't fragment. */
        if ( unlikely(((txreq.addr & ~PAGE_MASK) + txreq.size) >= PAGE_SIZE) ) 
        {
            DPRINTK("txreq.addr: %lx, size: %u, end: %lu\n", 
                    txreq.addr, txreq.size, 
                    (txreq.addr &~PAGE_MASK) + txreq.size);
            make_tx_response(netif, txreq.id, NETIF_RSP_ERROR);
            netif_put(netif);
            continue;
        }

        pending_idx = pending_ring[MASK_PEND_IDX(pending_cons)];

        if ( unlikely((skb = alloc_skb(PKT_PROT_LEN, GFP_ATOMIC)) == NULL) )
        {
            DPRINTK("Can't allocate a skb in start_xmit.\n");
            make_tx_response(netif, txreq.id, NETIF_RSP_ERROR);
            netif_put(netif);
            break;
        }

        mcl[0].op = __HYPERVISOR_update_va_mapping_otherdomain;
        mcl[0].args[0] = MMAP_VADDR(pending_idx) >> PAGE_SHIFT;
        mcl[0].args[1] = (txreq.addr & PAGE_MASK) | __PAGE_KERNEL;
        mcl[0].args[2] = 0;
        mcl[0].args[3] = (unsigned long)netif->domid;
        mcl[0].args[4] = (unsigned long)(netif->domid>>32);
        mcl++;
        
        ((tx_info_t *)&skb->cb[0])->idx = pending_idx;
        ((tx_info_t *)&skb->cb[0])->netif = netif;
        memcpy(&((tx_info_t *)&skb->cb[0])->req, &txreq, sizeof(txreq));
        __skb_queue_tail(&tx_queue, skb);

        pending_cons++;

        /* Filled the batch queue? */
        if ( (mcl - tx_mcl) == ARRAY_SIZE(tx_mcl) )
            break;
    }

    if ( mcl == tx_mcl )
        return;

    (void)HYPERVISOR_multicall(tx_mcl, mcl - tx_mcl);

    mcl = tx_mcl;
    while ( (skb = __skb_dequeue(&tx_queue)) != NULL )
    {
        pending_idx = ((tx_info_t *)&skb->cb[0])->idx;
        netif       = ((tx_info_t *)&skb->cb[0])->netif;
        memcpy(&txreq, &((tx_info_t *)&skb->cb[0])->req, sizeof(txreq));

        /* Check the remap error code. */
        if ( unlikely(mcl[0].args[5] != 0) )
        {
            DPRINTK("Bad page frame\n");
            make_tx_response(netif, txreq.id, NETIF_RSP_ERROR);
            netif_put(netif);
            kfree_skb(skb);
            mcl++;
            pending_ring[MASK_PEND_IDX(pending_prod++)] = pending_idx;
            continue;
        }

        phys_to_machine_mapping[__pa(MMAP_VADDR(pending_idx)) >> PAGE_SHIFT] =
            txreq.addr >> PAGE_SHIFT;

        __skb_put(skb, PKT_PROT_LEN);
        memcpy(skb->data, 
               (void *)(MMAP_VADDR(pending_idx)|(txreq.addr&~PAGE_MASK)),
               PKT_PROT_LEN);

        page = virt_to_page(MMAP_VADDR(pending_idx));

        /* Append the packet payload as a fragment. */
        skb_shinfo(skb)->frags[0].page        = page;
        skb_shinfo(skb)->frags[0].size        = txreq.size - PKT_PROT_LEN;
        skb_shinfo(skb)->frags[0].page_offset = 
            (txreq.addr + PKT_PROT_LEN) & ~PAGE_MASK;
        skb_shinfo(skb)->nr_frags = 1;
        skb->data_len  = txreq.size - PKT_PROT_LEN;
        skb->len      += skb->data_len;

        skb->dev      = netif->dev;
        skb->protocol = eth_type_trans(skb, skb->dev);

        /*
         * Destructor information. We hideously abuse the 'mapping' pointer,
         * which isn't otherwise used by us. The page deallocator is modified
         * to interpret a non-NULL value as a destructor function to be called.
         * This works okay because in all other cases the pointer must be NULL
         * when the page is freed (normally Linux will explicitly bug out if
         * it sees otherwise.
         */
        page->mapping = (struct address_space *)netif_page_release;
        atomic_set(&page->count, 1);
        pending_id[pending_idx] = txreq.id;
        pending_netif[pending_idx] = netif;

        netif->stats.tx_bytes += txreq.size;
        netif->stats.tx_packets++;

        netif_rx(skb);
        netif->dev->last_rx = jiffies;

        mcl++;
    }
}

static void netif_page_release(struct page *page)
{
    unsigned long flags;
    u16 pending_idx = page - virt_to_page(mmap_vstart);

    /* Stop the abuse. */
    page->mapping = NULL;

    spin_lock_irqsave(&dealloc_lock, flags);
    dealloc_ring[MASK_PEND_IDX(dealloc_prod++)] = pending_idx;
    spin_unlock_irqrestore(&dealloc_lock, flags);

    tasklet_schedule(&net_tx_tasklet);
}

#if 0
long flush_bufs_for_netif(netif_t *netif)
{
    NET_RING_IDX i;

    /* Return any outstanding receive buffers to the guest OS. */
    spin_lock(&netif->rx_lock);
    for ( i = netif->rx_req_cons; 
          (i != netif->rx->req_prod) &&
              ((i-netif->rx_resp_prod) != NETIF_RX_RING_SIZE);
          i++ )
    {
        make_rx_response(netif,
                         netif->rx->ring[MASK_NETIF_RX_IDX(i)].req.id,
                         NETIF_RSP_DROPPED, 0, 0);
    }
    netif->rx_req_cons = i;
    spin_unlock(&netif->rx_lock);

    /*
     * Flush pending transmit buffers. The guest may still have to wait for
     * buffers that are queued at a physical NIC.
     */
    spin_lock(&netif->tx_lock);
    for ( i = netif->tx_req_cons; 
          (i != netif->tx->req_prod) &&
              ((i-netif->tx_resp_prod) != NETIF_TX_RING_SIZE);
          i++ )
    {
        make_tx_response(netif,
                         netif->tx->ring[MASK_NETIF_TX_IDX(i)].req.id,
                         NETIF_RSP_DROPPED);
    }
    netif->tx_req_cons = i;
    spin_unlock(&netif->tx_lock);

    return 0;
}
#endif

void netif_be_int(int irq, void *dev_id, struct pt_regs *regs)
{
    netif_t *netif = dev_id;
    if ( tx_work_exists(netif) )
    {
        add_to_net_schedule_list_tail(netif);
        maybe_schedule_tx_action();
    }
}

static void make_tx_response(netif_t *netif, 
                             u16      id,
                             s8       st)
{
    NET_RING_IDX i = netif->tx_resp_prod;
    netif_tx_response_t *resp;

    resp = &netif->tx->ring[MASK_NETIF_TX_IDX(i)].resp;
    resp->id     = id;
    resp->status = st;
    wmb();
    netif->tx->resp_prod = netif->tx_resp_prod = ++i;

    mb(); /* Update producer before checking event threshold. */
    if ( i == netif->tx->event )
        notify_via_evtchn(netif->evtchn);
}

static int make_rx_response(netif_t     *netif, 
                            u16          id, 
                            s8           st,
                            netif_addr_t addr,
                            u16          size)
{
    NET_RING_IDX i = netif->rx_resp_prod;
    netif_rx_response_t *resp;

    resp = &netif->rx->ring[MASK_NETIF_RX_IDX(i)].resp;
    resp->addr   = addr;
    resp->id     = id;
    resp->status = (s16)size;
    if ( st < 0 )
        resp->status = (s16)st;
    wmb();
    netif->rx->resp_prod = netif->rx_resp_prod = ++i;

    mb(); /* Update producer before checking event threshold. */
    return (i == netif->rx->event);
}

static void netif_be_dbg(int irq, void *dev_id, struct pt_regs *regs)
{
    struct list_head *ent;
    netif_t *netif;
    int i = 0;

    printk(KERN_ALERT "netif_schedule_list:\n");
    spin_lock_irq(&net_schedule_list_lock);

    list_for_each ( ent, &net_schedule_list )
    {
        netif = list_entry(ent, netif_t, list);
        printk(KERN_ALERT " %d: private(rx_req_cons=%08x rx_resp_prod=%08x\n",
               i, netif->rx_req_cons, netif->rx_resp_prod);               
        printk(KERN_ALERT "   tx_req_cons=%08x tx_resp_prod=%08x)\n",
               netif->tx_req_cons, netif->tx_resp_prod);
        printk(KERN_ALERT "   shared(rx_req_prod=%08x rx_resp_prod=%08x\n",
               netif->rx->req_prod, netif->rx->resp_prod);
        printk(KERN_ALERT "   rx_event=%08x tx_req_prod=%08x\n",
               netif->rx->event, netif->tx->req_prod);
        printk(KERN_ALERT "   tx_resp_prod=%08x, tx_event=%08x)\n",
               netif->tx->resp_prod, netif->tx->event);
        i++;
    }

    spin_unlock_irq(&net_schedule_list_lock);
    printk(KERN_ALERT " ** End of netif_schedule_list **\n");
}

static int __init init_module(void)
{
    int i;

    if ( !(start_info.flags & SIF_INITDOMAIN) )
        return 0;

    skb_queue_head_init(&rx_queue);
    skb_queue_head_init(&tx_queue);

    netif_interface_init();

    if ( (mmap_vstart = allocate_empty_lowmem_region(MAX_PENDING_REQS)) == 0 )
        BUG();

    pending_cons = 0;
    pending_prod = MAX_PENDING_REQS;
    for ( i = 0; i < MAX_PENDING_REQS; i++ )
        pending_ring[i] = i;

    spin_lock_init(&net_schedule_list_lock);
    INIT_LIST_HEAD(&net_schedule_list);

    netif_ctrlif_init();

    (void)request_irq(bind_virq_to_irq(VIRQ_DEBUG),
                      netif_be_dbg, SA_SHIRQ, 
                      "net-be-dbg", NULL);

    return 0;
}

static void cleanup_module(void)
{
    BUG();
}

module_init(init_module);
module_exit(cleanup_module);
