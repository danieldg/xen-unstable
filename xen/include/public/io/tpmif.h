/******************************************************************************
 * tpmif.h
 *
 * TPM I/O interface for Xen guest OSes.
 *
 * Copyright (c) 2005, IBM Corporation
 *
 * Author: Stefan Berger, stefanb@us.ibm.com
 * Grant table support: Mahadevan Gomathisankaran
 *
 * This code has been derived from tools/libxc/xen/io/netif.h
 *
 * Copyright (c) 2003-2004, Keir Fraser
 */

#ifndef __XEN_PUBLIC_IO_TPMIF_H__
#define __XEN_PUBLIC_IO_TPMIF_H__

typedef struct {
    unsigned long addr;   /* Machine address of packet.   */
    int      ref;         /* grant table access reference */
    u16      id;          /* Echoed in response message.  */
    u16      size:15;     /* Packet size in bytes.        */
    u16      mapped:1;
} tpmif_tx_request_t;

/*
 * The TPMIF_TX_RING_SIZE defines the number of pages the
 * front-end and backend can exchange (= size of array).
 */
typedef u32 TPMIF_RING_IDX;

#define TPMIF_TX_RING_SIZE 16

/* This structure must fit in a memory page. */
typedef struct {
    union {
        tpmif_tx_request_t  req;
    } ring[TPMIF_TX_RING_SIZE];
} tpmif_tx_interface_t;

#endif
