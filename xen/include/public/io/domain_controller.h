/******************************************************************************
 * domain_controller.h
 * 
 * Interface to server controller (e.g., 'xend'). This header file defines the 
 * interface that is shared with guest OSes.
 * 
 * Copyright (c) 2004, K A Fraser
 */

#ifndef __XEN_PUBLIC_IO_DOMAIN_CONTROLLER_H__
#define __XEN_PUBLIC_IO_DOMAIN_CONTROLLER_H__

#include "ring.h"

/*
 * CONTROLLER MESSAGING INTERFACE.
 */

typedef struct {
    u8 type;     /*  0: echoed in response */
    u8 subtype;  /*  1: echoed in response */
    u8 id;       /*  2: echoed in response */
    u8 length;   /*  3: number of bytes in 'msg' */
    u8 msg[60];  /*  4: type-specific message data */
} PACKED control_msg_t; /* 64 bytes */

/* These are used by the control message deferred ring. */
#define CONTROL_RING_SIZE 8
typedef u32 CONTROL_RING_IDX;
#define MASK_CONTROL_IDX(_i) ((_i)&(CONTROL_RING_SIZE-1))

/*
 * Generate control ring structures and types.
 *
 * CONTROL_RING_MEM is currently an 8-slot ring of ctrl_msg_t structs and
 * two 32-bit counters:  (64 * 8) + (2 * 4) = 520
 */
#define CONTROL_RING_MEM 520
DEFINE_RING_TYPES(ctrl, control_msg_t, control_msg_t);

typedef struct {
    union {
        ctrl_sring_t tx_ring; /*    0: guest -> controller  */
        char __x[CONTROL_RING_MEM];
    } PACKED;
    union {
        ctrl_sring_t rx_ring; /*  520: controller -> guest  */
        char __y[CONTROL_RING_MEM];
    } PACKED;
} PACKED control_if_t; /* 1040 bytes */

/*
 * Top-level command types.
 */
#define CMSG_CONSOLE        0  /* Console                 */
#define CMSG_BLKIF_BE       1  /* Block-device backend    */
#define CMSG_BLKIF_FE       2  /* Block-device frontend   */
#define CMSG_NETIF_BE       3  /* Network-device backend  */
#define CMSG_NETIF_FE       4  /* Network-device frontend */
#define CMSG_SHUTDOWN       6  /* Shutdown messages       */
#define CMSG_MEM_REQUEST    7  /* Memory reservation reqs */
#define CMSG_USBIF_BE       8  /* USB controller backend  */
#define CMSG_USBIF_FE       9  /* USB controller frontend */

/******************************************************************************
 * CONSOLE DEFINITIONS
 */

/*
 * Subtypes for console messages.
 */
#define CMSG_CONSOLE_DATA       0


/******************************************************************************
 * BLOCK-INTERFACE FRONTEND DEFINITIONS
 */

/* Messages from domain controller to guest. */
#define CMSG_BLKIF_FE_INTERFACE_STATUS           0

/* Messages from guest to domain controller. */
#define CMSG_BLKIF_FE_DRIVER_STATUS             32
#define CMSG_BLKIF_FE_INTERFACE_CONNECT         33
#define CMSG_BLKIF_FE_INTERFACE_DISCONNECT      34
#define CMSG_BLKIF_FE_INTERFACE_QUERY           35

/* These are used by both front-end and back-end drivers. */
#define blkif_vdev_t   u16
#define blkif_pdev_t   u32
#define blkif_sector_t u64

/*
 * CMSG_BLKIF_FE_INTERFACE_STATUS:
 *  Notify a guest about a status change on one of its block interfaces.
 *  If the interface is DESTROYED or DOWN then the interface is disconnected:
 *   1. The shared-memory frame is available for reuse.
 *   2. Any unacknowledged messages pending on the interface were dropped.
 */
#define BLKIF_INTERFACE_STATUS_CLOSED       0 /* Interface doesn't exist.    */
#define BLKIF_INTERFACE_STATUS_DISCONNECTED 1 /* Exists but is disconnected. */
#define BLKIF_INTERFACE_STATUS_CONNECTED    2 /* Exists and is connected.    */
#define BLKIF_INTERFACE_STATUS_CHANGED      3 /* A device has been added or removed. */
typedef struct {
    u32 handle; /*  0 */
    u32 status; /*  4 */
    u16 evtchn; /*  8: (only if status == BLKIF_INTERFACE_STATUS_CONNECTED). */
    domid_t domid; /* 10: status != BLKIF_INTERFACE_STATUS_DESTROYED */
} PACKED blkif_fe_interface_status_t; /* 12 bytes */

/*
 * CMSG_BLKIF_FE_DRIVER_STATUS:
 *  Notify the domain controller that the front-end driver is DOWN or UP.
 *  When the driver goes DOWN then the controller will send no more
 *  status-change notifications.
 *  If the driver goes DOWN while interfaces are still UP, the domain
 *  will automatically take the interfaces DOWN.
 * 
 *  NB. The controller should not send an INTERFACE_STATUS_CHANGED message
 *  for interfaces that are active when it receives an UP notification. We
 *  expect that the frontend driver will query those interfaces itself.
 */
#define BLKIF_DRIVER_STATUS_DOWN   0
#define BLKIF_DRIVER_STATUS_UP     1
typedef struct {
    /* IN */
    u32 status;        /*  0: BLKIF_DRIVER_STATUS_??? */
    /* OUT */
    /* Driver should query interfaces [0..max_handle]. */
    u32 max_handle;    /*  4 */
} PACKED blkif_fe_driver_status_t; /* 8 bytes */

/*
 * CMSG_BLKIF_FE_INTERFACE_CONNECT:
 *  If successful, the domain controller will acknowledge with a
 *  STATUS_CONNECTED message.
 */
typedef struct {
    u32      handle;      /*  0 */
    u32      __pad;
    memory_t shmem_frame; /*  8 */
    MEMORY_PADDING;
} PACKED blkif_fe_interface_connect_t; /* 16 bytes */

/*
 * CMSG_BLKIF_FE_INTERFACE_DISCONNECT:
 *  If successful, the domain controller will acknowledge with a
 *  STATUS_DISCONNECTED message.
 */
typedef struct {
    u32 handle; /*  0 */
} PACKED blkif_fe_interface_disconnect_t; /* 4 bytes */

/*
 * CMSG_BLKIF_FE_INTERFACE_QUERY:
 */
typedef struct {
    /* IN */
    u32 handle; /*  0 */
    /* OUT */
    u32 status; /*  4 */
    u16 evtchn; /*  8: (only if status == BLKIF_INTERFACE_STATUS_CONNECTED). */
    domid_t domid; /* 10: status != BLKIF_INTERFACE_STATUS_DESTROYED */
} PACKED blkif_fe_interface_query_t; /* 12 bytes */


/******************************************************************************
 * BLOCK-INTERFACE BACKEND DEFINITIONS
 */

/* Messages from domain controller. */
#define CMSG_BLKIF_BE_CREATE      0  /* Create a new block-device interface. */
#define CMSG_BLKIF_BE_DESTROY     1  /* Destroy a block-device interface.    */
#define CMSG_BLKIF_BE_CONNECT     2  /* Connect i/f to remote driver.        */
#define CMSG_BLKIF_BE_DISCONNECT  3  /* Disconnect i/f from remote driver.   */
#define CMSG_BLKIF_BE_VBD_CREATE  4  /* Create a new VBD for an interface.   */
#define CMSG_BLKIF_BE_VBD_DESTROY 5  /* Delete a VBD from an interface.      */

/* Messages to domain controller. */
#define CMSG_BLKIF_BE_DRIVER_STATUS 32

/*
 * Message request/response definitions for block-device messages.
 */

/* Non-specific 'okay' return. */
#define BLKIF_BE_STATUS_OKAY                0
/* Non-specific 'error' return. */
#define BLKIF_BE_STATUS_ERROR               1
/* The following are specific error returns. */
#define BLKIF_BE_STATUS_INTERFACE_EXISTS    2
#define BLKIF_BE_STATUS_INTERFACE_NOT_FOUND 3
#define BLKIF_BE_STATUS_INTERFACE_CONNECTED 4
#define BLKIF_BE_STATUS_VBD_EXISTS          5
#define BLKIF_BE_STATUS_VBD_NOT_FOUND       6
#define BLKIF_BE_STATUS_OUT_OF_MEMORY       7
#define BLKIF_BE_STATUS_PHYSDEV_NOT_FOUND   8
#define BLKIF_BE_STATUS_MAPPING_ERROR       9

/* This macro can be used to create an array of descriptive error strings. */
#define BLKIF_BE_STATUS_ERRORS {    \
    "Okay",                         \
    "Non-specific error",           \
    "Interface already exists",     \
    "Interface not found",          \
    "Interface is still connected", \
    "VBD already exists",           \
    "VBD not found",                \
    "Out of memory",                \
    "Extent not found for VBD",     \
    "Could not map domain memory" }

/*
 * CMSG_BLKIF_BE_CREATE:
 *  When the driver sends a successful response then the interface is fully
 *  created. The controller will send a DOWN notification to the front-end
 *  driver.
 */
typedef struct { 
    /* IN */
    domid_t    domid;         /*  0: Domain attached to new interface.   */
    u16        __pad;
    u32        blkif_handle;  /*  4: Domain-specific interface handle.   */
    /* OUT */
    u32        status;        /*  8 */
} PACKED blkif_be_create_t; /* 12 bytes */

/*
 * CMSG_BLKIF_BE_DESTROY:
 *  When the driver sends a successful response then the interface is fully
 *  torn down. The controller will send a DESTROYED notification to the
 *  front-end driver.
 */
typedef struct { 
    /* IN */
    domid_t    domid;         /*  0: Identify interface to be destroyed. */
    u16        __pad;
    u32        blkif_handle;  /*  4: ...ditto...                         */
    /* OUT */
    u32        status;        /*  8 */
} PACKED blkif_be_destroy_t; /* 12 bytes */

/*
 * CMSG_BLKIF_BE_CONNECT:
 *  When the driver sends a successful response then the interface is fully
 *  connected. The controller will send a CONNECTED notification to the
 *  front-end driver.
 */
typedef struct { 
    /* IN */
    domid_t    domid;         /*  0: Domain attached to new interface.   */
    u16        __pad;
    u32        blkif_handle;  /*  4: Domain-specific interface handle.   */
    memory_t   shmem_frame;   /*  8: Page cont. shared comms window.     */
    MEMORY_PADDING;
    u32        evtchn;        /* 16: Event channel for notifications.    */
    /* OUT */
    u32        status;        /* 20 */
} PACKED blkif_be_connect_t;  /* 24 bytes */

/*
 * CMSG_BLKIF_BE_DISCONNECT:
 *  When the driver sends a successful response then the interface is fully
 *  disconnected. The controller will send a DOWN notification to the front-end
 *  driver.
 */
typedef struct { 
    /* IN */
    domid_t    domid;         /*  0: Domain attached to new interface.   */
    u16        __pad;
    u32        blkif_handle;  /*  4: Domain-specific interface handle.   */
    /* OUT */
    u32        status;        /*  8 */
} PACKED blkif_be_disconnect_t; /* 12 bytes */

/* CMSG_BLKIF_BE_VBD_CREATE */
typedef struct { 
    /* IN */
    domid_t    domid;         /*  0: Identify blkdev interface.          */
    u16        __pad;
    u32        blkif_handle;  /*  4: ...ditto...                         */
    blkif_pdev_t pdevice;     /*  8 */
    blkif_vdev_t vdevice;     /* 12: Interface-specific id for this VBD. */
    u16        readonly;      /* 14: Non-zero -> VBD isn't writable.     */
    /* OUT */
    u32        status;        /* 16 */
} PACKED blkif_be_vbd_create_t; /* 20 bytes */

/* CMSG_BLKIF_BE_VBD_DESTROY */
typedef struct {
    /* IN */
    domid_t    domid;         /*  0: Identify blkdev interface.          */
    u16        __pad0;        /*  2 */
    u32        blkif_handle;  /*  4: ...ditto...                         */
    blkif_vdev_t vdevice;     /*  8: Interface-specific id of the VBD.   */
    u16        __pad1;        /* 10 */
    /* OUT */
    u32        status;        /* 12 */
} PACKED blkif_be_vbd_destroy_t; /* 16 bytes */

/*
 * CMSG_BLKIF_BE_DRIVER_STATUS:
 *  Notify the domain controller that the back-end driver is DOWN or UP.
 *  If the driver goes DOWN while interfaces are still UP, the controller
 *  will automatically send DOWN notifications.
 */
typedef struct {
    u32        status;        /*  0: BLKIF_DRIVER_STATUS_??? */
} PACKED blkif_be_driver_status_t; /* 4 bytes */


/******************************************************************************
 * NETWORK-INTERFACE FRONTEND DEFINITIONS
 */

/* Messages from domain controller to guest. */
#define CMSG_NETIF_FE_INTERFACE_STATUS   0

/* Messages from guest to domain controller. */
#define CMSG_NETIF_FE_DRIVER_STATUS             32
#define CMSG_NETIF_FE_INTERFACE_CONNECT         33
#define CMSG_NETIF_FE_INTERFACE_DISCONNECT      34
#define CMSG_NETIF_FE_INTERFACE_QUERY           35

/*
 * CMSG_NETIF_FE_INTERFACE_STATUS:
 *  Notify a guest about a status change on one of its network interfaces.
 *  If the interface is CLOSED or DOWN then the interface is disconnected:
 *   1. The shared-memory frame is available for reuse.
 *   2. Any unacknowledged messgaes pending on the interface were dropped.
 */
#define NETIF_INTERFACE_STATUS_CLOSED       0 /* Interface doesn't exist.    */
#define NETIF_INTERFACE_STATUS_DISCONNECTED 1 /* Exists but is disconnected. */
#define NETIF_INTERFACE_STATUS_CONNECTED    2 /* Exists and is connected.    */
#define NETIF_INTERFACE_STATUS_CHANGED      3 /* A device has been added or removed. */
typedef struct {
    u32        handle; /*  0 */
    u32        status; /*  4 */
    u16        evtchn; /*  8: status == NETIF_INTERFACE_STATUS_CONNECTED */
    u8         mac[6]; /* 10: status == NETIF_INTERFACE_STATUS_CONNECTED */
    domid_t    domid;  /* 16: status != NETIF_INTERFACE_STATUS_DESTROYED */
} PACKED netif_fe_interface_status_t; /* 18 bytes */

/*
 * CMSG_NETIF_FE_DRIVER_STATUS:
 *  Notify the domain controller that the front-end driver is DOWN or UP.
 *  When the driver goes DOWN then the controller will send no more
 *  status-change notifications.
 *  If the driver goes DOWN while interfaces are still UP, the domain
 *  will automatically take the interfaces DOWN.
 * 
 *  NB. The controller should not send an INTERFACE_STATUS message
 *  for interfaces that are active when it receives an UP notification. We
 *  expect that the frontend driver will query those interfaces itself.
 */
#define NETIF_DRIVER_STATUS_DOWN   0
#define NETIF_DRIVER_STATUS_UP     1
typedef struct {
    /* IN */
    u32        status;        /*  0: NETIF_DRIVER_STATUS_??? */
    /* OUT */
    /* Driver should query interfaces [0..max_handle]. */
    u32        max_handle;    /*  4 */
} PACKED netif_fe_driver_status_t; /* 8 bytes */

/*
 * CMSG_NETIF_FE_INTERFACE_CONNECT:
 *  If successful, the domain controller will acknowledge with a
 *  STATUS_CONNECTED message.
 */
typedef struct {
    u32        handle;         /*  0 */
    u32        __pad;          /*  4 */
    memory_t   tx_shmem_frame; /*  8 */
    MEMORY_PADDING;
    memory_t   rx_shmem_frame; /* 16 */
    MEMORY_PADDING;
} PACKED netif_fe_interface_connect_t; /* 24 bytes */

/*
 * CMSG_NETIF_FE_INTERFACE_DISCONNECT:
 *  If successful, the domain controller will acknowledge with a
 *  STATUS_DISCONNECTED message.
 */
typedef struct {
    u32        handle;        /*  0 */
} PACKED netif_fe_interface_disconnect_t; /* 4 bytes */

/*
 * CMSG_NETIF_FE_INTERFACE_QUERY:
 */
typedef struct {
    /* IN */
    u32        handle; /*  0 */
    /* OUT */
    u32        status; /*  4 */
    u16        evtchn; /*  8: status == NETIF_INTERFACE_STATUS_CONNECTED */
    u8         mac[6]; /* 10: status == NETIF_INTERFACE_STATUS_CONNECTED */
    domid_t    domid;  /* 16: status != NETIF_INTERFACE_STATUS_DESTROYED */
} PACKED netif_fe_interface_query_t; /* 18 bytes */


/******************************************************************************
 * NETWORK-INTERFACE BACKEND DEFINITIONS
 */

/* Messages from domain controller. */
#define CMSG_NETIF_BE_CREATE      0  /* Create a new net-device interface. */
#define CMSG_NETIF_BE_DESTROY     1  /* Destroy a net-device interface.    */
#define CMSG_NETIF_BE_CONNECT     2  /* Connect i/f to remote driver.        */
#define CMSG_NETIF_BE_DISCONNECT  3  /* Disconnect i/f from remote driver.   */
#define CMSG_NETIF_BE_CREDITLIMIT 4  /* Limit i/f to a given credit limit. */

/* Messages to domain controller. */
#define CMSG_NETIF_BE_DRIVER_STATUS 32

/*
 * Message request/response definitions for net-device messages.
 */

/* Non-specific 'okay' return. */
#define NETIF_BE_STATUS_OKAY                0
/* Non-specific 'error' return. */
#define NETIF_BE_STATUS_ERROR               1
/* The following are specific error returns. */
#define NETIF_BE_STATUS_INTERFACE_EXISTS    2
#define NETIF_BE_STATUS_INTERFACE_NOT_FOUND 3
#define NETIF_BE_STATUS_INTERFACE_CONNECTED 4
#define NETIF_BE_STATUS_OUT_OF_MEMORY       5
#define NETIF_BE_STATUS_MAPPING_ERROR       6

/* This macro can be used to create an array of descriptive error strings. */
#define NETIF_BE_STATUS_ERRORS {    \
    "Okay",                         \
    "Non-specific error",           \
    "Interface already exists",     \
    "Interface not found",          \
    "Interface is still connected", \
    "Out of memory",                \
    "Could not map domain memory" }

/*
 * CMSG_NETIF_BE_CREATE:
 *  When the driver sends a successful response then the interface is fully
 *  created. The controller will send a DOWN notification to the front-end
 *  driver.
 */
typedef struct { 
    /* IN */
    domid_t    domid;         /*  0: Domain attached to new interface.   */
    u16        __pad0;        /*  2 */
    u32        netif_handle;  /*  4: Domain-specific interface handle.   */
    u8         mac[6];        /*  8 */
    u16        __pad1;        /* 14 */
    u8         be_mac[6];     /* 16 */
    u16        __pad2;        /* 22 */
    /* OUT */
    u32        status;        /* 24 */
} PACKED netif_be_create_t; /* 28 bytes */

/*
 * CMSG_NETIF_BE_DESTROY:
 *  When the driver sends a successful response then the interface is fully
 *  torn down. The controller will send a DESTROYED notification to the
 *  front-end driver.
 */
typedef struct { 
    /* IN */
    domid_t    domid;         /*  0: Identify interface to be destroyed. */
    u16        __pad;
    u32        netif_handle;  /*  4: ...ditto...                         */
    /* OUT */
    u32   status;             /*  8 */
} PACKED netif_be_destroy_t; /* 12 bytes */

/*
 * CMSG_NETIF_BE_CREDITLIMIT:
 *  Limit a virtual interface to "credit_bytes" bytes per "period_usec" 
 *  microseconds.  
 */
typedef struct { 
    /* IN */
    domid_t    domid;          /*  0: Domain attached to new interface.   */
    u16        __pad0;         /*  2 */
    u32        netif_handle;   /*  4: Domain-specific interface handle.   */
    u32        credit_bytes;   /*  8: Vifs credit of bytes per period.    */
    u32        period_usec;    /* 12: Credit replenishment period.        */
    /* OUT */
    u32        status;         /* 16 */
} PACKED netif_be_creditlimit_t; /* 20 bytes */

/*
 * CMSG_NETIF_BE_CONNECT:
 *  When the driver sends a successful response then the interface is fully
 *  connected. The controller will send a CONNECTED notification to the
 *  front-end driver.
 */
typedef struct { 
    /* IN */
    domid_t    domid;          /*  0: Domain attached to new interface.   */
    u16        __pad0;         /*  2 */
    u32        netif_handle;   /*  4: Domain-specific interface handle.   */
    memory_t   tx_shmem_frame; /*  8: Page cont. tx shared comms window.  */
    MEMORY_PADDING;
    memory_t   rx_shmem_frame; /* 16: Page cont. rx shared comms window.  */
    MEMORY_PADDING;
    u16        evtchn;         /* 24: Event channel for notifications.    */
    u16        __pad1;         /* 26 */
    /* OUT */
    u32        status;         /* 28 */
} PACKED netif_be_connect_t; /* 32 bytes */

/*
 * CMSG_NETIF_BE_DISCONNECT:
 *  When the driver sends a successful response then the interface is fully
 *  disconnected. The controller will send a DOWN notification to the front-end
 *  driver.
 */
typedef struct { 
    /* IN */
    domid_t    domid;         /*  0: Domain attached to new interface.   */
    u16        __pad;
    u32        netif_handle;  /*  4: Domain-specific interface handle.   */
    /* OUT */
    u32        status;        /*  8 */
} PACKED netif_be_disconnect_t; /* 12 bytes */

/*
 * CMSG_NETIF_BE_DRIVER_STATUS:
 *  Notify the domain controller that the back-end driver is DOWN or UP.
 *  If the driver goes DOWN while interfaces are still UP, the domain
 *  will automatically send DOWN notifications.
 */
typedef struct {
    u32        status;        /*  0: NETIF_DRIVER_STATUS_??? */
} PACKED netif_be_driver_status_t; /* 4 bytes */



/******************************************************************************
 * USB-INTERFACE FRONTEND DEFINITIONS
 */

/* Messages from domain controller to guest. */
#define CMSG_USBIF_FE_INTERFACE_STATUS_CHANGED   0

/* Messages from guest to domain controller. */
#define CMSG_USBIF_FE_DRIVER_STATUS_CHANGED     32
#define CMSG_USBIF_FE_INTERFACE_CONNECT         33
#define CMSG_USBIF_FE_INTERFACE_DISCONNECT      34
/*
 * CMSG_USBIF_FE_INTERFACE_STATUS_CHANGED:
 *  Notify a guest about a status change on one of its block interfaces.
 *  If the interface is DESTROYED or DOWN then the interface is disconnected:
 *   1. The shared-memory frame is available for reuse.
 *   2. Any unacknowledged messages pending on the interface were dropped.
 */
#define USBIF_INTERFACE_STATUS_DESTROYED    0 /* Interface doesn't exist.    */
#define USBIF_INTERFACE_STATUS_DISCONNECTED 1 /* Exists but is disconnected. */
#define USBIF_INTERFACE_STATUS_CONNECTED    2 /* Exists and is connected.    */
typedef struct {
    u32 status; /*  0 */
    u16 evtchn; /*  4: (only if status == BLKIF_INTERFACE_STATUS_CONNECTED). */
    domid_t domid; /* 6: status != BLKIF_INTERFACE_STATUS_DESTROYED */
    u32 bandwidth; /* 8 */
    u32 num_ports; /* 12 */
} PACKED usbif_fe_interface_status_changed_t; /* 12 bytes */

/*
 * CMSG_USBIF_FE_DRIVER_STATUS_CHANGED:
 *  Notify the domain controller that the front-end driver is DOWN or UP.
 *  When the driver goes DOWN then the controller will send no more
 *  status-change notifications.
 *  If the driver goes DOWN while interfaces are still UP, the domain
 *  will automatically take the interfaces DOWN.
 * 
 *  NB. The controller should not send an INTERFACE_STATUS_CHANGED message
 *  for interfaces that are active when it receives an UP notification. We
 *  expect that the frontend driver will query those interfaces itself.
 */
#define USBIF_DRIVER_STATUS_DOWN   0
#define USBIF_DRIVER_STATUS_UP     1
typedef struct {
    /* IN */
    u32 status;        /*  0: USBIF_DRIVER_STATUS_??? */
} PACKED usbif_fe_driver_status_changed_t; /* 4 bytes */

/*
 * CMSG_USBIF_FE_INTERFACE_CONNECT:
 *  If successful, the domain controller will acknowledge with a
 *  STATUS_CONNECTED message.
 */
typedef struct {
    u32      __pad;
    memory_t shmem_frame; /*  8 */
    MEMORY_PADDING;
} PACKED usbif_fe_interface_connect_t; /* 16 bytes */

/*
 * CMSG_BLKIF_FE_INTERFACE_DISCONNECT:
 *  If successful, the domain controller will acknowledge with a
 *  STATUS_DISCONNECTED message.
 */
typedef struct {} PACKED usbif_fe_interface_disconnect_t; /* 4 bytes */


/******************************************************************************
 * USB-INTERFACE BACKEND DEFINITIONS
 */

/* Messages from domain controller. */
#define CMSG_USBIF_BE_CREATE       0  /* Create a new block-device interface. */
#define CMSG_USBIF_BE_DESTROY      1  /* Destroy a block-device interface.    */
#define CMSG_USBIF_BE_CONNECT      2  /* Connect i/f to remote driver.        */
#define CMSG_USBIF_BE_DISCONNECT   3  /* Disconnect i/f from remote driver.   */
#define CMSG_USBIF_BE_CLAIM_PORT   4  /* Claim host port for a domain.        */
#define CMSG_USBIF_BE_RELEASE_PORT 5  /* Release host port.                   */
/* Messages to domain controller. */
#define CMSG_USBIF_BE_DRIVER_STATUS_CHANGED 32

/* Non-specific 'okay' return. */
#define USBIF_BE_STATUS_OKAY                0
/* Non-specific 'error' return. */
#define USBIF_BE_STATUS_ERROR               1
/* The following are specific error returns. */
#define USBIF_BE_STATUS_INTERFACE_EXISTS    2
#define USBIF_BE_STATUS_INTERFACE_NOT_FOUND 3
#define USBIF_BE_STATUS_INTERFACE_CONNECTED 4
#define USBIF_BE_STATUS_OUT_OF_MEMORY       7
#define USBIF_BE_STATUS_MAPPING_ERROR       9

/* This macro can be used to create an array of descriptive error strings. */
#define USBIF_BE_STATUS_ERRORS {    \
    "Okay",                         \
    "Non-specific error",           \
    "Interface already exists",     \
    "Interface not found",          \
    "Interface is still connected", \
    "Out of memory",                \
    "Could not map domain memory" }

/*
 * CMSG_USBIF_BE_CREATE:
 *  When the driver sends a successful response then the interface is fully
 *  created. The controller will send a DOWN notification to the front-end
 *  driver.
 */
typedef struct { 
    /* IN */
    domid_t    domid;         /*  0: Domain attached to new interface.   */
    u16        __pad;
    /* OUT */
    u32        status;        /*  8 */
} PACKED usbif_be_create_t; /* 12 bytes */

/*
 * CMSG_USBIF_BE_DESTROY:
 *  When the driver sends a successful response then the interface is fully
 *  torn down. The controller will send a DESTROYED notification to the
 *  front-end driver.
 */
typedef struct { 
    /* IN */
    domid_t    domid;         /*  0: Identify interface to be destroyed. */
    u16        __pad;
    /* OUT */
    u32        status;        /*  8 */
} PACKED usbif_be_destroy_t; /* 12 bytes */

/*
 * CMSG_USBIF_BE_CONNECT:
 *  When the driver sends a successful response then the interface is fully
 *  connected. The controller will send a CONNECTED notification to the
 *  front-end driver.
 */
typedef struct { 
    /* IN */
    domid_t    domid;         /*  0: Domain attached to new interface.   */
    u16        __pad;
    memory_t   shmem_frame;   /*  8: Page cont. shared comms window.     */
    MEMORY_PADDING;
    u32        evtchn;        /* 16: Event channel for notifications.    */
    u32        bandwidth;     /* 20: Bandwidth allocated for isoch / int - us
                               * per 1ms frame (ie between 0 and 900 or 800
                               * depending on USB version). */
    /* OUT */
    u32        status;        /* 24 */
} PACKED usbif_be_connect_t;  /* 28 bytes */

/*
 * CMSG_USBIF_BE_DISCONNECT:
 *  When the driver sends a successful response then the interface is fully
 *  disconnected. The controller will send a DOWN notification to the front-end
 *  driver.
 */
typedef struct { 
    /* IN */
    domid_t    domid;         /*  0: Domain attached to new interface.   */
    u16        __pad;
    /* OUT */
    u32        status;        /*  8 */
} PACKED usbif_be_disconnect_t; /* 12 bytes */

/*
 * CMSG_USBIF_BE_DRIVER_STATUS_CHANGED:
 *  Notify the domain controller that the back-end driver is DOWN or UP.
 *  If the driver goes DOWN while interfaces are still UP, the controller
 *  will automatically send DOWN notifications.
 */
typedef struct {
    u32        status;        /*  0: USBIF_DRIVER_STATUS_??? */
} PACKED usbif_be_driver_status_changed_t; /* 4 bytes */

#define USB_PATH_LEN 16

/*
 * CMSG_USBIF_BE_CLAIM_PORT:
 * Instruct the backend driver to claim any device plugged into the specified
 * host port and to allow the specified domain to control that port.
 */
typedef struct 
{
    /* IN */
    domid_t  domid;        /* 0:  which domain                 */
    u32      usbif_port;   /* 6:  port on the virtual root hub */
    u32      status;       /* 10: status of operation          */
    char path[USB_PATH_LEN]; /* Currently specified in the Linux style - may need to be
                    * converted to some OS-independent format at some stage. */
} PACKED usbif_be_claim_port_t;

/*
 * CMSG_USBIF_BE_RELEASE_PORT: 
 * Instruct the backend driver to release any device plugged into the specified
 * host port.
 */
typedef struct
{
    char     path[USB_PATH_LEN];
} PACKED usbif_be_release_port_t;

/******************************************************************************
 * SHUTDOWN DEFINITIONS
 */

/*
 * Subtypes for shutdown messages.
 */
#define CMSG_SHUTDOWN_POWEROFF  0   /* Clean shutdown (SHUTDOWN_poweroff).   */
#define CMSG_SHUTDOWN_REBOOT    1   /* Clean shutdown (SHUTDOWN_reboot).     */
#define CMSG_SHUTDOWN_SUSPEND   2   /* Create suspend info, then             */
                                    /* SHUTDOWN_suspend.                     */
#define CMSG_SHUTDOWN_SYSRQ     3

typedef struct {
    char key;      /* 0: sysrq key */
    char __pad[3]; /* 1: */
} PACKED shutdown_sysrq_t; /* 4 bytes */

/******************************************************************************
 * MEMORY CONTROLS
 */

#define CMSG_MEM_REQUEST_SET 0 /* Request a domain to set its mem footprint. */

/*
 * CMSG_MEM_REQUEST:
 *  Request that the domain change its memory reservation.
 */
typedef struct {
    /* OUT */
    u32 target;       /* 0: Target memory reservation in pages.       */
    /* IN  */
    u32 status;       /* 4: Return code indicates success or failure. */
} PACKED mem_request_t; /* 8 bytes */


#endif /* __XEN_PUBLIC_IO_DOMAIN_CONTROLLER_H__ */
