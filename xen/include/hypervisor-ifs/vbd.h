#ifndef __HYP_IFS_VBD_H__
#define __HYP_IFS_VBD_H__


/* 
 * Block I/O trap operations and associated structures.
 */

#define BLOCK_IO_OP_SIGNAL       0    /* let xen know we have work to do     */
#define BLOCK_IO_OP_RESET        1    /* reset ring indexes on quiescent i/f */
#define BLOCK_IO_OP_RING_ADDRESS 2    /* returns machine address of I/O ring */
#define BLOCK_IO_OP_VBD_CREATE   3    /* create a new VBD for a given domain */
#define BLOCK_IO_OP_VBD_GROW     4    /* append an extent to a given VBD     */
#define BLOCK_IO_OP_VBD_SHRINK   5    /* remove last extent from a given VBD */
#define BLOCK_IO_OP_VBD_SET_EXTENTS 6 /* provide a fresh extent list for VBD */
#define BLOCK_IO_OP_VBD_DELETE   7    /* delete a VBD */
#define BLOCK_IO_OP_VBD_PROBE    8    /* query VBD information for a domain */
#define BLOCK_IO_OP_VBD_INFO     9    /* query info about a particular VBD */

typedef struct _xen_extent { 
    u16       device; 
    u16       unused;
    ulong     start_sector; 
    ulong     nr_sectors;
} xen_extent_t; 

#define VBD_MODE_R         0x1
#define VBD_MODE_W         0x2

#define VBD_CAN_READ(_v)  ((_v)->mode & VBD_MODE_R)
#define VBD_CAN_WRITE(_v) ((_v)->mode & VBD_MODE_W)

  
typedef struct _vbd_create { 
    domid_t      domain;              /* create VBD for this domain */
    u16          vdevice;             /* id by which dom will refer to VBD */ 
    u16          mode;                /* OR of { VBD_MODE_R , VBD_MODE_W } */
} vbd_create_t; 

typedef struct _vbd_grow { 
    domid_t      domain;              /* domain in question */
    u16          vdevice;             /* 16 bit id domain refers to VBD as */
    xen_extent_t extent;              /* the extent to add to this VBD */
} vbd_grow_t; 

typedef struct _vbd_shrink { 
    domid_t      domain;              /* domain in question */
    u16          vdevice;             /* 16 bit id domain refers to VBD as */
} vbd_shrink_t; 

typedef struct _vbd_setextents { 
    domid_t      domain;              /* domain in question */
    u16          vdevice;             /* 16 bit id domain refers to VBD as */
    u16          nr_extents;          /* number of extents in the list */
    xen_extent_t *extents;            /* the extents to add to this VBD */
} vbd_setextents_t; 

typedef struct _vbd_delete {          
    domid_t      domain;              /* domain in question */
    u16          vdevice;             /* 16 bit id domain refers to VBD as */
} vbd_delete_t; 

#define VBD_PROBE_ALL (~0ULL)
typedef struct _vbd_probe { 
    domid_t          domain;          /* domain in question or VBD_PROBE_ALL */
    xen_disk_info_t  xdi;             /* where's our space for VBD/disk info */
} vbd_probe_t; 

typedef struct _vbd_info { 
    /* IN variables  */
    domid_t       domain;             /* domain in question */
    u16           vdevice;            /* 16 bit id domain refers to VBD as */ 
    u16           maxextents;         /* max # of extents to return info for */
    xen_extent_t *extents;            /* pointer to space for extent list */
    /* OUT variables */
    u16           nextents;           /* # extents in the above list */
    u16           mode;               /* VBD_MODE_{READONLY,READWRITE} */
} vbd_info_t; 


typedef struct block_io_op_st
{
    unsigned long cmd;
    union
    {
        /* no entry for BLOCK_IO_OP_SIGNAL */
        /* no entry for BLOCK_IO_OP_RESET  */
	unsigned long    ring_mfn; 
	vbd_create_t     create_params; 
	vbd_grow_t       grow_params; 
	vbd_shrink_t     shrink_params; 
	vbd_setextents_t setextents_params; 
	vbd_delete_t     delete_params; 
	vbd_probe_t      probe_params; 
	vbd_info_t       info_params; 
    }
    u;
} block_io_op_t;




#endif /* __HYP_IFS_VBD_H__ */
