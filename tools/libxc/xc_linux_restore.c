/******************************************************************************
 * xc_linux_restore.c
 *
 * Restore the state of a Linux session.
 *
 * Copyright (c) 2003, K A Fraser.
 */

#include <stdlib.h>
#include <unistd.h>

#include "xg_private.h"
#include "xg_save_restore.h"

/* max mfn of the current host machine */
static unsigned long max_mfn;

/* virtual starting address of the hypervisor */
static unsigned long hvirt_start;

/* #levels of page tables used by the currrent guest */
static unsigned int pt_levels;

/* total number of pages used by the current guest */
static unsigned long max_pfn;

/* Live mapping of the table mapping each PFN to its current MFN. */
static xen_pfn_t *live_p2m = NULL;

/* A table mapping each PFN to its new MFN. */
static xen_pfn_t *p2m = NULL;

/* A table of P2M mappings in the current region */
static xen_pfn_t *p2m_batch = NULL;


static ssize_t
read_exact(int fd, void *buf, size_t count)
{
    int r = 0, s;
    unsigned char *b = buf;

    while (r < count) {
        s = read(fd, &b[r], count - r);
        if ((s == -1) && (errno == EINTR))
            continue;
        if (s <= 0) {
            break;
        }
        r += s;
    }

    return (r == count) ? 1 : 0;
}

/*
** In the state file (or during transfer), all page-table pages are
** converted into a 'canonical' form where references to actual mfns
** are replaced with references to the corresponding pfns.
** This function inverts that operation, replacing the pfn values with
** the (now known) appropriate mfn values.
*/
static int uncanonicalize_pagetable(int xc_handle, uint32_t dom, 
                                    unsigned long type, void *page)
{
    int i, pte_last;
    unsigned long pfn;
    uint64_t pte;
    int nr_mfns = 0; 

    pte_last = PAGE_SIZE / ((pt_levels == 2)? 4 : 8);

    /* First pass: work out how many (if any) MFNs we need to alloc */
    for(i = 0; i < pte_last; i++) {
        
        if(pt_levels == 2)
            pte = ((uint32_t *)page)[i];
        else
            pte = ((uint64_t *)page)[i];
        
        /* XXX SMH: below needs fixing for PROT_NONE etc */
        if(!(pte & _PAGE_PRESENT))
            continue; 
        
        pfn = (pte >> PAGE_SHIFT) & MFN_MASK_X86;
        
        if(pfn >= max_pfn) {
            /* This "page table page" is probably not one; bail. */
            ERROR("Frame number in type %lu page table is out of range: "
                  "i=%d pfn=0x%lx max_pfn=%lu",
                  type >> 28, i, pfn, max_pfn);
            return 0;
        }
        
        if(p2m[pfn] == INVALID_P2M_ENTRY) {
            /* Have a 'valid' PFN without a matching MFN - need to alloc */
            p2m_batch[nr_mfns++] = pfn; 
        }
    }
    
    
    /* Alllocate the requistite number of mfns */
    if (nr_mfns && xc_domain_memory_populate_physmap(
            xc_handle, dom, nr_mfns, 0, 0, p2m_batch) != 0) { 
        ERROR("Failed to allocate memory for batch.!\n"); 
        errno = ENOMEM;
        return 0; 
    }
    
    /* Second pass: uncanonicalize each present PTE */
    nr_mfns = 0;
    for(i = 0; i < pte_last; i++) {

        if(pt_levels == 2)
            pte = ((uint32_t *)page)[i];
        else
            pte = ((uint64_t *)page)[i];
        
        /* XXX SMH: below needs fixing for PROT_NONE etc */
        if(!(pte & _PAGE_PRESENT))
            continue;
        
        pfn = (pte >> PAGE_SHIFT) & MFN_MASK_X86;
        
        if(p2m[pfn] == INVALID_P2M_ENTRY)
            p2m[pfn] = p2m_batch[nr_mfns++];

        pte &= ~MADDR_MASK_X86;
        pte |= (uint64_t)p2m[pfn] << PAGE_SHIFT;

        if(pt_levels == 2)
            ((uint32_t *)page)[i] = (uint32_t)pte;
        else
            ((uint64_t *)page)[i] = (uint64_t)pte;
    }

    return 1;
}

int xc_linux_restore(int xc_handle, int io_fd,
                     uint32_t dom, unsigned long nr_pfns,
                     unsigned int store_evtchn, unsigned long *store_mfn,
                     unsigned int console_evtchn, unsigned long *console_mfn)
{
    DECLARE_DOMCTL;
    int rc = 1, i, n, pae_extended_cr3 = 0;
    unsigned long mfn, pfn;
    unsigned int prev_pc, this_pc;
    int verify = 0;
    int nraces = 0;

    /* The new domain's shared-info frame number. */
    unsigned long shared_info_frame;
    unsigned char shared_info_page[PAGE_SIZE]; /* saved contents from file */
    shared_info_t *shared_info = (shared_info_t *)shared_info_page;

    /* A copy of the CPU context of the guest. */
    vcpu_guest_context_t ctxt;

    /* A table containing the type of each PFN (/not/ MFN!). */
    unsigned long *pfn_type = NULL;

    /* A table of MFNs to map in the current region */
    xen_pfn_t *region_mfn = NULL;

    /* Types of the pfns in the current region */
    unsigned long region_pfn_type[MAX_BATCH_SIZE];

    /* A temporary mapping, and a copy, of one frame of guest memory. */
    unsigned long *page = NULL;

    /* A copy of the pfn-to-mfn table frame list. */
    xen_pfn_t *p2m_frame_list = NULL;

    /* A temporary mapping of the guest's start_info page. */
    start_info_t *start_info;

    /* Our mapping of the current region (batch) */
    char *region_base;

    xc_mmu_t *mmu = NULL;

    /* used by debug verify code */
    unsigned long buf[PAGE_SIZE/sizeof(unsigned long)];

    struct mmuext_op pin[MAX_PIN_BATCH];
    unsigned int nr_pins;


    max_pfn = nr_pfns;

    DPRINTF("xc_linux_restore start: max_pfn = %lx\n", max_pfn);


    if(!get_platform_info(xc_handle, dom,
                          &max_mfn, &hvirt_start, &pt_levels)) {
        ERROR("Unable to get platform info.");
        return 1;
    }

    if (lock_pages(&ctxt, sizeof(ctxt))) {
        /* needed for build domctl, but might as well do early */
        ERROR("Unable to lock ctxt");
        return 1;
    }

    if (!(p2m_frame_list = malloc(P2M_FL_SIZE))) {
        ERROR("Couldn't allocate p2m_frame_list array");
        goto out;
    }

    /* Read first entry of P2M list, or extended-info signature (~0UL). */
    if (!read_exact(io_fd, p2m_frame_list, sizeof(long))) {
        ERROR("read extended-info signature failed");
        goto out;
    }

    if (p2m_frame_list[0] == ~0UL) {
        uint32_t tot_bytes;

        /* Next 4 bytes: total size of following extended info. */
        if (!read_exact(io_fd, &tot_bytes, sizeof(tot_bytes))) {
            ERROR("read extended-info size failed");
            goto out;
        }

        while (tot_bytes) {
            uint32_t chunk_bytes;
            char     chunk_sig[4];

            /* 4-character chunk signature + 4-byte remaining chunk size. */
            if (!read_exact(io_fd, chunk_sig, sizeof(chunk_sig)) ||
                !read_exact(io_fd, &chunk_bytes, sizeof(chunk_bytes))) {
                ERROR("read extended-info chunk signature failed");
                goto out;
            }
            tot_bytes -= 8;

            /* VCPU context structure? */
            if (!strncmp(chunk_sig, "vcpu", 4)) {
                if (!read_exact(io_fd, &ctxt, sizeof(ctxt))) {
                    ERROR("read extended-info vcpu context failed");
                    goto out;
                }
                tot_bytes   -= sizeof(struct vcpu_guest_context);
                chunk_bytes -= sizeof(struct vcpu_guest_context);

                if (ctxt.vm_assist & (1UL << VMASST_TYPE_pae_extended_cr3))
                    pae_extended_cr3 = 1;
            }

            /* Any remaining bytes of this chunk: read and discard. */
            while (chunk_bytes) {
                unsigned long sz = chunk_bytes;
                if ( sz > P2M_FL_SIZE )
                    sz = P2M_FL_SIZE;
                if (!read_exact(io_fd, p2m_frame_list, sz)) {
                    ERROR("read-and-discard extended-info chunk bytes failed");
                    goto out;
                }
                chunk_bytes -= sz;
                tot_bytes   -= sz;
            }
        }

        /* Now read the real first entry of P2M list. */
        if (!read_exact(io_fd, p2m_frame_list, sizeof(long))) {
            ERROR("read first entry of p2m_frame_list failed");
            goto out;
        }
    }

    /* First entry is already read into the p2m array. */
    if (!read_exact(io_fd, &p2m_frame_list[1], P2M_FL_SIZE - sizeof(long))) {
        ERROR("read p2m_frame_list failed");
        goto out;
    }

    /* We want zeroed memory so use calloc rather than malloc. */
    p2m        = calloc(max_pfn, sizeof(xen_pfn_t));
    pfn_type   = calloc(max_pfn, sizeof(unsigned long));
    region_mfn = calloc(MAX_BATCH_SIZE, sizeof(xen_pfn_t));
    p2m_batch  = calloc(MAX_BATCH_SIZE, sizeof(xen_pfn_t));

    if ((p2m == NULL) || (pfn_type == NULL) ||
        (region_mfn == NULL) || (p2m_batch == NULL)) {
        ERROR("memory alloc failed");
        errno = ENOMEM;
        goto out;
    }

    if (lock_pages(region_mfn, sizeof(xen_pfn_t) * MAX_BATCH_SIZE)) {
        ERROR("Could not lock region_mfn");
        goto out;
    }

    if (lock_pages(p2m_batch, sizeof(xen_pfn_t) * MAX_BATCH_SIZE)) {
        ERROR("Could not lock p2m_batch");
        goto out;
    }

    /* Get the domain's shared-info frame. */
    domctl.cmd = XEN_DOMCTL_getdomaininfo;
    domctl.domain = (domid_t)dom;
    if (xc_domctl(xc_handle, &domctl) < 0) {
        ERROR("Could not get information on new domain");
        goto out;
    }
    shared_info_frame = domctl.u.getdomaininfo.shared_info_frame;

    if (xc_domain_setmaxmem(xc_handle, dom, PFN_TO_KB(max_pfn)) != 0) {
        errno = ENOMEM;
        goto out;
    }

    /* Mark all PFNs as invalid; we allocate on demand */
    for ( pfn = 0; pfn < max_pfn; pfn++ )
        p2m[pfn] = INVALID_P2M_ENTRY;

    if(!(mmu = xc_init_mmu_updates(xc_handle, dom))) {
        ERROR("Could not initialise for MMU updates");
        goto out;
    }

    DPRINTF("Reloading memory pages:   0%%\n");

    /*
     * Now simply read each saved frame into its new machine frame.
     * We uncanonicalise page tables as we go.
     */
    prev_pc = 0;

    n = 0;
    while (1) {

        int j, nr_mfns = 0; 

        this_pc = (n * 100) / max_pfn;
        if ( (this_pc - prev_pc) >= 5 )
        {
            PPRINTF("\b\b\b\b%3d%%", this_pc);
            prev_pc = this_pc;
        }

        if (!read_exact(io_fd, &j, sizeof(int))) {
            ERROR("Error when reading batch size");
            goto out;
        }

        PPRINTF("batch %d\n",j);

        if (j == -1) {
            verify = 1;
            DPRINTF("Entering page verify mode\n");
            continue;
        }

        if (j == 0)
            break;  /* our work here is done */

        if (j > MAX_BATCH_SIZE) {
            ERROR("Max batch size exceeded. Giving up.");
            goto out;
        }

        if (!read_exact(io_fd, region_pfn_type, j*sizeof(unsigned long))) {
            ERROR("Error when reading region pfn types");
            goto out;
        }

        /* First pass for this batch: work out how much memory to alloc */
        nr_mfns = 0; 
        for ( i = 0; i < j; i++ )
        {
            unsigned long pfn, pagetype;
            pfn      = region_pfn_type[i] & ~XEN_DOMCTL_PFINFO_LTAB_MASK;
            pagetype = region_pfn_type[i] &  XEN_DOMCTL_PFINFO_LTAB_MASK;

            if ( (pagetype != XEN_DOMCTL_PFINFO_XTAB) && 
                 (p2m[pfn] == INVALID_P2M_ENTRY) )
            {
                /* Have a live PFN which hasn't had an MFN allocated */
                p2m_batch[nr_mfns++] = pfn; 
            }
        } 


        /* Now allocate a bunch of mfns for this batch */
        if (nr_mfns && xc_domain_memory_populate_physmap(
                xc_handle, dom, nr_mfns, 0, 0, p2m_batch) != 0) { 
            ERROR("Failed to allocate memory for batch.!\n"); 
            errno = ENOMEM;
            goto out;
        }

        /* Second pass for this batch: update p2m[] and region_mfn[] */
        nr_mfns = 0; 
        for ( i = 0; i < j; i++ )
        {
            unsigned long pfn, pagetype;
            pfn      = region_pfn_type[i] & ~XEN_DOMCTL_PFINFO_LTAB_MASK;
            pagetype = region_pfn_type[i] &  XEN_DOMCTL_PFINFO_LTAB_MASK;

            if ( pagetype == XEN_DOMCTL_PFINFO_XTAB)
                region_mfn[i] = ~0UL; /* map will fail but we don't care */
            else 
            {
                if (p2m[pfn] == INVALID_P2M_ENTRY) {
                    /* We just allocated a new mfn above; update p2m */
                    p2m[pfn] = p2m_batch[nr_mfns++]; 
                }

                /* setup region_mfn[] for batch map */
                region_mfn[i] = p2m[pfn]; 
            }
        } 

        /* Map relevant mfns */
        region_base = xc_map_foreign_batch(
            xc_handle, dom, PROT_WRITE, region_mfn, j);

        if ( region_base == NULL )
        {
            ERROR("map batch failed");
            goto out;
        }

        for ( i = 0; i < j; i++ )
        {
            void *page;
            unsigned long pagetype;

            pfn      = region_pfn_type[i] & ~XEN_DOMCTL_PFINFO_LTAB_MASK;
            pagetype = region_pfn_type[i] &  XEN_DOMCTL_PFINFO_LTAB_MASK;

            if ( pagetype == XEN_DOMCTL_PFINFO_XTAB )
                /* a bogus/unmapped page: skip it */
                continue;

            if ( pfn > max_pfn )
            {
                ERROR("pfn out of range");
                goto out;
            }

            pfn_type[pfn] = pagetype;

            mfn = p2m[pfn];

            /* In verify mode, we use a copy; otherwise we work in place */
            page = verify ? (void *)buf : (region_base + i*PAGE_SIZE);

            if (!read_exact(io_fd, page, PAGE_SIZE)) {
                ERROR("Error when reading page (type was %lx)", pagetype);
                goto out;
            }

            pagetype &= XEN_DOMCTL_PFINFO_LTABTYPE_MASK;

            if ( (pagetype >= XEN_DOMCTL_PFINFO_L1TAB) && 
                 (pagetype <= XEN_DOMCTL_PFINFO_L4TAB) )
            {
                /*
                ** A page table page - need to 'uncanonicalize' it, i.e.
                ** replace all the references to pfns with the corresponding
                ** mfns for the new domain.
                **
                ** On PAE we need to ensure that PGDs are in MFNs < 4G, and
                ** so we may need to update the p2m after the main loop.
                ** Hence we defer canonicalization of L1s until then.
                */
                if ((pt_levels != 3) ||
                    pae_extended_cr3 ||
                    (pagetype != XEN_DOMCTL_PFINFO_L1TAB)) {

                    if (!uncanonicalize_pagetable(xc_handle, dom, 
                                                  pagetype, page)) {
                        /*
                        ** Failing to uncanonicalize a page table can be ok
                        ** under live migration since the pages type may have
                        ** changed by now (and we'll get an update later).
                        */
                        DPRINTF("PT L%ld race on pfn=%08lx mfn=%08lx\n",
                                pagetype >> 28, pfn, mfn);
                        nraces++;
                        continue;
                    } 
                }
            }
            else if ( pagetype != XEN_DOMCTL_PFINFO_NOTAB )
            {
                ERROR("Bogus page type %lx page table is out of range: "
                    "i=%d max_pfn=%lu", pagetype, i, max_pfn);
                goto out;

            }


            if (verify) {

                int res = memcmp(buf, (region_base + i*PAGE_SIZE), PAGE_SIZE);

                if (res) {

                    int v;

                    DPRINTF("************** pfn=%lx type=%lx gotcs=%08lx "
                            "actualcs=%08lx\n", pfn, pfn_type[pfn],
                            csum_page(region_base + i*PAGE_SIZE),
                            csum_page(buf));

                    for (v = 0; v < 4; v++) {

                        unsigned long *p = (unsigned long *)
                            (region_base + i*PAGE_SIZE);
                        if (buf[v] != p[v])
                            DPRINTF("    %d: %08lx %08lx\n", v, buf[v], p[v]);
                    }
                }
            }

            if (xc_add_mmu_update(xc_handle, mmu,
                                  (((unsigned long long)mfn) << PAGE_SHIFT)
                                  | MMU_MACHPHYS_UPDATE, pfn)) {
                ERROR("failed machpys update mfn=%lx pfn=%lx", mfn, pfn);
                goto out;
            }
        } /* end of 'batch' for loop */

        munmap(region_base, j*PAGE_SIZE);
        n+= j; /* crude stats */
    }

    /*
     * Ensure we flush all machphys updates before potential PAE-specific
     * reallocations below.
     */
    if (xc_finish_mmu_updates(xc_handle, mmu)) {
        ERROR("Error doing finish_mmu_updates()");
        goto out;
    }

    DPRINTF("Received all pages (%d races)\n", nraces);

    if ((pt_levels == 3) && !pae_extended_cr3) {

        /*
        ** XXX SMH on PAE we need to ensure PGDs are in MFNs < 4G. This
        ** is a little awkward and involves (a) finding all such PGDs and
        ** replacing them with 'lowmem' versions; (b) upating the p2m[]
        ** with the new info; and (c) canonicalizing all the L1s using the
        ** (potentially updated) p2m[].
        **
        ** This is relatively slow (and currently involves two passes through
        ** the pfn_type[] array), but at least seems to be correct. May wish
        ** to consider more complex approaches to optimize this later.
        */

        int j, k;
        
        /* First pass: find all L3TABs current in > 4G mfns and get new mfns */
        for ( i = 0; i < max_pfn; i++ )
        {
            if ( ((pfn_type[i] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK) ==
                  XEN_DOMCTL_PFINFO_L3TAB) &&
                 (p2m[i] > 0xfffffUL) )
            {
                unsigned long new_mfn;
                uint64_t l3ptes[4];
                uint64_t *l3tab;

                l3tab = (uint64_t *)
                    xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                         PROT_READ, p2m[i]);

                for(j = 0; j < 4; j++)
                    l3ptes[j] = l3tab[j];

                munmap(l3tab, PAGE_SIZE);

                if (!(new_mfn=xc_make_page_below_4G(xc_handle, dom, p2m[i]))) {
                    ERROR("Couldn't get a page below 4GB :-(");
                    goto out;
                }

                p2m[i] = new_mfn;
                if (xc_add_mmu_update(xc_handle, mmu,
                                      (((unsigned long long)new_mfn)
                                       << PAGE_SHIFT) |
                                      MMU_MACHPHYS_UPDATE, i)) {
                    ERROR("Couldn't m2p on PAE root pgdir");
                    goto out;
                }

                l3tab = (uint64_t *)
                    xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                         PROT_READ | PROT_WRITE, p2m[i]);

                for(j = 0; j < 4; j++)
                    l3tab[j] = l3ptes[j];

                munmap(l3tab, PAGE_SIZE);

            }
        }

        /* Second pass: find all L1TABs and uncanonicalize them */
        j = 0;

        for ( i = 0; i < max_pfn; i++ )
        {
            if ( ((pfn_type[i] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK) ==
                  XEN_DOMCTL_PFINFO_L1TAB) )
            {
                region_mfn[j] = p2m[i];
                j++;
            }

            if(i == (max_pfn-1) || j == MAX_BATCH_SIZE) {

                if (!(region_base = xc_map_foreign_batch(
                          xc_handle, dom, PROT_READ | PROT_WRITE,
                          region_mfn, j))) {
                    ERROR("map batch failed");
                    goto out;
                }

                for(k = 0; k < j; k++) {
                    if(!uncanonicalize_pagetable(xc_handle, dom, 
                                                 XEN_DOMCTL_PFINFO_L1TAB,
                                                 region_base + k*PAGE_SIZE)) {
                        ERROR("failed uncanonicalize pt!");
                        goto out;
                    }
                }

                munmap(region_base, j*PAGE_SIZE);
                j = 0;
            }
        }

        if (xc_finish_mmu_updates(xc_handle, mmu)) {
            ERROR("Error doing finish_mmu_updates()");
            goto out;
        }
    }

    /*
     * Pin page tables. Do this after writing to them as otherwise Xen
     * will barf when doing the type-checking.
     */
    nr_pins = 0;
    for ( i = 0; i < max_pfn; i++ )
    {
        if ( (pfn_type[i] & XEN_DOMCTL_PFINFO_LPINTAB) == 0 )
            continue;

        switch ( pfn_type[i] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK )
        {
        case XEN_DOMCTL_PFINFO_L1TAB:
            pin[nr_pins].cmd = MMUEXT_PIN_L1_TABLE;
            break;

        case XEN_DOMCTL_PFINFO_L2TAB:
            pin[nr_pins].cmd = MMUEXT_PIN_L2_TABLE;
            break;

        case XEN_DOMCTL_PFINFO_L3TAB:
            pin[nr_pins].cmd = MMUEXT_PIN_L3_TABLE;
            break;

        case XEN_DOMCTL_PFINFO_L4TAB:
            pin[nr_pins].cmd = MMUEXT_PIN_L4_TABLE;
            break;

        default:
            continue;
        }

        pin[nr_pins].arg1.mfn = p2m[i];
        nr_pins++;

        /* Batch full? Then flush. */
        if (nr_pins == MAX_PIN_BATCH) {
            if (xc_mmuext_op(xc_handle, pin, nr_pins, dom) < 0) {
                ERROR("Failed to pin batch of %d page tables", nr_pins);
                goto out;
            }
            nr_pins = 0;
        }
    }

    /* Flush final partial batch. */
    if ((nr_pins != 0) && (xc_mmuext_op(xc_handle, pin, nr_pins, dom) < 0)) {
        ERROR("Failed to pin batch of %d page tables", nr_pins);
        goto out;
    }

    DPRINTF("\b\b\b\b100%%\n");
    DPRINTF("Memory reloaded.\n");

    /* Get the list of PFNs that are not in the psuedo-phys map */
    {
        unsigned int count;
        unsigned long *pfntab;
        int nr_frees, rc;

        if (!read_exact(io_fd, &count, sizeof(count))) {
            ERROR("Error when reading pfn count");
            goto out;
        }

        if(!(pfntab = malloc(sizeof(unsigned long) * count))) {
            ERROR("Out of memory");
            goto out;
        }

        if (!read_exact(io_fd, pfntab, sizeof(unsigned long)*count)) {
            ERROR("Error when reading pfntab");
            goto out;
        }

        nr_frees = 0; 
        for (i = 0; i < count; i++) {

            unsigned long pfn = pfntab[i];

            if(p2m[pfn] != INVALID_P2M_ENTRY) {
                /* pfn is not in physmap now, but was at some point during 
                   the save/migration process - need to free it */
                pfntab[nr_frees++] = p2m[pfn];
                p2m[pfn]  = INVALID_P2M_ENTRY; // not in pseudo-physical map
            }
        }

        if (nr_frees > 0) {

            struct xen_memory_reservation reservation = {
                .nr_extents   = nr_frees,
                .extent_order = 0,
                .domid        = dom
            };
            set_xen_guest_handle(reservation.extent_start, pfntab);

            if ((rc = xc_memory_op(xc_handle, XENMEM_decrease_reservation,
                                   &reservation)) != nr_frees) {
                ERROR("Could not decrease reservation : %d", rc);
                goto out;
            } else
                DPRINTF("Decreased reservation by %d pages\n", count);
        }
    }

    if (!read_exact(io_fd, &ctxt, sizeof(ctxt)) ||
        !read_exact(io_fd, shared_info_page, PAGE_SIZE)) {
        ERROR("Error when reading ctxt or shared info page");
        goto out;
    }

    /* Uncanonicalise the suspend-record frame number and poke resume rec. */
    pfn = ctxt.user_regs.edx;
    if ((pfn >= max_pfn) || (pfn_type[pfn] != XEN_DOMCTL_PFINFO_NOTAB)) {
        ERROR("Suspend record frame number is bad");
        goto out;
    }
    ctxt.user_regs.edx = mfn = p2m[pfn];
    start_info = xc_map_foreign_range(
        xc_handle, dom, PAGE_SIZE, PROT_READ | PROT_WRITE, mfn);
    start_info->nr_pages    = max_pfn;
    start_info->shared_info = shared_info_frame << PAGE_SHIFT;
    start_info->flags       = 0;
    *store_mfn = start_info->store_mfn       = p2m[start_info->store_mfn];
    start_info->store_evtchn                 = store_evtchn;
    start_info->console.domU.mfn    = p2m[start_info->console.domU.mfn];
    start_info->console.domU.evtchn = console_evtchn;
    *console_mfn                    = start_info->console.domU.mfn;
    munmap(start_info, PAGE_SIZE);

    /* Uncanonicalise each GDT frame number. */
    if (ctxt.gdt_ents > 8192) {
        ERROR("GDT entry count out of range");
        goto out;
    }

    for (i = 0; (512*i) < ctxt.gdt_ents; i++) {
        pfn = ctxt.gdt_frames[i];
        if ((pfn >= max_pfn) || (pfn_type[pfn] != XEN_DOMCTL_PFINFO_NOTAB)) {
            ERROR("GDT frame number is bad");
            goto out;
        }
        ctxt.gdt_frames[i] = p2m[pfn];
    }

    /* Uncanonicalise the page table base pointer. */
    pfn = xen_cr3_to_pfn(ctxt.ctrlreg[3]);

    if (pfn >= max_pfn) {
        ERROR("PT base is bad: pfn=%lu max_pfn=%lu type=%08lx",
            pfn, max_pfn, pfn_type[pfn]);
        goto out;
    }

    if ( (pfn_type[pfn] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK) !=
         ((unsigned long)pt_levels<<XEN_DOMCTL_PFINFO_LTAB_SHIFT) ) {
        ERROR("PT base is bad. pfn=%lu nr=%lu type=%08lx %08lx",
            pfn, max_pfn, pfn_type[pfn],
            (unsigned long)pt_levels<<XEN_DOMCTL_PFINFO_LTAB_SHIFT);
        goto out;
    }

    ctxt.ctrlreg[3] = xen_pfn_to_cr3(p2m[pfn]);

    /* clear any pending events and the selector */
    memset(&(shared_info->evtchn_pending[0]), 0,
           sizeof (shared_info->evtchn_pending));
    for ( i = 0; i < MAX_VIRT_CPUS; i++ )
        shared_info->vcpu_info[i].evtchn_pending_sel = 0;

    /* Copy saved contents of shared-info page. No checking needed. */
    page = xc_map_foreign_range(
        xc_handle, dom, PAGE_SIZE, PROT_WRITE, shared_info_frame);
    memcpy(page, shared_info, PAGE_SIZE);
    munmap(page, PAGE_SIZE);

    /* Uncanonicalise the pfn-to-mfn table frame-number list. */
    for (i = 0; i < P2M_FL_ENTRIES; i++) {
        pfn = p2m_frame_list[i];
        if ((pfn >= max_pfn) || (pfn_type[pfn] != XEN_DOMCTL_PFINFO_NOTAB)) {
            ERROR("PFN-to-MFN frame number is bad");
            goto out;
        }

        p2m_frame_list[i] = p2m[pfn];
    }

    /* Copy the P2M we've constructed to the 'live' P2M */
    if (!(live_p2m = xc_map_foreign_batch(xc_handle, dom, PROT_WRITE,
                                          p2m_frame_list, P2M_FL_ENTRIES))) {
        ERROR("Couldn't map p2m table");
        goto out;
    }

    memcpy(live_p2m, p2m, P2M_SIZE);
    munmap(live_p2m, P2M_SIZE);

    DPRINTF("Domain ready to be built.\n");

    domctl.cmd = XEN_DOMCTL_setvcpucontext;
    domctl.domain = (domid_t)dom;
    domctl.u.vcpucontext.vcpu   = 0;
    set_xen_guest_handle(domctl.u.vcpucontext.ctxt, &ctxt);
    rc = xc_domctl(xc_handle, &domctl);

    if (rc != 0) {
        ERROR("Couldn't build the domain");
        goto out;
    }

 out:
    if ( (rc != 0) && (dom != 0) )
        xc_domain_destroy(xc_handle, dom);
    free(mmu);
    free(p2m);
    free(pfn_type);

    DPRINTF("Restore exit with rc=%d\n", rc);
    
    return rc;
}
