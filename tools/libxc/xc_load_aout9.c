
#include "xc_private.h"
#include "xc_aout9.h"

#if defined(__i386__)
  #define A9_MAGIC I_MAGIC
#elif defined(__x86_64__)
  #define A9_MAGIC S_MAGIC
#elif defined(__ia64__)
  #define A9_MAGIC 0
#else
#error "Unsupported architecture"
#endif


#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)
#define round_pgdown(_p)  ((_p)&PAGE_MASK)

static int parseaout9image(char *, unsigned long, struct domain_setup_info *);
static int loadaout9image(char *, unsigned long, int, u32, unsigned long *, struct domain_setup_info *);
static void copyout(int, u32, unsigned long *, unsigned long, void *, int);
struct Exec *get_header(unsigned char *, unsigned long, struct Exec *);


int 
probe_aout9(
    char *image,
    unsigned long image_size,
    struct load_funcs *load_funcs)
{
    struct Exec ehdr;

    if (!get_header(image, image_size, &ehdr)) {
        ERROR("Kernel image does not have a a.out9 header.");
        return -EINVAL;
    }

    load_funcs->parseimage = parseaout9image;
    load_funcs->loadimage = loadaout9image;
    return 0;
}

static int 
parseaout9image(
    char *image,
    unsigned long image_size,
    struct domain_setup_info *dsi)
{
    struct Exec ehdr;
    unsigned long start, txtsz, end;

    if (!get_header(image, image_size, &ehdr)) {
        ERROR("Kernel image does not have a a.out9 header.");
        return -EINVAL;
    }

    if (sizeof ehdr + ehdr.text + ehdr.data > image_size) {
        ERROR("a.out program extends past end of image.");
        return -EINVAL;
    }

    start = round_pgdown(ehdr.entry);
    txtsz = round_pgup(ehdr.text);
    end = start + txtsz + ehdr.data + ehdr.bss;

    dsi->v_start	= start;
    dsi->v_kernstart	= start;
    dsi->v_kernend	= end;
    dsi->v_kernentry	= ehdr.entry;
    dsi->v_end		= end;

    /* XXX load symbols */

    return 0;
}

static int 
loadaout9image(
    char *image,
    unsigned long image_size,
    int xch, u32 dom,
    unsigned long *parray,
    struct domain_setup_info *dsi)
{
    struct Exec ehdr;
    unsigned long txtsz;

    if (!get_header(image, image_size, &ehdr)) {
        ERROR("Kernel image does not have a a.out9 header.");
        return -EINVAL;
    }

    txtsz = round_pgup(ehdr.text);
    copyout(xch, dom, parray, 
            0, image, sizeof ehdr + ehdr.text);
    copyout(xch, dom, parray, 
            txtsz, image + sizeof ehdr + ehdr.text, ehdr.data);
    /* XXX zeroing of BSS needed? */

    /* XXX load symbols */

    return 0;
}

/*
 * copyout data to the domain given an offset to the start
 * of its memory region described by parray.
 */
static void
copyout(
    int xch, u32 dom,
    unsigned long *parray,
    unsigned long off,
    void *buf,
    int sz)
{
    unsigned long pgoff, chunksz;
    void *pg;

    while (sz > 0) {
        pgoff = off & (PAGE_SIZE-1);
        chunksz = sz;
        if(chunksz > PAGE_SIZE - pgoff)
            chunksz = PAGE_SIZE - pgoff;

        pg = xc_map_foreign_range(xch, dom, PAGE_SIZE, PROT_WRITE, 
                                  parray[off>>PAGE_SHIFT]);
        memcpy(pg + pgoff, buf, chunksz);
        munmap(pg, PAGE_SIZE);

        off += chunksz;
        buf += chunksz;
        sz -= chunksz;
    }
}
    
/*
 * Decode the header from the start of image and return it.
 */
struct Exec *
get_header(
    unsigned char *image,
    unsigned long image_size,
    struct Exec *ehdr)
{
    unsigned long *v;
    int i;

    if (A9_MAGIC == 0)
        return 0;

    if (image_size < sizeof ehdr)
        return 0;

    /* ... all big endian words */
    v = (unsigned long *)ehdr;
    for (i = 0; i < sizeof *ehdr; i += 4) {
        v[i/4] = (image[i+0]<<24) | (image[i+1]<<16) | 
                 (image[i+2]<<8) | image[i+3];
    }

    if(ehdr->magic != A9_MAGIC)
        return 0;
    return ehdr;
}

