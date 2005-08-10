/*
 * Dynamic DMA mapping support.
 */

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <asm/io.h>
#include <asm-xen/balloon.h>

/* Map a set of buffers described by scatterlist in streaming
 * mode for DMA.  This is the scatter-gather version of the
 * above pci_map_single interface.  Here the scatter gather list
 * elements are each tagged with the appropriate dma address
 * and length.  They are obtained via sg_dma_{address,length}(SG).
 *
 * NOTE: An implementation may be able to use a smaller number of
 *       DMA address/length pairs than there are SG table elements.
 *       (for example via virtual mapping capabilities)
 *       The routine returns the number of addr/length pairs actually
 *       used, at most nents.
 *
 * Device ownership issues as mentioned above for pci_map_single are
 * the same here.
 */
int dma_map_sg(struct device *hwdev, struct scatterlist *sg,
	       int nents, int direction)
{
	int i;

	BUG_ON(direction == DMA_NONE);
 	for (i = 0; i < nents; i++ ) {
		struct scatterlist *s = &sg[i];
		BUG_ON(!s->page); 
		s->dma_address = virt_to_bus(page_address(s->page) +s->offset);
		s->dma_length = s->length;
	}
	return nents;
}

EXPORT_SYMBOL(dma_map_sg);

/* Unmap a set of streaming mode DMA translations.
 * Again, cpu read rules concerning calls here are the same as for
 * pci_unmap_single() above.
 */
void dma_unmap_sg(struct device *dev, struct scatterlist *sg,
		  int nents, int dir)
{
	int i;
	for (i = 0; i < nents; i++) { 
		struct scatterlist *s = &sg[i];
		BUG_ON(s->page == NULL); 
		BUG_ON(s->dma_address == 0); 
		dma_unmap_single(dev, s->dma_address, s->dma_length, dir);
	} 
}

EXPORT_SYMBOL(dma_unmap_sg);

struct dma_coherent_mem {
	void		*virt_base;
	u32		device_base;
	int		size;
	int		flags;
	unsigned long	*bitmap;
};

void *dma_alloc_coherent(struct device *dev, size_t size,
			   dma_addr_t *dma_handle, unsigned gfp)
{
	void *ret;
	unsigned int order = get_order(size);
	unsigned long vstart;

	struct dma_coherent_mem *mem = dev ? dev->dma_mem : NULL;

	/* ignore region specifiers */
	gfp &= ~(__GFP_DMA | __GFP_HIGHMEM);

	if (mem) {
		int page = bitmap_find_free_region(mem->bitmap, mem->size,
						     order);
		if (page >= 0) {
			*dma_handle = mem->device_base + (page << PAGE_SHIFT);
			ret = mem->virt_base + (page << PAGE_SHIFT);
			memset(ret, 0, size);
			return ret;
		}
		if (mem->flags & DMA_MEMORY_EXCLUSIVE)
			return NULL;
	}

	if (dev == NULL || (dev->coherent_dma_mask < 0xffffffff))
		gfp |= GFP_DMA;

	vstart = __get_free_pages(gfp, order);
	ret = (void *)vstart;
	if (ret == NULL)
		return ret;

	xen_contig_memory(vstart, order);

	memset(ret, 0, size);
	*dma_handle = virt_to_bus(ret);

	return ret;
}
EXPORT_SYMBOL(dma_alloc_coherent);

void dma_free_coherent(struct device *dev, size_t size,
			 void *vaddr, dma_addr_t dma_handle)
{
	struct dma_coherent_mem *mem = dev ? dev->dma_mem : NULL;
	int order = get_order(size);
	
	if (mem && vaddr >= mem->virt_base && vaddr < (mem->virt_base + (mem->size << PAGE_SHIFT))) {
		int page = (vaddr - mem->virt_base) >> PAGE_SHIFT;

		bitmap_release_region(mem->bitmap, page, order);
	} else
		free_pages((unsigned long)vaddr, order);
}
EXPORT_SYMBOL(dma_free_coherent);

#if 0
int dma_declare_coherent_memory(struct device *dev, dma_addr_t bus_addr,
				dma_addr_t device_addr, size_t size, int flags)
{
	void __iomem *mem_base;
	int pages = size >> PAGE_SHIFT;
	int bitmap_size = (pages + 31)/32;

	if ((flags & (DMA_MEMORY_MAP | DMA_MEMORY_IO)) == 0)
		goto out;
	if (!size)
		goto out;
	if (dev->dma_mem)
		goto out;

	/* FIXME: this routine just ignores DMA_MEMORY_INCLUDES_CHILDREN */

	mem_base = ioremap(bus_addr, size);
	if (!mem_base)
		goto out;

	dev->dma_mem = kmalloc(sizeof(struct dma_coherent_mem), GFP_KERNEL);
	if (!dev->dma_mem)
		goto out;
	memset(dev->dma_mem, 0, sizeof(struct dma_coherent_mem));
	dev->dma_mem->bitmap = kmalloc(bitmap_size, GFP_KERNEL);
	if (!dev->dma_mem->bitmap)
		goto free1_out;
	memset(dev->dma_mem->bitmap, 0, bitmap_size);

	dev->dma_mem->virt_base = mem_base;
	dev->dma_mem->device_base = device_addr;
	dev->dma_mem->size = pages;
	dev->dma_mem->flags = flags;

	if (flags & DMA_MEMORY_MAP)
		return DMA_MEMORY_MAP;

	return DMA_MEMORY_IO;

 free1_out:
	kfree(dev->dma_mem->bitmap);
 out:
	return 0;
}
EXPORT_SYMBOL(dma_declare_coherent_memory);

void dma_release_declared_memory(struct device *dev)
{
	struct dma_coherent_mem *mem = dev->dma_mem;
	
	if(!mem)
		return;
	dev->dma_mem = NULL;
	iounmap(mem->virt_base);
	kfree(mem->bitmap);
	kfree(mem);
}
EXPORT_SYMBOL(dma_release_declared_memory);

void *dma_mark_declared_memory_occupied(struct device *dev,
					dma_addr_t device_addr, size_t size)
{
	struct dma_coherent_mem *mem = dev->dma_mem;
	int pages = (size + (device_addr & ~PAGE_MASK) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	int pos, err;

	if (!mem)
		return ERR_PTR(-EINVAL);

	pos = (device_addr - mem->device_base) >> PAGE_SHIFT;
	err = bitmap_allocate_region(mem->bitmap, pos, get_order(pages));
	if (err != 0)
		return ERR_PTR(err);
	return mem->virt_base + (pos << PAGE_SHIFT);
}
EXPORT_SYMBOL(dma_mark_declared_memory_occupied);
#endif

static LIST_HEAD(dma_map_head);
static DEFINE_SPINLOCK(dma_map_lock);
struct dma_map_entry {
	struct list_head list;
	dma_addr_t dma;
	char *bounce, *host;
	size_t size;
};
#define DMA_MAP_MATCHES(e,d) (((e)->dma<=(d)) && (((e)->dma+(e)->size)>(d)))

dma_addr_t
dma_map_single(struct device *dev, void *ptr, size_t size,
	       enum dma_data_direction direction)
{
	struct dma_map_entry *ent;
	void *bnc;
	dma_addr_t dma;
	unsigned long flags;

	if (direction == DMA_NONE)
		out_of_line_bug();

	/*
	 * Even if size is sub-page, the buffer may still straddle a page
	 * boundary. Take into account buffer start offset. All other calls are
	 * conservative and always search the dma_map list if it's non-empty.
	 */
	if (((((unsigned long)ptr) & ~PAGE_MASK) + size) <= PAGE_SIZE) {
		dma = virt_to_bus(ptr);
	} else {
		BUG_ON((bnc = dma_alloc_coherent(dev, size, &dma, GFP_ATOMIC)) == NULL);
		BUG_ON((ent = kmalloc(sizeof(*ent), GFP_ATOMIC)) == NULL);
		if (direction != DMA_FROM_DEVICE)
			memcpy(bnc, ptr, size);
		ent->dma    = dma;
		ent->bounce = bnc;
		ent->host   = ptr;
		ent->size   = size;
		spin_lock_irqsave(&dma_map_lock, flags);
		list_add(&ent->list, &dma_map_head);
		spin_unlock_irqrestore(&dma_map_lock, flags);
	}

	if ((dma+size) & ~*dev->dma_mask)
		out_of_line_bug();
	return dma;
}
EXPORT_SYMBOL(dma_map_single);

void
dma_unmap_single(struct device *dev, dma_addr_t dma_addr, size_t size,
		 enum dma_data_direction direction)
{
	struct dma_map_entry *ent;
	unsigned long flags;

	if (direction == DMA_NONE)
		out_of_line_bug();

	/* Fast-path check: are there any multi-page DMA mappings? */
	if (!list_empty(&dma_map_head)) {
		spin_lock_irqsave(&dma_map_lock, flags);
		list_for_each_entry ( ent, &dma_map_head, list ) {
			if (DMA_MAP_MATCHES(ent, dma_addr)) {
				list_del(&ent->list);
				break;
			}
		}
		spin_unlock_irqrestore(&dma_map_lock, flags);
		if (&ent->list != &dma_map_head) {
			BUG_ON(dma_addr != ent->dma);
			BUG_ON(size != ent->size);
			if (direction != DMA_TO_DEVICE)
				memcpy(ent->host, ent->bounce, size);
			dma_free_coherent(dev, size, ent->bounce, ent->dma);
			kfree(ent);
		}
	}
}
EXPORT_SYMBOL(dma_unmap_single);

void
dma_sync_single_for_cpu(struct device *dev, dma_addr_t dma_handle, size_t size,
			enum dma_data_direction direction)
{
	struct dma_map_entry *ent;
	unsigned long flags, off;

	/* Fast-path check: are there any multi-page DMA mappings? */
	if (!list_empty(&dma_map_head)) {
		spin_lock_irqsave(&dma_map_lock, flags);
		list_for_each_entry ( ent, &dma_map_head, list )
			if (DMA_MAP_MATCHES(ent, dma_handle))
				break;
		spin_unlock_irqrestore(&dma_map_lock, flags);
		if (&ent->list != &dma_map_head) {
			off = dma_handle - ent->dma;
			BUG_ON((off + size) > ent->size);
			/*if (direction != DMA_TO_DEVICE)*/
				memcpy(ent->host+off, ent->bounce+off, size);
		}
	}
}
EXPORT_SYMBOL(dma_sync_single_for_cpu);

void
dma_sync_single_for_device(struct device *dev, dma_addr_t dma_handle, size_t size,
                           enum dma_data_direction direction)
{
	struct dma_map_entry *ent;
	unsigned long flags, off;

	/* Fast-path check: are there any multi-page DMA mappings? */
	if (!list_empty(&dma_map_head)) {
		spin_lock_irqsave(&dma_map_lock, flags);
		list_for_each_entry ( ent, &dma_map_head, list )
			if (DMA_MAP_MATCHES(ent, dma_handle))
				break;
		spin_unlock_irqrestore(&dma_map_lock, flags);
		if (&ent->list != &dma_map_head) {
			off = dma_handle - ent->dma;
			BUG_ON((off + size) > ent->size);
			/*if (direction != DMA_FROM_DEVICE)*/
				memcpy(ent->bounce+off, ent->host+off, size);
		}
	}

	flush_write_buffers();
}
EXPORT_SYMBOL(dma_sync_single_for_device);
