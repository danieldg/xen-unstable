/* block-ram.c
 *
 * Fast Ramdisk implementation.
 *
 * (c) 2006 Andrew Warfield and Julian Chesterfield
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <string.h>
#include "tapdisk.h"

#define MAX_DISK_SIZE 1024000 /*500MB disk limit*/

char *img;
long int   disksector_size;
long int   disksize;
long int   diskinfo;
static int connections = 0;

struct tdram_state {
        int fd;
	int poll_pipe[2]; /* dummy fd for polling on */
};

/*Get Image size, secsize*/
static int get_image_info(struct td_state *s, int fd)
{
	int ret;
	long size;
	unsigned long total_size;
	struct statvfs statBuf;
	struct stat stat;

	ret = fstat(fd, &stat);
	if (ret != 0) {
		DPRINTF("ERROR: fstat failed, Couldn't stat image");
		return -EINVAL;
	}

	if (S_ISBLK(stat.st_mode)) {
		/*Accessing block device directly*/
		s->size = 0;
		if (ioctl(fd,BLKGETSIZE,&s->size)!=0) {
			DPRINTF("ERR: BLKGETSIZE failed, couldn't stat image");
			return -EINVAL;
		}

		DPRINTF("Image size: \n\tpre sector_shift  [%llu]\n\tpost "
			"sector_shift [%llu]\n",
			(long long unsigned)(s->size << SECTOR_SHIFT),
			(long long unsigned)s->size);

		/*Get the sector size*/
#if defined(BLKSSZGET)
		{
			int arg;
			s->sector_size = DEFAULT_SECTOR_SIZE;
			ioctl(fd, BLKSSZGET, &s->sector_size);
			
			if (s->sector_size != DEFAULT_SECTOR_SIZE)
				DPRINTF("Note: sector size is %ld (not %d)\n",
					s->sector_size, DEFAULT_SECTOR_SIZE);
		}
#else
		s->sector_size = DEFAULT_SECTOR_SIZE;
#endif

	} else {
		/*Local file? try fstat instead*/
		s->size = (stat.st_size >> SECTOR_SHIFT);
		s->sector_size = DEFAULT_SECTOR_SIZE;
		DPRINTF("Image size: \n\tpre sector_shift  [%llu]\n\tpost "
			"sector_shift [%llu]\n",
			(long long unsigned)(s->size << SECTOR_SHIFT),
			(long long unsigned)s->size);
	}

	if (s->size == 0) {		
		s->size =((uint64_t) MAX_DISK_SIZE);
		s->sector_size = DEFAULT_SECTOR_SIZE;
	}
	s->info = 0;

        /*Store variables locally*/
	disksector_size = s->sector_size;
	disksize        = s->size;
	diskinfo        = s->info;
	DPRINTF("Image sector_size: \n\t[%lu]\n",
		s->sector_size);

	return 0;
}

static inline void init_fds(struct disk_driver *dd)
{
        int i;
	struct tdram_state *prv = (struct tdram_state *)dd->private;

        for(i =0 ; i < MAX_IOFD; i++)
		dd->io_fd[i] = 0;

        dd->io_fd[0] = prv->poll_pipe[0];
}

/* Open the disk file and initialize ram state. */
int tdram_open (struct disk_driver *dd, const char *name)
{
	char *p;
	uint64_t size;
	int i, fd, ret = 0, count = 0;
	struct td_state    *s     = dd->td_state;
	struct tdram_state *prv   = (struct tdram_state *)dd->private;

	connections++;
	
	/* set up a pipe so that we can hand back a poll fd that won't fire.*/
	ret = pipe(prv->poll_pipe);
	if (ret != 0)
		return (0 - errno);

	if (connections > 1) {
		s->sector_size = disksector_size;
		s->size        = disksize;
		s->info        = diskinfo; 
		DPRINTF("Image already open, returning parameters:\n");
		DPRINTF("Image size: \n\tpre sector_shift  [%llu]\n\tpost "
			"sector_shift [%llu]\n",
			(long long unsigned)(s->size << SECTOR_SHIFT),
			(long long unsigned)s->size);
		DPRINTF("Image sector_size: \n\t[%lu]\n",
			s->sector_size);

		prv->fd = -1;
		goto done;
	}

	/* Open the file */
        fd = open(name, O_RDWR | O_DIRECT | O_LARGEFILE);

        if ((fd == -1) && (errno == EINVAL)) {

                /* Maybe O_DIRECT isn't supported. */
                fd = open(name, O_RDWR | O_LARGEFILE);
                if (fd != -1) DPRINTF("WARNING: Accessing image without"
                                     "O_DIRECT! (%s)\n", name);

        } else if (fd != -1) DPRINTF("open(%s) with O_DIRECT\n", name);
	
        if (fd == -1) {
		DPRINTF("Unable to open [%s]!\n",name);
        	ret = 0 - errno;
        	goto done;
        }

        prv->fd = fd;

	ret = get_image_info(s, fd);
	size = MAX_DISK_SIZE;

	if (s->size > size) {
		DPRINTF("Disk exceeds limit, must be less than [%d]MB",
			(MAX_DISK_SIZE<<SECTOR_SHIFT)>>20);
		return -ENOMEM;
	}

	/*Read the image into memory*/
	p = img = malloc(s->size << SECTOR_SHIFT);
	if (img == NULL) {
		DPRINTF("Mem malloc failed\n");
		return -1;
	}
	DPRINTF("Reading %llu bytes.......",(long long unsigned)s->size << SECTOR_SHIFT);

	for (i = 0; i < s->size; i++) {
		ret = read(prv->fd, p, s->sector_size);
		if (ret != s->sector_size) {
			ret = 0 - errno;
			break;
		} else {
			count += ret;
			p = img + count;
		}
	}
	DPRINTF("[%d]\n",count);
	if (count != s->size << SECTOR_SHIFT) {
		ret = -1;
	} else {
		ret = 0;
	} 

	init_fds(dd);
done:
	return ret;
}

 int tdram_queue_read(struct disk_driver *dd, uint64_t sector,
		      int nb_sectors, char *buf, td_callback_t cb,
		      int id, void *private)
{
	struct td_state    *s   = dd->td_state;
	struct tdram_state *prv = (struct tdram_state *)dd->private;
	int      size    = nb_sectors * s->sector_size;
	uint64_t offset  = sector * (uint64_t)s->sector_size;

	memcpy(buf, img + offset, size);

	return cb(dd, 0, sector, nb_sectors, id, private);
}

int tdram_queue_write(struct disk_driver *dd, uint64_t sector,
		      int nb_sectors, char *buf, td_callback_t cb,
		      int id, void *private)
{
	struct td_state    *s   = dd->td_state;
	struct tdram_state *prv = (struct tdram_state *)dd->private;
	int      size    = nb_sectors * s->sector_size;
	uint64_t offset  = sector * (uint64_t)s->sector_size;
	
	/* We assume that write access is controlled
	 * at a higher level for multiple disks */
	memcpy(img + offset, buf, size);

	return cb(dd, 0, sector, nb_sectors, id, private);
}
 		
int tdram_submit(struct disk_driver *dd)
{
	return 0;	
}

int tdram_close(struct disk_driver *dd)
{
	struct tdram_state *prv = (struct tdram_state *)dd->private;
	
	connections--;
	
	return 0;
}

int tdram_do_callbacks(struct disk_driver *dd, int sid)
{
	/* always ask for a kick */
	return 1;
}

int tdram_has_parent(struct disk_driver *dd)
{
	return 0;
}

int tdram_get_parent(struct disk_driver *dd, struct disk_driver *parent)
{
	return -EINVAL;
}

struct tap_disk tapdisk_ram = {
	.disk_type          = "tapdisk_ram",
	.private_data_size  = sizeof(struct tdram_state),
	.td_open            = tdram_open,
	.td_queue_read      = tdram_queue_read,
	.td_queue_write     = tdram_queue_write,
	.td_submit          = tdram_submit,
	.td_has_parent      = tdram_has_parent,
	.td_get_parent      = tdram_get_parent,
	.td_close           = tdram_close,
	.td_do_callbacks    = tdram_do_callbacks,
};
