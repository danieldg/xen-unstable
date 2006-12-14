/******************************************************************************
 * Talks to Xen Store to figure out what devices we have.
 *
 * Copyright (C) 2005 Rusty Russell, IBM Corporation
 * Copyright (C) 2005 Mike Wray, Hewlett-Packard
 * Copyright (C) 2005, 2006 XenSource Ltd
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

#define DPRINTK(fmt, args...)				\
	pr_debug("xenbus_probe (%s:%d) " fmt ".\n",	\
		 __FUNCTION__, __LINE__, ##args)

#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/fcntl.h>
#include <linux/mm.h>
#include <linux/notifier.h>
#include <linux/kthread.h>
#include <linux/mutex.h>

#include <asm/io.h>
#include <asm/page.h>
#include <asm/maddr.h>
#include <asm/pgtable.h>
#include <asm/hypervisor.h>
#include <xen/xenbus.h>
#include <xen/xen_proc.h>
#include <xen/evtchn.h>
#include <xen/features.h>
#include <xen/hvm.h>

#include "xenbus_comms.h"
#include "xenbus_probe.h"

#ifdef HAVE_XEN_PLATFORM_COMPAT_H
#include <xen/platform-compat.h>
#endif

int xen_store_evtchn;
struct xenstore_domain_interface *xen_store_interface;
static unsigned long xen_store_mfn;

extern struct mutex xenwatch_mutex;

static struct notifier_block *xenstore_chain;

static void wait_for_devices(struct xenbus_driver *xendrv);

static int xenbus_probe_frontend(const char *type, const char *name);

static void xenbus_dev_shutdown(struct device *_dev);

/* If something in array of ids matches this device, return it. */
static const struct xenbus_device_id *
match_device(const struct xenbus_device_id *arr, struct xenbus_device *dev)
{
	for (; *arr->devicetype != '\0'; arr++) {
		if (!strcmp(arr->devicetype, dev->devicetype))
			return arr;
	}
	return NULL;
}

int xenbus_match(struct device *_dev, struct device_driver *_drv)
{
	struct xenbus_driver *drv = to_xenbus_driver(_drv);

	if (!drv->ids)
		return 0;

	return match_device(drv->ids, to_xenbus_device(_dev)) != NULL;
}

/* device/<type>/<id> => <type>-<id> */
static int frontend_bus_id(char bus_id[BUS_ID_SIZE], const char *nodename)
{
	nodename = strchr(nodename, '/');
	if (!nodename || strlen(nodename + 1) >= BUS_ID_SIZE) {
		printk(KERN_WARNING "XENBUS: bad frontend %s\n", nodename);
		return -EINVAL;
	}

	strlcpy(bus_id, nodename + 1, BUS_ID_SIZE);
	if (!strchr(bus_id, '/')) {
		printk(KERN_WARNING "XENBUS: bus_id %s no slash\n", bus_id);
		return -EINVAL;
	}
	*strchr(bus_id, '/') = '-';
	return 0;
}


static void free_otherend_details(struct xenbus_device *dev)
{
	kfree(dev->otherend);
	dev->otherend = NULL;
}


static void free_otherend_watch(struct xenbus_device *dev)
{
	if (dev->otherend_watch.node) {
		unregister_xenbus_watch(&dev->otherend_watch);
		kfree(dev->otherend_watch.node);
		dev->otherend_watch.node = NULL;
	}
}


int read_otherend_details(struct xenbus_device *xendev,
				 char *id_node, char *path_node)
{
	int err = xenbus_gather(XBT_NIL, xendev->nodename,
				id_node, "%i", &xendev->otherend_id,
				path_node, NULL, &xendev->otherend,
				NULL);
	if (err) {
		xenbus_dev_fatal(xendev, err,
				 "reading other end details from %s",
				 xendev->nodename);
		return err;
	}
	if (strlen(xendev->otherend) == 0 ||
	    !xenbus_exists(XBT_NIL, xendev->otherend, "")) {
		xenbus_dev_fatal(xendev, -ENOENT,
				 "unable to read other end from %s.  "
				 "missing or inaccessible.",
				 xendev->nodename);
		free_otherend_details(xendev);
		return -ENOENT;
	}

	return 0;
}


static int read_backend_details(struct xenbus_device *xendev)
{
	return read_otherend_details(xendev, "backend-id", "backend");
}


/* Bus type for frontend drivers. */
static struct xen_bus_type xenbus_frontend = {
	.root = "device",
	.levels = 2, 		/* device/type/<id> */
	.get_bus_id = frontend_bus_id,
	.probe = xenbus_probe_frontend,
	.bus = {
		.name     = "xen",
		.match    = xenbus_match,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
		.probe    = xenbus_dev_probe,
		.remove   = xenbus_dev_remove,
		.shutdown = xenbus_dev_shutdown,
#endif
	},
	.dev = {
		.bus_id = "xen",
	},
};

static void otherend_changed(struct xenbus_watch *watch,
			     const char **vec, unsigned int len)
{
	struct xenbus_device *dev =
		container_of(watch, struct xenbus_device, otherend_watch);
	struct xenbus_driver *drv = to_xenbus_driver(dev->dev.driver);
	enum xenbus_state state;

	/* Protect us against watches firing on old details when the otherend
	   details change, say immediately after a resume. */
	if (!dev->otherend ||
	    strncmp(dev->otherend, vec[XS_WATCH_PATH],
		    strlen(dev->otherend))) {
		DPRINTK("Ignoring watch at %s", vec[XS_WATCH_PATH]);
		return;
	}

	state = xenbus_read_driver_state(dev->otherend);

	DPRINTK("state is %d (%s), %s, %s", state, xenbus_strstate(state),
		dev->otherend_watch.node, vec[XS_WATCH_PATH]);

	/*
	 * Ignore xenbus transitions during shutdown. This prevents us doing
	 * work that can fail e.g., when the rootfs is gone.
	 */
	if (system_state > SYSTEM_RUNNING) {
		struct xen_bus_type *bus = bus;
		bus = container_of(dev->dev.bus, struct xen_bus_type, bus);
		/* If we're frontend, drive the state machine to Closed. */
		/* This should cause the backend to release our resources. */
		if ((bus == &xenbus_frontend) && (state == XenbusStateClosing))
			xenbus_frontend_closed(dev);
		return;
	}

	if (drv->otherend_changed)
		drv->otherend_changed(dev, state);
}


static int talk_to_otherend(struct xenbus_device *dev)
{
	struct xenbus_driver *drv = to_xenbus_driver(dev->dev.driver);

	free_otherend_watch(dev);
	free_otherend_details(dev);

	return drv->read_otherend_details(dev);
}


static int watch_otherend(struct xenbus_device *dev)
{
	return xenbus_watch_path2(dev, dev->otherend, "state",
				  &dev->otherend_watch, otherend_changed);
}


int xenbus_dev_probe(struct device *_dev)
{
	struct xenbus_device *dev = to_xenbus_device(_dev);
	struct xenbus_driver *drv = to_xenbus_driver(_dev->driver);
	const struct xenbus_device_id *id;
	int err;

	DPRINTK("%s", dev->nodename);

	if (!drv->probe) {
		err = -ENODEV;
		goto fail;
	}

	id = match_device(drv->ids, dev);
	if (!id) {
		err = -ENODEV;
		goto fail;
	}

	err = talk_to_otherend(dev);
	if (err) {
		printk(KERN_WARNING
		       "xenbus_probe: talk_to_otherend on %s failed.\n",
		       dev->nodename);
		return err;
	}

	err = drv->probe(dev, id);
	if (err)
		goto fail;

	err = watch_otherend(dev);
	if (err) {
		printk(KERN_WARNING
		       "xenbus_probe: watch_otherend on %s failed.\n",
		       dev->nodename);
		return err;
	}

	return 0;
fail:
	xenbus_dev_error(dev, err, "xenbus_dev_probe on %s", dev->nodename);
	xenbus_switch_state(dev, XenbusStateClosed);
	return -ENODEV;
}

int xenbus_dev_remove(struct device *_dev)
{
	struct xenbus_device *dev = to_xenbus_device(_dev);
	struct xenbus_driver *drv = to_xenbus_driver(_dev->driver);

	DPRINTK("%s", dev->nodename);

	free_otherend_watch(dev);
	free_otherend_details(dev);

	if (drv->remove)
		drv->remove(dev);

	xenbus_switch_state(dev, XenbusStateClosed);
	return 0;
}

static void xenbus_dev_shutdown(struct device *_dev)
{
	struct xenbus_device *dev = to_xenbus_device(_dev);
	unsigned long timeout = 5*HZ;

	DPRINTK("%s", dev->nodename);

	get_device(&dev->dev);
	if (dev->state != XenbusStateConnected) {
		printk("%s: %s: %s != Connected, skipping\n", __FUNCTION__,
		       dev->nodename, xenbus_strstate(dev->state));
		goto out;
	}
	xenbus_switch_state(dev, XenbusStateClosing);
	timeout = wait_for_completion_timeout(&dev->down, timeout);
	if (!timeout)
		printk("%s: %s timeout closing device\n", __FUNCTION__, dev->nodename);
 out:
	put_device(&dev->dev);
}

int xenbus_register_driver_common(struct xenbus_driver *drv,
				  struct xen_bus_type *bus)
{
	int ret;

	drv->driver.name = drv->name;
	drv->driver.bus = &bus->bus;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
	drv->driver.owner = drv->owner;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
	drv->driver.probe = xenbus_dev_probe;
	drv->driver.remove = xenbus_dev_remove;
	drv->driver.shutdown = xenbus_dev_shutdown;
#endif

	mutex_lock(&xenwatch_mutex);
	ret = driver_register(&drv->driver);
	mutex_unlock(&xenwatch_mutex);
	return ret;
}

int xenbus_register_frontend(struct xenbus_driver *drv)
{
	int ret;

	drv->read_otherend_details = read_backend_details;

	ret = xenbus_register_driver_common(drv, &xenbus_frontend);
	if (ret)
		return ret;

	/* If this driver is loaded as a module wait for devices to attach. */
	wait_for_devices(drv);

	return 0;
}
EXPORT_SYMBOL_GPL(xenbus_register_frontend);

void xenbus_unregister_driver(struct xenbus_driver *drv)
{
	driver_unregister(&drv->driver);
}
EXPORT_SYMBOL_GPL(xenbus_unregister_driver);

struct xb_find_info
{
	struct xenbus_device *dev;
	const char *nodename;
};

static int cmp_dev(struct device *dev, void *data)
{
	struct xenbus_device *xendev = to_xenbus_device(dev);
	struct xb_find_info *info = data;

	if (!strcmp(xendev->nodename, info->nodename)) {
		info->dev = xendev;
		get_device(dev);
		return 1;
	}
	return 0;
}

struct xenbus_device *xenbus_device_find(const char *nodename,
					 struct bus_type *bus)
{
	struct xb_find_info info = { .dev = NULL, .nodename = nodename };

	bus_for_each_dev(bus, NULL, &info, cmp_dev);
	return info.dev;
}

static int cleanup_dev(struct device *dev, void *data)
{
	struct xenbus_device *xendev = to_xenbus_device(dev);
	struct xb_find_info *info = data;
	int len = strlen(info->nodename);

	DPRINTK("%s", info->nodename);

	/* Match the info->nodename path, or any subdirectory of that path. */
	if (strncmp(xendev->nodename, info->nodename, len))
		return 0;

	/* If the node name is longer, ensure it really is a subdirectory. */
	if ((strlen(xendev->nodename) > len) && (xendev->nodename[len] != '/'))
		return 0;

	info->dev = xendev;
	get_device(dev);
	return 1;
}

static void xenbus_cleanup_devices(const char *path, struct bus_type *bus)
{
	struct xb_find_info info = { .nodename = path };

	do {
		info.dev = NULL;
		bus_for_each_dev(bus, NULL, &info, cleanup_dev);
		if (info.dev) {
			device_unregister(&info.dev->dev);
			put_device(&info.dev->dev);
		}
	} while (info.dev);
}

static void xenbus_dev_release(struct device *dev)
{
	if (dev)
		kfree(to_xenbus_device(dev));
}

static ssize_t xendev_show_nodename(struct device *dev,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,13)
				    struct device_attribute *attr,
#endif
				    char *buf)
{
	return sprintf(buf, "%s\n", to_xenbus_device(dev)->nodename);
}
DEVICE_ATTR(nodename, S_IRUSR | S_IRGRP | S_IROTH, xendev_show_nodename, NULL);

static ssize_t xendev_show_devtype(struct device *dev,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,13)
				   struct device_attribute *attr,
#endif
				   char *buf)
{
	return sprintf(buf, "%s\n", to_xenbus_device(dev)->devicetype);
}
DEVICE_ATTR(devtype, S_IRUSR | S_IRGRP | S_IROTH, xendev_show_devtype, NULL);


int xenbus_probe_node(struct xen_bus_type *bus,
		      const char *type,
		      const char *nodename)
{
	int err;
	struct xenbus_device *xendev;
	size_t stringlen;
	char *tmpstring;

	enum xenbus_state state = xenbus_read_driver_state(nodename);

	if (state != XenbusStateInitialising) {
		/* Device is not new, so ignore it.  This can happen if a
		   device is going away after switching to Closed.  */
		return 0;
	}

	stringlen = strlen(nodename) + 1 + strlen(type) + 1;
	xendev = kzalloc(sizeof(*xendev) + stringlen, GFP_KERNEL);
	if (!xendev)
		return -ENOMEM;

	xendev->state = XenbusStateInitialising;

	/* Copy the strings into the extra space. */

	tmpstring = (char *)(xendev + 1);
	strcpy(tmpstring, nodename);
	xendev->nodename = tmpstring;

	tmpstring += strlen(tmpstring) + 1;
	strcpy(tmpstring, type);
	xendev->devicetype = tmpstring;
	init_completion(&xendev->down);

	xendev->dev.parent = &bus->dev;
	xendev->dev.bus = &bus->bus;
	xendev->dev.release = xenbus_dev_release;

	err = bus->get_bus_id(xendev->dev.bus_id, xendev->nodename);
	if (err)
		goto fail;

	/* Register with generic device framework. */
	err = device_register(&xendev->dev);
	if (err)
		goto fail;

	device_create_file(&xendev->dev, &dev_attr_nodename);
	device_create_file(&xendev->dev, &dev_attr_devtype);

	return 0;
fail:
	kfree(xendev);
	return err;
}

/* device/<typename>/<name> */
static int xenbus_probe_frontend(const char *type, const char *name)
{
	char *nodename;
	int err;

	nodename = kasprintf(GFP_KERNEL, "%s/%s/%s", xenbus_frontend.root, type, name);
	if (!nodename)
		return -ENOMEM;

	DPRINTK("%s", nodename);

	err = xenbus_probe_node(&xenbus_frontend, type, nodename);
	kfree(nodename);
	return err;
}

static int xenbus_probe_device_type(struct xen_bus_type *bus, const char *type)
{
	int err = 0;
	char **dir;
	unsigned int dir_n = 0;
	int i;

	dir = xenbus_directory(XBT_NIL, bus->root, type, &dir_n);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	for (i = 0; i < dir_n; i++) {
		err = bus->probe(type, dir[i]);
		if (err)
			break;
	}
	kfree(dir);
	return err;
}

int xenbus_probe_devices(struct xen_bus_type *bus)
{
	int err = 0;
	char **dir;
	unsigned int i, dir_n;

	dir = xenbus_directory(XBT_NIL, bus->root, "", &dir_n);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	for (i = 0; i < dir_n; i++) {
		err = xenbus_probe_device_type(bus, dir[i]);
		if (err)
			break;
	}
	kfree(dir);
	return err;
}

static unsigned int char_count(const char *str, char c)
{
	unsigned int i, ret = 0;

	for (i = 0; str[i]; i++)
		if (str[i] == c)
			ret++;
	return ret;
}

static int strsep_len(const char *str, char c, unsigned int len)
{
	unsigned int i;

	for (i = 0; str[i]; i++)
		if (str[i] == c) {
			if (len == 0)
				return i;
			len--;
		}
	return (len == 0) ? i : -ERANGE;
}

void dev_changed(const char *node, struct xen_bus_type *bus)
{
	int exists, rootlen;
	struct xenbus_device *dev;
	char type[BUS_ID_SIZE];
	const char *p, *root;

	if (char_count(node, '/') < 2)
 		return;

	exists = xenbus_exists(XBT_NIL, node, "");
	if (!exists) {
		xenbus_cleanup_devices(node, &bus->bus);
		return;
	}

	/* backend/<type>/... or device/<type>/... */
	p = strchr(node, '/') + 1;
	snprintf(type, BUS_ID_SIZE, "%.*s", (int)strcspn(p, "/"), p);
	type[BUS_ID_SIZE-1] = '\0';

	rootlen = strsep_len(node, '/', bus->levels);
	if (rootlen < 0)
		return;
	root = kasprintf(GFP_KERNEL, "%.*s", rootlen, node);
	if (!root)
		return;

	dev = xenbus_device_find(root, &bus->bus);
	if (!dev)
		xenbus_probe_node(bus, type, root);
	else
		put_device(&dev->dev);

	kfree(root);
}

static void frontend_changed(struct xenbus_watch *watch,
			     const char **vec, unsigned int len)
{
	DPRINTK("");

	dev_changed(vec[XS_WATCH_PATH], &xenbus_frontend);
}

/* We watch for devices appearing and vanishing. */
static struct xenbus_watch fe_watch = {
	.node = "device",
	.callback = frontend_changed,
};

static int suspend_dev(struct device *dev, void *data)
{
	int err = 0;
	struct xenbus_driver *drv;
	struct xenbus_device *xdev;

	DPRINTK("");

	if (dev->driver == NULL)
		return 0;
	drv = to_xenbus_driver(dev->driver);
	xdev = container_of(dev, struct xenbus_device, dev);
	if (drv->suspend)
		err = drv->suspend(xdev);
	if (err)
		printk(KERN_WARNING
		       "xenbus: suspend %s failed: %i\n", dev->bus_id, err);
	return 0;
}

static int resume_dev(struct device *dev, void *data)
{
	int err;
	struct xenbus_driver *drv;
	struct xenbus_device *xdev;

	DPRINTK("");

	if (dev->driver == NULL)
		return 0;

	drv = to_xenbus_driver(dev->driver);
	xdev = container_of(dev, struct xenbus_device, dev);

	err = talk_to_otherend(xdev);
	if (err) {
		printk(KERN_WARNING
		       "xenbus: resume (talk_to_otherend) %s failed: %i\n",
		       dev->bus_id, err);
		return err;
	}

	xdev->state = XenbusStateInitialising;

	if (drv->resume) {
		err = drv->resume(xdev);
		if (err) { 
			printk(KERN_WARNING
			       "xenbus: resume %s failed: %i\n", 
			       dev->bus_id, err);
			return err;
		}
	}

	err = watch_otherend(xdev);
	if (err) {
		printk(KERN_WARNING
		       "xenbus_probe: resume (watch_otherend) %s failed: "
		       "%d.\n", dev->bus_id, err);
		return err;
	}

	return 0;
}

void xenbus_suspend(void)
{
	DPRINTK("");

	bus_for_each_dev(&xenbus_frontend.bus, NULL, NULL, suspend_dev);
	xenbus_backend_suspend(suspend_dev);
	xs_suspend();
}
EXPORT_SYMBOL_GPL(xenbus_suspend);

void xenbus_resume(void)
{
	xb_init_comms();
	xs_resume();
	bus_for_each_dev(&xenbus_frontend.bus, NULL, NULL, resume_dev);
	xenbus_backend_resume(resume_dev);
}
EXPORT_SYMBOL_GPL(xenbus_resume);


/* A flag to determine if xenstored is 'ready' (i.e. has started) */
int xenstored_ready = 0;


int register_xenstore_notifier(struct notifier_block *nb)
{
	int ret = 0;

	if (xenstored_ready > 0)
		ret = nb->notifier_call(nb, 0, NULL);
	else
		notifier_chain_register(&xenstore_chain, nb);

	return ret;
}
EXPORT_SYMBOL_GPL(register_xenstore_notifier);

void unregister_xenstore_notifier(struct notifier_block *nb)
{
	notifier_chain_unregister(&xenstore_chain, nb);
}
EXPORT_SYMBOL_GPL(unregister_xenstore_notifier);


void xenbus_probe(void *unused)
{
	BUG_ON((xenstored_ready <= 0));

	/* Enumerate devices in xenstore and watch for changes. */
	xenbus_probe_devices(&xenbus_frontend);
	register_xenbus_watch(&fe_watch);
	xenbus_backend_probe_and_watch();

	/* Notify others that xenstore is up */
	notifier_call_chain(&xenstore_chain, 0, NULL);
}


#if defined(CONFIG_PROC_FS) && defined(CONFIG_XEN_PRIVILEGED_GUEST)
static struct file_operations xsd_kva_fops;
static struct proc_dir_entry *xsd_kva_intf;
static struct proc_dir_entry *xsd_port_intf;

static int xsd_kva_mmap(struct file *file, struct vm_area_struct *vma)
{
	size_t size = vma->vm_end - vma->vm_start;

	if ((size > PAGE_SIZE) || (vma->vm_pgoff != 0))
		return -EINVAL;

	if (remap_pfn_range(vma, vma->vm_start, mfn_to_pfn(xen_store_mfn),
			    size, vma->vm_page_prot))
		return -EAGAIN;

	return 0;
}

static int xsd_kva_read(char *page, char **start, off_t off,
			int count, int *eof, void *data)
{
	int len;

	len  = sprintf(page, "0x%p", xen_store_interface);
	*eof = 1;
	return len;
}

static int xsd_port_read(char *page, char **start, off_t off,
			 int count, int *eof, void *data)
{
	int len;

	len  = sprintf(page, "%d", xen_store_evtchn);
	*eof = 1;
	return len;
}
#endif

static int __init xenbus_probe_init(void)
{
	int err = 0;
	unsigned long page = 0;

	DPRINTK("");

	if (!is_running_on_xen())
		return -ENODEV;

	/* Register ourselves with the kernel bus subsystem */
	bus_register(&xenbus_frontend.bus);
	xenbus_backend_bus_register();

	/*
	 * Domain0 doesn't have a store_evtchn or store_mfn yet.
	 */
	if (is_initial_xendomain()) {
		struct evtchn_alloc_unbound alloc_unbound;

		/* Allocate page. */
		page = get_zeroed_page(GFP_KERNEL);
		if (!page)
			return -ENOMEM;

		xen_store_mfn = xen_start_info->store_mfn =
			pfn_to_mfn(virt_to_phys((void *)page) >>
				   PAGE_SHIFT);

		/* Next allocate a local port which xenstored can bind to */
		alloc_unbound.dom        = DOMID_SELF;
		alloc_unbound.remote_dom = 0;

		err = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound,
						  &alloc_unbound);
		if (err == -ENOSYS)
			goto err;
		BUG_ON(err);
		xen_store_evtchn = xen_start_info->store_evtchn =
			alloc_unbound.port;

#if defined(CONFIG_PROC_FS) && defined(CONFIG_XEN_PRIVILEGED_GUEST)
		/* And finally publish the above info in /proc/xen */
		xsd_kva_intf = create_xen_proc_entry("xsd_kva", 0600);
		if (xsd_kva_intf) {
			memcpy(&xsd_kva_fops, xsd_kva_intf->proc_fops,
			       sizeof(xsd_kva_fops));
			xsd_kva_fops.mmap = xsd_kva_mmap;
			xsd_kva_intf->proc_fops = &xsd_kva_fops;
			xsd_kva_intf->read_proc = xsd_kva_read;
		}
		xsd_port_intf = create_xen_proc_entry("xsd_port", 0400);
		if (xsd_port_intf)
			xsd_port_intf->read_proc = xsd_port_read;
#endif
		xen_store_interface = mfn_to_virt(xen_store_mfn);
	} else {
		xenstored_ready = 1;
#ifdef CONFIG_XEN
		xen_store_evtchn = xen_start_info->store_evtchn;
		xen_store_mfn = xen_start_info->store_mfn;
		xen_store_interface = mfn_to_virt(xen_store_mfn);
#else
		xen_store_evtchn = hvm_get_parameter(HVM_PARAM_STORE_EVTCHN);
		xen_store_mfn = hvm_get_parameter(HVM_PARAM_STORE_PFN);
		xen_store_interface = ioremap(xen_store_mfn << PAGE_SHIFT,
					      PAGE_SIZE);
#endif
	}


	xenbus_dev_init();

	/* Initialize the interface to xenstore. */
	err = xs_init();
	if (err) {
		printk(KERN_WARNING
		       "XENBUS: Error initializing xenstore comms: %i\n", err);
		goto err;
	}

	/* Register ourselves with the kernel device subsystem */
	device_register(&xenbus_frontend.dev);
	xenbus_backend_device_register();

	if (!is_initial_xendomain())
		xenbus_probe(NULL);

	return 0;

 err:
	if (page)
		free_page(page);

	/*
	 * Do not unregister the xenbus front/backend buses here. The buses
	 * must exist because front/backend drivers will use them when they are
	 * registered.
	 */

	return err;
}

postcore_initcall(xenbus_probe_init);

MODULE_LICENSE("Dual BSD/GPL");


static int is_disconnected_device(struct device *dev, void *data)
{
	struct xenbus_device *xendev = to_xenbus_device(dev);
	struct device_driver *drv = data;

	/*
	 * A device with no driver will never connect. We care only about
	 * devices which should currently be in the process of connecting.
	 */
	if (!dev->driver)
		return 0;

	/* Is this search limited to a particular driver? */
	if (drv && (dev->driver != drv))
		return 0;

	return (xendev->state != XenbusStateConnected);
}

static int exists_disconnected_device(struct device_driver *drv)
{
	return bus_for_each_dev(&xenbus_frontend.bus, NULL, drv,
				is_disconnected_device);
}

static int print_device_status(struct device *dev, void *data)
{
	struct xenbus_device *xendev = to_xenbus_device(dev);
	struct device_driver *drv = data;

	/* Is this operation limited to a particular driver? */
	if (drv && (dev->driver != drv))
		return 0;

	if (!dev->driver) {
		/* Information only: is this too noisy? */
		printk(KERN_INFO "XENBUS: Device with no driver: %s\n",
		       xendev->nodename);
	} else if (xendev->state != XenbusStateConnected) {
		printk(KERN_WARNING "XENBUS: Timeout connecting "
		       "to device: %s (state %d)\n",
		       xendev->nodename, xendev->state);
	}

	return 0;
}

/* We only wait for device setup after most initcalls have run. */
static int ready_to_wait_for_devices;

/*
 * On a 10 second timeout, wait for all devices currently configured.  We need
 * to do this to guarantee that the filesystems and / or network devices
 * needed for boot are available, before we can allow the boot to proceed.
 *
 * This needs to be on a late_initcall, to happen after the frontend device
 * drivers have been initialised, but before the root fs is mounted.
 *
 * A possible improvement here would be to have the tools add a per-device
 * flag to the store entry, indicating whether it is needed at boot time.
 * This would allow people who knew what they were doing to accelerate their
 * boot slightly, but of course needs tools or manual intervention to set up
 * those flags correctly.
 */
static void wait_for_devices(struct xenbus_driver *xendrv)
{
	unsigned long timeout = jiffies + 10*HZ;
	struct device_driver *drv = xendrv ? &xendrv->driver : NULL;

	if (!ready_to_wait_for_devices || !is_running_on_xen())
		return;

	while (exists_disconnected_device(drv)) {
		if (time_after(jiffies, timeout))
			break;
		schedule_timeout_interruptible(HZ/10);
	}

	bus_for_each_dev(&xenbus_frontend.bus, NULL, drv,
			 print_device_status);
}

#ifndef MODULE
static int __init boot_wait_for_devices(void)
{
	ready_to_wait_for_devices = 1;
	wait_for_devices(NULL);
	return 0;
}

late_initcall(boot_wait_for_devices);
#endif
