#ifndef COMPAT_INCLUDE_XEN_PLATFORM_COMPAT_H
#define COMPAT_INCLUDE_XEN_PLATFORM_COMPAT_H

#include <linux/version.h>

#include <linux/spinlock.h>

#if defined(__LINUX_COMPILER_H) && !defined(__always_inline)
#define __always_inline inline
#endif

#if defined(__LINUX_SPINLOCK_H) && !defined(DEFINE_SPINLOCK)
#define DEFINE_SPINLOCK(x) spinlock_t x = SPIN_LOCK_UNLOCKED
#endif

#if defined(_LINUX_INIT_H) && !defined(__init)
#define __init
#endif

#if defined(__LINUX_CACHE_H) && !defined(__read_mostly)
#define __read_mostly
#endif

#if defined(_LINUX_SKBUFF_H) && !defined(NET_IP_ALIGN)
#define NET_IP_ALIGN 0
#endif

#if defined(_LINUX_FS_H) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9)
#define nonseekable_open(inode, filp) /* Nothing to do */
#endif

#if defined(_LINUX_MM_H) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
unsigned long vmalloc_to_pfn(void *addr);
#endif

#endif
