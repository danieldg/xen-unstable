/*
 * include/asm-x8664/cache.h
 */
#ifndef __ARCH_X8664_CACHE_H
#define __ARCH_X8664_CACHE_H

#include <xen/config.h>

/* L1 cache line size */
#define L1_CACHE_SHIFT	(CONFIG_X86_L1_CACHE_SHIFT)
#define L1_CACHE_BYTES	(1 << L1_CACHE_SHIFT)

#endif
