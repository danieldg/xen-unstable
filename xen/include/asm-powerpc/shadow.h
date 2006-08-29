/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005, 2006
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef _ASM_SHADOW_H_
#define _ASM_SHADOW_H_

#include <xen/sched.h>

#define shadow_mode_translate(_d) (1)
#define shadow_mode_refcounts(_d) (1)

#define __translate_gpfn_to_mfn(_d, gpfn)              \
    ( (shadow_mode_translate(_d))                      \
      ? translate_gpfn_to_mfn(_d, gpfn)                \
      : (gpfn) )

#define __mfn_to_gpfn(_d, mfn)                         \
    ( (shadow_mode_translate(_d))                      \
      ? machine_to_phys_mapping[(mfn)]                 \
      : (mfn) )

static inline unsigned long
translate_gpfn_to_mfn(struct domain *rd, unsigned long gpfn)
{
    trap();
    return 0;
}
extern void guest_physmap_add_page(
    struct domain *d, unsigned long gpfn, unsigned long mfn);

extern void guest_physmap_remove_page(
    struct domain *d, unsigned long gpfn, unsigned long mfn);

extern void shadow_drop_references(
    struct domain *d, struct page_info *page);

static inline void mark_dirty(struct domain *d, unsigned int mfn)
{
    return;
}
#define gnttab_mark_dirty(d, f) mark_dirty((d), (f))
#endif
