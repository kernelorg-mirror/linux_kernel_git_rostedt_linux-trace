/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SFRAME_DBG_H
#define _SFRAME_DBG_H

#include <linux/sframe.h>

/*
 * NOTE: The below debugging interfaces aren't enabled by default with
 * CONFIG_DYNAMIC_DEBUG because they introduce some uaccess objtool warnings
 * due to the pr_debug() calls between user_read_access_begin() and
 * user_read_access_end().  It's fine for testing but not for production.
 *
 * To enable the debug messages, define SFRAME_DEBUG here along with
 * CONFIG_DYNAMIC_DEBUG.
 *
 * TODO defer printks until after uaccess region
 */

#ifdef CONFIG_DYNAMIC_DEBUG
//#define SFRAME_DEBUG
#endif

#ifdef SFRAME_DEBUG

#define dbg(fmt, ...)						\
	pr_debug("[%s] " fmt, current->comm, ##__VA_ARGS__)

#define dbg_sec(fmt, ...)					\
	dbg("%s: " fmt, sec->filename, ##__VA_ARGS__)

static inline void dbg_init_section(struct sframe_section *sec)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;

	guard(mmap_read_lock)(mm);
	vma = vma_lookup(mm, sec->sframe_start);
	if (!vma)
		sec->filename = kstrdup("(vma gone???)", GFP_KERNEL);
	else if (vma->vm_file)
		sec->filename = kstrdup_quotable_file(vma->vm_file, GFP_KERNEL);
	else if (!vma->vm_mm)
		sec->filename = kstrdup("(vdso)", GFP_KERNEL);
	else
		sec->filename = kstrdup("(anonymous)", GFP_KERNEL);
}

static inline void dbg_free_section(struct sframe_section *sec)
{
	kfree(sec->filename);
}

#else /* !SFRAME_DEBUG */

#define dbg(args...)		no_printk(args)
#define dbg_sec(args...)	no_printk(args)

static inline void dbg_init_section(struct sframe_section *sec) {}
static inline void dbg_free_section(struct sframe_section *sec) {}

#endif /* !SFRAME_DEBUG */

#endif /* _SFRAME_DBG_H */
