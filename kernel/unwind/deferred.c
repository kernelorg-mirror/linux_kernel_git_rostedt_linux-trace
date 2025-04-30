// SPDX-License-Identifier: GPL-2.0
/*
 * Deferred user space unwinding
 */
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/unwind_deferred.h>

#define UNWIND_MAX_ENTRIES 512

int unwind_deferred_trace(struct unwind_stacktrace *trace)
{
	struct unwind_task_info *info = &current->unwind_info;
	struct unwind_cache *cache = &info->cache;

	/* Should always be called from faultable context */
	might_fault();

	if (current->flags & PF_EXITING)
		return -EINVAL;

	if (!cache->entries) {
		cache->entries = kmalloc_array(UNWIND_MAX_ENTRIES, sizeof(long),
					       GFP_KERNEL);
		if (!cache->entries)
			return -ENOMEM;
        }

	trace->entries = cache->entries;

	if (cache->nr_entries) {
               /*
                * The user stack has already been previously unwound in this
                * entry context.  Skip the unwind and use the cache.
                */
               trace->nr = cache->nr_entries;
               return 0;
       }

	trace->nr = 0;
	unwind_user(trace, UNWIND_MAX_ENTRIES);

	cache->nr_entries = trace->nr;

	return 0;
}

void unwind_task_init(struct task_struct *task)
{
	struct unwind_task_info *info = &task->unwind_info;

	memset(info, 0, sizeof(*info));
}

void unwind_task_free(struct task_struct *task)
{
	struct unwind_task_info *info = &task->unwind_info;

	kfree(info->cache.entries);
}
