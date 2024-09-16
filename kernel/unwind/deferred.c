// SPDX-License-Identifier: GPL-2.0
/*
* Deferred user space unwinding
*
* Copyright (C) 2024 Josh Poimboeuf <jpoimboe@kernel.org>
*/
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sframe.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/mm.h>
#include <linux/unwind_user_deferred.h>

#define UNWIND_MAX_ENTRIES 512

DEFINE_STATIC_SRCU(callbacks_srcu);
static DEFINE_MUTEX(callbacks_mutex);
static struct unwind_callback __rcu *callbacks[UNWIND_MAX_CALLBACKS];

/* Counter for entries from user space */
DEFINE_PER_CPU(u64, unwind_ctx_ctr);

/*
 * The context cookie is a unique identifier which allows post-processing to
 * correlate kernel trace(s) with user unwinds.  The high 12 bits are the CPU
 * id; the lower 48 bits are a per-CPU entry counter.
 */
static u64 ctx_to_cookie(u64 cpu, u64 ctx)
{
	BUILD_BUG_ON(NR_CPUS > 65535);
	return (ctx & ((1UL << 48) - 1)) | (cpu << 48);
}

/*
 * Schedule a user space unwind to be done in task work before exiting the
 * kernel.
 *
 * The @callback must have previously been registered with
 * unwind_user_register().
 *
 * The @cookie output is a unique identifer which will also be passed to the
 * callback function.  It can be used to stitch kernel and user traces together
 * in post-processing.
 *
 * If there are multiple calls to this function for a given @callback, the
 * cookie will usually be the same and the callback will only be called once.
 *
 * The only exception is when the task has migrated to another CPU, *and* this
 * is called while the task work is running (or has already run).  Then a new
 * cookie will be generated and the callback will be called again for the new
 * cookie.
 */
int unwind_user_deferred(struct unwind_callback *callback, u64 *ctx_cookie, void *data)
{
	struct unwind_task_info *info = &current->unwind_task_info;
	u64 cookie = info->ctx_cookie;
	int idx = callback->idx;

	if (WARN_ON_ONCE(in_nmi()))
		return -EINVAL;

	if (!current->mm)
		return -EINVAL;

	guard(irqsave)();

	/*
	 * If this is the first call since the most recent entry from user
	 * space, initialize the task context cookie.
	 */
	if (!cookie) {
		u64 cpu = raw_smp_processor_id();
		u64 ctx_ctr;

		ctx_ctr = __this_cpu_inc_return(unwind_ctx_ctr);
		cookie = ctx_to_cookie(cpu, ctx_ctr);
		info->ctx_cookie = cookie;

	} else {
		if (info->pending_callbacks & (1 << idx)) {
			/* callback already scheduled */
			goto done;
		}

		if (cookie == info->last_cookies[idx]) {
			/* callback already called */
			goto done;
		}
	}

	info->pending_callbacks |= (1 << idx);
	info->privs[idx] = data;
	info->last_cookies[idx] = cookie;

	if (!info->work_pending) {
		info->work_pending = 1;
		task_work_add(current, &info->work, TWA_RESUME);
	}


done:
	if (ctx_cookie)
		*ctx_cookie = cookie;
	return 0;
}

static void unwind_user_task_work(struct callback_head *head)
{
	struct unwind_task_info *info = container_of(head, struct unwind_task_info, work);
	struct task_struct *task = container_of(info, struct task_struct, unwind_task_info);
	void *privs[UNWIND_MAX_CALLBACKS];
	struct unwind_stacktrace trace;
	unsigned long pending;
	u64 cookie = 0;
	int i;

	BUILD_BUG_ON(UNWIND_MAX_CALLBACKS > 32);

	if (WARN_ON_ONCE(task != current))
		return;

	if (WARN_ON_ONCE(!info->ctx_cookie || !info->pending_callbacks || !info->work_pending))
		return;

	scoped_guard(irqsave) {
		pending = info->pending_callbacks;
		cookie = info->ctx_cookie;

		info->work_pending = 0;
		info->pending_callbacks = 0;
		memcpy(privs, info->privs, sizeof(void *) * UNWIND_MAX_CALLBACKS);
	}

	if (!info->entries) {
		info->entries = kmalloc(UNWIND_MAX_ENTRIES * sizeof(long),
					GFP_KERNEL);
		if (!info->entries)
			return;
	}

	trace.entries = info->entries;

	if (cookie == info->cached_cookie) {
		trace.nr = info->cached_nr;
	} else {
		trace.nr = 0;
		unwind_user(&trace, UNWIND_MAX_ENTRIES);
		info->cached_cookie = cookie;
		info->cached_nr = trace.nr;
	}

	guard(srcu)(&callbacks_srcu);

	for_each_set_bit(i, &pending, UNWIND_MAX_CALLBACKS) {
		struct unwind_callback *callback;

		callback = srcu_dereference(callbacks[i], &callbacks_srcu);

		if (callback && callback->enabled)
			callback->func(&trace, cookie, privs[i]);
	}
}

int unwind_user_register(struct unwind_callback *callback, unwind_callback_t func)
{
	guard(mutex)(&callbacks_mutex);

	for (int i = 0; i < UNWIND_MAX_CALLBACKS; i++) {
		if (!callbacks[i]) {
			callback->func = func;
			callback->idx = i;
			callback->enabled = true;

			rcu_assign_pointer(callbacks[i], callback);
			return 0;
		}
	}

	return -ENOSPC;
}

static void callback_remove(struct rcu_head *rcu)
{
	struct unwind_callback *callback = container_of(rcu, struct unwind_callback, rcu);

	guard(mutex)(&callbacks_mutex);
	rcu_assign_pointer(callbacks[callback->idx], NULL);
}

int unwind_user_unregister(struct unwind_callback *callback)
{
	callback->enabled = false;
	call_srcu(&callbacks_srcu, &callback->rcu, callback_remove);
	synchronize_srcu(&callbacks_srcu);

	return 0;
}

void unwind_task_init(struct task_struct *task)
{
	struct unwind_task_info *info = &task->unwind_task_info;

	info->entries		= NULL;
	info->pending_callbacks	= 0;
	info->ctx_cookie	= 0;
	info->work_pending	= 0;

	memset(info->last_cookies, 0, sizeof(u64) * UNWIND_MAX_CALLBACKS);
	memset(info->privs,	   0, sizeof(u64) * UNWIND_MAX_CALLBACKS);

	init_task_work(&info->work, unwind_user_task_work);
}

void unwind_task_free(struct task_struct *task)
{
	struct unwind_task_info *info = &task->unwind_task_info;

	kfree(info->entries);
}
