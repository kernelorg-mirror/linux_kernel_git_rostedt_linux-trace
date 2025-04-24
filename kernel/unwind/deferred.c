// SPDX-License-Identifier: GPL-2.0
/*
 * Deferred user space unwinding
 */
#include <linux/sched/task_stack.h>
#include <linux/unwind_deferred.h>
#include <linux/task_work.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/mm.h>

#define UNWIND_MAX_ENTRIES 512

/*
 * This is a unique percpu identifier for a given task entry context.
 * Conceptually, it's incremented every time the CPU enters the kernel from
 * user space, so that each "entry context" on the CPU gets a unique ID.  In
 * reality, as an optimization, it's only incremented on demand for the first
 * deferred unwind request after a given entry-from-user.
 *
 * It's combined with the CPU id to make a systemwide-unique "context cookie".
 */
static DEFINE_PER_CPU(u64, unwind_ctx_ctr);

/* Guards adding to and reading the list of callbacks */
static DEFINE_MUTEX(callback_mutex);
static LIST_HEAD(callbacks);

/*
 * The context cookie is a unique identifier that is assigned to a user
 * space stacktrace. As the user space stacktrace remains the same while
 * the task is in the kernel, the cookie is an identifier for the stacktrace.
 * Although it is possible for the stacktrace to get another cookie if another
 * request is made after the cookie was cleared and before reentering user
 * space.
 *
 * The high 16 bits are the CPU id; the lower 48 bits are a per-CPU entry
 * counter shifted left by one and or'd with 1 (to prevent it from ever being
 * zero).
 */
static u64 ctx_to_cookie(u64 cpu, u64 ctx)
{
	BUILD_BUG_ON(NR_CPUS > 65535);
	return ((ctx << 1) & ((1UL << 48) - 1)) | (cpu << 48) | 1;
}

/*
 * Read the task context cookie, first initializing it if this is the first
 * call to get_cookie() since the most recent entry from user.  This has to be
 * done carefully to coordinate with unwind_deferred_request_nmi().
 */
static u64 get_cookie(struct unwind_task_info *info)
{
	u64 ctx_ctr;
	u64 cookie;

	guard(irqsave)();

	cookie = READ_ONCE(info->cookie);
	if (cookie)
		return cookie;

	ctx_ctr = __this_cpu_read(unwind_ctx_ctr);

	/* Read ctx_ctr before info->nmi_cookie */
	barrier();

	cookie = READ_ONCE(info->nmi_cookie);
	if (cookie) {
		/*
		 * This is the first call to get_cookie() since an NMI handler
		 * first wrote it to info->nmi_cookie.  Sync it.
		 */
		WRITE_ONCE(info->cookie, cookie);
		WRITE_ONCE(info->nmi_cookie, 0);
		return cookie;
	}

	/*
	 * Write info->cookie.  It's ok to race with an NMI here.  The value of
	 * the cookie is based on ctx_ctr from before the NMI could have
	 * incremented it.  The result will be the same even if cookie or
	 * ctx_ctr end up getting written twice.
	 */
	cookie = ctx_to_cookie(raw_smp_processor_id(), ctx_ctr + 1);
	WRITE_ONCE(info->cookie, cookie);
	WRITE_ONCE(info->nmi_cookie, 0);
	barrier();
	__this_cpu_write(unwind_ctx_ctr, ctx_ctr + 1);

	return info->cookie;
}

int unwind_deferred_trace(struct unwind_stacktrace *trace)
{
	struct unwind_task_info *info = &current->unwind_info;
	struct unwind_cache *cache = &info->cache;

	/* Should always be called from faultable context */
	might_fault();

	/* Check for task exit path. */
	if (!current->mm)
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

static void unwind_deferred_task_work(struct callback_head *head)
{
	struct unwind_task_info *info = container_of(head, struct unwind_task_info, work);
	struct unwind_stacktrace trace;
	struct unwind_work *work;
	u64 cookie;

	if (WARN_ON_ONCE(!info->pending))
		return;

	/* Allow work to come in again */
	WRITE_ONCE(info->pending, 0);

	/*
	 * From here on out, the callback must always be called, even if it's
	 * just an empty trace.
	 */
	trace.nr = 0;
	trace.entries = NULL;

	unwind_deferred_trace(&trace);

	cookie = get_cookie(info);

	guard(mutex)(&callback_mutex);
	list_for_each_entry(work, &callbacks, list) {
		work->func(work, &trace, cookie);
	}
	barrier();
	/* If another task work is pending, reuse the cookie and stack trace */
	if (!READ_ONCE(info->pending))
		WRITE_ONCE(info->cookie, 0);
}

static int unwind_deferred_request_nmi(struct unwind_work *work, u64 *cookie)
{
	struct unwind_task_info *info = &current->unwind_info;
	bool inited_cookie = false;
	int ret;

	*cookie = info->cookie;
	if (!*cookie) {
		/*
		 * This is the first unwind request since the most recent entry
		 * from user.  Initialize the task cookie.
		 *
		 * Don't write to info->cookie directly, otherwise it may get
		 * cleared if the NMI occurred in the kernel during early entry
		 * or late exit before the task work gets to run.  Instead, use
		 * info->nmi_cookie which gets synced later by get_cookie().
		 */
		if (!info->nmi_cookie) {
			u64 cpu = raw_smp_processor_id();
			u64 ctx_ctr;

			ctx_ctr = __this_cpu_inc_return(unwind_ctx_ctr);
			info->nmi_cookie = ctx_to_cookie(cpu, ctx_ctr);

			inited_cookie = true;
		}

		*cookie = info->nmi_cookie;
	}

	if (info->pending)
		return 0;

	ret = task_work_add(current, &info->work, TWA_NMI_CURRENT);
	if (ret) {
		if (inited_cookie)
			info->nmi_cookie = 0;
		return ret;
	}

	info->pending = 1;

	return 0;
}

/*
 * Schedule a user space unwind to be done in task work before exiting the
 * kernel.
 *
 * The returned cookie output is a unique identifer for the current task entry
 * context.  Its value will also be passed to the callback function.  It can be
 * used to stitch kernel and user stack traces together in post-processing.
 *
 * It's valid to call this function multiple times for the same @work within
 * the same task entry context.  Each call will return the same cookie.
 * If the callback is not pending because it has already been previously called
 * for the same entry context, it will be called again with the same stack trace
 * and cookie.
 *
 * Returns 0 if the callback will be called on task to user space
 *   Negative if there's an error.
 */
int unwind_deferred_request(struct unwind_work *work, u64 *cookie)
{
	struct unwind_task_info *info = &current->unwind_info;
	int pending;
	int ret;

	*cookie = 0;

	if ((current->flags & PF_KTHREAD) || !user_mode(task_pt_regs(current)))
		return -EINVAL;

	if (in_nmi())
		return unwind_deferred_request_nmi(work, cookie);

	guard(irqsave)();

	*cookie = get_cookie(info);

	/* callback already pending? */
	pending = READ_ONCE(info->pending);
	if (pending)
		return 0;

	/* Claim the work unless an NMI just now swooped in to do so. */
	if (!try_cmpxchg(&info->pending, &pending, 1))
		return 0;

	/* The work has been claimed, now schedule it. */
	ret = task_work_add(current, &info->work, TWA_RESUME);
	if (WARN_ON_ONCE(ret)) {
		WRITE_ONCE(info->pending, 0);
		return ret;
	}

	return 0;
}

void unwind_deferred_cancel(struct unwind_work *work)
{
	if (!work)
		return;

	guard(mutex)(&callback_mutex);
	list_del(&work->list);
}

int unwind_deferred_init(struct unwind_work *work, unwind_callback_t func)
{
	memset(work, 0, sizeof(*work));

	guard(mutex)(&callback_mutex);
	list_add(&work->list, &callbacks);
	work->func = func;
	return 0;
}

void unwind_task_init(struct task_struct *task)
{
	struct unwind_task_info *info = &task->unwind_info;

	memset(info, 0, sizeof(*info));
	init_task_work(&info->work, unwind_deferred_task_work);
}

void unwind_task_free(struct task_struct *task)
{
	struct unwind_task_info *info = &task->unwind_info;

	kfree(info->cache.entries);
	task_work_cancel(task, &info->work);
}
