/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_UNWIND_USER_DEFERRED_TYPES_H
#define _LINUX_UNWIND_USER_DEFERRED_TYPES_H

#include <linux/unwind_user_types.h>

typedef void (*unwind_callback_t)(struct unwind_stacktrace *trace,
				  u64 ctx_cookie, void *data);

struct unwind_callback {
	struct rcu_head			rcu;
	unwind_callback_t		func;
	unsigned int			idx;
	bool				enabled;
};

#define UNWIND_MAX_CALLBACKS 4
struct unwind_task_info {
	u64			ctx_cookie;
	unsigned int		work_pending;
	u32			pending_callbacks;
	u64			last_cookies[UNWIND_MAX_CALLBACKS];
	void			*privs[UNWIND_MAX_CALLBACKS];
	unsigned long		*entries;
	u64			cached_cookie;
	struct callback_head	work;
	unsigned int		cached_nr;
};

#endif /* _LINUX_UNWIND_USER_DEFERRED_TYPES_H */
