/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_UNWIND_USER_DEFERRED_H
#define _LINUX_UNWIND_USER_DEFERRED_H

#include <linux/unwind_user.h>
#include <linux/unwind_user_deferred_types.h>

#ifdef CONFIG_UNWIND_USER

void unwind_task_init(struct task_struct *task);
void unwind_task_free(struct task_struct *task);

int unwind_user_register(struct unwind_callback *callback, unwind_callback_t func);
int unwind_user_unregister(struct unwind_callback *callback);

int unwind_user_deferred(struct unwind_callback *callback, u64 *ctx_cookie, void *data);

DECLARE_PER_CPU(u64, unwind_ctx_ctr);

static __always_inline void unwind_enter_from_user_mode(void)
{
	current->unwind_task_info.ctx_cookie = 0;
}

#else /* !CONFIG_UNWIND_USER */

static inline void unwind_task_init(struct task_struct *task) {}
static inline void unwind_task_free(struct task_struct *task) {}
static inline int unwind_user_register(struct unwind_callback *callback, unwind_callback_t func) { return -ENOSYS; }
static inline int unwind_user_unregister(struct unwind_callback *callback) { return -ENOSYS; }
static inline int unwind_user_deferred(struct unwind_callback *callback, u64 *ctx_cookie, void *data) { return -ENOSYS; }
static inline void unwind_enter_from_user_mode(void) {}

#endif /* !CONFIG_UNWIND_USER */

#endif /* _LINUX_UNWIND_USER_DEFERRED_H */
