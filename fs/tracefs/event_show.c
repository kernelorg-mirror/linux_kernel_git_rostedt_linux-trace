#include <linux/seq_file.h>
#include <linux/tracefs.h>
#include "internal.h"

/*
 * This will iterate three lists that correspond to the directory level
 * of the eventfs directory.
 *
 * level 0 : /sys/kernel/tracing/events
 * level 1 : /sys/kernel/tracing/events/<system>
 * level 2 : /sys/kernel/tracing/events/<system>/event
 *
 * The iterator needs to see all levels as they all contain dynamically
 * allocated dentries and inodes.
 */
struct event_list {
	int			level;
	struct list_head	*head[3];
	struct list_head	*next[3];
};

static void *e_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct event_list *elist = m->private;
	int level = elist->level;
	struct list_head *head = elist->head[level];
	struct list_head *next = elist->next[level];
	struct eventfs_inode *ei;

	(*pos)++;

	/* If next is equal to head, then the list is complete */
	while (next == head) {
		if (!level)
			return NULL;

		/* sublevel below top level, go up one */
		elist->level = --level;
		head = elist->head[level];
		/* Going down does not update next, so do it here */
		next = elist->next[level]->next;
		elist->next[level] = next;
	}

	if (!next)
		return NULL;

	ei = list_entry(next, struct eventfs_inode, list);

	/* For each entry (not at the bottom) do a breadth first search */
	if (!list_empty(&ei->children) && level < 2) {
		elist->level = ++level;
		head = &ei->children;
		elist->head[level] = head;
		next = head;
		/*
		 * Note, next is now pointing to the next sub level.
		 * Need to update the next for the previous level on the way up.
		 */
	}

	elist->next[level] = next->next;
	return ei;
}

static void *e_start(struct seq_file *m, loff_t *pos)
{
	struct event_list *elist = m->private;
	struct eventfs_inode *ei = NULL;
	loff_t l;

	mutex_lock(&eventfs_mutex);

	elist->level = 0;
	elist->next[0] = elist->head[0]->next;

	if (!*pos) {
		(*pos)++;
		return container_of(elist->head[0], struct eventfs_inode, children);
	}

	for (l = 1; l <= *pos; ) {
		ei = e_next(m, ei, &l);
		if (!ei)
			break;
	}
	return ei;
}

static int e_show(struct seq_file *m, void *v)
{
	struct eventfs_inode *ei = v;
	int i;

	seq_printf(m, "%s", ei->name);

	if (ei->dentry)
		seq_printf(m, " dentry: (%d)", d_count(ei->dentry));
	seq_putc(m, '\n');

	for (i = 0; i < ei->nr_entries; i++) {
		struct dentry *dentry = ei->d_children[i];
		if (dentry) {
			seq_printf(m, " %s dentry: %px (%d)\n",
				   ei->entries[i].name, dentry, d_count(dentry));
		}
	}
	return 0;
}

static void e_stop(struct seq_file *m, void *p)
{
	mutex_unlock(&eventfs_mutex);
}

static const struct seq_operations eventfs_show_dentry_seq_ops = {
	.start = e_start,
	.next = e_next,
	.show = e_show,
	.stop = e_stop,
};

static int
eventfs_show_dentry_open(struct inode *inode, struct file *file)
{
	const struct seq_operations *seq_ops = &eventfs_show_dentry_seq_ops;
	struct event_list *elist;
	struct eventfs_inode *ei;

	/* The inode private should have the eventfs_inode of the "events" directory */
	ei = inode->i_private;
	if (!ei)
		return -EINVAL;

	elist = __seq_open_private(file, seq_ops, sizeof(*elist));
	if (!elist)
		return -ENOMEM;

	/*
	 * Start off at level 0 (/sys/kernel/tracing/events)
	 * Initialize head to the events files and next to the
	 * first file.
	 */
	elist->level = 0;
	elist->head[0] = &ei->children;
	elist->next[0] = ei->children.next;

	return 0;
}

const struct file_operations eventfs_show_dentry_fops = {
	.open = eventfs_show_dentry_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release_private,
};
