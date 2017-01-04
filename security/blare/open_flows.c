/*
 * Blare Linux Security Module
 *
 * Authors: Christophe Hauser <christophe@cs.ucsb.edu>
 *          Guillaume Brogi <guillaume.brogi@akheros.com>
 *          Laurent Georget <laurent.georget@supelec.fr>
 *
 * Copyright (C) 2010-2016 CentraleSupelec
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/fsnotify.h>
#include <linux/hashtable.h>
#include <linux/msg.h>
#include <linux/workqueue.h>

#include "blare.h"

#define BLARE_HASHTABLE_SHIFT 10

/**
 * struct async_task_freer - Work struct responsible for freeing one task_struct
 * @task:	The task to free.
 * @work:	The work struct that can be enqueued in a work queue.
 */
struct async_task_freer {
	struct task_struct *task;
	struct work_struct work;
};

/**
 * struct discrete_flow - Describes a discrete flow from a file, a memory space
 * or a message to a file or a memory space.
 * @resp:	The process that has generated the flow.
 * @src:	The container of information source of the flow.
 * @dest:	The container of information destination of the flow.
 * @src_type:	The type of the source container, either BLARE_FILE_TYPE,
 * 		BLARE_MM_TYPE or BLARE_MSG_TYPE.
 * @dest_type:	The type of the destination container, either BLARE_FILE_TYPE
 * 		or BLARE_MM_TYPE.
 * @by_src:	The map source container -> discrete flows.
 * @by_task:	The map responsible task -> discrete flows.
 */
struct discrete_flow {
	struct task_struct *resp;
	union {
		struct file *file;
		struct mm_struct *mm;
		struct msg_msg *msg;
	} src;
	union {
		struct file *file;
		struct mm_struct *mm;
	} dest;
	int src_type;
	int dest_type;
	struct hlist_node by_src;	/* table of enabled flows, by source */
	struct hlist_node by_task;	/* table of enabled flows, by responsible task_struct* */
};

/**
 * struct bfs_elt - Describes an element of the Breadth-Depth Search needed by
 * the Jaume-Georget algorithm.
 * @src:	The source container of information.
 * @dest:	The destination container of information.
 * @src_type:	The type of the soruce container.
 * @dest_type:	The type of the destination container.
 * @list:	The queue of bfs_elt to visit in the BDS.
 */
struct bfs_elt {
	union {
		struct file *file;
		struct mm_struct *mm;
		struct msg_msg *msg;
	} src;
	union {
		struct file *file;
		struct mm_struct *mm;
	} dest;
	int src_type;
	int dest_type;
	struct list_head list;	/* list of bfs_elt to visit */
};

static DEFINE_HASHTABLE(enabled_flows_by_src, BLARE_HASHTABLE_SHIFT);
static DEFINE_HASHTABLE(enabled_flows_by_task, BLARE_HASHTABLE_SHIFT);
static DEFINE_MUTEX(flows_lock);

/**
 * get_mms_for_file() - Retrieves all the mm-s a file is mmapped in and enqueue
 * them for BFV.
 * @file:	The file of interest.
 * @visit_list:	The BFV queue.
 *
 * Returns: 0 or -ENOMEM.
 */
static int get_mms_for_file(struct file *file, struct list_head *visit_list)
{
	struct inode *inode = file_inode(file);
	struct address_space *maps = inode->i_mapping;
	struct vm_area_struct *vma;
	struct bfs_elt *elt;
	int ret = 0;

	i_mmap_lock_read(maps);
	vma_interval_tree_foreach(vma, &maps->i_mmap, 0, ULONG_MAX) {
		/* all vma-s are relevant here, we take a ref on the mm and we
		 * place it on the list of stuff to visit */
		struct mm_struct *mm = vma->vm_mm;

		/* do not consider already dead mm */
		if (!mm || !atomic_inc_not_zero(&mm->mm_users))
			continue;

		if (!mm->m_sec) {
			mmput(mm);
			continue;
		}

		elt = kmalloc(sizeof(struct bfs_elt), GFP_KERNEL);
		if (!elt) {
			ret = -ENOMEM;
			mmput(mm);
			goto unlock;
		}

		elt->src.file = file;
		elt->src_type = BLARE_FILE_TYPE;
		elt->dest.mm = mm;
		elt->dest_type = BLARE_MM_TYPE;
		BUG_ON(!mm->m_sec);
		list_add_tail(&elt->list, visit_list);
	}

unlock:
	i_mmap_unlock_read(maps);
	return ret;
}

/**
 * get_files_for_mm() - Retrieves all the files mmaped as shared and writable
 * in a given memory space.
 * @mm:		The memory space of interest.
 * @visit_list:	The BFV queue.
 *
 * Returns: 0 or -ENOMEM.
 */
static int get_files_for_mm(struct mm_struct *mm, struct list_head *visit_list)
{
	struct vm_area_struct *vma;
	struct file *file;
	struct bfs_elt *elt;
	int ret = 0;

	/* only VM_SHARED with a vm_file */
	down_read(&mm->mmap_sem);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (!(vma->vm_flags & VM_SHARED) || !(vma->vm_flags & VM_WRITE)
		    || !vma->vm_file)
			continue;

		file = vma->vm_file;
		if (!file_inode(file) || !file_inode(file)->i_security)
			continue;

		elt = kmalloc(sizeof(struct bfs_elt), GFP_KERNEL);
		if (!elt) {
			ret = -ENOMEM;
			goto unlock;
		}

		get_file(file);
		elt->src.mm = mm;
		elt->src_type = BLARE_MM_TYPE;
		elt->dest.file = file;
		elt->dest_type = BLARE_FILE_TYPE;
		list_add_tail(&elt->list, visit_list);

	}
unlock:
	up_read(&mm->mmap_sem);
	return ret;
}

/**
 * get_discrete_flows_for_file() - Retrieves all the discrete flows currently
 * occurring having a given file as source.
 * @file:	The file of interest.
 * @visit_list:	The BFV queue.
 *
 * Returns: 0 or -ENOMEM.
 */
static int get_discrete_flows_for_file(struct file *file,
				       struct list_head *visit_list)
{
	struct discrete_flow *flow;
	struct bfs_elt *elt;
	struct inode *inode = file_inode(file);
	u64 key = (u64) inode;
	pr_debug("kblare: key for inode %llu\n", key);
	hash_for_each_possible(enabled_flows_by_src, flow, by_src, key) {
		struct mm_struct *mm;
		// Check if the flow in the bucket is not for another key
		if (flow->dest_type != BLARE_MM_TYPE ||
		    file_inode(flow->src.file) != inode)
			continue;

		mm = flow->dest.mm;
		BUG_ON(!mm->m_sec);
		elt = kmalloc(sizeof(struct bfs_elt), GFP_KERNEL);
		if (!elt)
			return -ENOMEM;
		atomic_inc(&mm->mm_users);
		elt->src.file = file;
		elt->src_type = BLARE_FILE_TYPE;
		elt->dest.mm = mm;
		elt->dest_type = BLARE_MM_TYPE;
		list_add_tail(&elt->list, visit_list);
	}
	return 0;
}

/**
 * get_discrete_flows_for_mm() - Retrieves the discrete flows currently
 * occurring having a given mm as source.
 * @mm:		The memory space of interest.
 * @visit_list:	The BFV queue.
 *
 * Returns: 0 or -ENOMEM.
 */
static int get_discrete_flows_for_mm(struct mm_struct *mm,
				     struct list_head *visit_list)
{
	struct discrete_flow *flow;
	struct bfs_elt *elt;
	u64 key = (u64) mm;
	pr_debug("kblare: key for mm %llu\n", key);
	hash_for_each_possible(enabled_flows_by_src, flow, by_src, key) {
		struct file *file;
		// Check if the flow in the bucket is not for another key
		if (flow->dest_type != BLARE_FILE_TYPE || flow->src.mm != mm)
			continue;

		file = flow->dest.file;
		elt = kmalloc(sizeof(struct bfs_elt), GFP_KERNEL);
		if (!elt)
			return -ENOMEM;

		get_file(file);
		elt->src.mm = mm;
		elt->src_type = BLARE_MM_TYPE;
		elt->dest.file = file;
		elt->dest_type = BLARE_FILE_TYPE;
		list_add_tail(&elt->list, visit_list);
	}
	return 0;
}

/**
 * propagate_tags() - Merge a set of tags into another and compute the set
 * difference.
 * @dest:	The destination set of tags.
 * @src:	The source set of tags.
 * @tags_added:	Output set of tags which will receives src - dest or the empty
 * 		set if either the source or the destination stops the
 * 		propagation.
 *
 * When Blare is disabled, the set tags_added is computed anyway but dest is
 * left untouched.
 */
static void propagate_tags(struct info_tags *dest, const struct info_tags *src,
			   struct info_tags *tags_added)
{
	int i;

	/* short-circuit */
	if (blare_stop_propagate(src) || blare_stop_propagate(dest)) {
		for (i = 0; i < BLARE_TAGS_NUMBER; i++)
			tags_added->tags[i] = 0;
		return;
	}

	/* we have to merge the new tags with the ones already present
	 * in the destination container */
	for (i = 0; i < BLARE_TAGS_NUMBER; i++) {
		tags_added->tags[i] = src->tags[i] & ~(dest->tags[i]);
		if (blare_enabled)
			dest->tags[i] |= src->tags[i];
	}
}

/**
 * propagate_to_mm() - Propagates a set of tags to a memory space.
 * @mm:		The memory space of interest.
 * @visit_list:	The BFV queue.
 * @tags:	The tags to propagate.
 * @tags_added:	Where to store the tags effectively added to the memory space.
 *
 * This function merges tags into the mm's itags, computes the new tags that
 * have been added and add to the BFV queue the containers which are
 * destination of an enabled flow from that memory space. When Blare is
 * disabled, the mm's itags are left untouched but tags_added is computed
 * anyway.
 *
 * Returns: 0 or -ENOMEM.
 */
static int propagate_to_mm(struct mm_struct *mm, struct list_head *visit_list,
			   const struct info_tags *tags,
			   struct info_tags *tags_added)
{
	struct blare_mm_sec *msec = mm->m_sec;
	int ret = 0;

	propagate_tags(&msec->info, tags, tags_added);

	if (tags_count(tags_added) > 0) {
		ret = get_files_for_mm(mm, visit_list);
		if (!ret)
			ret = get_discrete_flows_for_mm(mm, visit_list);
	}

	return ret;
}

/**
 * propagate_to_file() - Propagates a set of tags to a file.
 * @file:		The file of interest.
 * @visit_list:	The BFV queue.
 * @tags:	The tags to propagate.
 * @tags_added:	Where to store the tags effectively added to the file.
 *
 * This function merges tags into the file's itags, computes the new tags that
 * have been added and add to the BFV queue the containers which are
 * destination of an enabled flow from that file. The extended attributes of the
 * files are also updated.
 * When Blare is disabled, the file's itags are left untouched but tags_added is
 * computed anyway.
 *
 * Returns: 0 or -ENOMEM.
 */
static int propagate_to_file(struct file *file, struct list_head *visit_list,
			     const struct info_tags *tags,
			     struct info_tags *tags_added)
{
	struct inode *inode = file_inode(file);
	struct blare_inode_sec *isec = inode->i_security;
	int ret = 0;

	propagate_tags(&isec->info, tags, tags_added);

	if (tags_count(tags_added) > 0) {
		struct dentry *dentry = dget(file_dentry(file));
		if (blare_enabled && dentry && inode->i_op->setxattr) {
			int rc;
			/* Convert the shared lock into an exclusive lock
			 * no race condition to be afraid of because the entire
			 * tag propagation is protected by mutex flows_lock
			 * and we have a reference on the inode */
			inode_unlock(inode);
			inode_lock(inode);
			rc = inode->i_op->setxattr(dentry, inode,
						   BLARE_XATTR_TAG,
						   isec->info.tags,
						   BLARE_TAGS_NUMBER *
						   sizeof(__u32), 0);
			if (!rc)
				fsnotify_xattr(dentry);
			inode_unlock(inode);
			inode_lock_shared(inode);
		}
		dput(dentry);

		ret = get_mms_for_file(file, visit_list);
		if (!ret)
			ret = get_discrete_flows_for_file(file, visit_list);
	}

	return ret;
}

/**
 * __trace_all() - Outputs a trace for all the traced tags in a given set of
 * tags
 * @tags:	The set of tags.
 * @flow:	The flow which causing the tags to be propagated.
 */
static void __trace_all(const struct info_tags *tags,
			const struct bfs_elt *flow)
{
	void *src =
	    flow->src_type == BLARE_MM_TYPE	?	(void *)flow->src.mm :
	    flow->src_type == BLARE_FILE_TYPE	?	(void *)flow->src.file :
	 /* flow->src_type == BLARE_MSG_TYPE	? */	(void *)flow->src.msg;
	void *dest =
	    flow->dest_type == BLARE_MM_TYPE	?	(void *)flow->dest.mm :
	 /* flow->dest_type == BLARE_FILE_TYPE	? */	(void *)flow->dest.file;

	blare_trace_all(tags, src, flow->src_type, dest, flow->dest_type);
}

/**
 * __register_new_flow() - Starts a tag propagation
 * @new_flow:	The first flow, starting the propagation.
 * @new_tags:	The tags involved in the first flow.
 *
 * This function does the Breadth-First Visit, starting with an initial flow.
 * The tags passed as parameters are propagated to all containers of information
 * reachable from the destination of that first flow.
 * Returns: 0 or -ENOMEM.
 */
static int __register_new_flow(struct bfs_elt *new_flow,
			       const struct info_tags *new_tags)
{
	LIST_HEAD(visit_list);
	struct bfs_elt *next, *temp;
	struct info_tags tags_added;
	int ret = 0;

	list_add(&new_flow->list, &visit_list);
	list_for_each_entry(next, &visit_list, list) {
		if (next->dest_type == BLARE_FILE_TYPE) {
			struct file *file = next->dest.file;
			struct inode *inode = file_inode(file);
			inode_lock_shared(inode);
			ret =
			    propagate_to_file(file, &visit_list, new_tags,
					      &tags_added);
			inode_unlock_shared(inode);
			fput(file);
		} else {
			struct mm_struct *mm = next->dest.mm;
			ret =
			    propagate_to_mm(mm, &visit_list, new_tags,
					    &tags_added);
			mmput(mm);
		}

		if (ret)
			goto free_all_and_abort;

		/* blare_trace_all can fail with ENOMEM but that's not
		 * critical, we might just lose a few trace messages
		 * silently */
		if (unlikely(blare_is_traced(&tags_added)))
			__trace_all(new_tags, next);
	}

free_all_and_abort:
	list_for_each_entry_safe(next, temp, &visit_list, list) {
		list_del(&next->list);
		kfree(next);
	}

	return ret;

}

/* called from:
 * - read
 * - recv
 * - mmap
 */
static int __register_flow_file_to_mm(struct file *file, struct mm_struct *mm)
{
	struct inode *inode = file_inode(file);
	struct blare_inode_sec *isec = inode->i_security;
	struct bfs_elt *first_flow;

	if (!isec || !mm->m_sec || tags_count(&isec->info) == 0)
		return 0;

	first_flow = kmalloc(sizeof(struct bfs_elt), GFP_KERNEL);
	if (!first_flow)
		return -ENOMEM;

	BUG_ON(!atomic_inc_not_zero(&mm->mm_users));
	BUG_ON(!mm->m_sec);
	first_flow->src.file = file;
	first_flow->src_type = BLARE_FILE_TYPE;
	first_flow->dest.mm = mm;
	first_flow->dest_type = BLARE_MM_TYPE;
	return __register_new_flow(first_flow, &isec->info);
}

/**
 * register_flow_file_to_mm() - Registers the enabling of a new discrete flow
 * from a file to a process, and start the tag propagation.
 * @file:	The file destination of the information flow.
 * @mm:		The memory structure of the process.
 *
 * Returns: 0 or -ENOMEM.
 */
int register_flow_file_to_mm(struct file *file, struct mm_struct *mm)
{
	int ret;
	mutex_lock(&flows_lock);
	ret = __register_flow_file_to_mm(file, mm);
	mutex_unlock(&flows_lock);
	return ret;
}

/* called from:
 * - write
 * - send
 */
static int __register_flow_mm_to_file(struct mm_struct *mm, struct file *file)
{
	struct inode *inode = file_inode(file);
	struct blare_mm_sec *msec = mm->m_sec;
	struct bfs_elt *first_flow;

	if (!msec || !inode->i_security || tags_count(&msec->info) == 0)
		return 0;

	first_flow = kmalloc(sizeof(struct bfs_elt), GFP_KERNEL);
	if (!first_flow)
		return -ENOMEM;

	get_file(file);
	first_flow->src.mm = mm;
	first_flow->src_type = BLARE_MM_TYPE;
	first_flow->dest.file = file;
	first_flow->dest_type = BLARE_FILE_TYPE;
	return __register_new_flow(first_flow, &msec->info);
}

/**
 * register_flow_mm_to_file() - Registers the enabling of a new discrete flow
 * from a process to a file, and start the tag propagation.
 * @mm:		The memory structure of the process.
 * @file:	The file destination of the information flow.
 *
 * Returns: 0 or -ENOMEM.
 */
int register_flow_mm_to_file(struct mm_struct *mm, struct file *file)
{
	int ret;
	mutex_lock(&flows_lock);
	ret = __register_flow_mm_to_file(mm, file);
	mutex_unlock(&flows_lock);
	return ret;
}

/*
 * called from:
 * - mq_timedreceive
 * - msgrcv
 */
static int __register_flow_msg_to_mm(struct msg_msg *msg, struct mm_struct *mm)
{
	struct blare_msg_sec *msgsec = msg->security;
	struct bfs_elt *first_flow;

	if (!msgsec || !mm->m_sec || tags_count(&msgsec->info) == 0)
		return 0;

	first_flow = kmalloc(sizeof(struct bfs_elt), GFP_KERNEL);
	if (!first_flow)
		return -ENOMEM;

	atomic_inc(&mm->mm_users);
	first_flow->src.msg = msg;
	first_flow->src_type = BLARE_MSG_TYPE;
	first_flow->dest.mm = mm;
	first_flow->dest_type = BLARE_MM_TYPE;
	return __register_new_flow(first_flow, &msgsec->info);
}


/**
 * register_msg_reception() - Registers the enabling of a new discrete flow
 * from a message to a process, and start the tag propagation.
 * @msg:	The message of interest.
 * @mm:		The memory structure of the receiving process.
 *
 * Returns: 0 or -ENOMEM.
 */
int register_flow_msg_to_mm(struct msg_msg *msg, struct mm_struct *mm)
{
	int ret;
	mutex_lock(&flows_lock);
	ret = __register_flow_msg_to_mm(msg, mm);
	mutex_unlock(&flows_lock);
	return ret;
}

/*
 * called from setprocattr (write into /proc/self/attr/current)
 */
static int __register_new_tags_for_mm(const struct info_tags *new_tags,
				      struct mm_struct *mm)
{
	struct bfs_elt *first_flow;

	if (!new_tags || !mm->m_sec || tags_count(new_tags) == 0)
		return 0;

	first_flow = kmalloc(sizeof(struct bfs_elt), GFP_KERNEL);
	if (!first_flow)
		return -ENOMEM;

	atomic_inc(&mm->mm_users);
	first_flow->src.mm = current->mm;
	first_flow->src_type = BLARE_MM_TYPE;
	first_flow->dest.mm = mm;
	first_flow->dest_type = BLARE_MM_TYPE;
	return __register_new_flow(first_flow, new_tags);
}

/**
 * register_new_tags_for_mm() - Register the addition of new tags to a process,
 * and start the propagation.
 * @tags:	The new tags.
 * @mm:		The memory space of the process receiving the new tags.
 *
 * Returns: 0 or -ENOMEM.
 */
int register_new_tags_for_mm(const struct info_tags *tags, struct mm_struct *mm)
{
	int ret;
	mutex_lock(&flows_lock);
	ret = __register_new_tags_for_mm(tags, mm);
	mutex_unlock(&flows_lock);
	return ret;
}

/**
 * register_read() - Registers the enabling of a new discrete flow from a file
 * to the current process, and start the tag propagation.
 * @file:	The file of interest.
 *
 * Returns: 0 or -ENOMEM.
 */
int register_read(struct file *file)
{
	int ret = 0;
	struct mm_struct *mm = current->mm;
	struct inode *inode = file_inode(file);
	struct discrete_flow *flow =
	    kmalloc(sizeof(struct discrete_flow), GFP_KERNEL);

	if (!flow)
		return -ENOMEM;

	atomic_inc(&mm->mm_users);
	flow->resp = current;
	flow->src.file = file;
	flow->src_type = BLARE_FILE_TYPE;
	flow->dest.mm = mm;
	flow->dest_type = BLARE_MM_TYPE;
	INIT_HLIST_NODE(&flow->by_src);
	INIT_HLIST_NODE(&flow->by_task);

	mutex_lock(&flows_lock);
	pr_debug("kblare: key for inode insertion %llu\n", (u64) inode);
	hash_add(enabled_flows_by_src, &flow->by_src, ((u64) inode));
	hash_add(enabled_flows_by_task, &flow->by_task, ((u64) current));
	ret = __register_flow_file_to_mm(file, mm);
	mutex_unlock(&flows_lock);

	return ret;
}

/**
 * register_write() - Registers the enabling of a new discrete flow from the
 * current process to a file, and start the tag propagation.
 * @file:	The file of interest.
 *
 * Returns: 0 or -ENOMEM.
 */
int register_write(struct file *file)
{
	int ret = 0;
	struct mm_struct *mm = current->mm;

	struct discrete_flow *flow =
	    kmalloc(sizeof(struct discrete_flow), GFP_KERNEL);

	if (!flow)
		return -ENOMEM;

	get_file(file);
	flow->resp = current;
	flow->src.mm = mm;
	flow->src_type = BLARE_MM_TYPE;
	flow->dest.file = file;
	flow->dest_type = BLARE_FILE_TYPE;
	INIT_HLIST_NODE(&flow->by_src);
	INIT_HLIST_NODE(&flow->by_task);

	mutex_lock(&flows_lock);
	pr_debug("kblare: key for mm insertion %llu\n", (u64) mm);
	hash_add(enabled_flows_by_src, &flow->by_src, ((u64) mm));
	hash_add(enabled_flows_by_task, &flow->by_task, ((u64) current));
	ret = __register_flow_mm_to_file(mm, file);
	mutex_unlock(&flows_lock);

	return ret;
}

/**
 * register_msg_reception() - Registers the enabling of a new discrete flow
 * from a message to the current process, and start the tag propagation.
 * @msg:	The message of interest.
 *
 * Returns: 0 or -ENOMEM.
 */
int register_msg_reception(struct msg_msg *msg)
{
	int ret = 0;
	struct mm_struct *mm = current->mm;
	struct discrete_flow *flow =
	    kmalloc(sizeof(struct discrete_flow), GFP_KERNEL);

	if (!flow)
		return -ENOMEM;

	atomic_inc(&mm->mm_users);
	flow->resp = current;
	flow->src.msg = msg;
	flow->src_type = BLARE_FILE_TYPE;
	flow->dest.mm = mm;
	flow->dest_type = BLARE_MM_TYPE;
	INIT_HLIST_NODE(&flow->by_src);
	INIT_HLIST_NODE(&flow->by_task);

	/* do not insert the msg in the discrete flows table because the
	 * message cannot be the destination of any flow */
	ret = register_flow_msg_to_mm(msg, mm);

	return ret;
}

/**
 * unregister_task_flow() - Marks the discrete flow generated by a given
 * process as finished.
 * @p:	The process of interest.
 */
static void unregister_task_flow(struct task_struct *p)
{
	struct discrete_flow *flow;
	mutex_lock(&flows_lock);
	hash_for_each_possible(enabled_flows_by_task, flow, by_task, ((u64) p)) {
		if (flow->resp == p) {
			hash_del(&flow->by_task);
			hash_del(&flow->by_src);
			if (flow->dest_type == BLARE_FILE_TYPE)
				fput(flow->dest.file);
			else
				mmput(flow->dest.mm);
			kfree(flow);
			break;
		}
	}
	mutex_unlock(&flows_lock);
}

/**
 * unregister_current_flow() - Marks the discrete flow generated by the current
 * process as finished.
 */
void unregister_current_flow(void)
{
	unregister_task_flow(current);
}

/**
 * task_maybe_hashed__unlocked() - Checks whether a task might be responsible
 * of an enabled discrete flow.
 * @task:	The task of interest.
 *
 * This function's error is one-sided: it is possible that it returns true
 * erroneaously but it will never say that a task is not responsible of any
 * flow when it in fact is.
 *
 * Returns: false only if it is impossible that the task is responsible of an
 * enabled discrete flow.
 */
static bool task_maybe_hashed__unlocked(struct task_struct *task)
{
	int i = hash_min((u64) task, HASH_BITS(enabled_flows_by_task));
	return !hlist_empty(&enabled_flows_by_task[i]);
}

/**
 * async_unregister_task_flow() - Removes all discrete flows caused by a task
 * which is about to disappear.
 * @freer:	The work structure which contains the task to handle.
 */
static void async_unregister_task_flow(struct work_struct *freer)
{
	struct async_task_freer *f =
	    container_of(freer, struct async_task_freer, work);
	unregister_task_flow(f->task);
	kfree(f);
}

 /**
  * unregister_dying_task_flow() - Removes all discrete flows caused by a task
  * which is about to disappear.
  * @task:	The dying process.
  *
  * This can be called from interrupt context from blare_task_free so populate
  * a workqueue to do the work
  */
void unregister_dying_task_flow(struct task_struct *task)
{
	struct async_task_freer *f;

	/* Kernel threads are not of our concern */
	if (!current->mm)
		return;

	/* we can take a quick look at the hash table without taking the lock
	 * because we cannot race with the insertion of a node by ourselves
	 * (remember we are exiting) */
	if (likely(!task_maybe_hashed__unlocked(task)))
		return;

	f = kmalloc(sizeof(*f), GFP_ATOMIC);
	/* In case of such a very low memory situation, there is not a lot we
	 * can do */
	if (!f)
		return;
	f->task = task;
	INIT_WORK(&f->work, async_unregister_task_flow);
	schedule_work(&f->work);
}

/**
 * register_ptrace_attach() - Registers the existence of a continuous flow
 * between a ptracer and a ptracee.
 * @tracer:	The process doing the ptrace.
 * @child:	The process being ptraced.
 *
 * This function propagates the tags between the ptracee and the ptracer and
 * then replaces the ptracee's memory space security structure by a reference
 * to the ptracer's one. This way, any tag propagation to one of the process
 * also impacts the other one.
 */
int register_ptrace_attach(struct task_struct *tracer,
			   struct task_struct *child)
{
	struct mm_struct *child_mm = child->mm;
	struct blare_mm_sec *child_msec = child_mm->m_sec;
	struct blare_mm_sec *tracer_msec = tracer->mm->m_sec;
	/* we do the m_sec sharing under mutex in order not to propagate tags
	 * inconsistently if the old m_sec is being used */
	mutex_lock(&flows_lock);
	msec_get(tracer_msec);
	child_mm->m_sec = tracer_msec;
	msec_put(child_msec);
	mutex_unlock(&flows_lock);

	return 0;
}

/**
 * unregister_ptrace() - Marks the continuous flow started by a ptrace
 * attachement as stopped.
 * @child:	The formerly ptraced process.
 *
 * This functions unshares the memory space security structures of the ptracer
 * and the ptracee, effectively stopping the automatic propagation of tags from
 * one to the other.
 */
void unregister_ptrace(struct task_struct *child)
{
	struct mm_struct *child_mm = child->mm;
	struct blare_mm_sec *tracer_msec = current->mm->m_sec;
	/* we do the m_sec shring under mutex in order not to propagate tags
	 * inconsistently if the old m_sec is being used */
	mutex_lock(&flows_lock);
	child_mm->m_sec = dup_msec(tracer_msec);
	/* Ups, no more memory but no way to return an error :/
	 * we will proceed as if the caller had ask for the tracee to be killed
	 * on detaching */
	if (IS_ERR(child_mm->m_sec)) {
		send_sig_info(SIGKILL, SEND_SIG_FORCED, child);
		child_mm->m_sec = NULL;
	}
	msec_put(tracer_msec);
	mutex_unlock(&flows_lock);
}

/**
 * dup_msec() - Duplicates a memory space security structure by allocating a new
 * one and copying the tags over.
 * @old_msec:	The security structure to duplicate.
 */
struct blare_mm_sec *dup_msec(struct blare_mm_sec *old_msec)
{
	struct blare_mm_sec *msec;
	msec = kmalloc(sizeof(struct blare_mm_sec), GFP_KERNEL);
	if (!msec)
		goto nomem;
	copy_tags(&msec->info, &old_msec->info);
	atomic_set(&msec->users, 1);
	return msec;

nomem:
	return ERR_PTR(-ENOMEM);
}

/**
 * msec_get() - Increases the reference counter of a memory space security
 * structure.
 * @msec: The memory space security structure of interest.
 */
void msec_get(struct blare_mm_sec *msec)
{
	atomic_inc_not_zero(&msec->users);
}

/**
 * msec_put() - Decreases the reference counter of a memory space security
 * structure and frees it if it reaches zero.
 * @msec: The memory space security structure of interest.
 */
void msec_put(struct blare_mm_sec *msec)
{
	if (atomic_dec_and_test(&msec->users)) {
		kfree(msec);
	}
}
