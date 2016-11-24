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
#include <linux/spinlock.h>
#include <linux/fsnotify.h>
#include <linux/hashtable.h>
#include <linux/msg.h>

#include "blare.h"

#define BLARE_HASHTABLE_SHIFT 10
#define BLARE_FILE_TYPE 0
#define BLARE_MM_TYPE 1

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
	int type;
	struct hlist_node by_src; /* table of enabled flows, by source */
	struct hlist_node by_task; /* table of enabled flows, by responsible task_struct* */
};

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
	int type;
	struct list_head list; /* list of bfs_elt to visit */
};

static DEFINE_HASHTABLE(enabled_flows_by_src , BLARE_HASHTABLE_SHIFT);
static DEFINE_HASHTABLE(enabled_flows_by_task, BLARE_HASHTABLE_SHIFT);
static DEFINE_MUTEX(flows_lock);

static int get_mms_for_file(struct file *file, struct list_head *visit_list)
{
	struct inode *inode = file_inode(file);
	struct address_space *maps = inode->i_mapping;
	struct vm_area_struct *vma;
	struct bfs_elt *elt;
	int ret = 0;

	i_mmap_lock_read(maps);
	vma_interval_tree_foreach(vma, &maps->i_mmap, 0, ULONG_MAX)
	{
		/* all vma-s are relevant here, we take a ref on the mm and we
		 * place it on the list of stuff to visit */
		struct mm_struct *mm = vma->vm_mm;

		/* do not consider already dead mm */
		if (!mm || !atomic_inc_not_zero(&mm->mm_users))
			continue;

		if(!mm->m_sec) {
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
		elt->dest.mm = mm;
		elt->type = BLARE_MM_TYPE;
		BUG_ON(!mm->m_sec);
		list_add_tail(&elt->list, visit_list);
	}

unlock:
	i_mmap_unlock_read(maps);
	return ret;
}

static int get_files_for_mm(struct mm_struct *mm, struct list_head *visit_list)
{
	struct vm_area_struct *vma;
	struct file *file;
	struct bfs_elt *elt;
	int ret = 0;

	/* only VM_SHARED with a vm_file */
	down_read(&mm->mmap_sem);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (!(vma->vm_flags & VM_SHARED) || !vma->vm_file)
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
		elt->dest.file = file;
		elt->type = BLARE_FILE_TYPE;
		list_add_tail(&elt->list, visit_list);

	}
unlock:
	up_read(&mm->mmap_sem);
	return ret;
}

static int get_discrete_flows_for_file(struct file *file, struct list_head *visit_list)
{
	struct discrete_flow *flow;
	struct bfs_elt *elt;
	struct inode *inode = file_inode(file);
	u64 key = (u64) inode;
	pr_debug("kblare: key for inode %llu\n",key);
	hash_for_each_possible(enabled_flows_by_src, flow, by_src, key) {
		struct mm_struct *mm;
		// Check if the flow in the bucket is not for another key
		if (flow->type != BLARE_MM_TYPE ||
		    file_inode(flow->src.file) != inode)
			continue;

		mm = flow->dest.mm;
		BUG_ON(!mm->m_sec);
		elt = kmalloc(sizeof(struct bfs_elt), GFP_KERNEL);
		if (!elt)
			return -ENOMEM;
		atomic_inc(&mm->mm_users);
		elt->src.file = file;
		elt->dest.mm = mm;
		elt->type = BLARE_MM_TYPE;
		list_add_tail(&elt->list, visit_list);
	}
	return 0;
}

static int get_discrete_flows_for_mm(struct mm_struct *mm, struct list_head *visit_list)
{
	struct discrete_flow *flow;
	struct bfs_elt *elt;
	u64 key = (u64) mm;
	pr_debug("kblare: key for mm %llu\n",key);
	hash_for_each_possible(enabled_flows_by_src, flow, by_src, key) {
		struct file *file;
		// Check if the flow in the bucket is not for another key
		if (flow->type != BLARE_FILE_TYPE ||
		    flow->src.mm != mm)
			continue;

		file = flow->dest.file;
		elt = kmalloc(sizeof(struct bfs_elt), GFP_KERNEL);
		if (!elt)
			return -ENOMEM;

		get_file(file);
		elt->src.mm = mm;
		elt->dest.file = file;
		elt->type = BLARE_FILE_TYPE;
		list_add_tail(&elt->list, visit_list);
	}
	return 0;
}

static int propagate_tags(struct info_tags *dest, struct info_tags *src,
		    struct info_tags *tags_added)
{
	__s32 *tags, *new_dest_tags;
	tags_added->count = 0;
	tags_added->tags = NULL;

	if (src->count == 0) {
		/* no tags in source, exit right away */
		return 0;
	}

	if (dest->count == 0) {
		/* this is the easy case, we can just copy the tags over */
		tags = kmemdup(src->tags, src->count * sizeof(__s32), GFP_KERNEL);
		if (!tags)
			return -ENOMEM;
		memcpy(tags, src->tags, src->count * sizeof(__s32));
		dest->tags = tags;
		dest->count = src->count;

		/* and the set of added tags is precisely the same set too */
		tags = kmemdup(src->tags, src->count * sizeof(__s32), GFP_KERNEL);
		if (!tags)
			return -ENOMEM;
		memcpy(tags, src->tags, src->count * sizeof(__s32));
		tags_added->tags = tags;
		tags_added->count = src->count;
		return 0;
	} else {
		/* we have to merge the new tags with the ones already present
		 * in the destination container */

		/* First of all, how many new tags are there? */
		int new_tags_count = 0;
		int i,j;
		int last_tag = 0;

		for (i = 0 ; i < src->count ; i++) {
			for (j = 0 ;
			     j < dest->count && src->tags[i] != dest->tags[j] ;
			     j++)
			{}
			if (j == dest->count) /* tag is absent */
				new_tags_count++;
		}

		if (!new_tags_count) {
			/* no new tags: fast path */
			return 0;
		}

		/* There are some new tags: make room for them and copy them
		 * over */
		tags = kmalloc(new_tags_count * sizeof(__s32), GFP_KERNEL);
		new_dest_tags = kmalloc((new_tags_count + dest->count) * sizeof(__s32), GFP_KERNEL);

		if (!tags || !new_dest_tags)
			return -ENOMEM;

		for (i = 0 ; i < src->count ; i++) {
			for (j = 0 ;
			     j < dest->count && src->tags[i] != dest->tags[j] ;
			     j++)
			{}
			if (j == dest->count) {
				tags[last_tag++] = src->tags[i];

			}
		}

		memcpy(new_dest_tags, dest->tags, dest->count * sizeof(__s32));
		memcpy(&(new_dest_tags[dest->count]), tags, new_tags_count * sizeof(__s32));

		/* all went well, commit */
		kfree(dest->tags);
		dest->count += new_tags_count;
		dest->tags = new_dest_tags;
		tags_added->count = new_tags_count;
		tags_added->tags = tags;
	}

	return 0;
}

static int propagate_to_mm(struct mm_struct *mm, struct list_head *visit_list, struct info_tags *tags)
{
	struct blare_mm_sec *msec = mm->m_sec;
	struct info_tags new_tags;
	int ret;

	ret = propagate_tags(&msec->info, tags, &new_tags);
	if (ret)
		return ret;

	if (new_tags.count > 0) {
		ret = get_files_for_mm(mm, visit_list);
		if (!ret)
			ret = get_discrete_flows_for_mm(mm, visit_list);
		kfree(new_tags.tags);
	}

	return ret;
}

static int propagate_to_file(struct file *file, struct list_head *visit_list, struct info_tags *tags)
{
	struct inode *inode = file_inode(file);
	struct blare_inode_sec *isec = inode->i_security;
	struct info_tags new_tags;

	int ret = propagate_tags(&isec->info, tags, &new_tags);
	if (ret)
		return ret;
	if (new_tags.count > 0) {
		struct dentry *dentry = dget(file_dentry(file));
		if (dentry && inode->i_op->setxattr) {
			int rc;
			/* Convert the shared lock into an exclusive lock
			 * no race condition to be afraid of because the entire
			 * tag propagation is protected by mutex flows_lock
			 * and we have a reference on the inode */
			inode_unlock(inode);
			inode_lock(inode);
			rc = inode->i_op->setxattr(dentry, inode,
				BLARE_XATTR_TAG, isec->info.tags,
				isec->info.count * sizeof(__s32), 0);
			if (!rc)
				fsnotify_xattr(dentry);
			inode_unlock(inode);
			inode_lock_shared(inode);
		}
		dput(dentry);

		ret = get_mms_for_file(file, visit_list);
		if (!ret)
			ret = get_discrete_flows_for_file(file, visit_list);
		kfree(new_tags.tags);
	}

	return ret;
}

static int __register_new_flow(struct bfs_elt *new_flow, struct info_tags *new_tags)
{
	LIST_HEAD(visit_list);
	struct bfs_elt *next, *temp;
	int ret = 0;
	int loop = 0;

	list_add(&new_flow->list, &visit_list);
	list_for_each_entry(next, &visit_list, list) {
		if (next->type == BLARE_FILE_TYPE) {
			struct file *file = next->dest.file;
			struct inode *inode = file_inode(file);
			inode_lock_shared(inode);
			ret = propagate_to_file(file, &visit_list, new_tags);
			inode_unlock_shared(inode);
			fput(file);
		} else {
			struct mm_struct *mm = next->dest.mm;
			ret = propagate_to_mm(mm, &visit_list, new_tags);
			mmput(mm);
			loop++;
		}

		if (ret)
			goto free_all_and_abort;
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
static int register_flow_file_to_mm(struct file *file, struct mm_struct *mm)
{
	struct inode *inode = file_inode(file);
	struct blare_inode_sec *isec = inode->i_security;
	struct bfs_elt *first_flow;

	if (!isec || !mm->m_sec || !tags_initialized(&isec->info))
		return 0;

	first_flow = kmalloc(sizeof(struct bfs_elt), GFP_KERNEL);
	if (!first_flow)
		return -ENOMEM;

	BUG_ON(!atomic_inc_not_zero(&mm->mm_users));
	BUG_ON(!mm->m_sec);
	first_flow->src.file = file;
	first_flow->dest.mm = mm;
	first_flow->type = BLARE_MM_TYPE;
	return __register_new_flow(first_flow, &isec->info);
}

/* called from:
 * - write
 * - send
 */
static int register_flow_mm_to_file(struct mm_struct *mm, struct file *file)
{
	struct inode *inode = file_inode(file);
	struct blare_mm_sec *msec = mm->m_sec;
	struct bfs_elt *first_flow;

	if (!msec || !inode->i_security || !tags_initialized(&msec->info))
		return 0;

	first_flow = kmalloc(sizeof(struct bfs_elt), GFP_KERNEL);
	if (!first_flow)
		return -ENOMEM;

	get_file(file);
	first_flow->src.mm = mm;
	first_flow->dest.file = file;
	first_flow->type = BLARE_FILE_TYPE;
	return __register_new_flow(first_flow, &msec->info);
}

/*
 * called from:
 * - mq_timedreceive
 * - msgrcv
 */
static int register_flow_msg_to_mm(struct msg_msg *msg, struct mm_struct *mm)
{
	struct blare_msg_sec *msgsec = msg->security;
	struct bfs_elt *first_flow;

	if (!msgsec || !mm->m_sec || !tags_initialized(&msgsec->info))
		return 0;

	first_flow = kmalloc(sizeof(struct bfs_elt), GFP_KERNEL);
	if (!first_flow)
		return -ENOMEM;

	atomic_inc(&mm->mm_users);
	first_flow->src.msg = msg;
	first_flow->dest.mm = mm;
	first_flow->type = BLARE_MM_TYPE;
	return __register_new_flow(first_flow, &msgsec->info);
}

/* other flows to cover: clone (and fork...) */

int register_read(struct file *file)
{
	int ret = 0;
	struct mm_struct *mm = current->mm;
	struct inode *inode =file_inode(file);
	struct discrete_flow *flow = kmalloc(sizeof(struct discrete_flow), GFP_KERNEL);

	if (!flow)
		return -ENOMEM;

	atomic_inc(&mm->mm_users);
	flow->resp = current;
	flow->src.file = file;
	flow->dest.mm = mm;
	flow->type = BLARE_MM_TYPE;
	INIT_HLIST_NODE(&flow->by_src);
	INIT_HLIST_NODE(&flow->by_task);

	mutex_lock(&flows_lock);
	pr_debug("kblare: key for inode insertion %llu\n", (u64) inode);
	hash_add(enabled_flows_by_src, &flow->by_src, ((u64) inode));
	hash_add(enabled_flows_by_task, &flow->by_task, ((u64) current));
	ret = register_flow_file_to_mm(file, mm);
	mutex_unlock(&flows_lock);

	return ret;
}

int register_write(struct file *file)
{
	int ret = 0;
	struct mm_struct *mm = current->mm;

	struct discrete_flow *flow = kmalloc(sizeof(struct discrete_flow), GFP_KERNEL);

	if (!flow)
		return -ENOMEM;

	get_file(file);
	flow->resp = current;
	flow->src.mm = mm;
	flow->dest.file = file;
	flow->type = BLARE_FILE_TYPE;
	INIT_HLIST_NODE(&flow->by_src);
	INIT_HLIST_NODE(&flow->by_task);

	mutex_lock(&flows_lock);
	pr_debug("kblare: key for mm insertion %llu\n", (u64) mm);
	hash_add(enabled_flows_by_src, &flow->by_src, ((u64) mm));
	hash_add(enabled_flows_by_task, &flow->by_task, ((u64) current));
	ret = register_flow_mm_to_file(mm, file);
	mutex_unlock(&flows_lock);

	return ret;
}

int register_msg_reception(struct msg_msg *msg)
{
	int ret = 0;
	struct mm_struct *mm = current->mm;
	struct discrete_flow *flow = kmalloc(sizeof(struct discrete_flow), GFP_KERNEL);

	if (!flow)
		return -ENOMEM;

	atomic_inc(&mm->mm_users);
	flow->resp = current;
	flow->src.msg = msg;
	flow->dest.mm = mm;
	flow->type = BLARE_MM_TYPE;
	INIT_HLIST_NODE(&flow->by_src);
	INIT_HLIST_NODE(&flow->by_task);

	mutex_lock(&flows_lock);
	/* do not insert the msg in the discrete flows table because the
	 * message cannot be the destination of any flow */
	ret = register_flow_msg_to_mm(msg, mm);
	mutex_unlock(&flows_lock);

	return ret;
}

void unregister_current_flow(void)
{
	struct discrete_flow *flow;
	mutex_lock(&flows_lock);
	hash_for_each_possible(enabled_flows_by_task, flow, by_task, ((u64) current)) {
		if (flow->resp == current) {
			hash_del(&flow->by_task);
			hash_del(&flow->by_src);
			if (flow->type == BLARE_FILE_TYPE)
				fput(flow->dest.file);
			else
				mmput(flow->dest.mm);
			kfree(flow);
			break;
		}
	}
	mutex_unlock(&flows_lock);
}

int register_ptrace_attach(struct task_struct *tracer, struct task_struct *child)
{
	struct mm_struct *child_mm = child->mm;
	struct blare_mm_sec *child_msec = child_mm->m_sec;
struct blare_mm_sec *tracer_msec = tracer->mm->m_sec;
/* we do the m_sec shring under mutex in order not to propagate tags
	 * inconsistently if the old m_sec is being used */
	mutex_lock(&flows_lock);
	msec_get(tracer_msec);
	child_mm->m_sec = tracer_msec;
	msec_put(child_msec);
	mutex_unlock(&flows_lock);

	return 0;
}

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

struct blare_mm_sec *dup_msec(struct blare_mm_sec *old_msec)
{
	struct blare_mm_sec *msec;
	msec = kmemdup(old_msec, sizeof(struct blare_mm_sec), GFP_KERNEL);
	if (!msec)
		goto nomem;
	if (tags_initialized(&old_msec->info) && old_msec->info.count > 0) {
		msec->info.tags = kmemdup(old_msec->info.tags,
			old_msec->info.count * sizeof(__s32), GFP_KERNEL);
		if (!msec->info.tags) {
			kfree(msec);
			goto nomem;
		}
	}
	atomic_set(&msec->users, 1);
	return msec;

nomem:
	return ERR_PTR(-ENOMEM);
}

void msec_get(struct blare_mm_sec *msec)
{
	atomic_inc(&msec->users);
}

void msec_put(struct blare_mm_sec *msec)
{
	if (atomic_dec_and_test(&msec->users)) {
		kfree(msec->info.tags);
		kfree(msec);
	}
}

#if 0
static noinline int generic_add_tags(struct info_tags *dest, struct dentry *dest_dentry, const struct info_tags *src)
{
	int rc;
	struct info_tags tags = {0, NULL};

	rc = add_tags(dest, src, &tags);
	if (rc < 0 || tags.count == 0)
		 return rc;

	rc = 0;
	if (dest_dentry) {
		struct inode *inode = d_backing_inode(dest_dentry);
		if (!inode) {
			pr_err("Blare: No inode corresponding to dentry");
			rc = -ENODATA;
		} else if (inode->i_op->setxattr) {
			inode_lock(inode);
			rc = inode->i_op->setxattr(dest_dentry, inode,
						   BLARE_XATTR_TAG,
						   tags.tags, tags.count,
						   0);
			if (!rc)
				fsnotify_xattr(dest_dentry);
			inode_unlock(inode);
		}
	}

	if (rc >= 0) { /* the new tags have been computed and propagated into the
		      inode's xattr, if required. Time to commit the changes */
		__s32 *old_tags = dest->tags;
		dest->tags = tags.tags;
		dest->count = tags.count;
		kfree(old_tags);
	}

	 return rc;
}
}
#endif
