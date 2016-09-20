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

#include "blare.h"

struct flow;


struct flow {
	struct list_head open_flows;
	struct task_struct *resp;
	struct info_tags *src;
	struct info_tags *dest;
	struct dentry *dest_dentry;
};

struct node {
	struct list_head list;
	struct info_tags *container;
	struct dentry *container_dentry;
};

static LIST_HEAD(flows);
static DEFINE_MUTEX(flows_lock);

static int visit_next(struct info_tags *ctn, struct dentry *ctn_dentry, struct node *next, struct node *visit_list);
static int bfs(struct info_tags *src, struct list_head *graph);
static int generic_add_tags(struct info_tags *dest, struct dentry *dest_dentry, const struct info_tags *src);


int register_flow(struct info_tags *dest, struct info_tags *src,
		  struct dentry *dest_dentry)
{
	struct flow *new_flow = kmalloc(sizeof(struct flow), GFP_KERNEL);
	if (!new_flow)
		return -ENOMEM;

	/* serialize everyone on one big mutex (and fix that some day) */
	mutex_lock(&flows_lock);

	new_flow->resp = current;
	new_flow->src = src;
	new_flow->dest = dest;
	new_flow->dest_dentry = dest_dentry;
	list_add(&new_flow->open_flows, &flows);
	bfs(src,&flows);

	mutex_unlock(&flows_lock);

	return 0;
}

void unregister_current_flow()
{
	struct flow *flow;
	mutex_lock(&flows_lock);
	flow = list_first_entry(&flows, struct flow, open_flows);
	while (flow->resp != current && &flow->open_flows != &flows) {
		flow = list_next_entry(flow, open_flows);
	}

	if (&flow->open_flows != &flows) { /* we found the flow to delete */
		list_del(&flow->open_flows);
		if (flow->dest_dentry)
			dput(flow->dest_dentry);
		kfree(flow);
	}
	mutex_unlock(&flows_lock);
}

static noinline int visit_next(struct info_tags *ctn, struct dentry *ctn_dentry, struct node *next, struct node *visit_list)
{
	// il faut d'abord vérifier si le nœud n'est pas déjà visité
	struct node *iter;
	struct node *new_node;
	bool ok = true;
	list_for_each_entry(iter, &visit_list->list, list) {
		if (iter->container == ctn) {
			ok = false;
			break;
		}
	}
	if (!ok)
		return 0;

	new_node = (struct node*) kmalloc(sizeof(struct node),
						       GFP_KERNEL);
	if (!new_node)
		return -ENOMEM;

	new_node->container = ctn;
	new_node->container_dentry = ctn_dentry;
	list_add_tail(&new_node->list, &visit_list->list);

	return 0;
}

static noinline int bfs(struct info_tags *src, struct list_head *graph)
{
	struct node visit;
	struct node *next;
	struct node *first = (struct node*) kmalloc(sizeof(struct node),
						    GFP_KERNEL);
	struct flow *iter;
	int rc;

	if (!first) {
		pr_err("Blare: couldn't allocate node in BFS");
		return -ENOMEM;
	}
	first->container = src;
	first->container_dentry = NULL; /* ignored, because we propagate
					   nothing INTO the src container */
	next = first;
//	pr_info("Blare: Starting BFS from %p, container: %p\n", first, first->container);

	rc = 0;
	INIT_LIST_HEAD(&visit.list);
	list_add_tail(&first->list, &visit.list);
	list_for_each_entry(next, &visit.list, list) {
		list_for_each_entry(iter, graph, open_flows) {
			if (iter->src == next->container) {
			//	pr_info("Blare: iter->src matches, propagation into: %p\n",iter->dest);
			//	if (iter->dest_dentry)
			//		pr_info("\t... dest is %s\n",iter->dest_dentry->d_name.name);
				rc = visit_next(iter->dest, iter->dest_dentry, next, &visit);
				if (rc)
					goto free_all;
			}
		}
		if (next != first) /* no tags to add into the source */
			generic_add_tags(next->container, next->container_dentry, src);
	}

free_all:
	while (!list_empty(&visit.list)) {
		next = list_entry(visit.list.next, struct node, list);
		list_del(&next->list);
		kfree(next);
	}

	return rc;
}


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
		/* dput(dentry); */
	}
commit:
	if (rc >= 0) { /* the new tags have been computed and propagated into the
		      inode's xattr, if required. Time to commit the changes */
		__s32 *old_tags = dest->tags;
		dest->tags = tags.tags;
		dest->count = tags.count;
		kfree(old_tags);
	}

	 return rc;
}

/**
 * Add the tags of src to the ones in dest, without duplicates. There should be
 * no dumplicates in dest and src. The result is stored in new_tags.
 * The caller may pass dest as new_tags. In any case, the method will leave
 * dest unchanged if the return code is different from 0.
 * If all tags in src were already in dest, the method returns an EMPTY
 * new_tags (count = 0 and no allocation done).
 * @dest the destination security structure
 * @src the source security structure
 * @new_tags the result of the merging of the tags in src and dest
 */
int add_tags(const struct info_tags* dest, const struct info_tags* src,
	     struct info_tags* new_tags)
{
	__s32 *tags;

	if (src->count == BLARE_UNINITIALIZED || src->count == 0) {
		/* no tags in source, exit right away */
		new_tags->count = 0;
		new_tags->tags = NULL;
		return 0;
	}

	if (dest->count == BLARE_UNINITIALIZED || dest->count == 0) {
		/* this is the easy case, we can just copy the tags over */
		tags = kmemdup(src->tags, src->count * sizeof(__s32), GFP_KERNEL);
		if (!tags)
			return -ENOMEM;
		memcpy(tags, src->tags, src->count * sizeof(__s32));
		new_tags->tags = tags;
		new_tags->count = src->count;
		return src->count;
	} else {
		/* we have to merge the new tags with the ones already present
		 * in the destination container */

		/* First of all, how many new tags are there? */
		int new_count = (dest->count == BLARE_UNINITIALIZED) ?
			0 : dest->count;
		int i,j;
		int last_tag;
		int ret;

		for (i = 0 ; i < src->count ; i++) {
			for (j = 0 ;
			     j < dest->count && src->tags[i] != dest->tags[j] ;
			     j++)
			{}
			if (j == dest->count) /* tag is absent */
				new_count++;
		}

		ret = new_count - dest->count;
		if (!ret) {
			/* no new tags: fast path */
			new_tags->count = 0;
			new_tags->tags = NULL;
			return 0;
		}

		/* There are some new tags: make room for them and copy them
		 * over */
		tags = kmalloc(new_count * sizeof(__s32), GFP_KERNEL);
		memcpy(tags, dest->tags, dest->count * sizeof(__s32));

		if (!tags)
			return -ENOMEM;

		last_tag = dest->count;

		for (i = 0 ; i < src->count ; i++) {
			for (j = 0 ;
			     j < dest->count && src->tags[i] != dest->tags[j] ;
			     j++)
			{}
			if (j == dest->count)
				tags[last_tag++] = src->tags[i];
		}

		if (new_tags == dest) /* the caller wants to replace dest */
			kfree(dest->tags);

		new_tags->count = new_count;
		new_tags->tags = tags;

		return ret;
	}
}
