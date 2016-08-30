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

#include "blare.h"

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/errno.h>

int copy_itags(struct itag *origin, struct itag *new)
{
	int size = origin->count * sizeof(__s32);

	new = kmalloc(size, GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	memcpy(new->tags, origin->tags, size);
	new->count = origin->count;
	return 0;
}

int merge_itags(struct itag *origin, struct itag *new, struct itag **result)
{
	int size;
	int merge_count;
	struct itag *merge;
	__s32* tags;
	int i,j;

	size = (origin->count + new->count) * sizeof(__s32);
	tags = kmalloc(size, GFP_KERNEL);
	if (!tags)
		return -ENOMEM;

	memcpy(origin->tags, tags, origin->count * sizeof(__s32));
	merge_count = origin->count;
	for (i=0 ; i<new->count ; i++) {
		for (j=0 ; j<origin->count && new->tags[i] != origin->tags[i] ;
		     j++) ;
		if  (j < origin->count)
			tags[merge_count++] = new->tags[i];
	}

	merge = kmalloc(sizeof(struct itag), GFP_KERNEL);
	if (!merge) {
		kfree(tags);
		return -ENOMEM;
	}
	merge->tags = kmalloc(merge_count * sizeof(__s32), GFP_KERNEL);
	if (!merge->tags) {
		kfree(tags);
		kfree(merge);
		return -ENOMEM;
	}

	memcpy(merge->tags, tags, merge_count*sizeof(__s32));
	merge->count = merge_count;
	*result = merge;
	kfree(tags);

	return 0;
}

void free_blare_file_struct(struct blare_file_struct *sec)
{
	kfree(sec->info);
	kfree(sec);
}

void free_blare_task_struct(struct blare_task_struct *sec)
{
	kfree(sec->info);
	kfree(sec);
}

static int is_subset(struct itag* content, size_t count, int* tags)
{
	int i,j;
	if (content->count > count)
		return 0;

	for (i = 0 ; i < content->count ; i++) {
		for (j = 0 ; j < count ; j++) {
			if (content->tags[i] == tags[j])
				break;
		}

		if (j == content->count) /* if we reach that point, */
			return 0;	 /* then content[i] is not in tags */
	}

	/* if we reach that point, for all i, content[i] is in tags */
	return 1;
}

int check_against_ptag(struct itag* content, struct ptag* policy)
{
	int i;
	for (i = 0 ; i < policy->mixes_count ; i++) {
		if (is_subset(content, policy->count[i], policy->tags[i]))
			break;
	}

	/* i <= policy->count means that content is a subset of policy mix i */
	return i < policy->mixes_count ? 1 : 0;
}
