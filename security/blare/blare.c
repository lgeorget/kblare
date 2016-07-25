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
#include <linux/errno.h>

/*
 * An itag (information tag) is the label identifying the content of a
 * container of information. It's an array of integers, representing a set of
 * identifiers of information classes. 
struct itag
{
	size_t count;
	int* tags;
}

 * A ptag (policy tag) is the label identifying the authorized content of a
 * container of information.  It's an array of arrays of integers, representing
 * the set of sets of authorized information mixes.
struct ptag
{
	size_t count;
	struct {
		size_t count;
		int* tags;
	} mixes;
}*/

int merge_itags(struct itag *origin, struct itag *new, struct itag **result)
{
	size_t size;
	struct itag *merge;

	size = origin->count + new->count;
	merge = (struct itag*) kmalloc(size, GFP_KERNEL);
	if (!merge)
		return -ENOMEM;

	memcpy(origin->tags, origin->count, merge->tags);
	memcpy(new->tags, new->count, &merge->tags[origin->count]);
	merge->count = size;
	*result = merge;

	return 0;
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
	for (i = 0 ; i < policy->count ; i++) {
		if (is_subset(content, policy->mixes[0]))
			break;
	}

	/* i == policy->count means that content is not a subset of any policy
	 * mix */
	return i == policy->count ? 0 : 1; 
}
