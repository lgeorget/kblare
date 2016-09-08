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

#include "blare.h"

int add_tags(const struct info_tags* dest, const struct info_tags* src, struct info_tags* new_tags)
{
	__s32 *tags;

	if (src->count == BLARE_UNINITIALIZED || src->count == 0)
		return 0;

	if (dest->count == BLARE_UNINITIALIZED || dest->count == 0) {
		/* this is the easy case, we can just copy the tags */
		tags = kmemdup(src->tags, src->count * sizeof(__s32), GFP_KERNEL);
		if (!tags)
			return -ENOMEM;
		memcpy(tags, src->tags, src->count * sizeof(__s32));
		new_tags->tags = tags;
		new_tags->count = src->count;
		return src->count;
	} else {
		/* if there were already tags, we have to merge them */
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
		if (!ret) /* no new tags */
			return 0;

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
			if (j == dest->count) /* tag is absent */
				tags[last_tag++] = src->tags[i];
		}

		if (new_tags == dest)
			kfree(dest->tags);

		new_tags->count = new_count;
		new_tags->tags = tags;

		return ret;
	}
}
