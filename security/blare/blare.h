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
#ifndef _BLARE_H
#define _BLARE_H

#include <linux/xattr.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/bitops.h>

struct msg_msg;

#define BLARE_XATTR_TAG_SUFFIX "blare.tag"
#define BLARE_XATTR_TAG XATTR_SECURITY_PREFIX BLARE_XATTR_TAG_SUFFIX
#define BLARE_XATTR_TAG_LEN (sizeof(BLARE_XATTR_TAG) - 1)

#define BLARE_TAGS_NUMBER 4

struct info_tags {
	__u32 tags[BLARE_TAGS_NUMBER];
};

struct blare_inode_sec {
	struct info_tags info;
};

struct blare_mm_sec {
	struct info_tags info;
	atomic_t users;
};

struct blare_msg_sec {
	struct info_tags info;
};

int register_read(struct file *file);
int register_write(struct file *file);
int register_msg_reception(struct msg_msg *msg);
int register_ptrace_attach(struct task_struct *tracer,
			   struct task_struct *child);
void unregister_current_flow(void);
void unregister_dying_task_flow(struct task_struct *p);
void unregister_ptrace(struct task_struct *child);
struct blare_mm_sec *dup_msec(struct blare_mm_sec *old_msec);
void msec_get(struct blare_mm_sec *msec);
void msec_put(struct blare_mm_sec *msec);

static inline int tags_count(struct info_tags *tags) {
	int count = 0;
	int i;
	for (i=0 ; i<BLARE_TAGS_NUMBER ; i++)
		count += hweight32(tags->tags[i]);
	return count;
}

static inline void initialize_tags(struct info_tags *tags) {
	int i;
	for (i=0 ; i<BLARE_TAGS_NUMBER ; i++)
		tags->tags[i] = 0;
}

static inline void copy_tags(struct info_tags *dest, const struct info_tags *src) {
	int i;
	for (i=0 ; i<BLARE_TAGS_NUMBER ; i++)
		dest->tags[i] = src->tags[i];
}

#endif // _BLARE_H
