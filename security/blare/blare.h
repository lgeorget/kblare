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

#include <linux/xattr.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/fs.h>

struct msg_msg;

#define BLARE_XATTR_TAG_SUFFIX "blare.tag"
#define BLARE_XATTR_TAG XATTR_SECURITY_PREFIX BLARE_XATTR_TAG_SUFFIX
#define BLARE_XATTR_TAG_LEN (sizeof(BLARE_XATTR_TAG) - 1);

struct info_tags {
	int count;
	__s32 *tags;
};

/* All the following structures are identical but it's useful to keep them
 * separated to benefit for readability and typing. Furthermore, we will need
 * to add a mutex or a counter in these structures when we make the big
 * flows_lock mutex disappear. */
struct blare_inode_sec {
	struct info_tags info;
};

struct blare_mm_sec {
	struct info_tags info;
};

struct blare_msg_sec {
	struct info_tags info;
};

int register_read(struct file *file);
int register_write(struct file *file);
int register_msg_reception(struct msg_msg *msg);
void unregister_current_flow(void);

static inline bool tags_initialized(struct info_tags *tags) {
	return !!(tags->tags);
}
