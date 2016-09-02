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

#include <linux/lsm_hooks.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/binfmts.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <linux/xattr.h>
#include <linux/types.h>

static int dummy_counter = 0;

const char DUMMY_XATTR_TAG[] = XATTR_SECURITY_PREFIX"dummy.tag";
const char *DUMMY_XATTR_TAG_SUFFIX = &(DUMMY_XATTR_TAG[XATTR_SECURITY_PREFIX_LEN]);
const int DUMMY_XATTR_TAG_LEN = sizeof(DUMMY_XATTR_TAG);

#define BLARE_UNINITIALIZED (-1)

struct info_tags {
	int count;
	__s32 *tags;
};

struct blare_inode_sec {
	struct info_tags info;
	struct mutex lock;
};

struct blare_task_sec {
	struct info_tags info;
	struct mutex lock;
};

static int update_inode_tags(struct blare_inode_sec *isec, const void *value, size_t size);
static int dummy_may_read(struct blare_inode_sec *isec, struct blare_task_sec *tsec);
static int dummy_may_write(struct blare_inode_sec *isec, struct blare_task_sec *tsec,
			   struct dentry *dentry);

static int dummy_bprm_set_creds(struct linux_binprm *bprm)
{
	struct blare_task_sec *tsec;
	struct inode *inode = file_inode(bprm->file);
	struct blare_inode_sec *isec;

	/* For now, we are only concerned with the permissions of the initial
	 * file, not the wrappers/interpreters/etc. */
	if (bprm->cred_prepared)
		return 0;

	isec = inode->i_security;
	if (!isec) {
		pr_warn("No security attributes in inode");
		return 0;
	}

	if (capable(CAP_MAC_ADMIN))
		return 0;

	tsec = kzalloc(sizeof(struct blare_task_sec), GFP_KERNEL);
	mutex_init(&tsec->lock);
	if (!tsec)
		return -ENOMEM;
	tsec->info.count = BLARE_UNINITIALIZED;

	if (isec->info.count > 0) {
		/* Copy the information tag */
		tsec->info.tags = kmemdup(isec->info.tags, isec->info.count * sizeof(__s32), GFP_KERNEL);
		if (!tsec->info.tags) {
			kfree(tsec);
			return -ENOMEM;
		}
		tsec->info.count = isec->info.count;
	} else {
		tsec->info.count = 0;
		tsec->info.tags = NULL;
	}
	bprm->cred->security = tsec;

	return 0;
}

static int dummy_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	/* Allocate a security structure for the process's tags */
	struct blare_task_sec *tsec = kzalloc(sizeof(struct blare_task_sec), gfp);
	if (!tsec)
		return -ENOMEM;

	tsec->info.count = BLARE_UNINITIALIZED;
	mutex_init(&tsec->lock);
	cred->security = tsec;
	return 0;
}

static void dummy_cred_free(struct cred *cred)
{
	struct blare_task_sec *tsec = cred->security;

	if (tsec) {
		kfree(tsec->info.tags);
		kfree(tsec);
	}
	cred->security = NULL;
}

static void dummy_cred_transfer(struct cred *new, const struct cred *old)
{
	const struct blare_task_sec *old_tsec = old->security;
	struct blare_task_sec *tsec = new->security;

	*tsec = *old_tsec;
}

static int dummy_inode_alloc_security(struct inode* inode)
{
	struct blare_inode_sec *isec;

	inode->i_security = kmalloc(sizeof(struct blare_inode_sec), GFP_NOFS);
	if (!inode->i_security)
		return -ENOMEM;

	isec = inode->i_security;
	mutex_init(&isec->lock);
	isec->info.count = BLARE_UNINITIALIZED;
	isec->info.tags = NULL;

	return 0;
}

static void dummy_inode_free_security(struct inode* inode)
{
	struct blare_inode_sec *isec = inode->i_security;
	if (isec) {
		kfree(isec->info.tags);
		kfree(isec);
	}
}

static int dummy_inode_setxattr(struct dentry *dentry, const char *name,
				const void *value, size_t size, int flags)
{
	struct inode *inode = d_backing_inode(dentry);

	if (strncmp(name, XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN)
			== 0) {
		if (strcmp(name, XATTR_NAME_CAPS) == 0) {
			if (!capable(CAP_SETFCAP))
				return -EPERM;
		} else if (strcmp(name, DUMMY_XATTR_TAG) == 0) {
			if (!uid_eq(current_fsuid(), inode->i_uid) &&
			    !capable(CAP_MAC_ADMIN)) {
				return -EPERM;
			}
		} else if (!capable(CAP_MAC_ADMIN)) {
			return -EPERM;
		}
	}

	return 0;
}

static int dummy_inode_getsecurity(struct inode *inode, const char *name, void **buffer, bool alloc)
{
	struct blare_inode_sec *isec;
	int size = 0;

	if (strcmp(name, DUMMY_XATTR_TAG_SUFFIX) != 0)
		return -EINVAL;

	if (!inode || !inode->i_security) {
		pr_warn("No security attached to the inode!");
		return -ENODATA;
	}

	isec = inode->i_security;
	size = isec->info.count == BLARE_UNINITIALIZED ?
		0 : isec->info.count * sizeof(__s32);
	if (!alloc || !buffer)
		goto ret;

	if (!size) {
		*buffer = NULL;
		goto ret;
	}

	*buffer = kmemdup(isec->info.tags, size, GFP_NOFS);
	if (!*buffer)
		return -ENOMEM;

ret:
	return size;
}

static void dummy_release_secctx(char *secdata, u32 seclen)
{
	kfree(secdata);
}

static int dummy_inode_setsecurity(struct inode *inode, const char *name,
				   const void *value, size_t size, int flags)
{
	struct blare_inode_sec *isec;

	if (strcmp(name, DUMMY_XATTR_TAG_SUFFIX) != 0)
		return -EOPNOTSUPP;

	if (!value || !size)
		return -EACCES;

	if (!inode || !inode->i_security) {
		pr_warn("No security attached to the inode!");
		return -ENODATA;
	}

	isec = inode->i_security;
	/* i_mutex is already hold */
	return update_inode_tags(isec, value, size);
}

static int add_tags(const struct info_tags* dest, const struct info_tags* src, struct info_tags* new_tags)
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
	} else {
		/* if there were already tags, we have to merge them */
		int new_count = (dest->count == BLARE_UNINITIALIZED) ?
			0 : dest->count;
		int i,j;
		int last_tag;

		for (i = 0 ; i < src->count ; i++) {
			for (j = 0 ;
			     j < dest->count && src->tags[i] != dest->tags[j] ;
			     j++)
			{}
			if (j == dest->count) /* tag is absent */
				new_count++;
		}

		if (new_count == dest->count) /* no new tags */
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
	}

	return 0;
}

static int dummy_may_read(struct blare_inode_sec *isec, struct blare_task_sec *tsec)
{
	return add_tags(&tsec->info, &isec->info, &tsec->info);
}

static int dummy_may_write(struct blare_inode_sec *isec, struct blare_task_sec *tsec,
			   struct dentry *dentry)
{
	struct info_tags tags = { .count = 0, .tags = NULL };
	int rc = add_tags(&isec->info, &tsec->info, &tags);
	if (rc < 0)
		return rc;

	rc = __vfs_setxattr_noperm(dentry, DUMMY_XATTR_TAG, tags.tags, tags.count * sizeof(__s32), 0);
	kfree(tags.tags);
	return rc;
}

static int dummy_file_permission(struct file *file, int mask)
{
	struct inode *inode = file_inode(file);
	struct blare_inode_sec *isec = inode->i_security;
	struct blare_task_sec *tsec = current_security();

	if (!mask) /* an existence check is not a flow */
		return 0;

	if (!tsec || !isec) /* the FS is not fully initialized or the task */
		return 0;   /* is privileged */

	if (mask & MAY_READ) {
		inode_lock(inode);
		mutex_lock(&tsec->lock);
		dummy_may_read(isec, tsec);
		mutex_unlock(&tsec->lock);
		inode_unlock(inode);
	}

	if (mask & MAY_APPEND || mask & MAY_WRITE) {
		struct dentry *dentry;
		inode_lock(inode);
		mutex_lock(&tsec->lock);
		dentry = dget(file_dentry(file));
		dummy_may_write(isec, tsec, dentry);
		dput(dentry);
		mutex_unlock(&tsec->lock);
		inode_unlock(inode);
	}

	return 0;
}

/* must be called with either i_mutex or i_security->lock hold */
static int update_inode_tags(struct blare_inode_sec *isec, const void *value, size_t size)
{
	int i;
	int len = size / sizeof(__s32);

	if (isec->info.count != BLARE_UNINITIALIZED &&
	    isec->info.count != 0) {
		kfree(isec->info.tags);
	}

	isec->info.tags = kmalloc(size, GFP_NOFS);
	if (!isec->info.tags)
		return -ENOMEM;

	for (i=0 ; i<len ; i++)
		isec->info.tags[i] = ((__s32*)value)[i];

	return 0;
}

static void dummy_d_instantiate(struct dentry *opt_dentry, struct inode *inode)
{
	struct blare_inode_sec *isec;
	struct dentry *dentry;
	int rc;
	int len;
	if (!inode)
		return;

	isec = inode->i_security;
	mutex_lock(&isec->lock);
	if (!inode->i_op->getxattr)
		goto unlock;

	dentry = dget(opt_dentry);
	if (!dentry) {
		pr_info("Void dentry: %s : %p (%p)\n", __func__, dentry, opt_dentry);
		goto unlock;
	}

	rc = inode->i_op->getxattr(dentry, inode, DUMMY_XATTR_TAG, NULL, 0);
	if (rc < 0) { /* no xattrs available, Blare cannot do much */
		goto dput;
	} else if (rc == 0) { /* there are xattrs but no tags */
		isec->info.count = 0;
		goto dput;
	}

	isec->info.tags = kmalloc(rc, GFP_NOFS);
	if (!isec->info.tags)
		goto dput;

	len = rc / sizeof(__s32);
	rc = inode->i_op->getxattr(dentry, inode, DUMMY_XATTR_TAG,
				   isec->info.tags, rc);
	if (rc < 0)
		kfree(isec->info.tags);
	else
		isec->info.count = len;

dput:
	dput(dentry);
unlock:
	mutex_unlock(&isec->lock);

}

static void dummy_inode_post_setxattr(struct dentry *dentry, const char *name,
				      const void *value, size_t size,
				      int flags)
{
	struct inode *inode = d_backing_inode(dentry);
	struct blare_inode_sec *isec;
	int len;
	int i;

	if (strcmp(name, DUMMY_XATTR_TAG) != 0)
		return;

	isec = inode->i_security;
	if (!isec)
		pr_err("Blare: missing inode security structure");

	len = size / sizeof(__s32);
	mutex_lock(&isec->lock);
	if (isec->info.count != BLARE_UNINITIALIZED &&
	    isec->info.count != 0) {
		kfree(isec->info.tags);
	}

	isec->info.count = BLARE_UNINITIALIZED;
	isec->info.tags = kmalloc(len, GFP_NOFS);
	if (!isec->info.tags)
		goto unlock;

	for (i=0 ; i<len ; i++)
		isec->info.tags[i] = ((__s32*)value)[i];
	isec->info.count = len;

unlock:
	mutex_unlock(&isec->lock);
}

static struct security_hook_list dummy_hooks[] = {
	LSM_HOOK_INIT(inode_alloc_security,dummy_inode_alloc_security),
	LSM_HOOK_INIT(inode_free_security,dummy_inode_free_security),
	LSM_HOOK_INIT(inode_getsecurity,dummy_inode_getsecurity),
	LSM_HOOK_INIT(inode_setsecurity,dummy_inode_setsecurity),
	LSM_HOOK_INIT(d_instantiate,dummy_d_instantiate),
	LSM_HOOK_INIT(inode_post_setxattr,dummy_inode_post_setxattr),
	LSM_HOOK_INIT(inode_setxattr,dummy_inode_setxattr),
	LSM_HOOK_INIT(release_secctx,dummy_release_secctx),
	LSM_HOOK_INIT(bprm_set_creds,dummy_bprm_set_creds),
	LSM_HOOK_INIT(cred_transfer,dummy_cred_transfer),
	LSM_HOOK_INIT(cred_free,dummy_cred_free),
	LSM_HOOK_INIT(cred_alloc_blank,dummy_cred_alloc_blank),
	LSM_HOOK_INIT(file_permission,dummy_file_permission),
};

static int __init dummy_install(void)
{
	pr_info("Dummy: Information Flow Monitor.\n");
	security_add_hooks(dummy_hooks, ARRAY_SIZE(dummy_hooks));
	return 0;
}

module_init(dummy_install);
