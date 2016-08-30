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
};

static int dummy_bprm_set_creds(struct linux_binprm *bprm)
{
	struct blare_task_sec *tstruct;
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

	tstruct = kzalloc(sizeof(struct blare_task_sec), GFP_KERNEL);
	if (!tstruct)
		return -ENOMEM;
	tstruct->info.count = BLARE_UNINITIALIZED;

	if (isec->info.count > 0) {
		/* Copy the information tag */
		tstruct->info.tags = kmemdup(isec->info.tags, isec->info.count * sizeof(__s32), GFP_KERNEL);
		if (!tstruct->info.tags) {
			kfree(tstruct);
			return -ENOMEM;
		}
		tstruct->info.count = isec->info.count;
	} else {
		tstruct->info.count = 0;
		tstruct->info.tags = NULL;
	}
	bprm->cred->security = tstruct;

	return 0;
}

static int dummy_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	/* Allocate a security structure for the process's tags */
	struct blare_task_sec *tstruct = kzalloc(sizeof(struct blare_task_sec), gfp);
	if (!tstruct)
		return -ENOMEM;

	tstruct->info.count = BLARE_UNINITIALIZED;
	cred->security = tstruct;
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
	size = isec->info.count * sizeof(__s32);
	if (!alloc || !buffer)
		return size;

	*buffer = kmemdup(isec->info.tags, size, GFP_NOFS);
	if (!*buffer)
		return -ENOMEM;

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
	int len;
	int rc;
	int i;

	if (strcmp(name, DUMMY_XATTR_TAG_SUFFIX) != 0)
		return -EOPNOTSUPP;

	if (!value || !size)
		return -EACCES;

	if (!inode || !inode->i_security) {
		pr_warn("No security attached to the inode!");
		return -ENODATA;
	}

	isec = inode->i_security;
	len = size / sizeof(__s32);

	mutex_lock(&isec->lock);
	if (isec->info.count != BLARE_UNINITIALIZED &&
	    isec->info.count != 0) {
		kfree(isec->info.tags);
	}

	rc = -ENOMEM;
	isec = inode->i_security;
	isec->info.tags = kmalloc(size, GFP_NOFS);
	if (!isec->info.tags)
		goto out;

	for (i=0 ; i<len ; i++)
		isec->info.tags[i] = ((__s32*)value)[i];
	rc = 0;
out:
	mutex_unlock(&isec->lock);
	return rc;
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
	if (isec->info.count != BLARE_UNINITIALIZED &&
	    isec->info.count != 0) {
		kfree(isec->info.tags);
	}

	isec->info.count = BLARE_UNINITIALIZED;
	isec->info.tags = kmalloc(len, GFP_NOFS);
	if (!isec->info.tags)
		return;

	for (i=0 ; i<len ; i++)
		isec->info.tags[i] = ((__s32*)value)[i];
	isec->info.count = len;
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
};

static int __init dummy_install(void)
{
	pr_info("Dummy: Information Flow Monitor.\n");
	security_add_hooks(dummy_hooks, ARRAY_SIZE(dummy_hooks));
	return 0;
}

module_init(dummy_install);
