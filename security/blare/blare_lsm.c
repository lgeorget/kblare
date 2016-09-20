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

#include "blare.h"

static int update_inode_tags(struct blare_inode_sec *isec, const void *value, size_t size);
static int blare_may_read(struct blare_inode_sec *isec, struct blare_task_sec *tsec);
static int blare_may_write(struct blare_inode_sec *isec, struct blare_task_sec *tsec,
			   struct dentry *dentry);

static int blare_bprm_set_creds(struct linux_binprm *bprm)
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

static int blare_cred_alloc_blank(struct cred *cred, gfp_t gfp)
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

static void blare_cred_free(struct cred *cred)
{
	struct blare_task_sec *tsec = cred->security;

	if (tsec) {
		kfree(tsec->info.tags);
		kfree(tsec);
	}
	cred->security = NULL;
}

static int blare_cred_prepare(struct cred *new, const struct cred *old,
			      gfp_t gfp)
{
	const struct blare_task_sec *old_tsec;
	struct blare_task_sec *tsec;

	old_tsec = old->security;

	if (!old_tsec)
		return 0;

	tsec = kmemdup(old_tsec, sizeof(struct blare_task_sec), gfp);
	if (!tsec)
		return -ENOMEM;
	if (old_tsec->info.tags) {
		tsec->info.tags = kmemdup(old_tsec->info.tags,
					  sizeof(struct blare_task_sec), gfp);
		if (!tsec->info.tags) {
			kfree(tsec);
			return -ENOMEM;
		}
	}

	new->security = tsec;
	return 0;
}

static void blare_cred_transfer(struct cred *new, const struct cred *old)
{
	const struct blare_task_sec *old_tsec = old->security;
	struct blare_task_sec *tsec = new->security;

	*tsec = *old_tsec;
}

static int blare_inode_alloc_security(struct inode* inode)
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

static void blare_inode_free_security(struct inode* inode)
{
	struct blare_inode_sec *isec = inode->i_security;
	if (isec) {
		kfree(isec->info.tags);
		kfree(isec);
	}
}

static int blare_inode_setxattr(struct dentry *dentry, const char *name,
				const void *value, size_t size, int flags)
{
	struct inode *inode = d_backing_inode(dentry);

	if (strcmp(name, BLARE_XATTR_TAG) == 0) {
		if (!uid_eq(current_fsuid(), inode->i_uid) &&
		    !capable(CAP_MAC_ADMIN))
			return -EPERM;
		else
			return 0;
	}

	/* general case */
	return cap_inode_setxattr(dentry, name, value, size, flags);
}

static int blare_inode_getsecurity(struct inode *inode, const char *name, void **buffer, bool alloc)
{
	struct blare_inode_sec *isec;
	int size = 0;

	if (strcmp(name, BLARE_XATTR_TAG_SUFFIX) != 0)
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

static void blare_release_secctx(char *secdata, u32 seclen)
{
	kfree(secdata);
}

static int blare_inode_setsecurity(struct inode *inode, const char *name,
				   const void *value, size_t size, int flags)
{
	struct blare_inode_sec *isec;

	if (strcmp(name, BLARE_XATTR_TAG_SUFFIX) != 0)
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

static int blare_may_read(struct blare_inode_sec *isec, struct blare_task_sec *tsec)
{
	return register_flow(&tsec->info, &isec->info, NULL);
}

static int blare_may_write(struct blare_inode_sec *isec, struct blare_task_sec *tsec,
			   struct dentry *dentry)
{
	return register_flow(&isec->info, &tsec->info, dentry);
}

static int blare_file_permission(struct file *file, int mask)
{
	struct inode *inode = file_inode(file);
	struct blare_inode_sec *isec = inode->i_security;
	struct blare_task_sec *tsec = current_security();

	if (!mask) /* an existence check is not a flow */
		return 0;

	if (!tsec || !isec) /* the FS is not fully initialized or the task */
		return 0;   /* is privileged */

	if (mask & MAY_READ) {
		blare_may_read(isec, tsec);
	}

	if (mask & MAY_APPEND || mask & MAY_WRITE) {
		struct dentry *dentry = file_dentry(file);
		dget(dentry);
		blare_may_write(isec, tsec, dentry);
	}

	return 0;
}

static int blare_socket_sendmsg(struct socket *socket, struct msghdr *msg, int size)
{
	struct inode *inode = SOCK_INODE(socket);
	struct blare_inode_sec *isec = inode->i_security;
	struct blare_task_sec *tsec = current_security();
	int rc;

	if (!tsec || !isec)
		return 0;

	/* Conceptually, the communication channel bears the security label,
	 * in practice, the sending end stores the security attributes */
	mutex_lock(&isec->lock);
	mutex_lock(&tsec->lock);
	rc = add_tags(&isec->info, &tsec->info, &isec->info);
	mutex_unlock(&tsec->lock);
	mutex_unlock(&isec->lock);
	return rc;
}

static int blare_socket_recvmsg(struct socket *socket, struct msghdr *msg, int size, int flags)
{
	struct blare_inode_sec *isec;
	struct blare_task_sec *tsec = current_security();
	struct sock *sk = socket->sk;
	struct sock *peer;
	int rc = 0;

	if (!tsec)
		return 0;

	if (sk->sk_family == PF_UNIX) {
		peer = unix_peer_get(sk);
		if (!peer)
			return 0;

		isec = SOCK_INODE(peer->sk_socket)->i_security;
		if (!isec)
			return 0;

		mutex_lock(&isec->lock);
		mutex_lock(&tsec->lock);
		rc = add_tags(&tsec->info, &isec->info, &tsec->info);
		mutex_unlock(&tsec->lock);
		mutex_unlock(&isec->lock);
		sock_put(peer);
	} /* else ? */
	return rc;
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

static void blare_d_instantiate(struct dentry *opt_dentry, struct inode *inode)
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

	rc = inode->i_op->getxattr(dentry, inode, BLARE_XATTR_TAG, NULL, 0);
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
	rc = inode->i_op->getxattr(dentry, inode, BLARE_XATTR_TAG,
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

static void __blare_regen_inode_sec(struct blare_inode_sec *isec,
				      const void *value, size_t size)
{
	int len = size / sizeof(__s32);
	if (isec->info.count != BLARE_UNINITIALIZED &&
	    isec->info.count != 0) {
		kfree(isec->info.tags);
	}

	isec->info.count = BLARE_UNINITIALIZED;
	isec->info.tags = kmalloc(size, GFP_NOFS);
	if (!isec->info.tags)
		return;

	memcpy(isec->info.tags, value, size);
	isec->info.count = len;
}

static void blare_inode_post_setxattr(struct dentry *dentry, const char *name,
				      const void *value, size_t size,
				      int flags)
{
	struct inode *inode = d_backing_inode(dentry);
	struct blare_inode_sec *isec;

	if (strcmp(name, BLARE_XATTR_TAG) != 0)
		return;

	isec = inode->i_security;
	if (!isec)
		pr_err("Blare: missing inode security structure");

	mutex_lock(&isec->lock);
	__blare_regen_inode_sec(isec, value, size);
	mutex_unlock(&isec->lock);
}

static struct security_hook_list blare_hooks[] = {
	LSM_HOOK_INIT(inode_alloc_security,blare_inode_alloc_security),
	LSM_HOOK_INIT(inode_free_security,blare_inode_free_security),
	LSM_HOOK_INIT(inode_getsecurity,blare_inode_getsecurity),
	LSM_HOOK_INIT(inode_setsecurity,blare_inode_setsecurity),
	LSM_HOOK_INIT(d_instantiate,blare_d_instantiate),
	LSM_HOOK_INIT(inode_post_setxattr,blare_inode_post_setxattr),
	LSM_HOOK_INIT(inode_setxattr,blare_inode_setxattr),
	LSM_HOOK_INIT(release_secctx,blare_release_secctx),
	LSM_HOOK_INIT(bprm_set_creds,blare_bprm_set_creds),
	LSM_HOOK_INIT(cred_prepare,blare_cred_prepare),
	LSM_HOOK_INIT(cred_transfer,blare_cred_transfer),
	LSM_HOOK_INIT(cred_free,blare_cred_free),
	LSM_HOOK_INIT(cred_alloc_blank,blare_cred_alloc_blank),
	LSM_HOOK_INIT(file_permission,blare_file_permission),
	LSM_HOOK_INIT(socket_sendmsg,blare_socket_sendmsg),
	LSM_HOOK_INIT(socket_recvmsg,blare_socket_recvmsg),
	LSM_HOOK_INIT(syscall_before_return,unregister_current_flow),
};

static int __init blare_install(void)
{
	pr_info("Dummy: Information Flow Monitor.\n");
	security_add_hooks(blare_hooks, ARRAY_SIZE(blare_hooks));
	return 0;
}

module_init(blare_install);
