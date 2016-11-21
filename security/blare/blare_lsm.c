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

static int blare_bprm_set_creds(struct linux_binprm *bprm)
{
	struct blare_mm_sec *msec;
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

	msec = kzalloc(sizeof(struct blare_mm_sec), GFP_KERNEL);
	if (!msec)
		return -ENOMEM;
	msec->info.count = 0;

	if (isec->info.count > 0) {
		/* Copy the information tag */
		msec->info.tags = kmemdup(isec->info.tags, isec->info.count * sizeof(__s32), GFP_KERNEL);
		if (!msec->info.tags) {
			kfree(msec);
			return -ENOMEM;
		}
		msec->info.count = isec->info.count;
	} else {
		msec->info.count = 0;
		msec->info.tags = NULL;
	}
	bprm->cred->security = msec;

	return 0;
}

static void blare_bprm_committing_creds(struct linux_binprm *bprm)
{
	/* the new process is not started yet so we cannot race with anybody,
	 * right? */
	current->mm->m_sec = bprm->cred->security;
	bprm->cred->security = NULL;
}

static int blare_inode_alloc_security(struct inode* inode)
{
	struct blare_inode_sec *isec;

	inode->i_security = kmalloc(sizeof(struct blare_inode_sec), GFP_NOFS);
	if (!inode->i_security)
		return -ENOMEM;

	isec = inode->i_security;
	isec->info.count = 0;
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

	/* You cannot change the security extended attributes unless you are
	 * the Security Administrator (capability MAC_ADMIN) or the owner of
	 * the file (for debugging or decentralization purposes) */
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

static int blare_inode_removexattr(struct dentry *dentry, const char *name)
{
	/* There's no post_removexattr hook so we must handle the removal of
	 * attributes here, this is very similar to setxattr but we must
	 * refresh the inode security attributes here */
	struct inode *inode = d_backing_inode(dentry);
	if (strcmp(name, BLARE_XATTR_TAG) == 0) {
		if (!uid_eq(current_fsuid(), inode->i_uid) &&
		    !capable(CAP_MAC_ADMIN)) {
			return -EPERM;
		} else {
			if (inode->i_security) {
				struct blare_inode_sec *isec = inode->i_security;
				kfree(isec->info.tags);
				isec->info.count = 0;
				isec->info.tags = NULL;
			}
			return 0;
		}
	}

	/* general case */
	return cap_inode_removexattr(dentry, name);
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
	size = isec->info.count * sizeof(__s32);
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

static int blare_file_permission(struct file *file, int mask)
{
	struct inode *inode = file_inode(file);
	struct blare_inode_sec *isec = inode->i_security;
	struct blare_mm_sec *msec;
	int ret = 0;
	char pathbuffer[256];
	char * path;

	if (!mask) /* an existence check is not a flow */
		return 0;

	if (!current->mm)
		return 0; /* kernel threads do not propagate flows */

	msec = current->mm->m_sec;
	if (!msec || !isec) /* the FS is not fully initialized or the task */
		return 0;   /* is privileged */

	if (mask & MAY_READ) {
		path = d_path(&file->f_path, pathbuffer, 256);
		pr_debug("kblare reading %s\n", path);
		ret = register_read(inode);
	}

	if (!ret && (mask & MAY_APPEND || mask & MAY_WRITE)) {
		/*struct dentry *dentry = file_dentry(file);
		dget(dentry);*/
		path = d_path(&file->f_path, pathbuffer, 256);
		pr_debug("kblare writing %s\n", path);
		ret = register_write(inode);
	}

	return ret;
}

static int blare_socket_sendmsg(struct socket *socket, struct msghdr *msg, int size)
{
	struct inode *inode = SOCK_INODE(socket);
	struct blare_inode_sec *isec = inode->i_security;
	struct blare_mm_sec *msec;

	if (!current->mm)
		return 0;

	msec = current->mm->m_sec;
	if (!msec || !isec)
		return 0;

	/* Conceptually, the communication channel bears the security label,
	 * in practice, the sending end stores the security attributes */
	return register_write(inode);
}

static int blare_socket_recvmsg(struct socket *socket, struct msghdr *msg, int size, int flags)
{
	struct inode *inode;
	struct blare_inode_sec *isec;
	struct blare_mm_sec *msec;
	struct sock *sk = socket->sk;
	struct sock *peer;
	int rc = 0;

	if (!current->mm)
		return 0;

	msec = current->mm->m_sec;
	if (!msec)
		return 0;

	if (sk->sk_family == PF_UNIX) {
		peer = unix_peer_get(sk);
		if (!peer)
			return 0;

		unix_state_lock(peer);
		if (!peer->sk_socket) {
			unix_state_unlock(peer);
			goto put_sock;
		}
		inode = SOCK_INODE(peer->sk_socket);
		unix_state_unlock(peer);
		isec = inode->i_security;
		if (!isec)
			goto put_sock;

		rc = register_read(inode);
put_sock:
		sock_put(peer);
	} /* else ? */
	return rc;
}

static int update_inode_tags(struct blare_inode_sec *isec, const void *value, size_t size)
{
	int i;
	int len = size / sizeof(__s32);

	if (tags_initialized(&isec->info))
		kfree(isec->info.tags);

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

	/* If this method is called with opt_dentry == root of the filesystem
	 * this may mean that the superblock is being initialized, in which case
	 * it is a bad idea to try to play with its xattrs.
	 * We just don't give tags to the dentry in this case
	 * TODO: defer the initialization and give the tags after the superblock
	 * is ready
	 */
	if (opt_dentry->d_parent == opt_dentry)
		return;

	isec = inode->i_security;
	if (!inode->i_op->getxattr)
		return;

	dentry = dget(opt_dentry);
	if (!dentry) {
		pr_info("Void dentry: %s : %p (%p)\n", __func__, dentry, opt_dentry);
		return;
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

}

static void __blare_regen_inode_sec(struct blare_inode_sec *isec,
				      const void *value, size_t size)
{
	int len = size / sizeof(__s32);
	if (tags_initialized(&isec->info))
		kfree(isec->info.tags);

	isec->info.count = 0;
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

	__blare_regen_inode_sec(isec, value, size);
}

static int blare_mm_dup_security(struct mm_struct *mm, struct mm_struct *oldmm)
{
	struct blare_mm_sec *old_msec = oldmm->m_sec;
	struct blare_mm_sec *msec;

	if (!old_msec) {
		mm->m_sec = NULL;
		return 0;
	}

	msec = kmemdup(old_msec, sizeof(struct blare_mm_sec), GFP_KERNEL);
	if (!msec)
		goto nomem;
	if (old_msec->info.tags) {
		msec->info.tags = kmemdup(old_msec->info.tags,
					  sizeof(struct blare_mm_sec), GFP_KERNEL);
		if (!msec->info.tags) {
			kfree(msec);
			goto nomem;
		}
	}
	mm->m_sec = msec;
	return 0;

nomem:
	mm->m_sec = NULL;
	return -ENOMEM;
}

static void blare_mm_sec_free(struct mm_struct *mm)
{
	struct blare_mm_sec *msec = mm->m_sec;

	if (msec) {
		kfree(msec->info.tags);
		kfree(msec);
		mm->m_sec = NULL;
	}
}

static struct security_hook_list blare_hooks[] = {
	LSM_HOOK_INIT(inode_alloc_security,blare_inode_alloc_security),
	LSM_HOOK_INIT(inode_free_security,blare_inode_free_security),
	LSM_HOOK_INIT(inode_getsecurity,blare_inode_getsecurity),
	LSM_HOOK_INIT(inode_setsecurity,blare_inode_setsecurity),
	LSM_HOOK_INIT(d_instantiate,blare_d_instantiate),
	LSM_HOOK_INIT(inode_post_setxattr,blare_inode_post_setxattr),
	LSM_HOOK_INIT(inode_setxattr,blare_inode_setxattr),
	LSM_HOOK_INIT(inode_removexattr,blare_inode_removexattr),
	LSM_HOOK_INIT(release_secctx,blare_release_secctx),
	LSM_HOOK_INIT(bprm_set_creds,blare_bprm_set_creds),
	LSM_HOOK_INIT(bprm_committing_creds,blare_bprm_committing_creds),
	LSM_HOOK_INIT(file_permission,blare_file_permission),
	LSM_HOOK_INIT(socket_sendmsg,blare_socket_sendmsg),
	LSM_HOOK_INIT(socket_recvmsg,blare_socket_recvmsg),
	LSM_HOOK_INIT(syscall_before_return,unregister_current_flow),
	LSM_HOOK_INIT(mm_dup_security,blare_mm_dup_security),
	LSM_HOOK_INIT(mm_sec_free,blare_mm_sec_free),
};

static int __init blare_install(void)
{
	pr_info("Dummy: Information Flow Monitor.\n");
	security_add_hooks(blare_hooks, ARRAY_SIZE(blare_hooks));
	return 0;
}

module_init(blare_install);
