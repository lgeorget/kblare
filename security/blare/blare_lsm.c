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
#include <linux/msg.h>
#include <linux/mman.h>

#include "blare.h"

static int blare_bprm_set_creds(struct linux_binprm *bprm)
{
	struct blare_mm_sec *msec;
	struct inode *inode = file_inode(bprm->file);
	struct blare_inode_sec *isec;

	bprm->cred->security = NULL;

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

	msec = kmalloc(sizeof(struct blare_mm_sec), GFP_KERNEL);
	if (!msec)
		return -ENOMEM;

	copy_tags(&msec->info, &isec->info);
	atomic_set(&msec->users, 1);
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
	initialize_tags(&isec->info);

	return 0;
}

static void blare_inode_free_security(struct inode* inode)
{
	struct blare_inode_sec *isec = inode->i_security;
	kfree(isec);
	inode->i_security = NULL;
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
				initialize_tags(&isec->info);
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
	size = sizeof(__u32) * BLARE_TAGS_NUMBER;
	if (!alloc || !buffer)
		goto ret;

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
	const __u32 *tags_value;
	int i;

	if (strcmp(name, BLARE_XATTR_TAG_SUFFIX) != 0)
		return -EOPNOTSUPP;

	if (!value || !size)
		return -EACCES;

	if (!inode || !inode->i_security) {
		pr_warn("No security attached to the inode!");
		return -ENODATA;
	}

	isec = inode->i_security;
	tags_value = value;

	for (i=0 ; i<BLARE_TAGS_NUMBER ; i++)
		isec->info.tags[i] = tags_value[i];

	return 0;
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
		ret = register_read(file);
	}

	if (!ret && (mask & MAY_APPEND || mask & MAY_WRITE)) {
		/*struct dentry *dentry = file_dentry(file);
		dget(dentry);*/
		path = d_path(&file->f_path, pathbuffer, 256);
		pr_debug("kblare writing %s\n", path);
		ret = register_write(file);
	}

	return ret;
}

static int blare_socket_sendmsg(struct socket *socket, struct msghdr *msg, int size)
{
	struct file *file = socket->file;
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
	return register_write(file);
}

static int blare_socket_recvmsg(struct socket *socket, struct msghdr *msg, int size, int flags)
{
	struct file *file;
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
		file = peer->sk_socket->file;
		unix_state_unlock(peer);
		isec = inode->i_security;
		if (!isec)
			goto put_sock;

		rc = register_read(file);
put_sock:
		sock_put(peer);
	} /* else ? */
	return rc;
}

static void blare_d_instantiate(struct dentry *opt_dentry, struct inode *inode)
{
	struct blare_inode_sec *isec;
	struct dentry *dentry;
	int rc;
	if (!inode || !inode->i_security)
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
	if (rc <= 0) { /* no xattrs available or no tags */
		goto dput;
	}
	WARN_ON(rc != BLARE_TAGS_NUMBER * sizeof(__u32));

	rc = inode->i_op->getxattr(dentry, inode, BLARE_XATTR_TAG,
				   isec->info.tags,
				   BLARE_TAGS_NUMBER * sizeof(__u32));

dput:
	dput(dentry);

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
	if (!isec) {
		pr_err("Blare: missing inode security structure");
		return;
	}

	WARN_ON(size != sizeof(__u32) * BLARE_TAGS_NUMBER);
	memcpy(isec->info.tags, value, size);
}

static int blare_mm_dup_security(struct mm_struct *mm, struct mm_struct *oldmm)
{
	struct blare_mm_sec *old_msec = oldmm->m_sec;
	struct blare_mm_sec *msec;

	mm->m_sec = NULL;
	if (!old_msec)
		return 0;

	msec = dup_msec(old_msec);
	if (IS_ERR(msec))
		return PTR_ERR(msec);

	mm->m_sec = msec;
	return 0;
}

static void blare_mm_sec_free(struct mm_struct *mm)
{
	struct blare_mm_sec *msec = mm->m_sec;

	if (msec) {
		msec_put(msec);
		mm->m_sec = NULL;
	}
}

static int blare_mq_store_msg(struct msg_msg *msg)
{
	int ret;
	struct blare_mm_sec *msec = current->mm->m_sec;
	if (!msec || !msg->security)
		return 0;

	ret = register_msg_reception(msg);
	return ret;
}

static int blare_msg_msg_alloc_security(struct msg_msg *msg)
{
	struct blare_mm_sec *msec = current->mm->m_sec;
	struct blare_msg_sec *msgsec;
	if (!msec)
		return 0;

	msgsec = kmalloc(sizeof(struct blare_msg_sec), GFP_KERNEL);
	if (!msgsec)
		goto nomem;
	copy_tags(&msgsec->info, &msec->info);

	msg->security = msgsec;
	return 0;

nomem:
	return -ENOMEM;
}

static void blare_msg_msg_free_security(struct msg_msg *msg)
{
	struct blare_msg_sec *msgsec = msg->security;
	kfree(msgsec);
}

static int blare_ptrace_access_check(struct task_struct *child,
				     unsigned int unused)
{
	struct blare_mm_sec *tracer_msec = current->mm->m_sec;
	struct blare_mm_sec *child_msec = child->mm->m_sec;

	if (!tracer_msec || !child_msec)
		return 0;

	return register_ptrace_attach(current, child);
}

static int blare_ptrace_traceme(struct task_struct *parent)
{
	struct blare_mm_sec *tracer_msec = parent->mm->m_sec;
	struct blare_mm_sec *child_msec = current->mm->m_sec;

	if (!tracer_msec || !child_msec)
		return 0;

	return register_ptrace_attach(parent, current);
}

static void blare_ptrace_unlink(struct task_struct *child)
{
	if (!child->mm || !child->mm->m_sec)
		return;

	/* don't bother detaching the mm->m_sec if the child won't use it */
	if (child->flags & PF_EXITING)
		return;

	unregister_ptrace(child);
}

/*
 * blare_task_free makes sure that the discrete_flows list does not get too
 * cluttered over time by making sure the entry corresponding to a given task
 * are removed when said task exits. A valid way to have a post-death entry
 * in the discrete_flows list is when a process is killed by a signal in the
 * middle of a system call for instance.
 */
static void blare_task_free(struct task_struct *task)
{
	unregister_dying_task_flow(task);
}

static int blare_mmap_file(struct file *file, unsigned long reqprot,
			   unsigned long prot, unsigned long flags)
{
	int ret;
	struct blare_mm_sec *msec;
	struct blare_inode_sec *isec;

	if (!current->mm || !file)
		return 0;

	msec = current->mm->m_sec;
	isec = file_inode(file)->i_security;

	if (!msec || !isec)
		return 0;

	ret = register_read(file);
	if (!ret && (prot & PROT_WRITE) && (flags & VM_SHARED))
		ret = register_write(file);

	return ret;
}

static int blare_file_mprotect(struct vm_area_struct *vma,
			       unsigned long reqprot, unsigned long prot)
{
	int ret = 0;
	struct file *file = vma->vm_file;
	struct blare_mm_sec *msec;
	struct blare_inode_sec *isec;

	if (!current->mm || !file)
		return 0;

	msec = current->mm->m_sec;
	isec = file_inode(file)->i_security;

	if (!msec || !isec)
		return 0;

	if ((prot & PROT_WRITE) && (vma->vm_flags & VM_SHARED))
		ret = register_write(file);

	return ret;
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
	LSM_HOOK_INIT(mq_store_msg,blare_mq_store_msg),
	LSM_HOOK_INIT(msg_msg_alloc_security,blare_msg_msg_alloc_security),
	LSM_HOOK_INIT(msg_msg_free_security,blare_msg_msg_free_security),
	LSM_HOOK_INIT(ptrace_access_check,blare_ptrace_access_check),
	LSM_HOOK_INIT(ptrace_traceme,blare_ptrace_traceme),
	LSM_HOOK_INIT(ptrace_unlink,blare_ptrace_unlink),
	LSM_HOOK_INIT(task_free,blare_task_free),
	LSM_HOOK_INIT(mmap_file, blare_mmap_file),
	LSM_HOOK_INIT(file_mprotect, blare_file_mprotect),
};

static int __init blare_install(void)
{
	pr_info("Dummy: Information Flow Monitor.\n");
	security_add_hooks(blare_hooks, ARRAY_SIZE(blare_hooks));
	return 0;
}

module_init(blare_install);
