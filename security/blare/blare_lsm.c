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

/**
 * blare_bprm_set_cred() - Prepare the new credentials of a process.
 * @bprm:	The program that will be executed.
 *
 * This LSM hook prepares the Blare part of the credentials of a process doing
 * an execve syscall (or changing its credentials for some reason).
 * It copies the information tags of the program file to the process.
 *
 * For testing/debugging purposes, processes with the CAP_MAC_ADMIN capability
 * (processes belonging to root) currently do not receive a Blare security
 * structure.
 *
 * Return: 0 if everything went well, -ENOMEM if no memory could be allocated
 * for the process's tags.
 */
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

/**
 * blare_cprm_committing_creds() - Installs the new credentials of a process.
 * @bprm:	The program to execute, containing the prepared credentials.
 *
 * In Blare, contrarily to most LSMs, the Blare part of credentials is not
 * stored in the task_struct but in mm_struct to cope with the processes
 * sharing the same memory space but not the same set of credentials.
 */
static void blare_bprm_committing_creds(struct linux_binprm *bprm)
{
	/* TODO: can we race with anybody here? */
	current->mm->m_sec = bprm->cred->security;
	bprm->cred->security = NULL;
}

/**
 * blare_inode_alloc_security() - Initializes an inode's tags.
 * @inode:	The inode wanting a security structure.
 *
 * Returns: 	0 if everything went well, -ENOMEM if not memory lacks to
 * 		allocates the security structure.
 */
static int blare_inode_alloc_security(struct inode *inode)
{
	struct blare_inode_sec *isec;

	inode->i_security = kmalloc(sizeof(struct blare_inode_sec), GFP_NOFS);
	if (!inode->i_security)
		return -ENOMEM;

	isec = inode->i_security;
	initialize_tags(&isec->info);

	return 0;
}

/**
 * blare_inode_free_security() - Frees an inode's tags.
 * @inode:	The inode that is getting freed.
 */
static void blare_inode_free_security(struct inode *inode)
{
	struct blare_inode_sec *isec = inode->i_security;
	kfree(isec);
	inode->i_security = NULL;
}

/**
 * blare_inode_setxattr() - Authorizes setting an extended attribute in a file.
 * @dentry:	The dentry affected by the change.
 * @name:	The name of the extended attribute to modify.
 * @value:	The new value of the attribute.
 * @size:	The size of value.
 * @flags:	More options.
 *
 * This function only handles Blare extended attributes and defaults to the
 * normal capability check if a non-Blare attribute is passed as an argument.
 * The only supported attribute is security.blare.tag, which corresponds to the
 * information tags. Only the owner of the file or the policy administrator
 * (i.e. a process with CAP_MAC_ADMIN capability) may change the Blare extended
 * attributes of a file.
 *
 * Returns:	0 if the operation is allowed, -EPERM if the operation has been
 * denied, -EINVAL if value and size do not correspond to a valid value for
 * information tags.
 */
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
		else {
			if (size % sizeof(__u32))
				return -EINVAL;
			if (size > BLARE_TAGS_NUMBER * sizeof(__u32)) {
				pr_err(
				     "Blare: The tags are too large for this "
				     "system.\n"
				     "Consider compiling your kernel with "
				     "CONFIG_SECURITY_BLARE_TAGS_SIZE = %lu "
				     "or more.",
				     size / sizeof(__u32));
				return -EINVAL;
			}

			return 0;
		}
	}

	/* general case */
	return cap_inode_setxattr(dentry, name, value, size, flags);
}

/**
 * blare_inode_removexattr() - Authorizes removing an extended attribute in a
 * file.
 * @dentry:	The dentry affected by the change.
 * @name:	The name of the extended attribute to modify.
 *
 * This function only handles Blare extended attributes and defaults to the
 * normal capability check if a non-Blare attribute is passed as an argument.
 * The only supported attribute is security.blare.tag, which corresponds to the
 * information tags. Only the owner of the file or the policy administrator
 * (i.e. a process with CAP_MAC_ADMIN capability) may remove the Blare extended
 * attributes of a file. The attribute is not actually removed but emptied.
 *
 * Returns:	0 if the operation went well, -EPERM if the operation has been
 * denied.
 */
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
				struct blare_inode_sec *isec =
				    inode->i_security;
				initialize_tags(&isec->info);
			}
			return 0;
		}
	}

	/* general case */
	return cap_inode_removexattr(dentry, name);
}

/**
 * blare_inode_getsecurity() - Get the value of a security extended attribute
 * from a file.
 * @inode:	The file of interest.
 * @name:	The name of the extended attribute to retrieve.
 * @buffer:	Where to store the value of the extended attribute.
 * @alloc:	Whether an allocation has been requested or only the size of
 * 		the value.
 *
 * Returns:	The size in bytes of the value if everything went well,
 *		-EINVAL if the attribute's name is not 'blare.tag' the only
 *		supported extended attribute, -ENODATA if the inode has no tags
 *		(this may happen if the file has been created while Blare was
 *		disabled) and -ENOMEM if there is not enough memory to perform
 *		the requested allocation.
 */
static int blare_inode_getsecurity(struct inode *inode, const char *name,
				   void **buffer, bool alloc)
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

/**
 * blare_release_secctx() - Frees security data.
 * @secdata:	A pointer to the data to free.
 * @seclen:	The size to free, unused.
 */
static void blare_release_secctx(char *secdata, u32 seclen)
{
	kfree(secdata);
}

/**
 * blare_inode_setsecurity() - Sets a Blare extended attribute of a file.
 * @inode:	The file of interest.
 * @name:	The name of the extended attribute.
 * @value:	The new value of the extended attribute.
 * @size:	The sze of value, in bytes.
 * @flags:	More options, unused.
 *
 * Returns: 0 if the modification took place without problem, -EOPNOTSUPP if
 * the extended attribute is not 'blare.tag', the only Blare-supported
 * attribute, -ENODATA if the file has no tags (see blare_inode_getsecurity()),
 * -EACCES if the value or the size is NULL/0, -EINVAL if the value or the size
 *  do not correspond to a valid set of itags.
 */
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

	if (size % sizeof(__u32))
		return -EINVAL;
	if (size > BLARE_TAGS_NUMBER * sizeof(__u32)) {
		pr_err("Blare: The tags are too large for this system.\n"
		       "Consider compiling your kernel with "
		       "CONFIG_SECURITY_BLARE_TAGS_SIZE = %lu or more.",
		       size / sizeof(__u32));
		return -EINVAL;
	}

	isec = inode->i_security;
	tags_value = value;

	for (i = 0; i < BLARE_TAGS_NUMBER; i++)
		isec->info.tags[i] = tags_value[i];

	return 0;
}

/**
 * blare_inode_post_setxattr() - Update the inode security structure after
 * having set the security extended attributes.
 * @dentry:	The file of interest.
 * @name:	The name of the extended attribute.
 * @value:	The new value of the attribute.
 * @size:	The size in bytes of value.
 * @flags:	More options, unused.
 */
static void blare_inode_post_setxattr(struct dentry *dentry, const char *name,
				      const void *value, size_t size, int flags)
{
	struct inode *inode = d_backing_inode(dentry);
	struct blare_inode_sec *isec;
	int i, j;

	if (strcmp(name, BLARE_XATTR_TAG) != 0)
		return;

	isec = inode->i_security;
	if (!isec) {
		pr_err("Blare: missing inode security structure");
		return;
	}
	/* Pad with 0 if the tags are smaller than expected, truncate
	 * if they are bigger */
	if (size >= BLARE_TAGS_NUMBER * sizeof(__u32)) {
		memcpy(isec->info.tags, value,
		       BLARE_TAGS_NUMBER * sizeof(__u32));
	} else {
		memcpy(isec->info.tags, value, size);
		for (i = size / sizeof(__u32), j = size; j < BLARE_TAGS_NUMBER;
		     i++, j += sizeof(__u32))
			isec->info.tags[i] = 0;
	}
}

/**
 * blare_file_permission() - Propagates tags between a file and the calling
 * process.
 * @file:	The file accessed.
 * @mask:	The accessed required.
 *
 * Returns:	0 if the access was granted and the tags propagation was done,
 *		-ENOMEM if there was not enough memory to perform the tags
 *		propagation.
 */
static int blare_file_permission(struct file *file, int mask)
{
	struct inode *inode = file_inode(file);
	struct blare_inode_sec *isec = inode->i_security;
	struct blare_mm_sec *msec;
	int ret = 0;
	char pathbuffer[256];
	char *path;

	if (!mask)		/* an existence check is not a flow */
		return 0;

	if (!current->mm)
		return 0;	/* kernel threads do not propagate flows */

	msec = current->mm->m_sec;
	if (!msec || !isec)	/* the FS is not fully initialized or the task */
		return 0;	/* is privileged */

	if (mask & MAY_READ) {
		path = d_path(&file->f_path, pathbuffer, 256);
		pr_debug("kblare reading %s\n", path);
		ret = register_read(file);
	}

	if (!ret && (mask & MAY_APPEND || mask & MAY_WRITE)) {
		/*struct dentry *dentry = file_dentry(file);
		   dget(dentry); */
		path = d_path(&file->f_path, pathbuffer, 256);
		pr_debug("kblare writing %s\n", path);
		ret = register_write(file);
	}

	return ret;
}

/**
 * blare_socket_sendmsg() - Propagate tags from the current process to a socket.
 * @socket:	The socket of interest.
 * @msg:	The message being sent, unused.
 * @size:	The size of the message being sent, unused.
 *
 * Returns:	0 if the tags propagation went well, -ENOMEM if memory was
 * insufficient.
 */
static int blare_socket_sendmsg(struct socket *socket, struct msghdr *msg,
				int size)
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

/**
 * blare_socket_sendmsg() - Propagate tags from a socket to the current process.
 * @socket:	The socket of interest.
 * @msg:	The message being sent, unused.
 * @size:	The size of the message being sent, unused.
 *
 * Returns:	0 if the tags propagation went well, -ENOMEM if memory was
 * insufficient.
 */
static int blare_socket_recvmsg(struct socket *socket, struct msghdr *msg,
				int size, int flags)
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
	}			/* else ? */
	return rc;
}

/**
 * blare_d_instantiate() - Populate an inode security structure with tags
 * stored in extended attributes.
 * @opt_dentry:	The dentry being instantiated.
 * @inode:	The inode backing the dentry.
 */
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
		pr_info("Void dentry: %s : %p (%p)\n", __func__, dentry,
			opt_dentry);
		return;
	}

	rc = inode->i_op->getxattr(dentry, inode, BLARE_XATTR_TAG, NULL, 0);
	if (rc <= 0)		/* no xattrs available or no tags */
		goto dput;

	if (rc % sizeof(__u32)) {
		pr_err("Blare: tags of file %pd2 have been corrupted on disk",
		       dentry);
		goto dput;
	}

	if (rc <= BLARE_TAGS_NUMBER * sizeof(__u32)) {
		int i, j;
		rc = inode->i_op->getxattr(dentry, inode, BLARE_XATTR_TAG,
					   isec->info.tags, rc);

		/* we have to adjust the tag size if rc < BLARE_TAGS_NUMBER
		 * (happens if the tag size is bigger now than when the file
		 * last got a new tag)
		 * we could also refresh the xattrs on disk while we are at it
		 * but is it really necessary? */
		for (i = rc / sizeof(__u32), j = rc; j < BLARE_TAGS_NUMBER;
		     i++, j += sizeof(__u32))
			isec->info.tags[i] = 0;
	} else {
		pr_err("Blare: file %pd2 comes from a system where tags are "
		       "longer.\nConsider compiling your kernel with "
		       "CONFIG_SECURITY_BLARE_TAGS_SIZE = %lu or more.",
		       dentry, rc / sizeof(__u32));
		rc = inode->i_op->getxattr(dentry, inode, BLARE_XATTR_TAG,
					   isec->info.tags,
					   BLARE_TAGS_NUMBER * sizeof(__u32));
	}

dput:
	dput(dentry);

}

/**
 * blare_mm_dup_security() - Duplicates a memory space security structure.
 * @mm:		The new memory space structure.
 * @oldmm:	The memory space structure whose security structure has to be
 *		duplicated.
 */
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

/**
 * blare_mm_sec_free() - Frees the security structure of a memory space being
 * destroyed.
 * @mm:	The memory space.
 */
static void blare_mm_sec_free(struct mm_struct *mm)
{
	struct blare_mm_sec *msec = mm->m_sec;

	if (msec) {
		msec_put(msec);
		mm->m_sec = NULL;
	}
}

/**
 * blare_mq_store_msg() - Propagates tags from a message received from a message
 * queue to the current process.
 * @msg:	The received message.
 *
 * Returns: 	0 if everything went well and the tags were propagated, -ENOMEM
 * 		if memory was insufficient.
 */
static int blare_mq_store_msg(struct msg_msg *msg)
{
	int ret;
	struct blare_mm_sec *msec = current->mm->m_sec;
	if (!msec || !msg->security)
		return 0;

	ret = register_msg_reception(msg);
	return ret;
}

/**
 * blare_msg_msg_alloc() - Allocates tags for a message.
 * @msg:	The message.
 *
 * The itags are initialized with the itags of the current process.
 * Returns: 	0 if the allocation went well, or if there was no allocation
 * 		needed because the current process is privileged, -ENOMEM if
 * 		memory was insufficient.
 */
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

/**
 * blare-msg_msg_free_security() - Frees the security structure attached to a
 * message.
 * @msg:	The message that is getting destroyed.
 */
static void blare_msg_msg_free_security(struct msg_msg *msg)
{
	struct blare_msg_sec *msgsec = msg->security;
	kfree(msgsec);
}

/**
 * blare_ptrace_access_check() - Shares the memory space itags of the current
 * process and a new ptracee process.
 * @child:	The process being ptraced.
 * @unused:	Some flags, unused.
 *
 * Returns:	0 if everything went well and the itags of the two processes are
 * 		now shared, -ENOMEM if memory was insufficient.
 */
static int blare_ptrace_access_check(struct task_struct *child,
				     unsigned int unused)
{
	struct blare_mm_sec *tracer_msec = current->mm->m_sec;
	struct blare_mm_sec *child_msec = child->mm->m_sec;

	if (!tracer_msec || !child_msec)
		return 0;

	return register_ptrace_attach(current, child);
}

/**
 * blare_ptrace_access_check() - Shares the memory space itags of the current
 * process and its ptracer.
 * @parent:	The process that will ptrace the current process.
 *
 * Returns:	0 if everything went well and the itags of the two processes are
 * 		now shared, -ENOMEM if memory was insufficient.
 */
static int blare_ptrace_traceme(struct task_struct *parent)
{
	struct blare_mm_sec *tracer_msec = parent->mm->m_sec;
	struct blare_mm_sec *child_msec = current->mm->m_sec;

	if (!tracer_msec || !child_msec)
		return 0;

	return register_ptrace_attach(parent, current);
}

/**
 * blare_ptrace_unlink() - Unshares the memory space itags of the current
 * process and its former ptracee child.
 * @child:	The process that the current process no longer wants to ptrace.
 */
static void blare_ptrace_unlink(struct task_struct *child)
{
	if (!child->mm || !child->mm->m_sec)
		return;

	/* don't bother detaching the mm->m_sec if the child won't use it */
	if (child->flags & PF_EXITING)
		return;

	unregister_ptrace(child);
}

/**
 * blare_task_free() - Deals with a dying process's state.
 * @task:	The dying process.
 *
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

/**
 * blare_mmap_file() - Propagates tags between the current process and a file
 * being mmaped.
 * @file:	The file being mmaped.
 * @reqprot:	The protection requested on the memory range supporting the
 * 		mapping, unused.
 * @prot:	The actual protection that will be enforced on the memory range
 * 		that will support the mapping.
 * @flags:	Mmaping options.
 *
 * Returns: 	0 if everything went well, either the tag propagation took place
 * 		or it was not necessary; -ENOMEM if memory was insufficient.
 */
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

	ret = register_flow_file_to_mm(file, current->mm);
	if (!ret && (prot & PROT_WRITE) && (flags & MAP_SHARED))
		ret = register_flow_mm_to_file(current->mm, file);

	return ret;
}

/**
 * blare_file_mprotect() - Adjusts the tag propagation from a mmaped file
 * changing memory protection.
 * @vma:	The memory area supporting the mapping.
 * @reqprot:	The new protection requested, unused.
 * @prot:	The actual new protection that will be enforced.
 *
 * It is necessary to redo the tag propagation if a mapping previously read-only
 * becomes suddenly read-write.
 * Returns: 0 if everything went well and the propagation took place or was
 * not necessary, -ENOMEM if memory was insufficient.
 */
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
		ret = register_flow_mm_to_file(current->mm, file);

	return ret;
}

/**
 * blare_getprocattr() - Fetches the tags of a process.
 * @p:		The target process.
 * @name:	The name of the attribute, only "current" is supported for now,
 * 		and corresponds to the itags.
 * @value:	Where to store the fetched attribute of p.
 *
 * Returns: 	The size in bytes of the value, -EINVAL if the process is not a
 * 		user process (don't know how that could happen, though) or if
 * 		the attribute name is not "current",
 * 		-ENODATA if the process is privileged and has no tags.
 */
static int blare_getprocattr(struct task_struct *p, char *name, char **value)
{
	struct blare_mm_sec *msec;

	if (!p->mm)
		return -EINVAL;

	msec = p->mm->m_sec;
	if (!msec)
		return -ENODATA;

	if (strcmp(name, "current") != 0)
		return -EINVAL;

	return blare_tags_to_string(msec->info.tags, value);
}

/**
 * blare_setprocattr() - Sets the tags of a process.
 * @p:		The target process.
 * @name:	The attribute name, only "current" (which corresponds to the
 * 		itags) is supported.
 * @value:	The new value of the attribute.
 * @size:	The size in bytes of the new value.
 *
 * The new itags do not replace the old ones but are added to them.
 * To change the tags of p, the current process must either be p itself or
 * a privileged process (CAP_MAC_ADMIN). The latter option can be useful for
 * testing/debugging but may not be entirely safe.
 * Returns: 	The value of size if everything went well, -EPERM if the current
 * 		process is neither p not a privileged (CAP_MAC_ADMIN) process,
 * 		-EINVAL if p is not a user process or if the value does not
 * 		correspond to a valid itags structure, -ENODATA if the process
 * 		has no itags.
 */
static int blare_setprocattr(struct task_struct *p, char *name,
			     void *value, size_t size)
{
	struct info_tags new_tags;
	struct blare_mm_sec *msec;
	const struct cred *tcred;
	int ret, nbytes;

	if (strcmp(name, "current") != 0)
		return -EINVAL;

	/* a task may change the tags of another if it is CAP_MAC_ADMIN */
	rcu_read_lock();
	tcred = __task_cred(p);
	if (p != current &&
	    !has_ns_capability(current, tcred->user_ns, CAP_MAC_ADMIN)) {
		rcu_read_unlock();
		return -EPERM;
	}
	rcu_read_unlock();

	if (!p->mm)
		return -EINVAL;

	msec = p->mm->m_sec;
	if (!msec)
		return -ENODATA;

	if ((nbytes =
	     blare_tags_from_string((char *)value, size, new_tags.tags)) < size)
		return -EINVAL;

	/* it is impossible to remove tags, you can only add some */
	ret = register_new_tags_for_mm(&new_tags, p->mm);
	if (ret)
		return ret;

	return nbytes;
}

static struct security_hook_list blare_hooks[] = {
	LSM_HOOK_INIT(inode_alloc_security, blare_inode_alloc_security),
	LSM_HOOK_INIT(inode_free_security, blare_inode_free_security),
	LSM_HOOK_INIT(inode_getsecurity, blare_inode_getsecurity),
	LSM_HOOK_INIT(inode_setsecurity, blare_inode_setsecurity),
	LSM_HOOK_INIT(d_instantiate, blare_d_instantiate),
	LSM_HOOK_INIT(inode_post_setxattr, blare_inode_post_setxattr),
	LSM_HOOK_INIT(inode_setxattr, blare_inode_setxattr),
	LSM_HOOK_INIT(inode_removexattr, blare_inode_removexattr),
	LSM_HOOK_INIT(release_secctx, blare_release_secctx),
	LSM_HOOK_INIT(bprm_set_creds, blare_bprm_set_creds),
	LSM_HOOK_INIT(bprm_committing_creds, blare_bprm_committing_creds),
	LSM_HOOK_INIT(file_permission, blare_file_permission),
	LSM_HOOK_INIT(socket_sendmsg, blare_socket_sendmsg),
	LSM_HOOK_INIT(socket_recvmsg, blare_socket_recvmsg),
	LSM_HOOK_INIT(syscall_before_return, unregister_current_flow),
	LSM_HOOK_INIT(mm_dup_security, blare_mm_dup_security),
	LSM_HOOK_INIT(mm_sec_free, blare_mm_sec_free),
	LSM_HOOK_INIT(mq_store_msg, blare_mq_store_msg),
	LSM_HOOK_INIT(msg_msg_alloc_security, blare_msg_msg_alloc_security),
	LSM_HOOK_INIT(msg_msg_free_security, blare_msg_msg_free_security),
	LSM_HOOK_INIT(ptrace_access_check, blare_ptrace_access_check),
	LSM_HOOK_INIT(ptrace_traceme, blare_ptrace_traceme),
	LSM_HOOK_INIT(ptrace_unlink, blare_ptrace_unlink),
	LSM_HOOK_INIT(task_free, blare_task_free),
	LSM_HOOK_INIT(mmap_file, blare_mmap_file),
	LSM_HOOK_INIT(file_mprotect, blare_file_mprotect),
	LSM_HOOK_INIT(getprocattr, blare_getprocattr),
	LSM_HOOK_INIT(setprocattr, blare_setprocattr),
};

/**
 * blare_install() - Initializes the Blare securityfs, add the hooks but leaves
 * Blare disabled.
 *
 * Returns: 0 if everything went well, an error from the securityfs if one of
 * the file could not be brought up.
 */
static int __init blare_install(void)
{
	int ret;
	pr_info("Blare: Information Flow Monitor.\n");
	ret = blare_init_fs();
	if (ret)
		return ret;
	blare_enabled = 0;
	security_add_hooks(blare_hooks, ARRAY_SIZE(blare_hooks));
	return 0;
}

module_init(blare_install);
