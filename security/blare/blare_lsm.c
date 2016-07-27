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

#include <linux/lsm_hooks.h>
#include <linux/binfmts.h>
#include <net/sock.h>
#include <net/af_unix.h>

static struct security_hook_list blare_hooks[] = {
	/* example: LSM_HOOK_INIT(task_free, blare_task_free), */
};

int blare_enabled = 0;

static int __init blare_install(void)
{
	pr_info("Blare: Information Flow Monitor.\n");
	security_add_hooks(blare_hooks, ARRAY_SIZE(blare_hooks));
	return 0;
}


static int blare_bprm_set_creds(struct linux_binprm *bprm)
{
	int rc;
	struct itag *file_info;
	struct blare_task_struct *tstruct;
	struct dentry *dp = file_dentry(bprm->file);

	/* For now, we are only concerned with the permissions of the initial
	 * file, not the wrappers/interpreters/etc. */
	if (bprm->cred_prepared || (blare_enabled == 0)) return 0;

	/* Allocate a security structure for the process's tags */
	tstruct = kzalloc(sizeof(struct blare_task_struct), GFP_KERNEL);

	if (!tstruct){
		kfree(file_info);
		return -ENOMEM;
	}

	/* Read the information tag */
	rc = blare_read_itag(dp, &file_info);
	if (rc < 0)
		return rc;
	tstruct->info = file_info; /* steal the itag structure */
	spin_lock_init(&tstruct->lock);
	atomic_set(&tstruct->refcnt, 1);
	bprm->cred->security = tstruct;

	return 0;
}

static int blare_security_prepare_creds(struct cred *new,
		const struct cred *old, gfp_t gfp)
{
	struct blare_task_struct *tnew;
	const struct blare_task_struct *told;
	int rc;

	new->security = NULL;

	/* If there is no security field attached to the old credentials, 
	 * we create a new empty one */
	tnew = kzalloc(sizeof(struct blare_task_struct), GFP_KERNEL);
	if (!tnew)
		return -ENOMEM;

	told = old->security;
	if (told) {
		if (told->info) {
			rc = copy_itags(told->info, tnew->info);
			if (rc < 0) {
				kfree(tnew);
				return rc;
			}
		}
	}

	new->security = tnew;
	return 0;
}

static int blare_task_create(unsigned long clone_flags)
{
	/* Parent & child share the same address space (i.e. copy_mm() does not
	 * allocate a new address space) */
	if ((clone_flags & CLONE_VM) && !(clone_flags & CLONE_THREAD))
		pr_err("Blare: CLONE_VM & ~CLONE_THREAD, we cannot track"
			 " all information flows in this case\n");

	/* TODO fix that bug somehow, for now we cannot allow that */
	return -EPERM;
}

static void blare_cred_free(struct cred *cred)
{
	struct blare_task_struct *tstruct;

	if (!cred->security)
		return;

	tstruct = cred->security;
	free_blare_task_struct(tstruct);
	cred->security = NULL;
}

/*
 * Allocate sufficient memory and attach to @cred for a transfer later.
 */
static int blare_cred_alloc_blank(struct cred *cred, gfp_t gfp){
	struct blare_task_struct *tnew;

	tnew = kzalloc(sizeof(struct blare_task_struct), gfp);
	if (!tnew)
		return -ENOMEM;

	tnew->info = NULL;
	cred->security = tnew;

	return 0;
}

/*
 * Transfer data from original creds to new creds
 */
static void blare_cred_transfer(struct cred *new, const struct cred *old){
	const struct blare_task_struct *old_sec =
		(struct blare_task_struct*) old->security;
	struct blare_task_struct *new_sec =
		(struct blare_task_struct*) new->security;
	spin_lock_init(&new_sec->lock);
	atomic_set(&new_sec->refcnt, 1);
	new_sec->info = old_sec->info;
}


static int blare_socket_recvmsg(struct socket *sock, struct msghdr *msg,
				int size, int flags)
{
	struct sock *sk, *peer;
	struct blare_task_struct *tstruct;
	int rc = 0;
	struct cred *cred;
	struct blare_socket_struct *sock_sec;

	sk = sock->sk;
	if (unlikely(!sk))
		return 0;

	if (!sk->sk_security)
		return 0;

	if (sk->sk_family == AF_UNIX) {
		unix_state_lock(sk);
		peer = unix_sk(sk)->peer;
		if (peer)
			sock_hold(peer);
		unix_state_unlock(sk);
		if (!peer) /* XXX can that happen? */
			return 0;
		if (!peer->sk_security)
			return 0;
		sock_sec = peer->sk_security;
	} else {
		sock_sec = sk->sk_security;
	}

	if (!sock_sec->info)
		return 0;

	cred = prepare_creds();
	if (unlikely(!cred))
		return 0;

	tstruct = cred->security;
	if (unlikely(!tstruct)){
		abort_creds(cred);
		return 0;
	}

	if (tstruct->info)
		rc = merge_itags(tstruct->info, sock_sec->info, &tstruct->info);
		/* TODO check policy here */
	else
		rc = copy_itags(sock_sec->info, tstruct->info);
	if (rc < 0) {
		abort_creds(cred);
		return rc;
	}

	commit_creds(cred);

	return 0;
}

static int blare_socket_sendmsg(struct socket *sock, struct msghdr *msg,
				int size)
{
	int rc;
	struct sock *sk;
	struct blare_task_struct *tstruct;
	struct blare_socket_struct *sock_sec;
	const struct cred *cred;

	sk = sock->sk;

	/* if (sk->sk_family != PF_INET && sk->sk_family != PF_UNIX)
		return 0; */

	cred = get_current_cred();
	if (unlikely(!cred))
		return 0;

	tstruct = cred->security;

	if (unlikely(!tstruct)) {
		put_cred(cred);
		return -ENODATA;
	}

	if (!tstruct->info || tstruct->info->count == 0) {
		put_cred(cred);
		return 0;
	}

	sock_sec = sk->sk_security;
	rc = merge_itags(sock_sec->info, tstruct->info, &sock_sec->info);

	if (rc  < 0) {
		pr_err("Blare: error %d setting socket attributes", rc);
		return rc;
	}

	return 0;
}


security_initcall(blare_install);
