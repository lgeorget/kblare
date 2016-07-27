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


static int blare_bprm_set_creds(struct linux_binprm *bprm){

	int rc;
	struct itag *file_info;
	struct blare_task_struct *tstruct;
	struct inode *inode = file_inode(bprm->file);

	/* For now, we are only concerned with the permissions of the initial
	 * file, not the wrappers/interpreters/etc. */
	if (bprm->cred_prepared || (blare_enabled == 0)) return 0;

	/* Allocate a temporary security structure for the executable file */
	fstruct = kzalloc(sizeof(struct blare_file_struct), GFP_KERNEL);
	if (!fstruct)
		return -ENOMEM;

	/* Allocate a security structure for the process's tags */
	tstruct = kzalloc(sizeof(struct blare_task_struct), GFP_KERNEL);

	if (!tstruct){
		kfree(fstruct);
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

security_initcall(blare_install);
