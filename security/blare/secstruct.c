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

/*
 * This file defines some useful function to manage the security structure
 * registered in kernel data structures such as task, file, etc.
 */

#include "blare.h"

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/cred.h>
#include <linux/sched.h>

/**
 * Allocate a security structure for a file and read the itag from the XATTR.
 * @dp the dentry of the file of interest
 * @sec the security structure that will get filled
 */
int blare_alloc_file_tag(struct dentry *dp, struct blare_file_struct *sec)
{
	int rc;
	
	rc = blare_read_itag(dp, &sec->info);
	if (rc < 0)
		return rc;

	rc = blare_read_ptag(dp, &sec->policy);
	if (rc < 0) {
		kfree(sec->info);
		return rc;
	}

	return 0;
}

/* The current process may read a file */
int blare_may_read(struct dentry *dp, struct blare_file_struct *fstruct)
{
    int rc, icount;
    struct cred *cred;
    struct blare_task_struct *tstruct;

    /* The kernel swapper does not propagate tags */
    if (current->pid == 0)
        return 0;

    cred = prepare_creds();
    if (unlikely(!cred || !cred->security)){
        abort_creds(cred);
        return -ENODATA;
    }

    /* if (fstruct->info_array)
     *	WARN ? */

    tstruct = cred->security;

    /* Information tag propagation */
    rc = blare_alloc_file_tag(dp,fstruct);
    if (rc < 0) {
		abort_creds();
	    return rc;
    }

    rc = merge_itags(tstruct->info,fstruct->info,&tstruct->info);
    free_blare_file_struct(fstruct);

    /* Note: here we want to continue with the other tags even if it fails
     * except when ENOMEM*/
    if (rc < 0)
	abort_creds();
    else
    	commit_creds(cred);

    return rc;
}

int blare_may_append(struct dentry *dp, struct blare_file_struct *fstruct)
{
    const struct cred *ro_cred;
    struct blare_task_struct *tstruct;
    int rc;
    struct list_head *newtag;

    if (current->pid == 0)
        return 0;

    ro_cred = get_current_cred();
    tstruct = ro_cred->security;

    if (unlikely(!tstruct)){
        put_cred(ro_cred);
        return -ENODATA;
    }

    if (!tstruct->info)
	    return 0;

    rc = blare_alloc_file_tag(dp,fstruct);
    if (rc < 0)
	    goto end;

    rc = merge_itags(fstruct->info, tstruct->info, &fstruct->info);

    if (rc < 0){
            goto end;

    rc = blare_write_itag(dp,fstruct->info);
    free_blare_file_struct(fstruct);

end:
    put_cred(ro_cred);
    return rc;
}
