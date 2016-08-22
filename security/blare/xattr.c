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

#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/errno.h>
#include <linux/dcache.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/gfp.h>

/* Read extended attribute @fieldname from dentry @dp
 * @dp the dentry whose inode is looked at for its special attribute. The caller
 * is responsible for dget-ing and dput-ing it.
 * @fieldname is the name of the field in the extended attributes,
 * e.g. "security.blare.info".
 * @buffer points to the address of a buffer allocated by this function (must
 * be freed afterwards if the operation succeeds)
 */
static int blare_read_xattr(struct dentry *dp, const char *fieldname, void **buffer){
	struct inode *ino;
	int size,rc;
	char *buff;

	if(!fieldname){
		pr_err("Blare: trying to read a NULL fieldname in the xattr of %s\n",
			dp->d_name.name);
		return -EINVAL;
	}

	ino = dp->d_inode;

	if (!ino->i_op->getxattr)
		return -EOPNOTSUPP;

	// Get the size of the xattr
	size = ino->i_op->getxattr(dp, ino, fieldname, NULL, 0);
	if (size < 0)
		return size;

	// Allocate memory
	buff = kzalloc(size,GFP_KERNEL);
	if (!buff)
		return -ENOMEM;

	// Read the xattr
	rc = ino->i_op->getxattr(dp, ino, fieldname, buff, size);
	if (rc < 0)
		kfree(buff);
	else
		*buffer = buff;

	return rc;
}

/* Set xattr @fieldname of file @dp to the value of @buffer
 * @dp is the dentry whose xattr is being modified
 * @fieldname identifies the extended attribute to modify
 * @buf is the new value for the security attribute and @bufsize its size
 */
static int blare_write_xattr(struct dentry *dp, const char *fieldname, void *buffer, int bufsize){
    struct inode *ino;
    int rc;

    ino = dp->d_inode;

    if (bufsize == 0) { 	/* removal of the xattr altogether */
	if (!ino->i_op->getxattr || !ino->i_op->getxattr)
		return -EOPNOTSUPP;

	rc = ino->i_op->getxattr(dp, ino, fieldname, NULL, 0);
	inode_lock(ino);
	rc = ino->i_op->removexattr(dp, fieldname);
	inode_unlock(ino);
    } else { 			/* new value for the xattr */
	inode_lock(ino);
	rc = __vfs_setxattr_noperm(dp, fieldname, buffer, bufsize, 0);
	inode_unlock(ino);
    }

    return rc;
}

static int blare_read_common(struct dentry *dp, void** dest, const char* attr)
{
	*dest = NULL;
	return blare_read_xattr(dp, attr, dest);
}

int blare_read_itag(struct dentry *dp, struct itag **info)
{
	return blare_read_common(dp, (void**)info, BLARE_XATTR_ITAG);
}

int blare_write_itag(struct dentry *dp, void *tags, int size)
{
	return blare_write_xattr(dp, BLARE_XATTR_ITAG, (void*) tags, size);
}

int blare_read_ptag(struct dentry *dp, struct ptag **policy)
{
	return blare_read_common(dp, (void**)policy, BLARE_XATTR_PTAG);
}

int blare_write_ptag(struct dentry *dp, void *tags, int size)
{
	return blare_write_xattr(dp, BLARE_XATTR_PTAG, (void*) tags, size);
}
