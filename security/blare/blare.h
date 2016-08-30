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
 * This file contains the definitions of various data structures and functions
 * used throughout the module.
 */

#include <linux/types.h>
#include <linux/spinlock_types.h>

struct dentry;

/*
 * An itag (information tag) is the label identifying the content of a
 * container of information. It's an array of integers, representing a set of
 * identifiers of information classes.
 *
 * Like ptag, this structure is packed to make it serializable. This should
 * not encur too much overhead because marshalling/unmarshalling is mostly all
 * we do with this structure.
 * */
struct itag
{
	__u32 count;
	__s32 *tags;
};

/*
 * A ptag (policy tag) is the label identifying the authorized content of a
 * container of information.  It's an array of arrays of integers, representing
 * the set of sets of authorized information mixes. */
struct ptag
{
	__u32 mixes_count;
	__u32 *count;
	__s32 **tags;
};

/*
 * The state Blare maintains about a process
 */
struct blare_task_struct
{
	spinlock_t lock;
	atomic_t refcnt;
	struct itag *info;
	struct ptag *policy;
};

/*
 * The state Blare maintains about a file
 */
struct blare_file_struct
{
	struct itag *info;
	struct ptag *policy;
};

/*
 * The state Blare maintains about a socket
 */
struct blare_socket_struct
{
	spinlock_t lock; /* for use in IRQ context */
	struct itag *info;
	struct ptag *policy;
};

/*
 * These macros define the name of the extended attributes' names
 */
#define BLARE_XATTR_ITAG "blare.xattr.itag"
#define BLARE_XATTR_PTAG "blare.xattr.ptag"

extern int blare_enabled;

int copy_itags(struct itag *origin, struct itag *new);
int merge_itags(struct itag *origin, struct itag *new, struct itag **result);
int check_against_ptag(struct itag* content, struct ptag* policy);

int blare_alloc_file_tag(struct dentry *dp, struct blare_file_struct *sec);

int blare_read_itag(struct dentry *dp, struct itag **info);
int blare_write_itag(struct dentry *dp, const struct itag *info);
int blare_read_ptag(struct dentry *dp, struct ptag **policy);

void free_blare_file_struct(struct blare_file_struct *sec);
void free_blare_task_struct(struct blare_task_struct *sec);

int blare_may_read(struct dentry *dp, struct blare_file_struct *fstruct);
int blare_may_append(struct dentry *dp, struct blare_file_struct *fstruct);
