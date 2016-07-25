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
} __attribute__((packed))

/*
 * A ptag (policy tag) is the label identifying the authorized content of a
 * container of information.  It's an array of arrays of integers, representing
 * the set of sets of authorized information mixes. */
struct ptag
{
	__u32 mixes_count;
	__u32 *count;
	__s32 *tags;
} __attribute__((packed))

/*
 * These macros define the name of the extended attributes' names
 */
#define BLARE_XATTR_ITAG "blare.xattr.itag"
#define BLARE_XATTR_PTAG "blare.xattr.ptag"

int merge_itags(struct itag *origin, struct itag *new, struct itag **result);
int check_against_ptag(struct itag* content, struct ptag* policy);
