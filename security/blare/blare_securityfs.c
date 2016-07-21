/*
 * Blare security module
 *
 * This file contains Blare interface (mounted as /sys/kernel/security/blare)
 *
 * Copyright (C) 2010-2016 CentraleSupelec
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/security.h>

static int __init blare_create_blarefs(void)
{
	int error;

error:
	return error;
}

fs_initcall(blare_create_blarefs);
