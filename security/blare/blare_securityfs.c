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
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/capability.h>
#include <linux/uaccess.h>

static const char rootdir_name[] __initconst = "blare";
static const char enabler_name[] __initconst = "enabled";

int blare_enabled = 0;

static ssize_t is_enabled(struct file* f, char __user *buf, size_t size,
			  loff_t* ppos)
{
	char str_enabled;
	ssize_t rc;

	if (*ppos != 0)
		return 0;

	sprintf(&str_enabled, "%d", blare_enabled);
	rc = simple_read_from_buffer(buf, size, ppos, &str_enabled, 1);
	return rc;
}

static ssize_t enable(struct file* f, const char __user *buf, size_t size,
		      loff_t* ppos)
{
	char temp;
	int value;

	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;

	if (size != 1)
		return -EINVAL;

	if (copy_from_user(&temp, buf, 1) != 0)
		return -EFAULT;

	value = temp - '0'; /* ASCII->int conversion */
	if (value != 0 && value != 1)
		return -EINVAL;

	blare_enabled = value;
	if (blare_enabled)
		pr_info("Blare: now enabled");
	else
		pr_info("Blare: now disabled");

	return 1;
}

static const struct file_operations blare_securityfs_enabled_ops = {
	.read = is_enabled,
	.write = enable,
};

static int __init blare_create_blarefs(void)
{
	int error;
	struct dentry* root;
	struct dentry* enabler;

	error = 0;
	root = securityfs_create_dir(rootdir_name, NULL);
	if (IS_ERR(root)) {
		error = PTR_ERR(root);
		goto error;
	}
	enabler = securityfs_create_file(enabler_name, 0644, root, NULL,
					 &blare_securityfs_enabled_ops);
	if (IS_ERR(root)) {
		error = PTR_ERR(enabler);
		goto free_root;
	}

free_root:
	securityfs_remove(root);
error:
	blare_enabled = (!error);
	return error;
}

fs_initcall(blare_create_blarefs);
