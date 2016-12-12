#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/stringify.h>

#include "blare.h"

#define BLARE_TAGS_NUMBER_STR __stringify(BLARE_TAGS_NUMBER)

static __u32 traced[BLARE_TAGS_NUMBER];
int blare_enabled;

bool blare_is_traced(int tag)
{
	int index;
	int offset;

	if (tag < 0 || tag >= BLARE_TAGS_NUMBER * 32)
		return false;

	index = tag / 32;
	offset = tag % 32;
	return traced[index] & (1 << offset);
}

int blare_tags_to_string(const __u32 *tag, char** buffer)
{
	int i,j;
	int length = 0;
	char *buf;
	int offset;
	/* compute the size needed for the buffer allocation */
	for (i=0 ; i<BLARE_TAGS_NUMBER ; i++)
		for (j=0 ; j<32 ; j++)
			if (tag[i] & (1 << j))
				length += snprintf(NULL, 0, "%d ", i*32 + j);

	buf = kmalloc(length + 1, GFP_KERNEL); /* +1 for the final \0 */
	if (!buf)
		return -ENOMEM;

	offset = 0;
	/* populate the buffer */
	for (i=0 ; i<BLARE_TAGS_NUMBER ; i++)
		for (j=0 ; j<32 ; j++)
			if (tag[i] & (1 << j))
				offset += snprintf(buf + offset, length - offset, "%d ", i*32 + j);

	/* Replace the last space by a line return and finish the string */
	buf[length-1] = '\n';
	buf[length] = '\0';

	*buffer = buf;

	return length;
}

int blare_tags_from_string(const char* buf, size_t length, __u32 *tags)
{
	int offset = 0;
	__u32 tag;
	int nbytes;

	memset(tags, 0, BLARE_TAGS_NUMBER * sizeof(__u32));
	while (offset < length &&
	       sscanf(buf + offset, "%d%n", &tag, &nbytes)) {
		offset += nbytes;
		if (tag < 0 || tag >= BLARE_TAGS_NUMBER * 32) {
			pr_err("blare: Invalid tag (off-range): %i", tag);
			continue;
		}

		tags[tag / 32] |= 1 << (tag % 32);
	}

	if (!offset)
		return -EINVAL;
	if (buf[offset] == '\n')
		offset++;
	return offset;
}

static int blare_fs_itag_size_show(struct seq_file *seq, void *v)
{
	seq_puts(seq, BLARE_TAGS_NUMBER_STR"\n");
	return 0;
}

static int blare_fs_itag_size_open(struct inode *inode, struct file *file)
{
	return single_open(file, blare_fs_itag_size_show, NULL);
}

static int blare_fs_traced_show(struct seq_file *seq, void *v)
{
	int i, j;
	for (i=0 ; i<BLARE_TAGS_NUMBER ; i++) {
		for (j=0 ; j<32 ; j++) {
			if (unlikely(traced[i] & (1 << j)))
				seq_printf(seq, "%d ", i * 32 + j);
		}
	}
	seq_puts(seq, "\n");
	return 0;
}

static int blare_fs_traced_open(struct inode *inode, struct file *file)
{
	return single_open(file, blare_fs_traced_show, NULL);
}

static void __blare_fs_mark_as_traced(int tag)
{
	int index = tag / 32;
	int offset = tag % 32;
	traced[index] |= 1 << offset;
}

static void __blare_fs_mark_as_untraced(int tag)
{
	int index = tag / 32;
	int offset = tag % 32;
	traced[index] &= ~(1 << offset);
}

static ssize_t __blare_fs_trace_untrace_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos, void(*marker)(int))
{
	char *new_tags;
	int nbytes, offset;
	__u32 tag;

	/* wow wow wow, calm down right now! */
	if (count >= PAGE_SIZE)
		return -ENOMEM;

	/* No partial writes. */
	if (*ppos != 0)
		return -EINVAL;

	new_tags = memdup_user_nul(buf, count);
	if (IS_ERR(new_tags))
		return PTR_ERR(new_tags);

	offset = 0;
	while (sscanf(new_tags + offset, "%d%n", &tag, &nbytes)) {
		offset += nbytes;
		if (tag < 0 || tag >= BLARE_TAGS_NUMBER * 32) {
			pr_err("blare: Invalid tag (off-range): %i", tag);
			continue;
		}

		marker(tag);
	}

	kfree(new_tags);

	if (!offset)
		return -EINVAL;

	/* \n at end of input is ok, just pretend having written it */
	if (new_tags[offset] == '\n')
		offset++;

	return offset;
}

static ssize_t blare_fs_trace_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos)
{
	return __blare_fs_trace_untrace_write(file, buf, count, ppos, __blare_fs_mark_as_traced);
}

static ssize_t blare_fs_untrace_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos)
{
	return __blare_fs_trace_untrace_write(file, buf, count, ppos, __blare_fs_mark_as_untraced);
}

static int blare_fs_enabled_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "%d\n", blare_enabled);
	return 0;
}

static int blare_fs_enabled_open(struct inode *inode, struct file *file)
{
	return single_open(file, blare_fs_enabled_show, NULL);
}

static ssize_t blare_fs_enabled_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos)
{
	char *data;
	int rc;
	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;

	if (*ppos != 0)
		return -EINVAL;

	if (count > 2)
		return -EINVAL;

	data = memdup_user(buf, count);
	if (IS_ERR(data))
		return PTR_ERR(data);

	if (count == 2 && data[1] != '\n') {
		rc = -EINVAL;
		goto out;
	}

	if (data[0] == '0') {
		blare_enabled = 0;
		pr_info("*** BLARE IS DISABLED ***");
		rc = count;
	} else if (data[0] == '1') {
		blare_enabled = 1;
		pr_info("*** BLARE IS ENABLED ***");
		rc = count;
	} else {
		rc = -EINVAL;
	}

out:
	kfree(data);
	return rc;
}

static const struct file_operations blare_itag_size_ops = {
	.owner		= THIS_MODULE,
	.open		= blare_fs_itag_size_open,
	.read		= seq_read,
	.release	= single_release,
};

static const struct file_operations blare_traced_ops = {
	.owner		= THIS_MODULE,
	.open		= blare_fs_traced_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static const struct file_operations blare_trace_ops = {
	.owner		= THIS_MODULE,
	.write		= blare_fs_trace_write,
};

static const struct file_operations blare_untrace_ops = {
	.owner		= THIS_MODULE,
	.write		= blare_fs_untrace_write,
};

static const struct file_operations blare_enabled_ops = {
	.owner		= THIS_MODULE,
	.open		= blare_fs_enabled_open,
	.read		= seq_read,
	.write		= blare_fs_enabled_write,
	.release	= single_release,
};

int blare_init_fs()
{
	struct dentry *root;
	struct dentry *itag_size, *traced, *trace, *untrace, *enabled;
	int ret;

	root = securityfs_create_dir("blare", NULL);
	if (IS_ERR(root)) {
		ret = PTR_ERR(root);
		goto error_root;
	}

	itag_size = securityfs_create_file("itag_size", 0444, root, NULL,
				      &blare_itag_size_ops);
	if (IS_ERR(itag_size)) {
		ret = PTR_ERR(itag_size);
		goto error_itag_size;
	}

	traced = securityfs_create_file("traced", 0444, root, NULL,
				      &blare_traced_ops);
	if (IS_ERR(traced)) {
		ret = PTR_ERR(traced);
		goto error_traced;
	}

	trace = securityfs_create_file("trace", 0600, root, NULL,
				      &blare_trace_ops);
	if (IS_ERR(trace)) {
		ret = PTR_ERR(trace);
		goto error_trace;
	}

	untrace = securityfs_create_file("untrace", 0600, root, NULL,
				      &blare_untrace_ops);
	if (IS_ERR(untrace)) {
		ret = PTR_ERR(untrace);
		goto error_untrace;
	}

	enabled = securityfs_create_file("enabled", 0644, root, NULL,
				      &blare_enabled_ops);
	if (IS_ERR(enabled)) {
		ret = PTR_ERR(enabled);
		goto error_enabled;
	}
	return 0;

error_enabled:
	securityfs_remove(untrace);
error_untrace:
	securityfs_remove(trace);
error_trace:
	securityfs_remove(traced);
error_traced:
	securityfs_remove(itag_size);
error_itag_size:
	securityfs_remove(root);
error_root:
	pr_err("Blare: Couldn't initialize Blare securityfs dir");
	return ret;
}
