#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/stringify.h>
#include <linux/msg.h>

#include "blare.h"

#define BLARE_TAGS_NUMBER_STR __stringify(BLARE_TAGS_NUMBER)

static __u32 blare_traced[BLARE_TAGS_NUMBER];
int blare_enabled;

/**
 * __blare_print_file() - Pretty-print a file to a string.
 * @file:	The file to print.
 *
 * Returns: 	A newly-allocated string containing a textual description of
 * 		file, or ERR_PTR(-ENOMEM) if memory is insufficient.
 */
static char *__blare_print_file(struct file *file)
{
	int n = snprintf(NULL, 0, "%pd4", file->f_path.dentry);
	char *str = kmalloc(n + 1, GFP_KERNEL);
	if (!str)
		return ERR_PTR(-ENOMEM);
	snprintf(str, n + 1, "%pd4", file->f_path.dentry);
	return str;
}

/**
 * __blare_print_task() - Pretty-print a task to a string.
 * @task:	The task to print.
 *
 * Returns: 	A newly-allocated string containing a textual description of
 * 		task, or ERR_PTR(-ENOMEM) if memory is insufficient.
 */
static char *__blare_print_task(struct task_struct *p)
{
	int n = snprintf(NULL, 0, "process %i | %s", p->pid, p->comm);
	char *str = kmalloc(n + 1, GFP_KERNEL);
	if (!str)
		return ERR_PTR(-ENOMEM);
	snprintf(str, n + 1, "process %i | %s", p->pid, p->comm);
	return str;
}

/**
 * __blare_print_msg() - Pretty-print a message to a string.
 * @msg:	The message to print.
 *
 * Returns: 	A newly-allocated string containing a textual description of
 * 		msg, or ERR_PTR(-ENOMEM) if memory is insufficient.
 */
static char *__blare_print_msg(struct msg_msg *msg)
{
	int n = snprintf(NULL, 0, "msg %p", msg);
	char *str = kmalloc(n + 1, GFP_KERNEL);
	if (!str)
		return ERR_PTR(-ENOMEM);
	snprintf(str, n + 1, "msg %p", msg);
	return str;
}

/**
 * __blare_trace_mm() - Print the trace of a tag reaching a memory space for the
 * first time.
 * @tag:	The tag involved in the propagation.
 * @mm:		The memory space acquiring the tag for the first time.
 * @src_str:	A textual description of the origin of the tag.
 *
 * Prints a trace line to the kernel ring buffer for every process having that
 * memory space.
 * Returns: 0 or -ENOMEM.
 */
static int __blare_trace_mm(int tag, struct mm_struct *mm, char *src_str)
{
	char *dest_str;
	struct task_struct *p;
	for_each_process(p) {
		if (!p->mm || p->mm != mm)
			continue;
		dest_str = __blare_print_task(p);
		if (IS_ERR(dest_str))
			return PTR_ERR(dest_str);
		pr_info(
		     "blare_trace: [itag %i]: %s -> %s "
		     "(current: _%s(pid %d;cpu %d;parent %d)_)",
		     tag, src_str, dest_str, current->comm, current->pid,
		     current->on_cpu, current->real_parent->pid);
		kfree(dest_str);
	}
	return 0;
}

/**
 * blare_trace() - Outputs a trace when a traced tag has reached a new container
 * of information.
 * @tag:		The traced tag involved in the tag propagation.
 * @src:		The source container.
 * @source_type:	The type of the source (message, memory space or file).
 * @dest:		The destination container.
 * @dest_type:		The type of the destination (memory space or file).
 *
 * A trace line is printed to the kernel ring buffer to log the occurrence of
 * the flow that made dest acquire tag. Several lines may be printed because
 * memory spaces are "dereferenced": a line is printed for every process owning
 * it.
 * Returns: 0 or -ENOMEM.
 */
static int blare_trace(int tag, void *src, int source_type, void *dest,
		       int dest_type)
{
	char *src_str;
	struct task_struct *p;
	int rc = 0;

	if (source_type == BLARE_MM_TYPE) {
		struct mm_struct *mm = (struct mm_struct *)src;
		for_each_process(p) {
			if (!p->mm || p->mm != mm)
				continue;
			src_str = __blare_print_task(p);
			if (IS_ERR(src_str)) {
				rc = PTR_ERR(src_str);
				break;
			}
			if (dest_type == BLARE_MM_TYPE) {
				struct mm_struct *dest_mm =
				    (struct mm_struct *)dest;
				rc = __blare_trace_mm(tag, dest_mm, src_str);
				if (rc) {
					kfree(src_str);
					break;
				}
			} else {
				char *dest_str =
				    __blare_print_file((struct file *)dest);

				if (IS_ERR(dest_str)) {
					kfree(src_str);
					rc = PTR_ERR(dest_str);
					break;
				}
				pr_info(
				    "blare_trace: [itag %i]: %s -> %s "
				    "(current: _%s(pid %d;cpu %d;parent %d)_)",
				     tag, src_str, dest_str, current->comm,
				     current->pid, current->on_cpu,
				     current->real_parent->pid);
			}
		}
	} else {
		if (source_type == BLARE_FILE_TYPE)
			src_str = __blare_print_file((struct file *)src);
		else
			src_str = __blare_print_msg((struct msg_msg *)src);

		if (IS_ERR(src_str)) {
			rc = PTR_ERR(src_str);
			goto end;
		}

		if (dest_type == BLARE_MM_TYPE) {
			struct mm_struct *dest_mm = (struct mm_struct *)dest;
			rc = __blare_trace_mm(tag, dest_mm, src_str);
			if (rc)
				goto end;
		} else {
			char *dest_str =
			    __blare_print_file((struct file *)dest);

			if (IS_ERR(dest_str)) {
				rc = PTR_ERR(dest_str);
				goto end;
			}
			pr_info(
			     "blare_trace: [itag %i]: %s -> %s "
			     "(current: _%s(pid %d;cpu %d;parent %d)_)",
			     tag, src_str, dest_str, current->comm,
			     current->pid, current->on_cpu,
			     current->real_parent->pid);
		}

end:
		kfree(src_str);
	}

	return rc;
}

/**
 * __is_traced() - Tells whether a given tag is traced.
 * @tag:	The tag of interest.
 *
 * Returns: A boolean value indicating whether tag is traced.
 */
static bool __is_traced(int tag)
{
	int index;
	int offset;

	if (tag < 0 || tag >= BLARE_TAGS_NUMBER * 32)
		return false;

	index = tag / 32;
	offset = tag % 32;
	return blare_traced[index] & (1 << offset);
}

/**
 * blare_is_traced() - Tests whether a set of propagated tags includes a traced
 * tag.
 * @tags_added:	A set of tags.
 *
 * Returns: A boolean value indicating whether tags_added includes a traced tag.
 */
bool blare_is_traced(const struct info_tags *tags_added)
{
	int i;
	for (i = 0; i < BLARE_TAGS_NUMBER; i++)
		if (tags_added->tags[i] & blare_traced[i])
			return true;
	return false;
}

/**
 * blare_trace_all() - Outputs a trace for every traced tags in a set of tags.
 * @tags_added:	A set of tags.
 * @src:	The source container of the information flow.
 * @src_type:	The type of the source container, memory space, message or file.
 * @dest:	The destination container.
 * @dest_type:	The type of the destination container.
 *
 * Returns: 0 or -ENOMEM.
 */
int blare_trace_all(const struct info_tags *tags_added, void *src, int src_type,
		    void *dest, int dest_type)
{
	int tag;
	int rc;
	for (tag = 0; tag < BLARE_TAGS_NUMBER * 32; tag++) {
		if (unlikely(__is_traced(tag))) {
			rc = blare_trace(tag, src, src_type, dest, dest_type);
			if (rc)
				return rc;
		}
	}

	return 0;
}

/**
 * blare_tags_to_string() - Stringifies a bitfield of tags for output.
 * @tag:	The tags to stringify.
 * @buffer:	Where to output the result string, will be allocated by this
 * 		function.
 *
 * Returns: The length of the buffer or -ENOMEM. The buffer is left untouched in
 * the latter case.
 */
int blare_tags_to_string(const __u32 * tag, char **buffer)
{
	int i, j;
	int length = 0;
	char *buf;
	int offset;
	/* compute the size needed for the buffer allocation */
	for (i = 0; i < BLARE_TAGS_NUMBER; i++)
		for (j = 0; j < 32; j++)
			if (tag[i] & (1 << j))
				length += snprintf(NULL, 0, "%d ", i * 32 + j);

	buf = kmalloc(length + 1, GFP_KERNEL);	/* +1 for the final \0 */
	if (!buf)
		return -ENOMEM;

	offset = 0;
	/* populate the buffer */
	for (i = 0; i < BLARE_TAGS_NUMBER; i++)
		for (j = 0; j < 32; j++)
			if (tag[i] & (1 << j))
				offset +=
				    snprintf(buf + offset, length - offset,
					     "%d ", i * 32 + j);

	/* Replace the last space by a line return and finish the string */
	buf[length - 1] = '\n';
	buf[length] = '\0';

	*buffer = buf;

	return length;
}

/**
 * blare_tags_from_string() - Parses a string to build a bitfield of tags.
 * @buf:	The string to parse.
 * @length:	The length of the string, not including the final nul byte.
 * @tags:	Where to store the result, must be allocated by the caller.
 *
 * Returns:	The length of the input string if it could be parsed correctly,
 * 		-EINVAL otherwise.
 */
int blare_tags_from_string(const char *buf, size_t length, __u32 * tags)
{
	int offset = 0;
	__u32 tag;
	int nbytes;

	memset(tags, 0, BLARE_TAGS_NUMBER * sizeof(__u32));
	while (offset < length && sscanf(buf + offset, "%d%n", &tag, &nbytes)) {
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

/**
 * blare_fs_itag_size_show() - Outputs the size of the itags bitfield.
 * @seq:	The output file.
 * @v:		An argument, unused.
 *
 * Returns: 0.
 */
static int blare_fs_itag_size_show(struct seq_file *seq, void *v)
{
	seq_puts(seq, BLARE_TAGS_NUMBER_STR "\n");
	return 0;
}

/**
 * blare_fs_itag_size_open() - Opens the itag size file.
 * @inode:	The inode to open, unused.
 * @file:	The file to open.
 *
 * Returns: Whatever single_open() returns.
 */
static int blare_fs_itag_size_open(struct inode *inode, struct file *file)
{
	return single_open(file, blare_fs_itag_size_show, NULL);
}

/**
 * blare_fs_traced_show() - Outputs the currently traced tags.
 * @seq:	The output file.
 * @v:		An argument, unused.
 *
 * Returns: 0.
 */
static int blare_fs_traced_show(struct seq_file *seq, void *v)
{
	int i, j;
	for (i = 0; i < BLARE_TAGS_NUMBER; i++) {
		for (j = 0; j < 32; j++) {
			if (unlikely(blare_traced[i] & (1 << j)))
				seq_printf(seq, "%d ", i * 32 + j);
		}
	}
	seq_puts(seq, "\n");
	return 0;
}

/**
 * blare_fs_traced_open() - Opens the traced file.
 * @inode:	The inode to open, unused.
 * @file:	The file to open.
 *
 * Returns: Whatever single_open() returns.
 */
static int blare_fs_traced_open(struct inode *inode, struct file *file)
{
	return single_open(file, blare_fs_traced_show, NULL);
}


/**
 * __blare_fs_mark_as_traced() - Marks a tag as traced.
 * @tag:	The tag to mark as traced.
 */
static void __blare_fs_mark_as_traced(int tag)
{
	int index = tag / 32;
	int offset = tag % 32;
	blare_traced[index] |= 1 << offset;
}

/**
 * __blare_fs_mark_as_untraced() - Marks a tag as no longer traced.
 * @tag:	The tag to mark as untraced.
 */
static void __blare_fs_mark_as_untraced(int tag)
{
	int index = tag / 32;
	int offset = tag % 32;
	blare_traced[index] &= ~(1 << offset);
}

/**
 * __blare_fs_trace_untrace_write() - Changes the set of traced tags.
 * @file:	The file being written to, either "trace" or "untrace".
 * @buf:	The strings containing the tags to start/stop tracing.
 * @count:	The length of the string.
 * @ppos:	The offset to which the file is written, must be 0.
 * @marker:	Either __blare_fs_mark_as_trace to start tracing the tags, or
 * 		__blare_fs_mark_as_untraced to stop tracing them.
 *
 * This function is common to both  the "trace" and "untrace" file, the only
 * difference is in what is done about the tags: they are either added to the
 * set of traced tags or removed depending on function pointer "marker".
 * buf must be a string composed of a series of integers separated by blank
 * characters and optionally followed by a newline character. Negative or too
 * big values are discarded.
 *
 * Returns:	The value count if buf could be succesfully parsed and all the
 * 		tags handled. -ENOMEM if there is not enough memory to handle
 * 		input. -EINVAL if ppos is not 0 or if buf could not be parsed
 * 		successfully.
 */
static ssize_t __blare_fs_trace_untrace_write(struct file *file,
					      const char __user * buf,
					      size_t count, loff_t * ppos,
					      void (*marker) (int))
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

/**
 * blare_fs_untrace_write() - Writes a set of tags to start tracing to the
 * trace file.
 * @file:	The trace file.
 * @buf:	The input string containing the tags to trace.
 * @count:	The length of buf.
 * @ppos:	The offset to which the writing will be done, must be 0.
 *
 * Returns: The result from __blare_fs_trace_untrace_write.
 */
static ssize_t blare_fs_trace_write(struct file *file, const char __user * buf,
				    size_t count, loff_t * ppos)
{
	return __blare_fs_trace_untrace_write(file, buf, count, ppos,
					      __blare_fs_mark_as_traced);
}

/**
 * blare_fs_untrace_write() - Writes a set of tags to stop tracing to the
 * untrace file.
 * @file:	The untrace file.
 * @buf:	The input string containing the tags to untrace.
 * @count:	The length of buf.
 * @ppos:	The offset to which the writing will be done, must be 0.
 *
 * Returns: The result from __blare_fs_trace_untrace_write.
 */
static ssize_t blare_fs_untrace_write(struct file *file,
				      const char __user * buf, size_t count,
				      loff_t * ppos)
{
	return __blare_fs_trace_untrace_write(file, buf, count, ppos,
					      __blare_fs_mark_as_untraced);
}

/**
 * blare_fs_enabled_show() - Outputs the state of Blare (enabled or disabled)
 * @seq:	The output file.
 * @v:		An argument, unused.
 *
 * Returns: 0.
 */
static int blare_fs_enabled_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "%d\n", blare_enabled);
	return 0;
}

/**
 * blare_fs_enabled_open() - Opens the enabled file.
 * @inode:	The inode to open, unused.
 * @file:	The file to open.
 *
 * Returns: Whatever single_open() returns.
 */
static int blare_fs_enabled_open(struct inode *inode, struct file *file)
{
	return single_open(file, blare_fs_enabled_show, NULL);
}

/**
 * blare_fs_enabled_write() - Handles writes to the enabled file, to enable or
 * disable Blare.
 * @file:	The file written.
 * @buf:	What is written, must be "0", "1", "0\n" or "1\n".
 * @count:	The size of what is written, must be 1 or 2.
 * @ppos:	The offset at which the file is written, must be 0.
 *
 * The only acceptable inputs are "0" and "1", optionally followed by a line
 * return which will be silently ignored. These values respectively disable and
 * enable Blare. Enabling Blare while it is already enabled or disabling it
 * while it is already disabled is a no-op.
 *
 * Returns: The length of the input if it was accepted, -EPERM if the writer is
 * not privileged (CAP_MAC_ADMIN), -EINVAL if the offset is not 0 or the input
 * invalid.
 */
static ssize_t blare_fs_enabled_write(struct file *file,
				      const char __user * buf, size_t count,
				      loff_t * ppos)
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
	.owner = THIS_MODULE,
	.open = blare_fs_itag_size_open,
	.read = seq_read,
	.release = single_release,
};

static const struct file_operations blare_traced_ops = {
	.owner = THIS_MODULE,
	.open = blare_fs_traced_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations blare_trace_ops = {
	.owner = THIS_MODULE,
	.write = blare_fs_trace_write,
};

static const struct file_operations blare_untrace_ops = {
	.owner = THIS_MODULE,
	.write = blare_fs_untrace_write,
};

static const struct file_operations blare_enabled_ops = {
	.owner = THIS_MODULE,
	.open = blare_fs_enabled_open,
	.read = seq_read,
	.write = blare_fs_enabled_write,
	.release = single_release,
};

/**
 * blare_init_fs() - Initializes Blare's securityfs.
 *
 * Returns:	0 if the securityfs could be initialized succesfully, the error
 * 		code from the securityfs API otherwise.
 */
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
