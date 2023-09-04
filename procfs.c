#include <linux/build_bug.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/version.h>

#include "common.h"
#include "procfs.h"
#include "syncookie.h"

#define _BUFFER_SIZE 512
#define _PROC_PREFIX "isn_sync_"
#define _VAR(__name) __name##_link

#define _DEFINE_VAR_WRITE(__name) \
    static ssize_t __name##_write(struct file *file, \
            const char* buffer, size_t len, loff_t *off) \
    { \
        return _var_write(_VAR(__name), sizeof(*_VAR(__name)), file, buffer, len, off); \
    }

static ssize_t _var_write(void *var_ptr, size_t var_size,
        struct file *file, const char *buffer, size_t len, loff_t *off)
{
    int err;
    char kbuffer[_BUFFER_SIZE];

    if ((len - 1) != (2 * var_size))
        return -EINVAL; \

    err = copy_from_user(kbuffer, buffer, len);
    if (err)
        return err;

    err = hex2bin((u8 *)var_ptr, kbuffer, var_size);
    if (err)
        return err;

    return len;
}

#define _DEFINE_VAR_READ(__name) \
    static int __name##_show(struct seq_file *file, void *v) \
    { \
        return _var_show(_VAR(__name), sizeof(*_VAR(__name)), file, v); \
    } \
    \
    static int __name##_open(struct inode *inode, struct file *file) \
    { \
        return single_open(file, __name##_show, NULL); \
    } \

static int _var_show(const void *var_ptr, size_t var_size,
        struct seq_file *file, void *v)
{
    char kbuffer[_BUFFER_SIZE];

    if (var_ptr) {
        bin2hex(kbuffer, var_ptr, var_size);
        kbuffer[2 * var_size] = '\0';
        seq_printf(file, "%s\n", kbuffer);
    }

    return 0;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 6, 0)
#define _DEFINE_PROC_VAR_OPS(__name) \
    _DEFINE_VAR_WRITE(__name) \
    _DEFINE_VAR_READ(__name) \
    \
    static const struct file_operations __name##_proc_ops = { \
        .open    = __name##_open, \
        .read    = seq_read, \
        .write   = __name##_write, \
        .llseek  = seq_lseek, \
        .release = single_release, \
    }
#else
#define _DEFINE_PROC_VAR_OPS(__name) \
    _DEFINE_VAR_WRITE(__name) \
    _DEFINE_VAR_READ(__name) \
    \
    static const struct proc_ops __name##_proc_ops = { \
        .proc_open    = __name##_open, \
        .proc_read    = seq_read, \
        .proc_write   = __name##_write, \
        .proc_lseek   = seq_lseek, \
        .proc_release = single_release, \
    }
#endif

#define _DEFINE_PROC_VAR(__name) \
    _Static_assert((2 * sizeof(*_VAR(__name)) + 1) <= _BUFFER_SIZE, ""); \
    \
    _DEFINE_PROC_VAR_OPS(__name); \
    \
    static struct proc_dir_entry *isn_procfs_entry_##__name; \
    \
    void isn_procfs_exit_##__name(void) \
    { \
        if (isn_procfs_entry_##__name) { \
            remove_proc_entry(_PROC_PREFIX #__name, 0); \
            isn_procfs_entry_##__name = NULL; \
        } \
    } \
    \
    bool isn_procfs_init_##__name(void) \
    { \
        static const char *entry_name = _PROC_PREFIX #__name; \
        \
        isn_procfs_entry_##__name = proc_create( \
                entry_name, 044, NULL, &__name##_proc_ops); \
        if (!isn_procfs_entry_##__name) { \
            pr_err(KBUILD_MODNAME ": can't create proc entry=%s", entry_name); \
            return false; \
        } \
        \
        return true; \
    } \

_DEFINE_PROC_VAR(net_secret)
_DEFINE_PROC_VAR(syncookie_secret)
_DEFINE_PROC_VAR(ts_secret)

bool isn_procfs_init(void)
{
    return isn_procfs_init_net_secret() &&
            isn_procfs_init_syncookie_secret() &&
            isn_procfs_init_ts_secret();
}

void isn_procfs_exit(void)
{
    isn_procfs_exit_ts_secret();
    isn_procfs_exit_syncookie_secret();
    isn_procfs_exit_net_secret();
}
