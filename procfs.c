#include <linux/build_bug.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 0, 0)
#include <linux/hex.h>
#endif

#include "common.h"
#include "procfs.h"
#include "syncookie.h"

#define _BUFFER_SIZE 512
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

#define _DEFINE_PROC_VAR_SECRET(__name) \
    _Static_assert((2 * sizeof(*_VAR(__name)) + 1) <= _BUFFER_SIZE, ""); \
    _DEFINE_VAR_WRITE(__name) \
    _DEFINE_VAR_READ(__name) \
    _DEFINE_PROC_VAR(__name) \

_DEFINE_PROC_VAR_SECRET(net_secret)
_DEFINE_PROC_VAR_SECRET(syncookie_secret)
_DEFINE_PROC_VAR_SECRET(syncookie6_secret)
_DEFINE_PROC_VAR_SECRET(ts_secret)

bool isn_procfs_init(void)
{
    return isn_procfs_init_net_secret() &&
            isn_procfs_init_syncookie_secret() &&
            isn_procfs_init_syncookie6_secret() &&
            isn_procfs_init_ts_secret();
}

void isn_procfs_exit(void)
{
    isn_procfs_exit_ts_secret();
    isn_procfs_exit_syncookie6_secret();
    isn_procfs_exit_syncookie_secret();
    isn_procfs_exit_net_secret();
}
