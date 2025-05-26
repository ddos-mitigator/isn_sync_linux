#include <linux/module.h>
#include <linux/version.h>

#include "common.h"
#include "filter.h"
#include "procfs.h"
#include "syncookie.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#error "Kernel 4.13.0+ is required."
#endif

void isn_deinit(void);

static int __init isn_init(void)
{
    bool is_ok = isn_syncookie_init() && isn_filter_init() && isn_procfs_init();
    if (!is_ok) {
        isn_deinit();
        return -EIO;
    }
    return 0;
}

void isn_deinit(void)
{
    isn_procfs_exit();
    isn_filter_exit();
    isn_syncookie_exit();
}

static void __exit isn_exit(void)
{
    isn_deinit();
}

module_init(isn_init);
module_exit(isn_exit);

MODULE_AUTHOR("MITIGATOR");
MODULE_DESCRIPTION("MITIGATOR Agent");
MODULE_LICENSE("GPL");
MODULE_VERSION(MOD_VERSION);
