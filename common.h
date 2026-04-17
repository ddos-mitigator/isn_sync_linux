#pragma once

#include <linux/ftrace.h>
#include <linux/printk.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#define ftrace_regs pt_regs
static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
    return fregs;
}
#endif

#define ISN_DO_LOOKUP_ON_INIT(__is_ok, __sym) \
    if (__is_ok) { \
        __sym##_link = (__sym##_t) isn_lookup_name(#__sym); \
        if (!(__is_ok = !!__sym##_link)) \
            pr_err(KBUILD_MODNAME ": can't lookup " #__sym "!\n"); \
    }

#define ISN_UNDO_LOOKUP_ON_EXIT(__sym) \
    __sym##_link = NULL;

#define ISN_DO_FTRACE_ON_INIT(__is_ok, __func) \
    if (__is_ok) { \
        __is_ok = isn_register_ftrace(&isn_##__func##_ops, __func##_link); \
        if (!__is_ok) \
            pr_err(KBUILD_MODNAME ": no access to " #__func "()!\n"); \
        else \
            __func##_orig = isn_find_func_beginning((void*) __func##_link); \
    }

#define ISN_UNDO_FTRACE_ON_EXIT(__func) \
    if (__func##_orig) { \
        isn_unregister_ftrace(&isn_##__func##_ops, __func##_link); \
        __func##_orig = NULL; \
    }

#define ISN_DEFINE_FTRACE_OPS(__name, __wrapper) \
    static void notrace handler_##__name( \
            unsigned long ip, unsigned long parent_ip, \
            struct ftrace_ops *fops, struct ftrace_regs *fregs) \
    { \
        struct pt_regs *regs = ftrace_get_regs(fregs); \
        regs->ip = (unsigned long)__wrapper; \
    } \
    \
    static struct ftrace_ops __name __read_mostly = { \
        .func = handler_##__name, \
        .flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY, \
    }

unsigned long isn_lookup_name(const char *name);
void* isn_find_func_beginning(unsigned char *func_ptr);
bool isn_register_ftrace(struct ftrace_ops *fops, void *ptr);
void isn_unregister_ftrace(struct ftrace_ops *fops, void *ptr);

#define _PROC_PREFIX "isn_sync_"

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 6, 0)
#define _DEFINE_PROC_VAR_OPS(__name) \
    static const struct file_operations __name##_proc_ops = { \
        .open    = __name##_open, \
        .read    = seq_read, \
        .write   = __name##_write, \
        .llseek  = seq_lseek, \
        .release = single_release, \
    }
#else
#define _DEFINE_PROC_VAR_OPS(__name) \
    static const struct proc_ops __name##_proc_ops = { \
        .proc_open    = __name##_open, \
        .proc_read    = seq_read, \
        .proc_write   = __name##_write, \
        .proc_lseek   = seq_lseek, \
        .proc_release = single_release, \
    }
#endif

#define _DEFINE_PROC_VAR(__name) \
    _DEFINE_PROC_VAR_OPS(__name); \
    \
    static struct proc_dir_entry *isn_procfs_entry_##__name; \
    \
    static void isn_procfs_exit_##__name(void) \
    { \
        if (isn_procfs_entry_##__name) { \
            remove_proc_entry(_PROC_PREFIX #__name, 0); \
            isn_procfs_entry_##__name = NULL; \
        } \
    } \
    \
    static bool isn_procfs_init_##__name(void) \
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
    }
