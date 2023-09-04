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
        if (!is_ok) \
            pr_err(KBUILD_MODNAME ": no access to " #__func "()!\n"); \
        else \
            __func##_orig = (void*)((unsigned long) __func##_link + MCOUNT_INSN_SIZE); \
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
bool isn_register_ftrace(struct ftrace_ops *fops, void *ptr);
void isn_unregister_ftrace(struct ftrace_ops *fops, void *ptr);
