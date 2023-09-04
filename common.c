#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#ifndef CONFIG_KPROBES
#error "KPROBES support not enabled in kernel."
#endif
#define USE_KPROBES
#include <linux/kprobes.h>

#else
#ifndef CONFIG_KALLSYMS
#error "KALLSYMS support not enabled in kernel."
#endif
#include <linux/kallsyms.h>
#endif

#include "common.h"

#ifdef USE_KPROBES
typedef unsigned long (*isn_kallsyms_lookup_name_t)(const char *name);

static int isn_dummy_kprobe_handler(struct kprobe *p, struct pt_regs *regs)
{
    return 0;
}

static isn_kallsyms_lookup_name_t find_kallsyms_lookup_name_symbol(void)
{
    int err;
    isn_kallsyms_lookup_name_t addr;
    struct kprobe probe;

    memset(&probe, 0, sizeof(probe));
    probe.pre_handler = isn_dummy_kprobe_handler;
    probe.symbol_name = "kallsyms_lookup_name";
    if ((err = register_kprobe(&probe))) {
        pr_err(KBUILD_MODNAME ": can't regiter_kprobe(). err=%d\n", err);
        return NULL;
    }
    addr = (isn_kallsyms_lookup_name_t)probe.addr;
    unregister_kprobe(&probe);
    return addr;
}
#endif

unsigned long isn_lookup_name(const char *name)
{
#ifdef USE_KPROBES
    static isn_kallsyms_lookup_name_t func_ptr = NULL;
    if (!func_ptr)
        func_ptr = find_kallsyms_lookup_name_symbol();
    return func_ptr(name);
#else
    return kallsyms_lookup_name(name);
#endif
}

bool isn_register_ftrace(struct ftrace_ops *fops, void *ptr)
{
    int err;

    err = ftrace_set_filter_ip(fops, (unsigned long)ptr, 0, 0);
    if (err) {
        pr_err(KBUILD_MODNAME ": can't set ftrace filter. err=%d\n", err);
        return false;
    }

    err = register_ftrace_function(fops);
    if (err) {
        ftrace_set_filter_ip(fops, (unsigned long)ptr, 1, 0);
        pr_err(KBUILD_MODNAME ": can't set ftrace function. err=%d\n", err);
        return false;
    }

    return true;
}

void isn_unregister_ftrace(struct ftrace_ops *fops, void *ptr)
{
    int err;

    if (!ptr)
        return;

    err = unregister_ftrace_function(fops);
    if (err)
        pr_err(KBUILD_MODNAME ": can't unregister ftrace function. err=%d\n", err);

    err = ftrace_set_filter_ip(fops, (unsigned long)ptr, 1, 0);
    if (err)
        pr_err(KBUILD_MODNAME ": can't unregister filter. err=%d\n", err);
}
