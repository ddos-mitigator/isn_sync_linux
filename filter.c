#include <net/tcp.h>

#include "common.h"
#include "filter.h"

#define _DATAPLANE_SYN_MARKER 0x0100

typedef int (*tcp_filter_t)(struct sock *sk, struct sk_buff *skb);
static tcp_filter_t tcp_filter_link;
static tcp_filter_t tcp_filter_orig;

static int isn_tcp_filter(struct sock *sk, struct sk_buff *skb)
{
    const struct tcphdr* th = (const struct tcphdr *)skb->data;

    if (th->syn && (th->urg_ptr == _DATAPLANE_SYN_MARKER))
        return -EPERM;

    if (tcp_filter_orig)
        return tcp_filter_orig(sk, skb);

    return -EPERM;
}

static bool isn_filter_init_lookup(void)
{
    bool is_ok = true;

    ISN_DO_LOOKUP_ON_INIT(is_ok, tcp_filter)

    return is_ok;
}

static void isn_filter_exit_lookup(void)
{
    ISN_UNDO_LOOKUP_ON_EXIT(tcp_filter)
}

ISN_DEFINE_FTRACE_OPS(isn_tcp_filter_ops, isn_tcp_filter);

static bool isn_filter_init_ftrace(void)
{
    bool is_ok = true;

    ISN_DO_FTRACE_ON_INIT(is_ok, tcp_filter)

    return is_ok;
}

static void isn_filter_exit_ftrace(void)
{
    ISN_UNDO_FTRACE_ON_EXIT(tcp_filter)
}

bool isn_filter_init(void)
{
    bool is_ok = isn_filter_init_lookup() && isn_filter_init_ftrace();
    if (!is_ok)
        isn_filter_exit();
    return is_ok;
}

void isn_filter_exit(void)
{
    isn_filter_exit_ftrace();
    isn_filter_exit_lookup();
}
