#include <linux/ftrace.h>
#include <linux/timekeeping.h>
#include <linux/time64.h>
#include <net/tcp.h>
#include <net/secure_seq.h>

#include "common.h"
#include "syncookie.h"

#define ISN_TIME_DRIFT_MS 5000
#define ISN_TSBITS 6
#define ISN_TSMASK (((__u32)1 << ISN_TSBITS) - 1)

#define ISN_COOKIEBITS 24
#define ISN_COOKIEMASK (((__u32)1 << ISN_COOKIEBITS) - 1)

#define ISN_MAX_SYNCOOKIE_AGE 2
#define ISN_TCP_SYNCOOKIE_PERIOD_NS (60 * NSEC_PER_SEC) // 1 min

typedef u32 (*__cookie_v4_init_sequence_t)
        (const struct iphdr *iph, const struct tcphdr *th, u16 *mssp);
static __cookie_v4_init_sequence_t __cookie_v4_init_sequence_link;
static __cookie_v4_init_sequence_t __cookie_v4_init_sequence_orig;

typedef int (*__cookie_v4_check_t)
        (const struct iphdr *iph, const struct tcphdr *th, u32 cookie);
static __cookie_v4_check_t __cookie_v4_check_link;
static __cookie_v4_check_t __cookie_v4_check_orig;

typedef struct sock *(*cookie_v4_check_t)
        (struct sock *sk, struct sk_buff *skb);
static cookie_v4_check_t cookie_v4_check_link;
static cookie_v4_check_t cookie_v4_check_orig;

typedef u32 (*secure_tcp_ts_off_t)(const struct net *net, __be32 saddr, __be32 daddr);
static secure_tcp_ts_off_t secure_tcp_ts_off_link;
static secure_tcp_ts_off_t secure_tcp_ts_off_orig;

net_secret_t net_secret_link = NULL;
syncookie_secret_t syncookie_secret_link = NULL;
ts_secret_t ts_secret_link = NULL;

static __u16 const msstab[] = {
        536,
        1300,
        1440,
        1460,
    };

static inline u32 isn_tcp_cookie_time(void)
{
    u64 now = ktime_get_real_ns();
    return now / ISN_TCP_SYNCOOKIE_PERIOD_NS;
}

static inline u32 isn_cookie_hash(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport,
        u32 count, int c)
{
    return siphash_4u32(
            (__force u32)saddr, (__force u32)daddr,
            (__force u32)sport << 16 | (__force u32)dport,
            count, &(*syncookie_secret_link)[c]);
}

static inline __u32 isn_check_tcp_syn_cookie(__u32 cookie, __be32 saddr, __be32 daddr,
        __be16 sport, __be16 dport, __u32 sseq)
{
    u32 count, ch1, ch2, diff;

    count = isn_tcp_cookie_time();
    ch1 = isn_cookie_hash(saddr, daddr, sport, dport, 0, 0);
    cookie -= ch1 + sseq;
    diff = (count - (cookie >> ISN_COOKIEBITS)) & ((__u32)-1 >> ISN_COOKIEBITS);
    if (diff >= ISN_MAX_SYNCOOKIE_AGE)
        return (__u32)-1;
    ch2 = isn_cookie_hash(saddr, daddr, sport, dport, count - diff, 1);
    return (cookie - ch2) & ISN_COOKIEMASK;
}

int isn___cookie_v4_check(const struct iphdr *iph, const struct tcphdr *th, u32 cookie)
{
    __u32 seq = ntohl(th->seq) - 1;
    __u32 mssind = isn_check_tcp_syn_cookie(cookie,
            iph->saddr, iph->daddr,
            th->source, th->dest,
            seq);
    return (mssind < ARRAY_SIZE(msstab)) ? msstab[mssind] : 0;
}

static inline __u32 isn_secure_tcp_syn_cookie(__be32 saddr, __be32 daddr,
        __be16 sport, __be16 dport, __u32 sseq, __u32 data)
{
    u32 count = isn_tcp_cookie_time();
    u32 ch1 = isn_cookie_hash(saddr, daddr, sport, dport, 0, 0);
    u32 ch2 = isn_cookie_hash(saddr, daddr, sport, dport, count, 1);
    return (ch1 + sseq + (count << ISN_COOKIEBITS) + ((ch2 + data) & ISN_COOKIEMASK));
}

u32 isn___cookie_v4_init_sequence(const struct iphdr* iph, const struct tcphdr* th,
        u16* mssp)
{
    int mssind;
    const __u16 mss = *mssp;
    for (mssind = ARRAY_SIZE(msstab) - 1; mssind; mssind--) {
        if (mss >= msstab[mssind])
            break;
    }
    *mssp = msstab[mssind];
    return isn_secure_tcp_syn_cookie(
            iph->saddr, iph->daddr,
            th->source, th->dest,
            ntohl(th->seq), mssind);
}

struct sock *isn_cookie_v4_check(struct sock *sk, struct sk_buff *skb)
{
    if (sock_net(sk)->ipv4.sysctl_tcp_syncookies == 2)
        tcp_synq_overflow(sk);
    if (cookie_v4_check_orig)
        return cookie_v4_check_orig(sk, skb);
    return NULL;
}

u32 isn_secure_tcp_ts_off(const struct net *net, __be32 saddr, __be32 daddr)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
    // Same as tcp_ns_to_ts().
    u32 now = div_u64(ktime_get_real_ns(), NSEC_PER_SEC / TCP_TS_HZ);
#else
    u32 now = tcp_ns_to_ts(ktime_get_real_ns());
#endif
    u32 diff = (now - tcp_time_stamp_raw() + ISN_TIME_DRIFT_MS) & ~ISN_TSMASK;
    if (secure_tcp_ts_off_orig)
        return secure_tcp_ts_off_orig(net, saddr, daddr) + diff;
    return 0;
}

static bool isn_syncookie_init_lookup(void)
{
    bool is_ok = true;

    ISN_DO_LOOKUP_ON_INIT(is_ok, __cookie_v4_init_sequence)
    ISN_DO_LOOKUP_ON_INIT(is_ok, __cookie_v4_check)
    ISN_DO_LOOKUP_ON_INIT(is_ok, cookie_v4_check)
    ISN_DO_LOOKUP_ON_INIT(is_ok, secure_tcp_ts_off)

    ISN_DO_LOOKUP_ON_INIT(is_ok, net_secret)
    ISN_DO_LOOKUP_ON_INIT(is_ok, syncookie_secret)
    ISN_DO_LOOKUP_ON_INIT(is_ok, ts_secret)

    return is_ok;
}

static void isn_syncookie_exit_lookup(void)
{
    ISN_UNDO_LOOKUP_ON_EXIT(ts_secret)
    ISN_UNDO_LOOKUP_ON_EXIT(syncookie_secret)
    ISN_UNDO_LOOKUP_ON_EXIT(net_secret)

    ISN_UNDO_LOOKUP_ON_EXIT(secure_tcp_ts_off)
    ISN_UNDO_LOOKUP_ON_EXIT(cookie_v4_check)
    ISN_UNDO_LOOKUP_ON_EXIT(__cookie_v4_check)
    ISN_UNDO_LOOKUP_ON_EXIT(__cookie_v4_init_sequence)
}

ISN_DEFINE_FTRACE_OPS(isn___cookie_v4_init_sequence_ops, isn___cookie_v4_init_sequence);
ISN_DEFINE_FTRACE_OPS(isn___cookie_v4_check_ops, isn___cookie_v4_check);
ISN_DEFINE_FTRACE_OPS(isn_cookie_v4_check_ops, isn_cookie_v4_check);
ISN_DEFINE_FTRACE_OPS(isn_secure_tcp_ts_off_ops, isn_secure_tcp_ts_off);

static bool isn_syncookie_init_ftrace(void)
{
    bool is_ok = true;

    ISN_DO_FTRACE_ON_INIT(is_ok, __cookie_v4_init_sequence);
    ISN_DO_FTRACE_ON_INIT(is_ok, __cookie_v4_check);
    ISN_DO_FTRACE_ON_INIT(is_ok, cookie_v4_check);
    ISN_DO_FTRACE_ON_INIT(is_ok, secure_tcp_ts_off);

    return is_ok;
}

static void isn_syncookie_exit_ftrace(void)
{
    ISN_UNDO_FTRACE_ON_EXIT(secure_tcp_ts_off)
    ISN_UNDO_FTRACE_ON_EXIT(cookie_v4_check)
    ISN_UNDO_FTRACE_ON_EXIT(__cookie_v4_check)
    ISN_UNDO_FTRACE_ON_EXIT(__cookie_v4_init_sequence)
}

static bool isn_init_secrets(void)
{
    struct iphdr ih = {};
    struct tcphdr th = {};
    struct in6_addr ih6 = {};
    u16 mss = 0;

    // Force init net_secret.
    secure_tcp_seq(0, 0, 0, 0);
    // Force init syncookie_secret.
    __cookie_v4_init_sequence(&ih, &th, &mss);
    // Force init ts_secret (secure_tcp_ts_off() - is not exported).
    secure_tcpv6_ts_off(&init_net, (const __be32 *)&ih6, (const __be32 *)&ih6);

    return true;
}

bool isn_syncookie_init(void)
{
    bool is_ok = isn_init_secrets() &&
            isn_syncookie_init_lookup() &&
            isn_syncookie_init_ftrace();
    if (!is_ok)
        isn_syncookie_exit();
    return is_ok;
}

void isn_syncookie_exit(void)
{
    isn_syncookie_exit_ftrace();
    isn_syncookie_exit_lookup();
}
