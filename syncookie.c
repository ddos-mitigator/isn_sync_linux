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

typedef int (*__cookie_v4_check_t)
        (const struct iphdr *iph, const struct tcphdr *th, u32 cookie);
static __cookie_v4_check_t __cookie_v4_check_link;
static __cookie_v4_check_t __cookie_v4_check_orig;

typedef u32 (*__cookie_v4_init_sequence_t)
        (const struct iphdr *iph, const struct tcphdr *th, u16 *mssp);
static __cookie_v4_init_sequence_t __cookie_v4_init_sequence_link;
static __cookie_v4_init_sequence_t __cookie_v4_init_sequence_orig;

typedef struct sock *(*cookie_v4_check_t)
        (struct sock *sk, struct sk_buff *skb);
static cookie_v4_check_t cookie_v4_check_link;
static cookie_v4_check_t cookie_v4_check_orig;

typedef u32 (*secure_tcp_ts_off_t)(const struct net *net, __be32 saddr, __be32 daddr);
static secure_tcp_ts_off_t secure_tcp_ts_off_link;
static secure_tcp_ts_off_t secure_tcp_ts_off_orig;

#if IS_ENABLED(CONFIG_IPV6)

typedef int (*__cookie_v6_check_t)
        (const struct ipv6hdr *iph, const struct tcphdr *th, u32 cookie);
static __cookie_v6_check_t __cookie_v6_check_link;
static __cookie_v6_check_t __cookie_v6_check_orig;

typedef u32 (*__cookie_v6_init_sequence_t)
        (const struct ipv6hdr *iph, const struct tcphdr *th, __u16 *mssp);
static __cookie_v6_init_sequence_t __cookie_v6_init_sequence_link;
static __cookie_v6_init_sequence_t __cookie_v6_init_sequence_orig;

typedef struct sock *(*cookie_v6_check_t)(struct sock *sk, struct sk_buff *skb);
static cookie_v6_check_t cookie_v6_check_link;
static cookie_v6_check_t cookie_v6_check_orig;

typedef u32 (*secure_tcpv6_ts_off_t)
        (const struct net *net, const __be32 *saddr, const __be32 *daddr);
static secure_tcpv6_ts_off_t secure_tcpv6_ts_off_link;
static secure_tcpv6_ts_off_t secure_tcpv6_ts_off_orig;

#endif

net_secret_t net_secret_link = NULL;
syncookie_secret_t syncookie_secret_link = NULL;
syncookie6_secret_t syncookie6_secret_link = NULL;
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 8, 0)

static int isn___cookie_v4_check(const struct iphdr *iph, const struct tcphdr *th,
        u32 cookie)
{
    __u32 seq = ntohl(th->seq) - 1;
    __u32 mssind = isn_check_tcp_syn_cookie(cookie,
            iph->saddr, iph->daddr,
            th->source, th->dest,
            seq);
    return (mssind < ARRAY_SIZE(msstab)) ? msstab[mssind] : 0;
}

#else

/*
 * Kernel v6.8 changes:
 * `tcp: Don't pass cookie to __cookie_v[46]_check().` (7577bc8249c3)
*/
static int isn___cookie_v4_check(const struct iphdr *iph, const struct tcphdr *th)
{
    __u32 cookie = ntohl(th->ack_seq) - 1;
    __u32 seq = ntohl(th->seq) - 1;
    __u32 mssind = isn_check_tcp_syn_cookie(cookie,
            iph->saddr, iph->daddr,
            th->source, th->dest,
            seq);
    return (mssind < ARRAY_SIZE(msstab)) ? msstab[mssind] : 0;
}

#endif

static inline __u32 isn_secure_tcp_syn_cookie(__be32 saddr, __be32 daddr,
        __be16 sport, __be16 dport, __u32 sseq, __u32 data)
{
    u32 count = isn_tcp_cookie_time();
    u32 ch1 = isn_cookie_hash(saddr, daddr, sport, dport, 0, 0);
    u32 ch2 = isn_cookie_hash(saddr, daddr, sport, dport, count, 1);
    return (ch1 + sseq + (count << ISN_COOKIEBITS) + ((ch2 + data) & ISN_COOKIEMASK));
}

static u32 isn___cookie_v4_init_sequence(const struct iphdr* iph,
        const struct tcphdr* th, u16* mssp)
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

static struct sock *isn_cookie_v4_check(struct sock *sk, struct sk_buff *skb)
{
    if (sock_net(sk)->ipv4.sysctl_tcp_syncookies == 2)
        tcp_synq_overflow(sk);
    if (cookie_v4_check_orig)
        return cookie_v4_check_orig(sk, skb);
    return NULL;
}

static u32 isn_time_diff(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
    u32 now = div_u64(ktime_get_real_ns(), NSEC_PER_SEC / TCP_TS_HZ);
    return (now - tcp_time_stamp_raw() + ISN_TIME_DRIFT_MS) & ~ISN_TSMASK;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 7, 0)
    u32 now = tcp_ns_to_ts(ktime_get_real_ns());
    return (now - tcp_time_stamp_raw() + ISN_TIME_DRIFT_MS) & ~ISN_TSMASK;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0)
    /*
    * Kernel v6.7 changes:
    * `tcp: replace tcp_time_stamp_raw()` (16cf6477741b)
    * `tcp: move tcp_ns_to_ts() to net/ipv4/syncookies.c` (003e07a1e48e)
    */
    u32 now = div_u64(ktime_get_real_ns(), NSEC_PER_SEC / TCP_TS_HZ);
    return (now - tcp_clock_ts(false) + ISN_TIME_DRIFT_MS) & ~ISN_TSMASK;
#else
    /*
    * Kernel v6.9 changes:
    * `tcp: Move tcp_ns_to_ts() to tcp.h` (b18afb6f4229)
    */
    u32 now = tcp_ns_to_ts(false, ktime_get_real_ns());
    return (now - tcp_ns_to_ts(false, tcp_clock_ns()) + ISN_TIME_DRIFT_MS) & ~ISN_TSMASK;
#endif
}

static u32 isn_secure_tcp_ts_off(const struct net *net, __be32 saddr, __be32 daddr)
{
    if (secure_tcp_ts_off_orig)
        return secure_tcp_ts_off_orig(net, saddr, daddr) + isn_time_diff();
    return 0;
}

#if IS_ENABLED(CONFIG_IPV6)

static __u16 const msstab_v6[] = {
        1280 - 60, /* IPV6_MIN_MTU - 60 */
        1480 - 60,
        1500 - 60,
        9000 - 60,
};

static inline u32 isn_cookie_hash_v6(
        const struct in6_addr *saddr, const struct in6_addr *daddr,
        u16 sport, u16 dport, u32 count, int c)
{
    struct {
        struct in6_addr saddr;
        struct in6_addr daddr;
        u32 count;
        __be16 sport;
        __be16 dport;
    } __aligned(SIPHASH_ALIGNMENT) combined = {
            .saddr = *saddr,
            .daddr = *daddr,
            .count = count,
            .sport = sport,
            .dport = dport
    };

    _Static_assert(offsetofend(typeof(combined), dport) == 40);
    return siphash(&combined, offsetofend(typeof(combined), dport),
            &(*syncookie6_secret_link)[c]);
}

static inline __u32 isn_check_tcp_syn_cookie_v6(u32 cookie,
        const struct in6_addr *saddr, const struct in6_addr *daddr,
        __be16 sport, __be16 dport, __u32 sseq)
{
    u32 count, ch1, ch2, diff;
    count = isn_tcp_cookie_time();
    ch1 = isn_cookie_hash_v6(saddr, daddr, sport, dport, 0, 0);
    cookie -= ch1 + sseq;
    diff = (count - (cookie >> ISN_COOKIEBITS)) & ((__u32)-1 >> ISN_COOKIEBITS);
    if (diff >= ISN_MAX_SYNCOOKIE_AGE)
        return (__u32)-1;
    ch2 = isn_cookie_hash_v6(saddr, daddr, sport, dport, count - diff, 1);
    return (cookie - ch2) & ISN_COOKIEMASK;
}

static inline __u32 isn_secure_tcp_syn_cookie_v6(
        const struct in6_addr *saddr, const struct in6_addr *daddr,
        __be16 sport, __be16 dport, __u32 sseq, __u32 data)
{
    u32 count = isn_tcp_cookie_time();
    u32 ch1 = isn_cookie_hash_v6(saddr, daddr, sport, dport, 0, 0);
    u32 ch2 = isn_cookie_hash_v6(saddr, daddr, sport, dport, count, 1);
    return (ch1 + sseq + (count << ISN_COOKIEBITS) + ((ch2 + data) & ISN_COOKIEMASK));
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 8, 0)

static int isn___cookie_v6_check(const struct ipv6hdr *iph, const struct tcphdr *th,
        u32 cookie)
{
    __u32 seq = ntohl(th->seq) - 1;
    __u32 mssind = isn_check_tcp_syn_cookie_v6(cookie, &iph->saddr, &iph->daddr,
            th->source, th->dest, seq);
    return (mssind < ARRAY_SIZE(msstab_v6)) ? msstab_v6[mssind] : 0;
}

#else

/*
 * Kernel v6.8 changes:
 * `tcp: Don't pass cookie to __cookie_v[46]_check().` (7577bc8249c3)
*/
static int isn___cookie_v6_check(const struct ipv6hdr *iph,
        const struct tcphdr *th)
{
    __u32 cookie = ntohl(th->ack_seq) - 1;
    __u32 seq = ntohl(th->seq) - 1;
    __u32 mssind = isn_check_tcp_syn_cookie_v6(cookie,
            &iph->saddr, &iph->daddr,
            th->source, th->dest,
            seq);
    return (mssind < ARRAY_SIZE(msstab)) ? msstab[mssind] : 0;
}

#endif

static u32 isn___cookie_v6_init_sequence(const struct ipv6hdr *iph,
        const struct tcphdr *th, __u16 *mssp)
{
    int mssind;
    const __u16 mss = *mssp;
    for (mssind = ARRAY_SIZE(msstab_v6) - 1; mssind ; mssind--) {
        if (mss >= msstab_v6[mssind])
            break;
    }
    *mssp = msstab_v6[mssind];
    return isn_secure_tcp_syn_cookie_v6(&iph->saddr, &iph->daddr, th->source, th->dest,
            ntohl(th->seq), mssind);
}

static struct sock *isn_cookie_v6_check(struct sock *sk, struct sk_buff *skb)
{
    if (sock_net(sk)->ipv4.sysctl_tcp_syncookies == 2)
        tcp_synq_overflow(sk);
    if (cookie_v6_check_orig)
        return cookie_v6_check_orig(sk, skb);
    return NULL;
}

static u32 isn_secure_tcpv6_ts_off(const struct net *net,
        const __be32 *saddr, const __be32 *daddr)
{
    if (secure_tcpv6_ts_off_orig)
        return secure_tcpv6_ts_off_orig(net, saddr, daddr) + isn_time_diff();
    return 0;
}

#endif

static bool isn_syncookie_init_lookup(void)
{
    bool is_ok = true;

    ISN_DO_LOOKUP_ON_INIT(is_ok, __cookie_v4_check)
    ISN_DO_LOOKUP_ON_INIT(is_ok, __cookie_v4_init_sequence)
    ISN_DO_LOOKUP_ON_INIT(is_ok, cookie_v4_check)
    ISN_DO_LOOKUP_ON_INIT(is_ok, secure_tcp_ts_off)

#if IS_ENABLED(CONFIG_IPV6)
    ISN_DO_LOOKUP_ON_INIT(is_ok, __cookie_v6_check)
    ISN_DO_LOOKUP_ON_INIT(is_ok, __cookie_v6_init_sequence)
    ISN_DO_LOOKUP_ON_INIT(is_ok, cookie_v6_check)
    ISN_DO_LOOKUP_ON_INIT(is_ok, secure_tcpv6_ts_off)
#endif

    ISN_DO_LOOKUP_ON_INIT(is_ok, net_secret)
    ISN_DO_LOOKUP_ON_INIT(is_ok, syncookie_secret)
    ISN_DO_LOOKUP_ON_INIT(is_ok, syncookie6_secret)
    ISN_DO_LOOKUP_ON_INIT(is_ok, ts_secret)

    return is_ok;
}

static void isn_syncookie_exit_lookup(void)
{
    ISN_UNDO_LOOKUP_ON_EXIT(ts_secret)
    ISN_UNDO_LOOKUP_ON_EXIT(syncookie6_secret)
    ISN_UNDO_LOOKUP_ON_EXIT(syncookie_secret)
    ISN_UNDO_LOOKUP_ON_EXIT(net_secret)

#if IS_ENABLED(CONFIG_IPV6)
    ISN_UNDO_LOOKUP_ON_EXIT(secure_tcpv6_ts_off)
    ISN_UNDO_LOOKUP_ON_EXIT(cookie_v6_check)
    ISN_UNDO_LOOKUP_ON_EXIT(__cookie_v6_init_sequence)
    ISN_UNDO_LOOKUP_ON_EXIT(__cookie_v6_check)
#endif

    ISN_UNDO_LOOKUP_ON_EXIT(secure_tcp_ts_off)
    ISN_UNDO_LOOKUP_ON_EXIT(cookie_v4_check)
    ISN_UNDO_LOOKUP_ON_EXIT(__cookie_v4_init_sequence)
    ISN_UNDO_LOOKUP_ON_EXIT(__cookie_v4_check)
}

ISN_DEFINE_FTRACE_OPS(isn___cookie_v4_check_ops, isn___cookie_v4_check);
ISN_DEFINE_FTRACE_OPS(isn___cookie_v4_init_sequence_ops, isn___cookie_v4_init_sequence);
ISN_DEFINE_FTRACE_OPS(isn_cookie_v4_check_ops, isn_cookie_v4_check);
ISN_DEFINE_FTRACE_OPS(isn_secure_tcp_ts_off_ops, isn_secure_tcp_ts_off);

#if IS_ENABLED(CONFIG_IPV6)
ISN_DEFINE_FTRACE_OPS(isn___cookie_v6_check_ops, isn___cookie_v6_check);
ISN_DEFINE_FTRACE_OPS(isn___cookie_v6_init_sequence_ops, isn___cookie_v6_init_sequence);
ISN_DEFINE_FTRACE_OPS(isn_cookie_v6_check_ops, isn_cookie_v6_check);
ISN_DEFINE_FTRACE_OPS(isn_secure_tcpv6_ts_off_ops, isn_secure_tcpv6_ts_off);
#endif

static bool isn_syncookie_init_ftrace(void)
{
    bool is_ok = true;

    ISN_DO_FTRACE_ON_INIT(is_ok, __cookie_v4_check);
    ISN_DO_FTRACE_ON_INIT(is_ok, __cookie_v4_init_sequence);
    ISN_DO_FTRACE_ON_INIT(is_ok, cookie_v4_check);
    ISN_DO_FTRACE_ON_INIT(is_ok, secure_tcp_ts_off);

#if IS_ENABLED(CONFIG_IPV6)
    ISN_DO_FTRACE_ON_INIT(is_ok, __cookie_v6_check);
    ISN_DO_FTRACE_ON_INIT(is_ok, __cookie_v6_init_sequence);
    ISN_DO_FTRACE_ON_INIT(is_ok, cookie_v6_check);
    ISN_DO_FTRACE_ON_INIT(is_ok, secure_tcpv6_ts_off);
#endif

    return is_ok;
}

static void isn_syncookie_exit_ftrace(void)
{
#if IS_ENABLED(CONFIG_IPV6)
    ISN_UNDO_FTRACE_ON_EXIT(secure_tcpv6_ts_off)
    ISN_UNDO_FTRACE_ON_EXIT(cookie_v6_check)
    ISN_UNDO_FTRACE_ON_EXIT(__cookie_v6_init_sequence)
    ISN_UNDO_FTRACE_ON_EXIT(__cookie_v6_check)
#endif

    ISN_UNDO_FTRACE_ON_EXIT(secure_tcp_ts_off)
    ISN_UNDO_FTRACE_ON_EXIT(cookie_v4_check)
    ISN_UNDO_FTRACE_ON_EXIT(__cookie_v4_init_sequence)
    ISN_UNDO_FTRACE_ON_EXIT(__cookie_v4_check)
}

static bool isn_init_secrets(void)
{
    struct iphdr ih = {};
    struct ipv6hdr ih6 = {};
    struct tcphdr th = {};
    u16 mss = 0;

    // Force init net_secret.
    secure_tcp_seq(0, 0, 0, 0);
    // Force init syncookie_secret.
    __cookie_v4_init_sequence(&ih, &th, &mss);
    __cookie_v6_init_sequence(&ih6, &th, &mss);

/*
* Kernel v6.15 changes:
* `tcp: use EXPORT_IPV6_MOD[_GPL]()` (6dc4c2526f6d)
* (`secure_tcpv6_ts_off` is not exported)
*/
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
    // Force init ts_secret (secure_tcp_ts_off() - is not exported).
    struct in6_addr i6_addr = {};
    secure_tcpv6_ts_off(&init_net, (const __be32 *)&i6_addr, (const __be32 *)&i6_addr);
#endif

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
