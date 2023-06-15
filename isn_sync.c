#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/siphash.h>
#include <linux/ftrace.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <net/net_namespace.h>
#include <net/secure_seq.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#error "Kernel 4.13.0+ is required."
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
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

#define LOG_PREFIX "isn_sync: "
#define PROC_ENTRY "isn_sync"
#define SEND_SYN_MARKER 0x0100

typedef struct sock * (*cookie_v4_check_type)(
	struct sock *sk, struct sk_buff *skb);
typedef u32 (*secure_tcp_seq_type)(
	__be32 saddr, __be32 daddr, __be16 sport, __be16 dport);
typedef int (*tcp_filter_type)(struct sock *sk, struct sk_buff *skb);

static cookie_v4_check_type cookie_v4_check_ptr;
static secure_tcp_seq_type secure_tcp_seq_ptr;
static tcp_filter_type tcp_filter_ptr;

static siphash_key_t (*syncookie_secret_ptr)[2] = NULL;
static siphash_key_t *net_secret_ptr = NULL;
static siphash_key_t *timestamp_secret_ptr = NULL;

static struct proc_dir_entry *proc_entry;

static void show_bytes(struct seq_file *m, const char *name,
			   const void *in, size_t size)
{
	size_t i;

	seq_printf(m, "%s: ", name);
	for (i = 0; i < size; i++) {
		const u8 *bytes = (const u8 *)in;
		seq_printf(m, "%02x", (unsigned int)bytes[i]);
	}
	seq_printf(m, "\n");
}

static int isn_sync_show(struct seq_file *m, void *v)
{
	seq_printf(m, "tcp_options.wscale_enabled: %d\n",
		init_net.ipv4.sysctl_tcp_window_scaling);
	seq_printf(m, "tcp_options.timestamps_enabled: %d\n",
		init_net.ipv4.sysctl_tcp_timestamps);
	seq_printf(m, "tcp_options.sack_enabled: %d\n",
		init_net.ipv4.sysctl_tcp_sack);
	seq_printf(m, "tcp_options.ecn_enabled: %d\n",
		init_net.ipv4.sysctl_tcp_ecn != 0);

	seq_printf(m, "clock.time_ms: %llu\n", ktime_get_real_ns() / NSEC_PER_MSEC);
	seq_printf(m, "clock.uptime_ms: %u\n", tcp_time_stamp_raw());
	seq_printf(m, "clock.jiffies: %llu\n", get_jiffies_64());
	seq_printf(m, "clock.hz: %d\n", HZ);

	show_bytes(m, "timestamp_secret",
		timestamp_secret_ptr, sizeof(*timestamp_secret_ptr));
	show_bytes(m, "net_secret",
		net_secret_ptr, sizeof(*net_secret_ptr));
	show_bytes(m, "cookie_secret",
		syncookie_secret_ptr, sizeof(*syncookie_secret_ptr));

	return 0;
}

static int isn_sync_open(struct inode *inode, struct file *file)
{
	return single_open(file, isn_sync_show, NULL);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
static const struct file_operations isn_sync_fops = {
	.open		= isn_sync_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#else
static const struct proc_ops isn_sync_fops = {
	.proc_open	= isn_sync_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};
#endif

#ifdef USE_KPROBES
typedef unsigned long (*kallsyms_lookup_name_type)(const char *name);

static int dummy_kprobe_handler(struct kprobe *p, struct pt_regs *regs) {
	return 0;
}

static kallsyms_lookup_name_type find_kallsyms_lookup_name_symbol(void) {
	struct kprobe probe;
	int ret;
	kallsyms_lookup_name_type addr;

	memset(&probe, 0, sizeof(probe));
	probe.pre_handler = dummy_kprobe_handler;
	probe.symbol_name = "kallsyms_lookup_name";
	ret = register_kprobe(&probe);
	if (ret) {
		printk(LOG_PREFIX "register_kprobe() = %d", ret);
		return NULL;
	}
	addr = (kallsyms_lookup_name_type)probe.addr;
	unregister_kprobe(&probe);

	printk(LOG_PREFIX "register_kprobe() = %p", addr);
	return addr;
}
#endif

static unsigned long lookup_name(const char *name) {
#ifdef USE_KPROBES
	static kallsyms_lookup_name_type func_ptr = NULL;
	if (!func_ptr) {
		func_ptr = find_kallsyms_lookup_name_symbol();
    }

	return func_ptr(name);
#else
	return kallsyms_lookup_name(name);
#endif
}

static struct sock *cookie_v4_check_wrapper(struct sock *sk,
                                            struct sk_buff *skb)
{
	cookie_v4_check_type old_func =
		(void*)((unsigned long)cookie_v4_check_ptr + MCOUNT_INSN_SIZE);

	if (sock_net(sk)->ipv4.sysctl_tcp_syncookies == 2) {
		tcp_synq_overflow(sk);
	}
	return old_func(sk, skb);
}

static int tcp_filter_wrapper(struct sock *sk, struct sk_buff *skb)
{
	const struct tcphdr *th = (const struct tcphdr *)skb->data;

	tcp_filter_type old_func =
			(void*)((unsigned long)tcp_filter_ptr + MCOUNT_INSN_SIZE);

	if (th->syn && (th->urg_ptr == SEND_SYN_MARKER))
		return 1;

	return old_func(sk, skb);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define ftrace_regs pt_regs
static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

static void notrace
isn_sync_ftrace_handler(unsigned long ip, unsigned long parent_ip,
			  struct ftrace_ops *fops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	regs->ip = (unsigned long)cookie_v4_check_wrapper;
}

static struct ftrace_ops isn_sync_ftrace_ops __read_mostly = {
	.func = isn_sync_ftrace_handler,
	.flags = FTRACE_OPS_FL_SAVE_REGS,
};

static void notrace isn_sync_tcp_filter_handler(unsigned long ip,
		unsigned long parent_ip, struct ftrace_ops *fops,
		struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	regs->ip = (unsigned long)tcp_filter_wrapper;
}

static struct ftrace_ops isn_sync_tcp_filter_ops __read_mostly = {
	.func = isn_sync_tcp_filter_handler,
	.flags = FTRACE_OPS_FL_SAVE_REGS,
};

static void fix_cookie_v4_check(void)
{
	int ret;

	ret = ftrace_set_filter_ip(
		&isn_sync_ftrace_ops, (unsigned long)cookie_v4_check_ptr, 0, 0);
	if (ret)
		printk(LOG_PREFIX "can't set ftrace filter: err=%d\n", ret);

	ret = register_ftrace_function(&isn_sync_ftrace_ops);
	if (ret)
		printk(LOG_PREFIX "can't set ftrace function: err=%d\n", ret);
}

static void fix_tcp_filter(void)
{
	int ret;

	ret = ftrace_set_filter_ip(
		&isn_sync_tcp_filter_ops, (unsigned long)tcp_filter_ptr, 0, 0);
	if (ret)
		printk(LOG_PREFIX "can't set ftrace filter: err=%d\n", ret);

	ret = register_ftrace_function(&isn_sync_tcp_filter_ops);
	if (ret)
		printk(LOG_PREFIX "can't set ftrace function: err=%d\n", ret);
}

/* Force generation of secrets. */
static void isn_sync_init_secrets(void)
{
	struct iphdr ip = {};
	struct tcphdr tcp = {};
	struct in6_addr addr = {};
	u16 mss;

	/* syncookie_secret */
	__cookie_v4_init_sequence(&ip, &tcp, &mss);

	/* net_secret */
	secure_tcp_seq_ptr(0, 0, 0, 0);

	/* IPv4 version is not exported, but uses the same ts_secret.
	 * Addresses are passed as __be32*, but are used as IPv6.
	 */
	secure_tcpv6_ts_off(&init_net, (const __be32 *)&addr, (const __be32 *)&addr);
}

static int __init isn_sync_init(void) {
	int res = 0;

	do {
	#define _CHECK(_var) \
		if (_var == NULL) { \
			res = -ENXIO; \
			break; \
		}

		cookie_v4_check_ptr = (cookie_v4_check_type)lookup_name("cookie_v4_check");
		_CHECK(cookie_v4_check_ptr)

		tcp_filter_ptr = (tcp_filter_type)lookup_name("tcp_filter");
		_CHECK(tcp_filter_ptr)

		syncookie_secret_ptr = (siphash_key_t(*)[2])lookup_name("syncookie_secret");
		_CHECK(syncookie_secret_ptr)

		net_secret_ptr = (siphash_key_t*)lookup_name("net_secret");
		_CHECK(net_secret_ptr)

		timestamp_secret_ptr = (siphash_key_t*)lookup_name("ts_secret");
		_CHECK(timestamp_secret_ptr)

		secure_tcp_seq_ptr = (secure_tcp_seq_type)lookup_name("secure_tcp_seq");
		_CHECK(secure_tcp_seq_ptr)

	#undef _CHECK
	} while (false);

	if (res != 0) {
		printk(LOG_PREFIX "no access to cookie_v4_check!\n");
		return res;
	}

	fix_cookie_v4_check();
	fix_tcp_filter();

	proc_entry = proc_create(PROC_ENTRY, 0, NULL, &isn_sync_fops);
	if (proc_entry == NULL) {
		printk(LOG_PREFIX "can't create /proc/" PROC_ENTRY "!\n");
		return -EIO;
	}

	isn_sync_init_secrets();
	return 0;
}
module_init(isn_sync_init);

static void __exit isn_sync_exit(void)
{
	int ret;

	if (cookie_v4_check_ptr) {
		ret = unregister_ftrace_function(&isn_sync_ftrace_ops);
		if (ret)
			printk(LOG_PREFIX "can't unregister ftrace\n");

		ret = ftrace_set_filter_ip(&isn_sync_ftrace_ops,
				(unsigned long)cookie_v4_check_ptr, 1, 0);
		if (ret)
			printk(LOG_PREFIX "can't unregister filter\n");

		cookie_v4_check_ptr = NULL;
	}

	if (tcp_filter_ptr) {
		ret = unregister_ftrace_function(&isn_sync_tcp_filter_ops);
		if (ret)
			printk(LOG_PREFIX "can't unregister ftrace\n");

		ret = ftrace_set_filter_ip(&isn_sync_tcp_filter_ops,
				(unsigned long)tcp_filter_ptr, 1, 0);
		if (ret)
			printk(LOG_PREFIX "can't unregister filter\n");

		tcp_filter_ptr = NULL;
	}

	syncookie_secret_ptr = NULL;
	net_secret_ptr = NULL;
	timestamp_secret_ptr = NULL;

	if (proc_entry) {
		remove_proc_entry(PROC_ENTRY, 0);
		proc_entry = NULL;
	}
}
module_exit(isn_sync_exit);

MODULE_AUTHOR("DDoS MITIGATOR");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Provides access to TCP secret keys");
