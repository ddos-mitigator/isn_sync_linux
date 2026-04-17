#include <linux/in6.h>
#include <linux/inet.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/version.h>

#include "common.h"
#include "fixed_dst.h"

#define _BUFFER_SIZE 512

bool isn_use_fixed_dst = false;
__be32 isn_fixed_dst_ip = 0;
__be16 isn_fixed_dst_port = 0;

bool isn_use_fixed_dst_v6 = false;
struct in6_addr isn_fixed_dst_ip_v6;
__be16 isn_fixed_dst_port_v6 = 0;

__be32 get_dst_ip(__be32 daddr)
{
    if (isn_use_fixed_dst) {
        return isn_fixed_dst_ip;
    }
    return daddr;
}

__be16 get_dst_port(__be16 dport)
{
    if (isn_use_fixed_dst) {
        return isn_fixed_dst_port;
    }
    return dport;
}

const struct in6_addr* get_dst_ip_v6(const struct in6_addr *daddr) {
    if (isn_use_fixed_dst_v6) {
        return &isn_fixed_dst_ip_v6;
    }
    return daddr;
}

__be16 get_dst_port_v6(__be16 dport)
{
    if (isn_use_fixed_dst_v6) {
        return isn_fixed_dst_port_v6;
    }
    return dport;
}

static int parse_port(const char *str, __be16 *port)
{
    u32 res = 0;

    if (sscanf(str, "%u", &res) != 1)
        return -EINVAL;

    if (res > __UINT16_MAX__)
        return -EINVAL;

    *port = __cpu_to_be16(res);
    return 0;
}

static int fixed_dst_show(struct seq_file *file, void *v)
{
    if (!isn_use_fixed_dst)
        return 0;

    seq_printf(file, "%pI4:%u\n", &isn_fixed_dst_ip, __be16_to_cpu(isn_fixed_dst_port));

    return 0;
}

static int fixed_dst_open(struct inode *inode, struct file *file)
{
    return single_open(file, fixed_dst_show, NULL);
}

static ssize_t fixed_dst_write(struct file *file, const char* buffer, size_t len,
        loff_t *off)
{
    int err;
    char kbuffer[_BUFFER_SIZE];
    const char *ptr;
    __be32 dst_ip;
    __be16 dst_port;

    if (len == 0)
        goto disabled;

    err = copy_from_user(kbuffer, buffer, min(len, _BUFFER_SIZE));
    if (err)
        return err;

    ptr = skip_spaces(kbuffer);

    if (*ptr == 0)
        goto disabled;

    if (in4_pton(ptr, len, (u8 *)&dst_ip, ':', &ptr) == 0)
        return -EINVAL;

    if (*ptr++ != ':')
        return -EINVAL;

    err = parse_port(ptr, &dst_port);
    if (err)
        return err;

    isn_fixed_dst_ip = dst_ip;
    isn_fixed_dst_port = dst_port;
    isn_use_fixed_dst = true;
    return len;

disabled:
    isn_use_fixed_dst = false;
    return len;
}

_DEFINE_PROC_VAR(fixed_dst);

static int fixed_dst_v6_show(struct seq_file *file, void *v)
{
    if (!isn_use_fixed_dst_v6)
        return 0;

    seq_printf(file, "[%pI6]:%u\n", &isn_fixed_dst_ip_v6.in6_u.u6_addr8,
            __be16_to_cpu(isn_fixed_dst_port_v6));

    return 0;
}

static int fixed_dst_v6_open(struct inode *inode, struct file *file)
{
    return single_open(file, fixed_dst_v6_show, NULL);
}

static ssize_t fixed_dst_v6_write(struct file *file, const char* buffer, size_t len,
        loff_t *off)
{
    int err;
    char kbuffer[_BUFFER_SIZE];
    const char *ptr;
    struct in6_addr dst_ip;
    __be16 dst_port;

    if (len == 0)
        goto disabled;

    err = copy_from_user(kbuffer, buffer, min(len, _BUFFER_SIZE));
    if (err)
        return err;

    ptr = skip_spaces(kbuffer);

    if (*ptr == 0)
        goto disabled;

    if (*ptr++ != '[')
        return -EINVAL;

    if (in6_pton(ptr, len, dst_ip.in6_u.u6_addr8, ']', &ptr) == 0)
        return -EINVAL;

    if (*ptr++ != ']')
        return -EINVAL;
    if (*ptr++ != ':')
        return -EINVAL;

    err = parse_port(ptr, &dst_port);
    if (err)
        return -EINVAL;

    isn_fixed_dst_ip_v6 = dst_ip;
    isn_fixed_dst_port_v6 = dst_port;
    isn_use_fixed_dst_v6 = true;
    return len;

disabled:
    isn_use_fixed_dst_v6 = false;
    return len;
}

_DEFINE_PROC_VAR(fixed_dst_v6);

bool isn_fixed_dst_init(void)
{
    return isn_procfs_init_fixed_dst() && isn_procfs_init_fixed_dst_v6();
}

void isn_fixed_dst_exit(void)
{
    isn_procfs_exit_fixed_dst_v6();
    isn_procfs_exit_fixed_dst();
}
