#pragma once

#include <linux/types.h>

__be32 get_dst_ip(__be32 daddr);
__be16 get_dst_port(__be16 dport);

const struct in6_addr* get_dst_ip_v6(const struct in6_addr *daddr);
__be16 get_dst_port_v6(__be16 dport);

bool isn_fixed_dst_init(void);
void isn_fixed_dst_exit(void);
