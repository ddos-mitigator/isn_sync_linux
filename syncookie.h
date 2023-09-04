#pragma once

#include <linux/siphash.h>

typedef siphash_key_t *net_secret_t;
extern net_secret_t net_secret_link;

typedef siphash_key_t (*syncookie_secret_t)[2];
extern syncookie_secret_t syncookie_secret_link;

typedef siphash_key_t *ts_secret_t;
extern ts_secret_t ts_secret_link;

bool isn_syncookie_init(void);
void isn_syncookie_exit(void);
