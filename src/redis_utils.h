#ifndef REDIS_UTILS_H
#define REDIS_UTILS_H

#include <hiredis/hiredis.h>

redisContext* redis_connect(const char* host, int port);
int redis_save_user(redisContext *ctx, const char *username, const char *pubkey, const char *ip);
int redis_get_pubkey(redisContext *ctx, const char *username, char *out_pubkey, size_t out_len);
int redis_user_exists(redisContext *ctx, const char *username);

#endif