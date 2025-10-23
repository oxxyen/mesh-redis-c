#include "redis_utils.h"
#include <hiredis/hiredis.h>
#include <string.h>
#include <stdlib.h>

redisContext* redis_connect(const char* host, int port) {
    redisContext *ctx = redisConnect(host, port);
    if (!ctx || ctx->err) {
        if (ctx) {
            fprintf(stderr, "Redis error: %s\n", ctx->errstr);
            redisFree(ctx);
        }
        return NULL;
    }
    return ctx;
}

int redis_save_user(redisContext *ctx, const char *username, const char *pubkey, const char *ip) {
    if (!ctx || !username || !pubkey || !ip) return 0;
    redisReply *r = redisCommand(ctx, "HSET user:%s pubkey %s ip %s", username, pubkey, ip);
    if (!r) return 0;
    freeReplyObject(r);
    return 1;
}

int redis_get_pubkey(redisContext *ctx, const char *username, char *out_pubkey, size_t out_len) {
    if (!ctx || !username || !out_pubkey) return 0;
    redisReply *r = redisCommand(ctx, "HGET user:%s pubkey", username);
    if (!r || r->type != REDIS_REPLY_STRING) {
        if (r) freeReplyObject(r);
        return 0;
    }
    if (r->len >= (long)out_len) {
        freeReplyObject(r);
        return 0; // too long
    }
    memcpy(out_pubkey, r->str, r->len + 1);
    freeReplyObject(r);
    return 1;
}

int redis_user_exists(redisContext *ctx, const char *username) {
    if (!ctx || !username) return 0;
    redisReply *r = redisCommand(ctx, "EXISTS user:%s", username);
    if (!r || r->type != REDIS_REPLY_INTEGER) {
        if (r) freeReplyObject(r);
        return 0;
    }
    int exists = (r->integer == 1);
    freeReplyObject(r);
    return exists;
}