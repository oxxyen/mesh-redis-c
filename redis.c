#include <stdio.h>
#include <stdlib.h>
#include <hiredis/hiredis.h>
#include <strings.h>
#include <unistd.h>

#define IP_REDIS "127.0.0.1"
#define PORT_REDIS 6379

int main() {
    redisContext *c;
    redisReply *reply;

    c = redisConnect(IP_REDIS, PORT_REDIS);

    if(c == NULL || c->err) {
        if(c) {
            printf("error connect: %s\n", c->errstr);
            redisFree(c);
        } else {
            printf("no select context!\n");
        }
        exit(1);
    }

    reply = redisCommand(c, "SET mykey \"Hello from C!\"");
    freeReplyObject(reply);

    reply = redisCommand(c, "GET mykey");
    printf("GET: %s\n", reply->str);

    redisFree(c);
    return 0;
}