#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <sodium.h>

#include "../include/config.h"
#include <hiredis/hiredis.h>

// Forward
int generate_ssh_keypair(char *pubkey_b64, size_t pubkey_len, char *privkey_b64, size_t privkey_len);

// =============== DATA MODELS ===============
typedef struct {
    int fd;
    char pubkey[MAX_PUBKEY_B64];
    char username[MAX_USERNAME];
    int is_authenticated;
} client_t;

static client_t g_online[MAX_CLIENTS] = {0};
static pthread_mutex_t g_online_mutex = PTHREAD_MUTEX_INITIALIZER;

// Приватные чаты: кто с кем
typedef struct {
    char initiator[MAX_PUBKEY_B64];
    char target[MAX_PUBKEY_B64];
    int pending; // 1 = ожидает accept
} invite_t;

static invite_t g_invites[MAX_CLIENTS] = {0};
static pthread_mutex_t g_invite_mutex = PTHREAD_MUTEX_INITIALIZER;

// Группы
typedef struct {
    char name[MAX_GROUP_NAME];
    char members[MAX_GROUP_MEMBERS][MAX_PUBKEY_B64];
    int member_count;
    int active;
} group_t;

static group_t g_groups[MAX_GROUPS] = {0};
static pthread_mutex_t g_group_mutex = PTHREAD_MUTEX_INITIALIZER;

// =============== GLOBALS ===============
static redisContext *g_redis = NULL;
static volatile sig_atomic_t g_shutdown = 0;

// =============== UTILS ===============
void trim_newline(char *s) {
    s[strcspn(s, "\r\n")] = 0;
}

client_t* find_online_by_fd(int fd) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_online[i].fd == fd) return &g_online[i];
    }
    return NULL;
}

client_t* find_online_by_pubkey(const char *pubkey) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_online[i].is_authenticated && strcmp(g_online[i].pubkey, pubkey) == 0) {
            return &g_online[i];
        }
    }
    return NULL;
}

const char* get_username_by_pubkey(const char *pubkey) {
    static char username[MAX_USERNAME];
    redisReply *r = redisCommand(g_redis, "HGET user:%s username", pubkey);
    if (r && r->type == REDIS_REPLY_STRING) {
        strncpy(username, r->str, MAX_USERNAME - 1);
        freeReplyObject(r);
        return username;
    }
    if (r) freeReplyObject(r);
    return "unknown";
}

void send_to_client(int fd, const char *msg) {
    send(fd, msg, strlen(msg), MSG_NOSIGNAL);
}

// =============== INVITE SYSTEM ===============
int create_invite(const char *initiator, const char *target) {
    pthread_mutex_lock(&g_invite_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!g_invites[i].pending) {
            strncpy(g_invites[i].initiator, initiator, MAX_PUBKEY_B64 - 1);
            strncpy(g_invites[i].target, target, MAX_PUBKEY_B64 - 1);
            g_invites[i].pending = 1;
            pthread_mutex_unlock(&g_invite_mutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_invite_mutex);
    return 0;
}

int accept_invite(const char *acceptor, const char *initiator) {
    pthread_mutex_lock(&g_invite_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_invites[i].pending &&
            strcmp(g_invites[i].initiator, initiator) == 0 &&
            strcmp(g_invites[i].target, acceptor) == 0) {
            g_invites[i].pending = 0;
            pthread_mutex_unlock(&g_invite_mutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_invite_mutex);
    return 0;
}

int is_private_allowed(const char *pk1, const char *pk2) {
    pthread_mutex_lock(&g_invite_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!g_invites[i].pending) {
            if ((strcmp(g_invites[i].initiator, pk1) == 0 && strcmp(g_invites[i].target, pk2) == 0) ||
                (strcmp(g_invites[i].initiator, pk2) == 0 && strcmp(g_invites[i].target, pk1) == 0)) {
                pthread_mutex_unlock(&g_invite_mutex);
                return 1;
            }
        }
    }
    pthread_mutex_unlock(&g_invite_mutex);
    return 0;
}

// =============== GROUP SYSTEM ===============
int create_group(const char *name, const char *creator_pubkey) {
    if (strlen(name) > MAX_GROUP_NAME - 1) return 0;
    pthread_mutex_lock(&g_group_mutex);
    for (int i = 0; i < MAX_GROUPS; i++) {
        if (!g_groups[i].active) {
            strncpy(g_groups[i].name, name, MAX_GROUP_NAME - 1);
            strncpy(g_groups[i].members[0], creator_pubkey, MAX_PUBKEY_B64 - 1);
            g_groups[i].member_count = 1;
            g_groups[i].active = 1;
            pthread_mutex_unlock(&g_group_mutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_group_mutex);
    return 0;
}

int join_group(const char *name, const char *pubkey) {
    pthread_mutex_lock(&g_group_mutex);
    for (int i = 0; i < MAX_GROUPS; i++) {
        if (g_groups[i].active && strcmp(g_groups[i].name, name) == 0) {
            if (g_groups[i].member_count >= MAX_GROUP_MEMBERS) {
                pthread_mutex_unlock(&g_group_mutex);
                return 0;
            }
            for (int j = 0; j < g_groups[i].member_count; j++) {
                if (strcmp(g_groups[i].members[j], pubkey) == 0) {
                    pthread_mutex_unlock(&g_group_mutex);
                    return 1; // уже в группе
                }
            }
            strncpy(g_groups[i].members[g_groups[i].member_count], pubkey, MAX_PUBKEY_B64 - 1);
            g_groups[i].member_count++;
            pthread_mutex_unlock(&g_group_mutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_group_mutex);
    return 0;
}

void broadcast_to_group(const char *group_name, const char *sender_pubkey, const char *msg) {
    pthread_mutex_lock(&g_group_mutex);
    for (int i = 0; i < MAX_GROUPS; i++) {
        if (g_groups[i].active && strcmp(g_groups[i].name, group_name) == 0) {
            for (int j = 0; j < g_groups[i].member_count; j++) {
                client_t *c = find_online_by_pubkey(g_groups[i].members[j]);
                if (c && strcmp(c->pubkey, sender_pubkey) != 0) {
                    char buf[BUFFER_SIZE];
                    const char *uname = get_username_by_pubkey(sender_pubkey);
                    snprintf(buf, sizeof(buf), "[groups:%s] [%s]: %s\n", group_name, uname, msg);
                    send_to_client(c->fd, buf);
                }
            }
        }
    }
    pthread_mutex_unlock(&g_group_mutex);
}

// =============== MESSAGE HANDLERS ===============
void handle_register(client_t *client, const char *username) {
    if (strlen(username) > MAX_USERNAME - 1 || strlen(username) == 0) {
        send_to_client(client->fd, "ERR: Invalid username\n");
        return;
    }
    char pubkey_b64[MAX_PUBKEY_B64];
    char privkey_b64[200];
    if (!generate_ssh_keypair(pubkey_b64, sizeof(pubkey_b64), privkey_b64, sizeof(privkey_b64))) {
        send_to_client(client->fd, "ERR: Key generation failed\n");
        return;
    }
    redisReply *r = redisCommand(g_redis,
        "HSET user:%s username %s privkey %s ip %s",
        pubkey_b64, username, privkey_b64, "127.0.0.1"
    );
    if (!r || r->type == REDIS_REPLY_ERROR) {
        freeReplyObject(r);
        send_to_client(client->fd, "ERR: Redis save failed\n");
        return;
    }
    freeReplyObject(r);
    char reply[BUFFER_SIZE];
    snprintf(reply, sizeof(reply),
        "OK: Registered!\nYour public key (SAVE IT):\n%s\nUse /login <key> next time.\n",
        pubkey_b64);
    send_to_client(client->fd, reply);
}

void handle_login(client_t *client, const char *pubkey) {
    redisReply *r = redisCommand(g_redis, "HGET user:%s username", pubkey);
    if (!r || r->type != REDIS_REPLY_STRING) {
        freeReplyObject(r);
        send_to_client(client->fd, "ERR: User not found\n");
        return;
    }
    strncpy(client->pubkey, pubkey, MAX_PUBKEY_B64 - 1);
    strncpy(client->username, r->str, MAX_USERNAME - 1);
    client->is_authenticated = 1;
    freeReplyObject(r);
    send_to_client(client->fd, "OK: Logged in. Use:\n/public <msg>\n/invite <pubkey>\n/accept <pubkey>\n/create_group <name>\n/join_group <name>\n/send_group <name> <msg>\n");
}

void handle_invite(client_t *client, const char *target_pk) {
    client_t *target = find_online_by_pubkey(target_pk);
    if (!target) {
        send_to_client(client->fd, "ERR: User not online\n");
        return;
    }
    if (!create_invite(client->pubkey, target_pk)) {
        send_to_client(client->fd, "ERR: Too many invites\n");
        return;
    }
    char msg[BUFFER_SIZE];
    snprintf(msg, sizeof(msg), "INCOMING INVITE from %s (%s)\n", client->pubkey, client->username);
    send_to_client(target->fd, msg);
    send_to_client(client->fd, "OK: Invite sent\n");
}

void handle_accept(client_t *client, const char *initiator_pk) {
    if (!accept_invite(client->pubkey, initiator_pk)) {
        send_to_client(client->fd, "ERR: No pending invite from this user\n");
        return;
    }
    send_to_client(client->fd, "OK: Private chat established\n");
}

void handle_create_group(client_t *client, const char *name) {
    if (create_group(name, client->pubkey)) {
        send_to_client(client->fd, "OK: Group created\n");
    } else {
        send_to_client(client->fd, "ERR: Group creation failed\n");
    }
}

void handle_join_group(client_t *client, const char *name) {
    if (join_group(name, client->pubkey)) {
        send_to_client(client->fd, "OK: Joined group\n");
    } else {
        send_to_client(client->fd, "ERR: Cannot join group\n");
    }
}

void handle_send_group(client_t *client, const char *cmd) {
    char group_name[MAX_GROUP_NAME];
    char *msg = strchr(cmd, ' ');
    if (!msg) {
        send_to_client(client->fd, "Usage: /send_group <group> <message>\n");
        return;
    }
    *msg = '\0';
    strncpy(group_name, cmd, MAX_GROUP_NAME - 1);
    msg++;
    broadcast_to_group(group_name, client->pubkey, msg);
    char echo[BUFFER_SIZE];
    snprintf(echo, sizeof(echo), "[me@%s]: %s\n", group_name, msg);
    send_to_client(client->fd, echo);
}

void handle_public(client_t *client, const char *msg) {
    pthread_mutex_lock(&g_online_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_online[i].fd > 0 && strcmp(g_online[i].pubkey, client->pubkey) != 0) {
            char buf[BUFFER_SIZE];
           snprintf(buf, sizeof(buf), "[public] [%s]: %s\n", client->username, msg);
           send_to_client(g_online[i].fd, buf); 
        }
    }
    pthread_mutex_unlock(&g_online_mutex);
    char echo[BUFFER_SIZE];
    snprintf(echo, sizeof(echo), "[me]: %s\n", msg);
    send_to_client(client->fd, echo);
}

void handle_private(client_t *client, const char *cmd) {
    char target_pk[MAX_PUBKEY_B64];
    char *msg = strchr(cmd, ' ');
    if (!msg) {
        send_to_client(client->fd, "Usage: /private <pubkey> <message>\n");
        return;
    }
    *msg = '\0';
    strncpy(target_pk, cmd, MAX_PUBKEY_B64 - 1);
    msg++;
    if (!is_private_allowed(client->pubkey, target_pk)) {
        send_to_client(client->fd, "ERR: No private session. Use /invite first.\n");
        return;
    }
    client_t *target = find_online_by_pubkey(target_pk);
    if (!target) {
        send_to_client(client->fd, "ERR: User offline\n");
        return;
    }
    char buf[BUFFER_SIZE];
    snprintf(buf, sizeof(buf), "[private] [%s]: %s\n", client->username, msg);
    send_to_client(target->fd, buf);
    snprintf(buf, sizeof(buf), "[me -> %s]: %s\n", get_username_by_pubkey(target_pk), msg);
    send_to_client(client->fd, buf);
}

// =============== CLIENT HANDLER ===============
void* client_handler(void* arg) {
    int client_fd = *(int*)arg;
    free(arg);

    client_t client = {0};
    client.fd = client_fd;
    send(client_fd, 
        "🔐 Secure Chat v2.0\n"
        "/register <username>\n"
        "/login <your_pubkey>\n", 60, 0);

    char buffer[BUFFER_SIZE];

    while (!g_shutdown) {
        ssize_t n = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
        if (n <= 0) break;
        buffer[n] = '\0';
        trim_newline(buffer);

        if (strncmp(buffer, "/register ", 10) == 0) {
            handle_register(&client, buffer + 10);
        } else if (strncmp(buffer, "/login ", 7) == 0) {
            handle_login(&client, buffer + 7);
        } else if (strncmp(buffer, "/invite ", 8) == 0) {
            if (!client.is_authenticated) { send_to_client(client_fd, "ERR: Login first\n"); continue; }
            handle_invite(&client, buffer + 8);
        } else if (strncmp(buffer, "/accept ", 8) == 0) {
            if (!client.is_authenticated) { send_to_client(client_fd, "ERR: Login first\n"); continue; }
            handle_accept(&client, buffer + 8);
        } else if (strncmp(buffer, "/create_group ", 14) == 0) {
            if (!client.is_authenticated) { send_to_client(client_fd, "ERR: Login first\n"); continue; }
            handle_create_group(&client, buffer + 14);
        } else if (strncmp(buffer, "/join_group ", 12) == 0) {
            if (!client.is_authenticated) { send_to_client(client_fd, "ERR: Login first\n"); continue; }
            handle_join_group(&client, buffer + 12);
        } else if (strncmp(buffer, "/send_group ", 12) == 0) {
            if (!client.is_authenticated) { send_to_client(client_fd, "ERR: Login first\n"); continue; }
            handle_send_group(&client, buffer + 12);
        } else if (strncmp(buffer, "/public ", 8) == 0) {
            if (!client.is_authenticated) { send_to_client(client_fd, "ERR: Login first\n"); continue; }
            handle_public(&client, buffer + 8);
        } else if (strncmp(buffer, "/private ", 9) == 0) {
            if (!client.is_authenticated) { send_to_client(client_fd, "ERR: Login first\n"); continue; }
            handle_private(&client, buffer + 9);
        } else if (strcmp(buffer, "/quit") == 0) {
            break;
        } else if (client.is_authenticated) {
            // По умолчанию — публичное сообщение
            handle_public(&client, buffer);
        } else {
            send_to_client(client_fd, "ERR: Unknown command. Use /register or /login\n");
        }
    }

    // Cleanup
    pthread_mutex_lock(&g_online_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_online[i].fd == client_fd) {
            g_online[i].fd = 0;
            break;
        }
    }
    pthread_mutex_unlock(&g_online_mutex);

    close(client_fd);
    return NULL;
}

// =============== MAIN ===============
void signal_handler(int sig) {
    (void)sig;
    g_shutdown = 1;
}

int main() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (sodium_init() < 0) {
        fprintf(stderr, "[FATAL] libsodium init failed\n");
        exit(EXIT_FAILURE);
    }

    g_redis = redisConnect(REDIS_HOST, REDIS_PORT);
    if (!g_redis) {
        fprintf(stderr, "[FATAL] Redis context allocation failed\n");
        exit(EXIT_FAILURE);
    }
    if (g_redis->err) {
        fprintf(stderr, "[FATAL] Redis error: %s\n", g_redis->errstr);
        redisFree(g_redis);
        exit(EXIT_FAILURE);
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) exit(EXIT_FAILURE);

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(SERVER_PORT);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) exit(EXIT_FAILURE);
    if (listen(server_fd, MAX_CLIENTS) < 0) exit(EXIT_FAILURE);

    printf("✅ Secure Chat Server v2.0 running on port %d\n", SERVER_PORT);
    printf("   Features: /register, /login, /invite, /accept, groups, media\n");

    while (!g_shutdown) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int *pfd = malloc(sizeof(int));
        *pfd = accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);

        if (*pfd < 0) {
            free(pfd);
            if (errno == EINTR) continue;
            break;
        }

        pthread_mutex_lock(&g_online_mutex);
        int found = 0;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (g_online[i].fd == 0) {
                g_online[i].fd = *pfd;
                found = 1;
                break;
            }
        }
        pthread_mutex_unlock(&g_online_mutex);

        if (!found) {
            close(*pfd);
            free(pfd);
            continue;
        }

        pthread_t tid;
        if (pthread_create(&tid, NULL, client_handler, pfd) != 0) {
            close(*pfd);
            free(pfd);
        } else {
            pthread_detach(tid);
        }
    }

    redisFree(g_redis);
    close(server_fd);
    return 0;
}