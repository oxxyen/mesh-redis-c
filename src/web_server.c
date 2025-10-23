#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <libwebsockets.h>
#include <pthread.h>

#include "../include/config.h"

// Статические файлы
static char *html_content = NULL;
static size_t html_len = 0;
static char *css_content = NULL;
static size_t css_len = 0;

#define CHAT_CORE_PORT 8080

struct session {
    int tcp_fd;
};

static struct session g_sessions[100] = {0};
static pthread_mutex_t g_session_mutex = PTHREAD_MUTEX_INITIALIZER;

// Загрузка файла
static int load_file(const char *path, char **out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    *out_len = ftell(f);
    fseek(f, 0, SEEK_SET);
    *out = malloc(*out_len);
    if (!*out) { fclose(f); return -1; }
    fread(*out, 1, *out_len, f);
    fclose(f);
    return 0;
}

// TCP → WebSocket
void* tcp_reader(void* arg) {
    struct lws *wsi = (struct lws*)arg;
    struct session *sess = (struct session*)lws_wsi_user(wsi);
    if (!sess) return NULL;

    char buffer[8192];
    while (1) {
        ssize_t n = recv(sess->tcp_fd, buffer, sizeof(buffer) - 1, 0);
        if (n <= 0) break;
        buffer[n] = '\0';

        unsigned char *buf = malloc(n + LWS_PRE);
        if (!buf) break;
        memcpy(buf + LWS_PRE, buffer, n);
        lws_write(wsi, buf + LWS_PRE, n, LWS_WRITE_TEXT);
        free(buf);
    }
    close(sess->tcp_fd);
    sess->tcp_fd = 0;
    lws_callback_on_writable(wsi);
    return NULL;
}
static int callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    (void)user; (void)in; (void)len;

    switch (reason) {
        case LWS_CALLBACK_HTTP: {
            unsigned char buffer[2048];
            unsigned char *p = buffer + LWS_PRE;
            unsigned char *end = buffer + sizeof(buffer) - 1;

            if (strcmp((const char*)in, "/") == 0 || strcmp((const char*)in, "/index.html") == 0) {
                if (!html_content) {
                    lws_return_http_status(wsi, 500, NULL);
                    return -1;
                }
                if (lws_add_http_header_status(wsi, 200, &p, end) ||
                    lws_add_http_header_by_name(wsi, (unsigned char*)"Content-Type:", (unsigned char*)"text/html", 10, &p, end) ||
                    lws_finalize_http_header(wsi, &p, end)) {
                    return -1;
                }
                // Отправляем заголовки
                int n = lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
                if (n < 0) return -1;

                // Отправляем тело
                n = lws_write(wsi, (unsigned char*)html_content, html_len, LWS_WRITE_HTTP);
                if (n < 0) return -1;

                // Завершаем сессию
                lws_http_transaction_completed(wsi);
                return 0;
            } else if (strcmp((const char*)in, "/style.css") == 0) {
                if (!css_content) {
                    lws_return_http_status(wsi, 500, NULL);
                    return -1;
                }
                if (lws_add_http_header_status(wsi, 200, &p, end) ||
                    lws_add_http_header_by_name(wsi, (unsigned char*)"Content-Type:", (unsigned char*)"text/css", 8, &p, end) ||
                    lws_finalize_http_header(wsi, &p, end)) {
                    return -1;
                }
                int n = lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
                if (n < 0) return -1;

                n = lws_write(wsi, (unsigned char*)css_content, css_len, LWS_WRITE_HTTP);
                if (n < 0) return -1;

                lws_http_transaction_completed(wsi);
                return 0;
            } else {
                lws_return_http_status(wsi, 404, NULL);
                return 0;
            }
        }
        default:
            return 0;
    }
}

static int callback_ws(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    struct session *sess = (struct session*)user;
    (void)in; (void)len;

    switch (reason) {
        case LWS_CALLBACK_ESTABLISHED: {
            pthread_mutex_lock(&g_session_mutex);
            for (int i = 0; i < 100; i++) {
                if (g_sessions[i].tcp_fd == 0) {
                    sess = &g_sessions[i];
                    break;
                }
            }
            pthread_mutex_unlock(&g_session_mutex);

            if (!sess) return 1;

            int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(CHAT_CORE_PORT);
            inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
            if (connect(tcp_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                close(tcp_fd);
                return 1;
            }
            sess->tcp_fd = tcp_fd;

            // Запускаем читателя
            pthread_t tid;
            pthread_create(&tid, NULL, tcp_reader, wsi);
            pthread_detach(tid);
            break;
        }
        case LWS_CALLBACK_RECEIVE: {
            if (sess && sess->tcp_fd > 0) {
                send(sess->tcp_fd, in, len, 0);
            }
            break;
        }
        case LWS_CALLBACK_CLOSED: {
            if (sess) {
                close(sess->tcp_fd);
                sess->tcp_fd = 0;
            }
            break;
        }
        default:
            return 0;
    }
    return 0;
}

// Важно: 7 полей в структуре
static struct lws_protocols protocols[] = {
    { "http", callback_http, 0, 0, 0, NULL, 0 },
    { "ws", callback_ws, sizeof(struct session), 0, 0, NULL, 0 },
    { NULL, NULL, 0, 0, 0, NULL, 0 }
};

int main(void) {
    if (load_file("src/static/index.html", &html_content, &html_len) < 0) {
        fprintf(stderr, "Failed to load index.html\n");
        return 1;
    }
    if (load_file("src/static/style.css", &css_content, &css_len) < 0) {
        fprintf(stderr, "Failed to load style.css\n");
        free(html_content);
        return 1;
    }

    printf("✅ Loaded index.html (%zu bytes)\n", html_len);
    printf("✅ Loaded style.css (%zu bytes)\n", css_len);

    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
    info.port = 8081;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;

    struct lws_context *context = lws_create_context(&info);
    if (!context) {
        fprintf(stderr, "libwebsockets init failed\n");
        free(html_content);
        free(css_content);
        return 1;
    }

    printf("🌐 Web server running on http://localhost:8081\n");

    while (1) {
        lws_service(context, 1000);
    }

    lws_context_destroy(context);
    free(html_content);
    free(css_content);
    return 0;
}