//* client.c  */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <termios.h>
#include <ctype.h>

#include "../include/config.h"

#define GRAY "\033[90m"
#define GREEN "\033[32m"
#define CYAN "\033[36m"
#define YELLOW "\033[33m"
#define RED "\033[31m"
#define RESET "\033[0m"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <server_ip>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) exit(EXIT_FAILURE);

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, argv[1], &addr.sin_addr) <= 0) exit(EXIT_FAILURE);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) exit(EXIT_FAILURE);

    struct termios old_term, new_term;
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

    char input[BUFFER_SIZE];
    int pos = 0;
    char msg[BUFFER_SIZE];

    struct pollfd fds[2] = {
        {sock, POLLIN, 0},
        {STDIN_FILENO, POLLIN, 0}
    };

    printf(GREEN "🔐 C-Mesh v2.0\n" RESET);
    printf(CYAN "> " RESET);
    fflush(stdout);

    while (1) {
        if (poll(fds, 2, -1) <= 0) break;

        if (fds[0].revents & POLLIN) {
            ssize_t n = recv(sock, msg, sizeof(msg) - 1, 0);
            if (n <= 0) break;
            msg[n] = '\0';

            // Цветной вывод
            char *out = msg;
            if (strstr(msg, "ERR:")) {
                printf(RED "%.*s" RESET, (int)n, msg);
            } else if (strstr(msg, "OK:") || strstr(msg, "INCOMING")) {
                printf(YELLOW "%.*s" RESET, (int)n, msg);
            } else {
                printf("%.*s", (int)n, msg);
            }

            if (pos > 0) {
                printf("\r%s> %.*s", CYAN, pos, input);
            }
            printf(CYAN "> " RESET);
            fflush(stdout);
        }

        if (fds[1].revents & POLLIN) {
            char c;
            if (read(STDIN_FILENO, &c, 1) == 1) {
                if (c == '\n' || c == '\r') {
                    if (pos > 0) {
                        input[pos] = '\0';
                        send(sock, input, pos, 0);
                        if (strcmp(input, "/quit") == 0) break;
                        pos = 0;
                    }
                    printf("\n" CYAN "> " RESET);
                    fflush(stdout);
                } else if (c == 127 || c == '\b') {
                    if (pos > 0) {
                        pos--;
                        printf("\r%s> %.*s ", CYAN, pos, input);
                        printf(CYAN "> " RESET);
                        fflush(stdout);
                    }
                } else if (pos < BUFFER_SIZE - 1 && isprint(c)) {
                    input[pos++] = c;
                    printf("%c", c);
                    fflush(stdout);
                }
            }
        }
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    printf("\n" GRAY "🔒 Disconnected.\n" RESET);
    close(sock);
    return 0;
}