// SPDX-License-Identifier: Apache-2.0
// Link against identity_counter.c compiled with -Dmain=identity_counter.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define SERVICE_PORT 34567

int identity_counter(void);

static int endpoint(int kind)
{
    int fd = socket(AF_INET, kind | SOCK_CLOEXEC, 0);
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(SERVICE_PORT),
        .sin_addr = { .s_addr = INADDR_ANY },
    };
    if (fd < 0 || bind(fd, (struct sockaddr *)&address, sizeof(address)))
        _exit(6);
    return fd;
}

static void serve(void)
{
    struct pollfd sockets[] = {
        { .fd = endpoint(SOCK_STREAM), .events = POLLIN },
        { .fd = endpoint(SOCK_DGRAM), .events = POLLIN },
    };
    if (listen(sockets[0].fd, 8))
        _exit(7);
    while (poll(sockets, 2, -1) > 0) {
        char buffer[256];
        if (sockets[0].revents & POLLIN) {
            int accepted = accept4(sockets[0].fd, NULL, NULL, SOCK_CLOEXEC);
            if (accepted >= 0) {
                ssize_t count = recv(accepted, buffer, sizeof(buffer), 0);
                if (count > 0)
                    send(accepted, buffer, count, MSG_NOSIGNAL);
                close(accepted);
            }
        }
        if (sockets[1].revents & POLLIN) {
            struct sockaddr_in peer;
            socklen_t length = sizeof(peer);
            ssize_t count = recvfrom(sockets[1].fd, buffer, sizeof(buffer), 0,
                                     (struct sockaddr *)&peer, &length);
            if (count > 0)
                sendto(sockets[1].fd, buffer, count, 0, (struct sockaddr *)&peer, length);
        }
    }
    _exit(8);
}

int main(void)
{
    int service = fork();
    if (service < 0)
        return 9;
    if (service == 0)
        serve();
    return identity_counter();
}
