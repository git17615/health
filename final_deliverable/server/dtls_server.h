#ifndef DTLS_SERVER_H
#define DTLS_SERVER_H

#include <openssl/ssl.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET socket_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
typedef int socket_t;
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#endif

#define MAX_CLIENTS 100
#define BUFFER_SIZE 2048
#define SERVER_PORT 4444

#include "../common.h"

typedef struct {
    int active;
    socket_t fd;
    SSL *ssl;
    struct sockaddr_storage addr;
    socklen_t addr_len;
} ClientContext;

void cleanup_client(ClientContext *client);

#endif // DTLS_SERVER_H
