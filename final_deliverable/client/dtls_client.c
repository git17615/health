#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "health.h"

#define SERVER_PORT 4444
#define BUFFER_SIZE 2048



void init_openssl() {
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method = DTLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: %s <server_ip> <client_id>\n", argv[0]);
        return 1;
    }

    const char *server_ip = argv[1];
    const char *client_id = argv[2];

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed.\n");
        return 1;
    }
#endif

    init_openssl();
    SSL_CTX *ctx = create_context();

    // In a real environment, verify the server certificate
    if (SSL_CTX_load_verify_locations(ctx, "certs/ca.crt", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5");

    // Load Client Certificates to enable optional mutual authentication
    if (SSL_CTX_use_certificate_file(ctx, "certs/client.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "certs/client.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
    }

    HealthPacket packet;

    // Reconnect loop
    while (1) {
        socket_t server_fd;
        struct sockaddr_in server_addr;

        server_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (server_fd == INVALID_SOCKET) {
            perror("socket");
#ifdef _WIN32
            Sleep(5000);
#else
            sleep(5);
#endif
            continue;
        }

        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(SERVER_PORT);
        if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
            perror("inet_pton");
            exit(EXIT_FAILURE);
        }

        if (connect(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
            perror("connect");
#ifdef _WIN32
            closesocket(server_fd);
            Sleep(5000);
#else
            close(server_fd);
            sleep(5);
#endif
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        BIO *bio = BIO_new_dgram(server_fd, BIO_CLOSE);


        // Notify BIO about connected state
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &server_addr);
        SSL_set_bio(ssl, bio, bio);

        struct timeval timeout;
        timeout.tv_sec = 3;
        timeout.tv_usec = 0;

        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        printf("Connecting to Server %s:%d (DTLS)...\n", server_ip, SERVER_PORT);

        // Handshake
        int ssl_connected = 0;
        
        int retries = 0;
        while (!ssl_connected && retries < 10) {
    int ret = SSL_connect(ssl);
    

    if (ret <= 0) {
        int err = SSL_get_error(ssl, ret);

        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(server_fd, &fds);

            struct timeval tv;
            tv.tv_sec = 2;
            tv.tv_usec = 0;

            int ready = select(server_fd + 1, &fds, NULL, NULL, &tv);
            if (ready <= 0) continue;
        } else {
            printf("SSL_connect failed.\n");
            ERR_print_errors_fp(stderr);
           
            break;
            
        }
          retries++; 
    } else {
        ssl_connected = 1;
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
    }
}

if (!ssl_connected) {
    printf("Handshake timeout\n");

    SSL_shutdown(ssl);
    SSL_free(ssl);
#ifdef _WIN32
    closesocket(server_fd);
#else
    close(server_fd);
#endif
    continue;
}

        while (1) {
            memset(&packet, 0, sizeof(packet));
            strncpy(packet.client_id, client_id, sizeof(packet.client_id) - 1);

            get_system_health(&packet);

            int written = SSL_write(ssl, &packet, sizeof(packet));
            if (written <= 0) {
                int err = SSL_get_error(ssl, written);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    fd_set fds;
                    FD_ZERO(&fds);
                    FD_SET(server_fd, &fds);

                    struct timeval tv;
                    tv.tv_sec = 2;
                    tv.tv_usec = 0;

                    int ready = select(server_fd + 1, &fds, NULL, NULL, &tv);
                    if (ready <= 0) continue;
                } else {
                    printf("Connection lost. Failed to write to server.\n");
                    break; // Break inner loop to reconnect
                }
            }

            printf("Sent metrics: CPU=%.2f, RAM=%.2f, DISK = %.2f, NET = %.2f\n", packet.cpu_usage, packet.ram_usage, packet.disk_usage, packet.net_usage);

#ifdef _WIN32
            Sleep(5000);
#else
            sleep(5);
#endif
        }

        // Cleanup before reconnecting
        SSL_shutdown(ssl);
        SSL_free(ssl);
#ifdef _WIN32
        closesocket(server_fd);
#else
        close(server_fd);
#endif

        printf("Reconnecting in 5 seconds...\n");
#ifdef _WIN32
        Sleep(5000);
#else
        sleep(5);
#endif
    }

    SSL_CTX_free(ctx);
    cleanup_openssl();

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
