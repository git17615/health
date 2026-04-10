#include "dtls_server.h"
#include "logger.h"
#include <openssl/err.h>
#include <openssl/bio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// To handle select() on multiple sockets
ClientContext clients[MAX_CLIENTS];

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    // A simple cookie generator for demonstration. In production, use HMAC with a secret.
    *cookie_len = 16;
    RAND_bytes(cookie, *cookie_len);
    return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
    if (cookie_len == 16 ) return 1;
    return 0;
}

void cleanup_client(ClientContext *client) {
    if (client->ssl) {
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
        client->ssl = NULL;
    }
#ifdef _WIN32
    if (client->fd != INVALID_SOCKET) closesocket(client->fd);
#else
    if (client->fd != INVALID_SOCKET) close(client->fd);
#endif
    client->active = 0;
    client->fd = INVALID_SOCKET;
}

void init_openssl() {
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method = DTLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    // Set cookie generation and verification callbacks
    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);
    
    // Optional but recommended
    SSL_CTX_set_read_ahead(ctx, 1);
    
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    // Load Certificates
    if (SSL_CTX_use_certificate_file(ctx, "certs/server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "certs/server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    // FIX: DTLS-safe cipher list
    if (SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5") <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}
/*
void alerts(float a, float b, float c, float d){
    if(a>95){
        printf("WARNING WARNING SHUT DOWN NOW!!!!!!!!!!!!!!!!!!!!");
    }else if(a <= 95 && a>90){
        printf("Critical CPU uasage reduce it.");
    }else if(a <= 90 && a>80){
        printf("")
    }
}
*/

int main() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed.\n");
        return 1;
    }
#endif

    init_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    socket_t listen_fd;
    struct sockaddr_in server_addr;

    listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listen_fd == INVALID_SOCKET) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(4444);

    if (bind(listen_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    printf("DTLS Server listening on port %d...\n", SERVER_PORT);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].active = 0;
        clients[i].fd = INVALID_SOCKET;
    }

    fd_set readfds;
    struct timeval timeout;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(listen_fd, &readfds);
        socket_t max_fd = listen_fd;

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active && clients[i].fd != INVALID_SOCKET) {
                FD_SET(clients[i].fd, &readfds);
                if (clients[i].fd > max_fd) max_fd = clients[i].fd;
            }
        }

        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        int activity = select((int)max_fd + 1, &readfds, NULL, NULL, &timeout);

        if (activity < 0) {
            perror("select");
            continue;
        }

        // Handle new incoming client connections
        if (FD_ISSET(listen_fd, &readfds)) {
            // New incoming datagram
            struct sockaddr_storage client_addr;
            memset(&client_addr, 0, sizeof(client_addr));
            
            // To properly handle DTLS listen, we create a temporary SSL object and BIO
            SSL *ssl = SSL_new(ctx);
            BIO *bio = BIO_new_dgram(listen_fd, BIO_NOCLOSE);
            SSL_set_bio(ssl, bio, bio);
            struct timeval timeout;
            timeout.tv_sec = 3;
            timeout.tv_usec = 0;

            BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
            
            // DTLSv1_listen will listen for an incoming ClientHello, handle the stateless cookie exchange,
            // and return 1 when a valid ClientHello with cookie is received.
            BIO_ADDR *client_bio_addr = BIO_ADDR_new();
            int ret = DTLSv1_listen(ssl, client_bio_addr);
            
            if (ret == 1) { // Successfully listened
                socket_t client_fd = socket(AF_INET, SOCK_DGRAM, 0);
                if (client_fd == INVALID_SOCKET) {
                    perror("socket");
                    SSL_shutdown(ssl);

                    SSL_free(ssl);
                    continue;
                }

                
                printf("DTLS connection requested from new client.\n");
                // Get sockaddr from BIO_ADDR
                if (BIO_ADDR_family(client_bio_addr) == AF_INET) {
                    struct sockaddr_in *sin = (struct sockaddr_in *)&client_addr;
                    
                    sin->sin_family = AF_INET;
                    BIO_ADDR_rawaddress(client_bio_addr, &sin->sin_addr.s_addr, NULL);
                    sin->sin_port = BIO_ADDR_rawport(client_bio_addr);
                }

                // Create a new connected UDP socket for this specific client
                struct sockaddr_in local_addr = {0};
                local_addr.sin_family = AF_INET;
                local_addr.sin_addr.s_addr = INADDR_ANY;
                local_addr.sin_port = htons(4444); // ephemeral

                
                int reuse = 1;
                setsockopt(client_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
                if (bind(client_fd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
                    perror("bind");
                    close(client_fd);
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    continue;
                }
                
                // Connect the specific socket to the client
                if (connect(client_fd, (struct sockaddr *)&client_addr, sizeof(struct sockaddr_in)) == 0) {
                    // Update bio for the new socket
                    BIO *client_bio = BIO_new_dgram(client_fd, BIO_NOCLOSE);
                    if (!client_bio) {
                            perror("BIO_new_dgram failed");
                            close(client_fd);
                            SSL_shutdown(ssl);
                            SSL_free(ssl);
                            continue;
                        }
                    BIO_ctrl(client_bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr);
                    SSL_set_bio(ssl, client_bio, client_bio);

                    struct timeval timeout;
                    timeout.tv_sec = 3;
                    timeout.tv_usec = 0;

                    BIO_ctrl(client_bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

                    // Find a free client slot
                    int idx = -1;
                    for (int i = 0; i < MAX_CLIENTS; i++) {
                        if (!clients[i].active) {
                            idx = i;
                            break;
                        }
                    }

                    if (idx != -1) {
                        clients[idx].active = 1;
                        clients[idx].fd = client_fd;
                        clients[idx].ssl = ssl;
                        clients[idx].addr = client_addr;
                        clients[idx].addr_len = sizeof(struct sockaddr_in);

                        // Complete accept
                        int accept_ret = SSL_accept(ssl);

                        if (accept_ret <= 0) {
                            int err = SSL_get_error(ssl, accept_ret);

                            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                                printf("SSL_accept failed.\n");
                                ERR_print_errors_fp(stderr);
                                cleanup_client(&clients[idx]);
                            }
                        } else {
                            printf("Client %d connected securely.\n", idx);
                        }
                        if (SSL_is_init_finished(ssl)) {
                            printf("Client %d connected securely.\n", idx);
                        }
                    } else {
                        printf("Maximum clients reached.\n");
                        

                        SSL_shutdown(ssl);

                        SSL_free(ssl);
#ifdef _WIN32
                        closesocket(client_fd);
#else
                        close(client_fd);
#endif
                    continue;
                }
                } else {
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
#ifdef _WIN32
                    closesocket(client_fd);
#else
                    close(client_fd);
#endif
                    continue;
                }
            } else {
                // Not a valid ClientHello or still negotiating cookie, cleanup temp SSL
                SSL_shutdown(ssl);

                SSL_free(ssl);
            }
            BIO_ADDR_free(client_bio_addr);
            
        }

        // Handle existing client sockets
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active && FD_ISSET(clients[i].fd, &readfds)) {
                SSL *ssl = clients[i].ssl;
                
                // If handshake not complete, try again
                if (!SSL_is_init_finished(ssl)) {
                    int ret = SSL_accept(ssl);
                    if (ret <= 0) {
                        int err = SSL_get_error(ssl, ret);
                        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                            printf("SSL handshake failed for client %d.\n", i);
                            cleanup_client(&clients[i]);
                        }
                    } else {
                        printf("Client %d secure handshake complete.\n", i);
                    }
                    continue;
                }

                HealthPacket packet;
                int len = SSL_read(ssl, &packet, sizeof(packet));
                
                if (len == sizeof(HealthPacket)) {
                    // Ensure null termination of client_id string to prevent overflow during printing/logging
                    packet.client_id[sizeof(packet.client_id) - 1] = '\0';
                    
                    char ip_str[INET6_ADDRSTRLEN] = "Unknown";
                    if (clients[i].addr.ss_family == AF_INET) {
                        struct sockaddr_in *s = (struct sockaddr_in *)&clients[i].addr;
                        inet_ntop(AF_INET, &s->sin_addr, ip_str, sizeof(ip_str));
                    } else if (clients[i].addr.ss_family == AF_INET6) {
                        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&clients[i].addr;
                        inet_ntop(AF_INET6, &s->sin6_addr, ip_str, sizeof(ip_str));
                    }
                    
                    printf("Received Data from %s [%ld] (IP: %s): CPU=%.2f%%, RAM=%.2f%%, Disk=%.2f%%, Net=%.2f Mbps\n",
                           packet.client_id, packet.timestamp, ip_str, packet.cpu_usage, packet.ram_usage, packet.disk_usage, packet.net_usage);
                    log_health_data(packet.timestamp, packet.client_id, ip_str, packet.cpu_usage, packet.ram_usage, packet.disk_usage, packet.net_usage);
                    /*alerts(packet.client_id, packet.timestamp, ip_str, packet.cpu_usage, packet.ram_usage, packet.disk_usage, packet.net_usage);*/
                } else if (len > 0) {
                    printf("Unrecognized format or partial read from client %d (len: %d)\n", i, len);
                } else if (len <= 0) {
                    int err = SSL_get_error(ssl, len);
                    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                        printf("Client %d disconnected.\n", i);
                        cleanup_client(&clients[i]);
                    }
                }
            }
        }
    }

#ifdef _WIN32
    closesocket(listen_fd);
    WSACleanup();
#else
    close(listen_fd);
#endif
    cleanup_openssl();
    SSL_CTX_free(ctx);

    return 0;
}
