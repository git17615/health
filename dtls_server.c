#include "dtls_server.h"
#include "logger.h"
#include <openssl/err.h>
#include <openssl/bio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <zlib.h>

// To handle select() on multiple sockets
ClientContext clients[MAX_CLIENTS];

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    // A simple cookie generator for demonstration. In production, use HMAC with a secret.
    *cookie_len = 16;
    memset(cookie, 0xAB, 16);
    return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
    if (cookie_len == 16 && cookie[0] == 0xAB) return 1;
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
    // Enable strict mutual authentication: Server verifies Client
    if (SSL_CTX_load_verify_locations(ctx, "certs/ca.crt", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    // Reject untrusted client certs strictly
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    // Load Certificates
    if (SSL_CTX_use_certificate_file(ctx, "certs/server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "certs/server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    // Use AES encryption
    if (SSL_CTX_set_cipher_list(ctx, "AES256-SHA:AES128-SHA") <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

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
    server_addr.sin_port = htons(SERVER_PORT);

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
            
            // To properly handle DTLS listen, we create a temporary SSL object and BIO
            SSL *ssl = SSL_new(ctx);
            BIO *bio = BIO_new_dgram(listen_fd, BIO_NOCLOSE);
            SSL_set_bio(ssl, bio, bio);
            
            // DTLSv1_listen will listen for an incoming ClientHello, handle the stateless cookie exchange,
            // and return 1 when a valid ClientHello with cookie is received.
            BIO_ADDR *client_bio_addr = BIO_ADDR_new();
            int ret = DTLSv1_listen(ssl, client_bio_addr);
            
            if (ret == 1) { // Successfully listened
                printf("DTLS connection requested from new client.\n");
                // Get sockaddr from BIO_ADDR
                if (BIO_ADDR_family(client_bio_addr) == AF_INET) {
                    struct sockaddr_in *sin = (struct sockaddr_in *)&client_addr;
                    sin->sin_family = AF_INET;
                    BIO_ADDR_rawaddress(client_bio_addr, &sin->sin_addr.s_addr, NULL);
                    sin->sin_port = BIO_ADDR_rawport(client_bio_addr);
                }

                // Create a new connected UDP socket for this specific client
                socket_t client_fd = socket(AF_INET, SOCK_DGRAM, 0);
                int reuse = 1;
                setsockopt(client_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
                bind(client_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
                
                // Connect the specific socket to the client
                if (connect(client_fd, (struct sockaddr *)&client_addr, sizeof(struct sockaddr_in)) == 0) {
                    // Update bio for the new socket
                    BIO_set_fd(bio, client_fd, BIO_NOCLOSE);
                    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr);
                    SSL_set_bio(ssl, bio, bio);

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
                        memcpy(&clients[idx].addr, &client_addr, sizeof(struct sockaddr_storage));
                        clients[idx].last_seen = time(NULL);
                        clients[idx].alerted_disconnected = 0;
                        clients[idx].expected_seq = 0;
                        clients[idx].last_packet_timestamp = 0;
                        memset(clients[idx].last_client_id, 0, sizeof(clients[idx].last_client_id));
                        memset(clients[idx].last_ip_str, 0, sizeof(clients[idx].last_ip_str));
                        clients[idx].addr_len = sizeof(struct sockaddr_in);

                        // Complete accept
                        int accept_ret = SSL_accept(ssl);
                        if (accept_ret <= 0) {
                            int err = SSL_get_error(ssl, accept_ret);
                            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                                printf("SSL_accept failed.\n");
                                cleanup_client(&clients[idx]);
                            }
                        } else {
                            printf("Client %d connected securely.\n", idx);
                        }
                    } else {
                        printf("Maximum clients reached.\n");
                        SSL_free(ssl);
#ifdef _WIN32
                        closesocket(client_fd);
#else
                        close(client_fd);
#endif
                    }
                } else {
                    SSL_free(ssl);
#ifdef _WIN32
                    closesocket(client_fd);
#else
                    close(client_fd);
#endif
                }
            } else {
                // Not a valid ClientHello or still negotiating cookie, cleanup temp SSL
                SSL_free(ssl);
            }
            BIO_ADDR_free(client_bio_addr);
        }

        // Check for client timeouts
        time_t now = time(NULL);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active && SSL_is_init_finished(clients[i].ssl)) {
                if (now - clients[i].last_seen > 15) {
                    const char *cid = strlen(clients[i].last_client_id) > 0 ? clients[i].last_client_id : "UNKNOWN";
                    const char *cip = strlen(clients[i].last_ip_str) > 0 ? clients[i].last_ip_str : "UNKNOWN";
                    printf("Client %s disconnected\n", cid);
                    log_alert((long)now, cid, cip, "Client disconnected");
                    
                    // Mark client as inactive and properly close the SSL socket gracefully
                    cleanup_client(&clients[i]);
                }
            }
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

                unsigned char recv_buf[BUFFER_SIZE];
                int len = SSL_read(ssl, recv_buf, sizeof(recv_buf));
                
                if (len > 0) {
                    HealthPacket packet;
                    uLongf uncompressed_len = sizeof(HealthPacket);
                    
                    if (uncompress((unsigned char *)&packet, &uncompressed_len, recv_buf, len) != Z_OK || uncompressed_len != sizeof(HealthPacket)) {
                        printf("Failed to fully decompress ZLib packet from client %d (buffer len: %d)\n", i, len);
                    } else {
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
                        
                        // Replay Attack Tracking
                        if (clients[i].last_packet_timestamp != 0 && packet.timestamp < clients[i].last_packet_timestamp) {
                            printf(">> [ALERT] %s (%s) - Replay attack detected! Dropping packet.\n", packet.client_id, ip_str);
                            log_alert((long)time(NULL), packet.client_id, ip_str, "Replay attack detected");
                            continue;
                        }
                        clients[i].last_packet_timestamp = packet.timestamp;
                        
                        printf("Received Data from %s [%ld] (IP: %s): CPU=%.2f%%, RAM=%.2f%%, Disk=%.2f%%, Net=%.2f Mbps\n",
                               packet.client_id, (long)packet.timestamp, ip_str, packet.cpu_usage, packet.ram_usage, packet.disk_usage, packet.net_usage);
                        log_health_data((long)packet.timestamp, packet.client_id, ip_str, packet.cpu_usage, packet.ram_usage, packet.disk_usage, packet.net_usage);
                        
                        // Update client context
                        clients[i].last_seen = time(NULL);
                        clients[i].alerted_disconnected = 0;
                        snprintf(clients[i].last_client_id, sizeof(clients[i].last_client_id), "%s", packet.client_id);
                        snprintf(clients[i].last_ip_str, sizeof(clients[i].last_ip_str), "%s", ip_str);
                        
                        // Evaluate UDP packet sequence desynchronization
                        if (clients[i].expected_seq != 0 && packet.sequence_number > clients[i].expected_seq) {
                            char reason[128];
                            snprintf(reason, sizeof(reason), "Packet loss detected (Expected: %u, Got: %u)", clients[i].expected_seq, packet.sequence_number);
                            printf(">> [ALERT] %s (%s) - %s\n", packet.client_id, ip_str, reason);
                            log_alert((long)time(NULL), packet.client_id, ip_str, reason);
                        }
                        clients[i].expected_seq = packet.sequence_number + 1;
                        
                        // Alert Triggers
                        if (packet.cpu_usage > 85.0f) {
                            char reason[128];
                            snprintf(reason, sizeof(reason), "CPU Usage > 85%% (%.2f%%)", packet.cpu_usage);
                            printf(">> [ALERT] %s (%s) - %s\n", packet.client_id, ip_str, reason);
                            log_alert((long)time(NULL), packet.client_id, ip_str, reason);
                        }
                        if (packet.ram_usage > 90.0f) {
                            char reason[128];
                            snprintf(reason, sizeof(reason), "RAM Usage > 90%% (%.2f%%)", packet.ram_usage);
                            printf(">> [ALERT] %s (%s) - %s\n", packet.client_id, ip_str, reason);
                            log_alert((long)time(NULL), packet.client_id, ip_str, reason);
                        }
                        if (packet.disk_usage > 90.0f) {
                            char reason[128];
                            snprintf(reason, sizeof(reason), "Disk Usage > 90%% (%.2f%%)", packet.disk_usage);
                            printf(">> [ALERT] %s (%s) - %s\n", packet.client_id, ip_str, reason);
                            log_alert((long)time(NULL), packet.client_id, ip_str, reason);
                        }
                    }
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
