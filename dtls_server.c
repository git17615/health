#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define PORT 4444
#define BUFFER_SIZE 1024

int main()
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(DTLS_server_method());

    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_use_certificate_file(ctx, "server-cert.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM);

    int sockfd;
    struct sockaddr_in servaddr, cliaddr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);

    bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    printf("DTLS Monitoring Gateway running on port %d\n", PORT);

    char buffer[BUFFER_SIZE];
    socklen_t len = sizeof(cliaddr);

    while (1)
    {
        int n = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                         (struct sockaddr *)&cliaddr, &len);

        if (n > 0)
        {
            int system_id = buffer[0];
            int cpu = buffer[1];
            int mem = buffer[2];
            int disk = buffer[3];

            printf("\nSystem %d Metrics Received\n", system_id);
            printf("CPU Usage: %d%%\n", cpu);
            printf("Memory Usage: %d%%\n", mem);
            printf("Disk Usage: %d%%\n", disk);

            if (cpu > 90)
                printf("ALERT: System %d CPU overload\n", system_id);

            if (mem > 90)
                printf("ALERT: System %d Memory critical\n", system_id);

            if (disk > 90)
                printf("ALERT: System %d Disk nearly full\n", system_id);
        }
    }

    close(sockfd);
    SSL_CTX_free(ctx);
}