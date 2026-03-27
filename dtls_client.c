#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/statvfs.h>

#define SERVER_PORT 4444

// Get Disk Usage
int get_disk_usage()
{
    struct statvfs stat;
    statvfs("/", &stat);

    float total = stat.f_blocks * stat.f_frsize;
    float free = stat.f_bfree * stat.f_frsize;
    float used = ((total - free) / total) * 100;

    return (int)used;
}

// Get Memory Usage
int get_memory_usage()
{
    FILE *fp = fopen("/proc/meminfo", "r");
    int total, free;
    char label[50];

    fscanf(fp, "%s %d", label, &total);
    fscanf(fp, "%s %d", label, &free);

    fclose(fp);

    int used = ((total - free) * 100) / total;
    return used;
}

// Get CPU Usage
int get_cpu_usage()
{
    FILE *fp = fopen("/proc/stat", "r");

    int user, nice, system, idle;
    fscanf(fp, "cpu %d %d %d %d", &user, &nice, &system, &idle);
    fclose(fp);

    int total = user + nice + system + idle;
    int usage = ((total - idle) * 100) / total;

    return usage;
}

int main()
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(DTLS_client_method());

    int sockfd;
    struct sockaddr_in servaddr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERVER_PORT);
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    srand(time(NULL));
    int system_id = rand() % 100;

    int mode;
    printf("Select Mode:\n");
    printf("1 → Simulated Metrics\n");
    printf("2 → Real System Metrics\n");
    scanf("%d", &mode);

    printf("Monitoring agent started for system %d\n", system_id);

    while (1)
    {
        char packet[4];

        packet[0] = system_id;

        if (mode == 1)
        {
            packet[1] = rand() % 100;
            packet[2] = rand() % 100;
            packet[3] = rand() % 100;
        }
        else
        {
            packet[1] = get_cpu_usage();
            packet[2] = get_memory_usage();
            packet[3] = get_disk_usage();
        }

        send(sockfd, packet, sizeof(packet), 0);

        printf("System %d → CPU:%d MEM:%d DISK:%d\n",
               system_id, packet[1], packet[2], packet[3]);

        sleep(5);
    }

    close(sockfd);
    SSL_CTX_free(ctx);
}