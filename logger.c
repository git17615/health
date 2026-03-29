#include "logger.h"
#include <stdio.h>

void log_health_data(long timestamp, const char* client_id, const char* ip, float cpu, float ram, float disk, float network) {
    FILE *f = fopen("health_log.csv", "a");
    if (f == NULL) {
        perror("Error opening log file");
        return;
    }

    // Write header if file is empty
    fseek(f, 0, SEEK_END);
    if (ftell(f) == 0) {
        fprintf(f, "timestamp, client_id, client_ip, cpu_usage, ram_usage, disk_usage, net_usage\n");
    }

    fprintf(f, "%ld, %s, %s, %.2f, %.2f, %.2f, %.2f\n", timestamp, client_id, ip, cpu, ram, disk, network);
    fclose(f);
}

void log_alert(long timestamp, const char* client_id, const char* ip, const char* alert_reason) {
    FILE *f = fopen("alerts.csv", "a");
    if (f == NULL) {
        perror("Error opening alerts file");
        return;
    }

    // Write header if file is empty
    fseek(f, 0, SEEK_END);
    if (ftell(f) == 0) {
        fprintf(f, "timestamp, client_id, client_ip, alert_reason\n");
    }

    fprintf(f, "%ld, %s, %s, %s\n", timestamp, client_id, ip, alert_reason);
    fclose(f);
}
