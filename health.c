#include "health.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>

static unsigned long long prev_user = 0, prev_nice = 0, prev_system = 0, prev_idle = 0;
static unsigned long long prev_iowait = 0, prev_irq = 0, prev_softirq = 0, prev_steal = 0;
static unsigned long long prev_rx_bytes = 0, prev_tx_bytes = 0;
static unsigned long long prev_net_time_ms = 0;

double get_cpu_usage() {
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) return 0.0;
    
    char buffer[1024];
    if (!fgets(buffer, sizeof(buffer), fp)) {
        fclose(fp);
        return 0.0;
    }
    fclose(fp);
    
    unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;
    if (sscanf(buffer, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
               &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal) < 8) {
        return 0.0;
    }
    
    unsigned long long prev_idle_all = prev_idle + prev_iowait;
    unsigned long long idle_all = idle + iowait;
    
    unsigned long long prev_non_idle = prev_user + prev_nice + prev_system + prev_irq + prev_softirq + prev_steal;
    unsigned long long non_idle = user + nice + system + irq + softirq + steal;
    
    unsigned long long prev_total = prev_idle_all + prev_non_idle;
    unsigned long long total = idle_all + non_idle;
    
    unsigned long long totald = total - prev_total;
    unsigned long long idled = idle_all - prev_idle_all;
    
    double cpu_percentage = 0.0;
    if (totald > 0) {
        cpu_percentage = (double)(totald - idled) / totald * 100.0;
    }
    
    prev_user = user;
    prev_nice = nice;
    prev_system = system;
    prev_idle = idle;
    prev_iowait = iowait;
    prev_irq = irq;
    prev_softirq = softirq;
    prev_steal = steal;
    
    return cpu_percentage;
}

double get_ram_usage() {
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) return 0.0;
    
    char buffer[256];
    unsigned long long mem_total = 0, mem_free = 0, buffers = 0, cached = 0, s_reclaimable = 0;
    
    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strncmp(buffer, "MemTotal:", 9) == 0) sscanf(buffer + 9, "%llu", &mem_total);
        else if (strncmp(buffer, "MemFree:", 8) == 0) sscanf(buffer + 8, "%llu", &mem_free);
        else if (strncmp(buffer, "Buffers:", 8) == 0) sscanf(buffer + 8, "%llu", &buffers);
        else if (strncmp(buffer, "Cached:", 7) == 0) sscanf(buffer + 7, "%llu", &cached);
        else if (strncmp(buffer, "SReclaimable:", 13) == 0) sscanf(buffer + 13, "%llu", &s_reclaimable);
    }
    fclose(fp);
    
    if (mem_total == 0) return 0.0;
    
    unsigned long long mem_used = mem_total - mem_free - buffers - cached - s_reclaimable;
    return (double)mem_used / mem_total * 100.0;
}

double get_disk_usage() {
    struct statvfs stat;
    if (statvfs("/", &stat) != 0) return 0.0;
    
    unsigned long long total = (unsigned long long)stat.f_blocks * stat.f_frsize;
    unsigned long long free = (unsigned long long)stat.f_bfree * stat.f_frsize;
    
    if (total == 0) return 0.0;
    
    unsigned long long used = total - free;
    return (double)used / total * 100.0;
}

double get_network_usage() {
    FILE *fp = fopen("/proc/net/dev", "r");
    if (!fp) return 0.0;
    
    char buffer[1024];
    unsigned long long current_rx = 0, current_tx = 0;
    
    // skip 2 header lines
    if (!fgets(buffer, sizeof(buffer), fp)) { fclose(fp); return 0.0; }
    if (!fgets(buffer, sizeof(buffer), fp)) { fclose(fp); return 0.0; }
    
    while (fgets(buffer, sizeof(buffer), fp)) {
        char *colon = strchr(buffer, ':');
        if (colon) {
            *colon = ' '; // format string by replacing colon
            char iface[32];
            unsigned long long rbytes = 0, rpackets = 0, rerrs = 0, rdrop = 0, rfifo = 0, rframe = 0, rcomp = 0, rmcast = 0;
            unsigned long long tbytes = 0, tpackets = 0, terrs = 0, tdrop = 0, tfifo = 0, tcolls = 0, tcarrier = 0, tcomp = 0;
            
            if (sscanf(buffer, "%31s %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
                       iface, &rbytes, &rpackets, &rerrs, &rdrop, &rfifo, &rframe, &rcomp, &rmcast,
                       &tbytes, &tpackets, &terrs, &tdrop, &tfifo, &tcolls, &tcarrier, &tcomp) >= 10) {
                if (strcmp(iface, "lo") != 0) {
                    current_rx += rbytes;
                    current_tx += tbytes;
                }
            }
        }
    }
    fclose(fp);
    
    struct timeval tv;
    gettimeofday(&tv, NULL);
    unsigned long long current_time_ms = (unsigned long long)(tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);
    
    double mbps = 0.0;
    if (prev_net_time_ms > 0) {
        unsigned long long time_diff = current_time_ms - prev_net_time_ms;
        if (time_diff > 0) {
            unsigned long long bytes_diff = (current_rx - prev_rx_bytes) + (current_tx - prev_tx_bytes);
            double bps = ((double)bytes_diff * 8.0) / ((double)time_diff / 1000.0);
            mbps = bps / 1000000.0;
        }
    }
    
    prev_rx_bytes = current_rx;
    prev_tx_bytes = current_tx;
    prev_net_time_ms = current_time_ms;
    
    return mbps;
}

void get_system_health(HealthPacket *packet) {
    if (!packet) return;
    packet->cpu_usage = (float)get_cpu_usage();
    packet->ram_usage = (float)get_ram_usage();
    packet->disk_usage = (float)get_disk_usage();
    packet->net_usage = (float)get_network_usage();
    packet->timestamp = (long)time(NULL);
}
