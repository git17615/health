#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

// Enforce strict 1-byte padding boundary alignment across compilers via pack pushing and gcc attribute to guarantee networking serialization stability across different architectures
#pragma pack(push, 1)
typedef struct {
    char client_id[32];
    uint32_t sequence_number;
    float cpu_usage;
    float ram_usage;
    float disk_usage;
    float net_usage;
    int64_t timestamp; // Utilizing guaranteed 64-bit int across differing 32-bit/64-bit arch compilations
} __attribute__((packed)) HealthPacket;
#pragma pack(pop)

#endif // COMMON_H
