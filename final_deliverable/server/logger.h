#ifndef LOGGER_H
#define LOGGER_H

void log_health_data(long timestamp, const char* client_id, const char* ip, float cpu, float ram, float disk, float network);

#endif // LOGGER_H
