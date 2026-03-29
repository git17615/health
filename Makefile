CC=gcc
CFLAGS=-Wall -O2

all: server_app client_app

server_app: server/dtls_server.c server/logger.c
	$(CC) $(CFLAGS) server/dtls_server.c server/logger.c -o server_app -lssl -lcrypto -lz

client_app: client/dtls_client.c client/health.c
	$(CC) $(CFLAGS) client/dtls_client.c client/health.c -o client_app -lssl -lcrypto -lz

clean:
	rm -f server_app client_app
