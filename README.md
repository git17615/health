gcc dtls_server.c -o server -lssl -lcrypto
---
gcc dtls_client.c -o client -lssl -lcrypto
--
./server
---
./client
