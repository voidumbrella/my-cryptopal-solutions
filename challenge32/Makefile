# crappy makefile

all: server client

server: server.c hash.c utils.c
	$(CC) -O3 server.c hash.c utils.c -o server

client: main.c hash.c utils.c
	$(CC) -O3 main.c hash.c utils.c -o client -pthread

clean:
	rm -f server
	rm -f client
	rm -f hmac_socket
