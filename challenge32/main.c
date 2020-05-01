/*
 * Break HMAC-SHA1 with a slightly less artificial timing leak
 *
 * Can't seem to go below 3 ms
 */

#define _GNU_SOURCE

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "hash.h"
#include "utils.h"

int connect_to_socket(const char *path) {
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);

    int socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("socket");
        exit(-1);
    }
    if (connect(socket_fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("connect");
        exit(-1);
    }
    return socket_fd;
}

unsigned long times[256];

struct thread_args {
    uint8_t byte;
    uint8_t *buffer;
    size_t buffer_size;
    size_t hash_index;
};

int worker(struct thread_args *args) {
    uint8_t byte = args->byte;

    int s = connect_to_socket("hmac_socket");

    for (int trials = 0; trials < 50; ++trials) {
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        int valid;
        send(s, args->buffer, args->buffer_size, 0);
        recv(s, &valid, sizeof (int), 0);
        if (valid)
            return valid;

        clock_gettime(CLOCK_MONOTONIC, &end);

        unsigned long current_time = (end.tv_sec - start.tv_sec) * 1000000000 + end.tv_nsec - start.tv_nsec;
        times[args->byte] += current_time;
    }
    close(s);

    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Expected string as argument\n");
        exit(-1);
    }
    char *filename = argv[1];
    uint32_t size = strlen(filename);

    uint8_t signature[SHA1_HASH_SIZE] = {0};

    size_t buf_size = sizeof (uint32_t) + size + SHA1_HASH_SIZE;
    uint8_t *buf = malloc(buf_size);
    memcpy(buf, &size, sizeof (uint32_t));
    memcpy(buf + sizeof (uint32_t), filename, size);
    memcpy(buf + sizeof (uint32_t) + size, signature, SHA1_HASH_SIZE);

    struct thread_args args[256];
    pthread_t threads[256];
    for (int c = 0; c < 256; ++c) {
        uint8_t *copy = malloc(buf_size);
        memcpy(copy, buf, buf_size);
        args[c].buffer = copy;
        args[c].buffer_size = buf_size;
    }

    size_t sig_offset = buf_size - SHA1_HASH_SIZE;
    for (size_t i = 0; i < SHA1_HASH_SIZE; ++i) {
        for (int c = 0; c < 256; ++c) {
            times[c] = 0;
            memcpy(args[c].buffer, buf, buf_size);
            args[c].buffer[sig_offset + i] = c;
            args[c].byte = c;
            args[c].hash_index = i;
            pthread_create(&threads[c], 0, (void *)&worker, &args[c]);
        }

        unsigned long max_time = 0;
        uint8_t best_guess;
        for (int c = 0; c < 256; ++c) {
            int valid;
            pthread_join(threads[c], (void **)&valid);

            if (valid) {
                buf[sig_offset + i] = c;
                puts("Found valid HMAC!");
                print_bin(buf + sig_offset, SHA1_HASH_SIZE);
                return 0;
            }
            if (times[c] > max_time) {
                best_guess = c;
                max_time = times[c];
            }
        }

        buf[sig_offset + i] = best_guess;
        print_bin(buf + sig_offset, i+1);
    }

    puts("Could not determine a valid HMAC...");
    return 1;
}
