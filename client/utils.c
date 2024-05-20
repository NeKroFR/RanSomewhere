#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "config.h"

void get_key(int *id, char *key) {
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[256];

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid address/Address not supported");
        exit(EXIT_FAILURE);
    }

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    if (read(sockfd, buffer, sizeof(buffer) - 1) < 0) {
        perror("Read failed");
        exit(EXIT_FAILURE);
    }
    buffer[sizeof(buffer) - 1] = '\0';
    sscanf(buffer, "%*s %d", id);

    if (read(sockfd, buffer, sizeof(buffer) - 1) < 0) {
        perror("Read failed");
        exit(EXIT_FAILURE);
    }
    buffer[sizeof(buffer) - 1] = '\0';
    sscanf(buffer, "%*s %64s", key);
    close(sockfd);
}
