#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "config.h"

int get_key(int *id, char *key) {
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[512];
    int bytes_read;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        return 0;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid address/Address not supported");
        close(sockfd);
        return 0;
    }

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sockfd);
        return 0;
    }

    bytes_read = read(sockfd, buffer, sizeof(buffer) - 1);
    if (bytes_read < 0) {
        perror("Read failed");
        close(sockfd);
        return 0;
    }
    buffer[bytes_read] = '\0';
    
    char *id_str = strtok(buffer, "\n");
    char *key_str = strtok(NULL, "\n");

    if (id_str && key_str) {
        *id = atoi(id_str);
        strncpy(key, key_str, 512);
        key[511] = '\0';
    } else {
        fprintf(stderr, "Failed to parse ID and Key\n");
    }
    close(sockfd);
    return 1;
}
