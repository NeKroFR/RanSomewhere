#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include "config.h"

int get_key(int *id, char *key) {
    WSADATA wsaData;
    SOCKET sockfd;
    struct sockaddr_in server_addr;
    char buffer[512];
    int bytes_read;

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("Winsock initialization failed\n");
        return 0;
    }

    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        perror("Socket creation failed");
        WSACleanup();
        return 0;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    // Use inet_addr instead of inet_pton for IP address conversion
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    if (server_addr.sin_addr.s_addr == INADDR_NONE) {
        perror("Invalid address/Address not supported");
        closesocket(sockfd);
        WSACleanup();
        return 0;
    }

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        perror("Connection failed");
        closesocket(sockfd);
        WSACleanup();
        return 0;
    }

    // Receive data from the server
    bytes_read = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read == SOCKET_ERROR) {
        perror("Read failed");
        closesocket(sockfd);
        WSACleanup();
        return 0;
    }

    buffer[bytes_read] = '\0';

    // Parse the received data for ID and key
    char *id_str = strtok(buffer, "\n");
    char *key_str = strtok(NULL, "\n");

    if (id_str && key_str) {
        *id = atoi(id_str);
        strncpy(key, key_str, 512);
        key[511] = '\0';
    } else {
        fprintf(stderr, "Failed to parse ID and Key\n");
    }

    // Clean up
    closesocket(sockfd);
    WSACleanup();

    return 1;
}
