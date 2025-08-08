#include "keygen.h"
#include "config.h"
#include "common.h"
#include <winsock2.h>
#include <ws2tcpip.h>

// Retrieves ID and RSA public modulus from the remote server via TCP.
int get_key(int *id, char *key, size_t key_size) {
    if (!id || !key || key_size == 0)
        return ERR_INVALID_ARG;
    int err = ERR_SUCCESS;
    char* external_ip = get_config_value("external_ip");
    char* keygen_port_str = get_config_value("keygen_port");
    if (!external_ip || !keygen_port_str) {
        if (external_ip)
            free(external_ip);
        if (keygen_port_str)
            free(keygen_port_str);
        err = ERR_GENERAL;
        return err;
    }
    int keygen_port = atoi(keygen_port_str);
    free(keygen_port_str);
    if (keygen_port < 1 || keygen_port > 65535) {
        free(external_ip);
        err = ERR_INVALID_ARG;
        return err;
    }
    WSADATA wsa_data;
    SOCKET sock_fd = INVALID_SOCKET;
    struct addrinfo *result = NULL, hints = {0};
    char port_str[6] = {0};
    if (_snprintf_s(port_str, sizeof(port_str), _TRUNCATE, "%d", keygen_port) == -1) {
        free(external_ip);
        err = ERR_GENERAL;
        return err;
    }
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(external_ip, port_str, &hints, &result) != 0) {
        free(external_ip);
        err = ERR_NETWORK;
        return err;
    }
    free(external_ip);
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        freeaddrinfo(result);
        err = ERR_NETWORK;
        return err;
    }
    sock_fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock_fd == INVALID_SOCKET) {
        freeaddrinfo(result);
        WSACleanup();
        err = ERR_NETWORK;
        return err;
    }
    DWORD timeout = 5000;
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    if (connect(sock_fd, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
        closesocket(sock_fd);
        freeaddrinfo(result);
        WSACleanup();
        err = ERR_NETWORK;
        return err;
    }
    freeaddrinfo(result);
    char buffer[512] = {0};
    int bytes_read = recv(sock_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read == SOCKET_ERROR || bytes_read == 0) {
        closesocket(sock_fd);
        WSACleanup();
        err = ERR_NETWORK;
        return err;
    }
    buffer[bytes_read] = '\0';
    char *id_str = strtok(buffer, "\n");
    char *key_str = strtok(NULL, "\n");
    if (!id_str || !key_str || strtok(NULL, "\n") != NULL) {
        closesocket(sock_fd);
        WSACleanup();
        err = ERR_GENERAL;
        return err;
    }
    *id = atoi(id_str);
    if (strncpy_s(key, key_size, key_str, _TRUNCATE) != 0)
        err = ERR_GENERAL;
    closesocket(sock_fd);
    WSACleanup();
    return err;
}
