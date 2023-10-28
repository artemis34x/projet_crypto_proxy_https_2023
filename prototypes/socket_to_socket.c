//
// Created by antoine on 12/06/23.
//

#include <sys/socket.h>
#include "socket_to_socket.h"

int socket_to_socket(int sender, int receiver, struct ssl_st* ssl_sender, struct ssl_st* ssl_receiver, Callback_STS callback, char* buffer, int buffer_size, char* to_buffer, int to_buffer_size, int *to_buffer_length, void* args_user, int in_debug) {
    // premier read sans timeout pour le premier byte afin d'attendre le serveur
    if(((sender == NO_USE_SOCKET) != (ssl_sender == NULL)) || (receiver == NO_USE_SOCKET && ssl_receiver == NULL)) {
        printf("Error [socket_to_socket]: sender and ssl_sender must be both used or both unused, receiver and ssl_receiver must be both used or both unused.\n");
        return 7;
    }
    if (receiver < 0 && receiver != NO_USE_SOCKET) {
        printf("Error [socket_to_socket]: receiver must be a valid socket or NO_USE_SOCKET.\n");
        return 2;
    }
    if (sender < 0 && sender != NO_USE_SOCKET) {
        printf("Error [socket_to_socket]: sender must be a valid socket or NO_USE_SOCKET.\n");
        return 3;
    }

    int bytes;

    fd_set readfds;
    int socket_sender = SSL_get_fd(ssl_sender);
    int result;

    FD_ZERO(&readfds);
    FD_SET(socket_sender, &readfds);
    struct timeval tv;
    tv.tv_sec = TIMEOUT_SEC;
    tv.tv_usec = TIMEOUT_USEC;
    while (1) {
        result = select(socket_sender + 1, &readfds, NULL, NULL, &tv);

        if (result > 0 && FD_ISSET(socket_sender, &readfds)) {
            bytes = (sender == NO_USE_SOCKET?SSL_read(ssl_sender, buffer, buffer_size): (int)recv(sender, buffer, buffer_size, 0));

            if (callback != NULL) {
                if (callback(buffer, bytes, args_user) != 0) {
                    printf("Error [socket_to_socket]: callback returned an error.\n");
                    return 11;
                }
            }

            if (to_buffer != NULL) {
                if (to_buffer_size < *to_buffer_length + bytes) {
                    printf("Error [socket_to_socket]: to_buffer is too small.\n");
                    return 10;
                }
                memcpy(to_buffer + *to_buffer_length, buffer, bytes);
                *to_buffer_length += bytes;
            }

            if (bytes == buffer_size) {
                buffer[bytes] = '\0';
                printf("%s", buffer);
                if ((receiver == NO_USE_SOCKET?SSL_write(ssl_receiver, buffer, bytes):send(receiver, buffer, bytes, 0)) <= 0) {
                    printf("[socket_to_socket]: error writing to the target server.\n");
                    return 6;
                }
            } else if (bytes >= 0) {
                return 0;
            } else {
                printf("Error [socket_to_socket]: error reading from the source server. out=%d\n",bytes);
                return 8;
            }
        } else if (result == 0) {
            printf("[socket_to_socket]: timeout.\n");
            return 1;
        } else {
            printf("Error [socket_to_socket]: error reading from the source server. out=%d\n",result);
            return 9;
        }
    }
}