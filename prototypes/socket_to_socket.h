//
// Created by antoine on 12/06/23.
//

#ifndef PROJET_CRYPTO_SOCKET_TO_SOCKET_H
#define PROJET_CRYPTO_SOCKET_TO_SOCKET_H

#define TIMEOUT_SEC 5
#define TIMEOUT_USEC 100000 // 100ms
#define NO_USE_SOCKET (-2)

#include <openssl/ssl.h>

// length_buffer, buffer, args
// return 0 if ok, 1 if error
typedef int (*Callback_STS)(char* buffer, int length_buffer, void* args_user);

// return 0 if ok, 1 if error
int socket_to_socket(int sender, int receiver, struct ssl_st* ssl_sender, struct ssl_st* ssl_receiver, Callback_STS callback, char buffer[], int buffer_size, char* to_buffer, int to_buffer_size, int *to_buffer_length, void* args_user,int in_debug);

#endif //PROJET_CRYPTO_SOCKET_TO_SOCKET_H
