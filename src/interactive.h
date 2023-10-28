//
// Created by antoine on 13/06/23.
//

#ifndef PROJET_CRYPTO_INTERACTIVE_H
#define PROJET_CRYPTO_INTERACTIVE_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/err.h>

int start_interactive(int port);
void send_request_info_interactive(int sock_interactive, char *ip_server, unsigned int port_server);
void send_response_info_interactive(int sock_interactive, char *ip_server, unsigned int port_server);

#endif //PROJET_CRYPTO_INTERACTIVE_H
