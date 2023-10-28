//
// Created by antoine on 13/06/23.
//

#ifndef PROJET_CRYPTO_SNI_CALLBACK_H
#define PROJET_CRYPTO_SNI_CALLBACK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <arpa/inet.h>

struct sni_callback_args {
    char host_target[256];
    int port_target;
    SSL_CTX *ctx_site_new_crt;
    SSL_CTX *ctx_default;
    int socket_server;
    SSL *ssl_server;
    SSL_CTX *ctx_server;
    EVP_PKEY* pkey_ca;
    X509* ca_cert;
};

int sni_callback(SSL *ssl, int *ad, void *arg);

void free_sni_callback_inter_loop(struct sni_callback_args* args);
void free_sni_callback_full(struct sni_callback_args* args);

#endif //PROJET_CRYPTO_SNI_CALLBACK_H
