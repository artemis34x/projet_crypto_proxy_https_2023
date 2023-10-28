//
// Created by antoine on 13/06/23.
//
//https://www.offsec.com/
#include "sni_callback.h"

int sni_callback(SSL *ssl, int *ad, void *arg) {
    struct sni_callback_args* args = (struct sni_callback_args*) arg;
    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    struct hostent *server;
    struct sockaddr_in serv_addr;

    // creation du contexte SSL pour le serveur web
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        printf("Error creating SSL context.\n");
        return SSL_TLSEXT_ERR_NOACK;

    }

    // creation de la socket pour le serveur web
    server = gethostbyname(args->host_target);
    if (server == NULL) {
        fprintf(stderr,"Error, no such host\n");
        return SSL_TLSEXT_ERR_NOACK;

    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(args->port_target);

    args->socket_server = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(args->socket_server,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) {
        printf("Error connecting to the target server.\n");
        return SSL_TLSEXT_ERR_NOACK;

    }

    // creation du SSL pour le serveur web
    args->ssl_server = SSL_new(ctx);
    SSL_set_fd(args->ssl_server, args->socket_server);
    if (!SSL_set_tlsext_host_name(args->ssl_server, servername)) {
        printf("Error setting SNI host name.\n");
        SSL_free(args->ssl_server);
        close(args->socket_server);
        return SSL_TLSEXT_ERR_NOACK;
    }

    // creation de la connexion SSL pour le serveur web
    if (SSL_connect(args->ssl_server) != 1) {
        printf("Error creating SSL connection.\n");
        ERR_print_errors_fp(stderr);
        SSL_free(args->ssl_server);
        close(args->socket_server);
        return SSL_TLSEXT_ERR_NOACK;
    }

    // recuperation du certificat du serveur web
    X509* server_cert = SSL_get_peer_certificate(args->ssl_server);

    if (server_cert == NULL) {
        printf("Error retrieving server certificate.\n");
        SSL_free(args->ssl_server);
        close(args->socket_server);
        return SSL_TLSEXT_ERR_NOACK;
    }

    // creation du nouveau certificat
    X509 *new_cert = X509_new();
    if (new_cert == NULL) {
        printf("Error creating new certificate.\n");
        SSL_free(args->ssl_server);
        close(args->socket_server);
        return SSL_TLSEXT_ERR_NOACK;
    }

    // copie des informations du certificat du serveur web dans le nouveau certificat
    X509_set_version(new_cert, X509_get_version(server_cert));
    X509_set_serialNumber(new_cert, X509_get_serialNumber(server_cert)); // SEC_ERROR_REUSED_ISSUER_AND_SERIAL
    X509_set_subject_name(new_cert, X509_get_subject_name(server_cert));
    X509_set_issuer_name(new_cert, X509_get_issuer_name(args->ca_cert));

    X509_set_notBefore(new_cert, X509_get_notBefore(server_cert));
    X509_set_notAfter(new_cert, X509_get_notAfter(server_cert));
    X509_set_pubkey(new_cert, args->pkey_ca);

    // copie des extensions du certificat du serveur web dans le nouveau certificat
    int num_ext = X509_get_ext_count(server_cert);
    for (int i = 0; i < num_ext; i++) {
        X509_EXTENSION *ext = X509_get_ext(server_cert, i);
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);

        int nid = OBJ_obj2nid(obj);
        if (nid == NID_basic_constraints || nid == NID_key_usage || nid == NID_ext_key_usage ||
            nid == NID_subject_alt_name || nid == NID_certificate_policies || nid == NID_crl_distribution_points ||
            nid == NID_info_access) {
            X509_add_ext(new_cert, ext, -1);
        }
    }

    // signature du nouveau certificat par la cle privee de l'autorite de certification
    if (X509_sign(new_cert, args->pkey_ca, EVP_sha256()) <= 0) {
        printf("Error signing new certificate.\n");
        SSL_free(args->ssl_server);
        close(args->socket_server);
        return SSL_TLSEXT_ERR_NOACK;
    }

    // utilisation du nouveau certificat pour la connexion SSL
    if (SSL_use_certificate(ssl, new_cert) != 1) {
        printf("Error using new certificate.\n");
        SSL_free(args->ssl_server);
        close(args->socket_server);
        return SSL_TLSEXT_ERR_NOACK;
    }

    return SSL_TLSEXT_ERR_OK;
}

void free_sni_callback_inter_loop(struct sni_callback_args* args) {
    SSL_free(args->ssl_server);
    close(args->socket_server);
}

void free_sni_callback_full(struct sni_callback_args* args) {
    X509_free(args->ca_cert);
    EVP_PKEY_free(args->pkey_ca);
}