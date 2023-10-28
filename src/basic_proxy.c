#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "sni_callback.h"

#define BUFFER_SIZE 1024
#define PORT_NUMBER 8443

char buffer[BUFFER_SIZE];
//https://www.offsec.com/
int ssl_socket_to_ssl_socket(SSL *ssl_sender, SSL *ssl_receiver) {
    char data[BUFFER_SIZE] = { 0 };

    while (1) {
        int bytes = SSL_read(ssl_sender, data, sizeof(data));
        if (bytes > 0) {
            SSL_write(ssl_receiver, data, bytes);
            if (bytes < sizeof(data)) {
                return 0;
            }
        }else{
            printf("Error reading from sender.\n");
            return 1;
        }
    }
    return 1;
}

void help() {
    printf("Usage: <ENV VAR PROXY_CA_KEY> ./basic_proxy.bin [options]\n"
           "\n"
           "Options:\n"
           "  -h / --help Show this message and exit\n"
           "\n"
           "ENV VAR:\n"
           " PROXY_CA_KEY: The path to the authority certificate and the key used by the proxy (previously saved in the browser), the key and the certificate must have the same name and the extension .key and .crt, the environment variable is that of the key without the extension.\n");
}

int main(int argc, char *argv[]) {
    if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        help();
        return 0;
    }else if(argc != 1){
        printf("Error: too many arguments or wrong arguments.\n");
        printf("Usage: basic_proxy.bin --help\n");
        return 1;
    }

    // creation du socket d'ecoute pour le navigateur
    SSL_CTX *base_ctx;
    SSL *client_ssl;
    int client_sock, proxy_https_sock;
    struct sockaddr_in proxy_https_addr, client_addr;
    socklen_t client_addrlen;
    int bytes;
    struct sni_callback_args args_sni;

    // Initialiser la bibliothèque OpenSSL.
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Lire la variable d'environnement.
    char *base_ca_file = getenv("PROXY_CA_KEY");
    if (base_ca_file == NULL) {
        printf("Error reading environment variable PROXY_CA_KEY.(environment variable not found)\n");
        return 1;
    }

    // Charger la clé privée et le certificat du proxy.
    char* ca_key_file = malloc(strlen(base_ca_file) + 5);
    strcpy(ca_key_file, base_ca_file);
    strcat(ca_key_file, ".key");

    char* ca_cert_file = malloc(strlen(base_ca_file) + 5);
    strcpy(ca_cert_file, base_ca_file);
    strcat(ca_cert_file, ".crt");

    BIO *certbio = BIO_new(BIO_s_file());
    BIO_read_filename(certbio, ca_cert_file);

    args_sni.ca_cert = PEM_read_bio_X509(certbio, NULL, 0, NULL);
    if (args_sni.ca_cert == NULL) {
        printf("Error loading CA cert.\n");
        BIO_free_all(certbio);
        return 1;
    }

    BIO *keybio = BIO_new(BIO_s_file());
    BIO_read_filename(keybio, ca_key_file);

    args_sni.pkey_ca = PEM_read_bio_PrivateKey(keybio, NULL, 0, NULL);
    if (args_sni.pkey_ca == NULL) {
        printf("Error loading CA key.\n");
        BIO_free_all(certbio);
        BIO_free_all(keybio);
        return 2;
    }

    // Créer un nouveau contexte SSL.
    base_ctx = SSL_CTX_new(TLS_server_method());
    if (!base_ctx) {
        perror("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }

    // Charger le certificat du proxy.
    if (!SSL_CTX_use_PrivateKey(base_ctx, args_sni.pkey_ca)) {
        printf("Error loading private key.\n");
        SSL_CTX_free(base_ctx);
        return 3;
    }

    // Ajouter le SNI callback pour la génération dynamique des certificats.
    SSL_CTX_set_tlsext_servername_callback(base_ctx, sni_callback);
    SSL_CTX_set_tlsext_servername_arg(base_ctx, &args_sni);

    // Créer un socket pour écouter les connexions des clients.
    proxy_https_sock = socket(AF_INET, SOCK_STREAM, 0);
    memset(&proxy_https_addr, 0, sizeof(proxy_https_addr));
    proxy_https_addr.sin_family = AF_INET;
    proxy_https_addr.sin_addr.s_addr = INADDR_ANY;
    proxy_https_addr.sin_port = htons(PORT_NUMBER);
    bind(proxy_https_sock, (struct sockaddr *)&proxy_https_addr, sizeof(proxy_https_addr));
    listen(proxy_https_sock, 1);

    printf("Listening on port %d...\n", PORT_NUMBER);
    while (1) {
        // Accepter une nouvelle connexion de client.
        client_addrlen = sizeof(client_addr);
        client_sock = accept(proxy_https_sock, (struct sockaddr *)&client_addr, &client_addrlen);

        printf("New connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        // Lire la requête CONNECT du client.
        bytes = read(client_sock, buffer, sizeof(buffer) - 1);
        if (bytes <= 0) {
            //close(client_sock);
            printf("Read failed CONNECT\n");
            continue;
        }
        buffer[bytes] = '\0';

        // Vérifier si c'est une requête CONNECT.
        if (strncmp(buffer, "CONNECT ", 8) != 0) {
            // Ce n'est pas une requête CONNECT, donc nous ne pouvons pas la gérer.
            close(client_sock);
            continue;
        }

        // Envoyer une réponse 200 pour indiquer que la connexion a été établie.
        write(client_sock, "HTTP/1.1 200 Connection Established\r\n\r\n", 39);

        // Parser le host et le port à partir de la requête CONNECT.

        sscanf(buffer, "CONNECT %255[^:]:%d HTTP/1.1\r\n", args_sni.host_target, &args_sni.port_target);

        printf("Connecting to %s:%d\n", args_sni.host_target, args_sni.port_target);

        // Créer une nouvelle structure SSL pour le client.
        client_ssl = SSL_new(base_ctx);
        SSL_set_fd(client_ssl, client_sock);

        printf("Creating SSL connection\n");

        // Effectuer la poignée de main SSL/TLS avec le client.
        if (SSL_accept(client_ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            printf("Handshake failed.\n");
            //close(client_sock);
            continue;
        }
        printf("Handshake Browser -> Proxy OK\n");

        printf("Communication Browser -> Server web\n");
        // Navigateur -> Serveur Web
        ssl_socket_to_ssl_socket(client_ssl,args_sni.ssl_server);
        printf("Communication Server web -> Browser\n");
        // Serveur Web -> Navigateur
        ssl_socket_to_ssl_socket(args_sni.ssl_server, client_ssl);
        printf("End of communication\n");

        // Libérer les ressources et fermer les sockets.
        SSL_free(client_ssl);
        SSL_free(args_sni.ssl_server);
        close(client_sock);
        close(args_sni.socket_server);
        SSL_CTX_free(args_sni.ctx_site_new_crt);
        printf("Connection closed\n");
        printf("\n--------------------------------------------------\n\n");
    }

    // Nettoyer OpenSSL.
    SSL_CTX_free(base_ctx);
    free(ca_key_file);
    free(ca_cert_file);
    //SSL_CTX_free(args_sni.ctx_default); // not used
    EVP_cleanup();

    return 0;
}