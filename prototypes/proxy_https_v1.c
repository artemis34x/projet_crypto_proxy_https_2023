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

#define SERVER_CERT_FILE "/home/antoine/CLionProjects/projet_crypto/http.crt"
#define SERVER_KEY_FILE "/home/antoine/CLionProjects/projet_crypto/http.key"
#define BUFFER_SIZE 4096
#define PORT_NUMBER 8443


int main() {
    SSL_CTX *ctx;
    SSL *client_ssl, *server_ssl;
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addrlen;
    char buffer[BUFFER_SIZE];
    int bytes;

    // Initialiser la bibliothèque OpenSSL.
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    // Créer un nouveau contexte SSL.
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }

    // Configurer le contexte SSL.
    // Vous devez ajouter ici votre propre configuration, telle que le chargement de vos certificats.
    // load cert and key
    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_FILE, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // verify private key
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(EXIT_FAILURE);
    }

    // Créer un socket pour écouter les connexions des clients.
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT_NUMBER);
    bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_sock, 1);

    while (1) {
        // Accepter une nouvelle connexion de client.
        client_addrlen = sizeof(client_addr);
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_addrlen);

        // Lire la requête CONNECT du client.
        bytes = read(client_sock, buffer, sizeof(buffer) - 1);
        if (bytes <= 0) {
            close(client_sock);
            printf("Read failedA1\n");
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
        char host[256];
        int port;
        sscanf(buffer, "CONNECT %255[^:]:%d HTTP/1.1\r\n", host, &port);

        // Résoudre l'adresse du serveur.
        struct hostent *server = gethostbyname(host);
        if (!server) {
            close(client_sock);
            printf("Unknown host: %s\n", host);
            continue;
        }

        printf("Connect to %s:%d\n", inet_ntoa(*(struct in_addr *)server->h_addr), port);

        // Créer un socket pour se connecter au serveur.
        int remote_sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in remote_addr;
        memset(&remote_addr, 0, sizeof(remote_addr));
        remote_addr.sin_family = AF_INET;
        memcpy(&remote_addr.sin_addr.s_addr, server->h_addr, server->h_length);
        remote_addr.sin_port = htons(port);

        printf("A\n");

        // Se connecter au serveur.
        if (connect(remote_sock, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) == -1) {
            close(client_sock);
            close(remote_sock);
            printf("Connect failed\n");
            continue;
        }

        printf("B\n");

        SSL_CTX *remote_ctx = SSL_CTX_new(SSLv23_client_method());
        if (!remote_ctx) {
            perror("Unable to create SSL context for remote server");
            exit(EXIT_FAILURE);
        }

        // Configurez le contexte SSL pour vérifier le certificat du serveur distant
        /*SSL_CTX_set_verify(remote_ctx, SSL_VERIFY_PEER, NULL);
        if (SSL_CTX_load_verify_locations(remote_ctx, "", NULL) != 1) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }*/

        printf("BA\n");

        // Créer une nouvelle structure SSL pour le client et le serveur.
        client_ssl = SSL_new(ctx);
        SSL_set_fd(client_ssl, client_sock);
        server_ssl = SSL_new(remote_ctx);
        SSL_set_fd(server_ssl, remote_sock);

        printf("C\n");

        // Effectuer la poignée de main SSL/TLS avec le client et le serveur.
        if (SSL_accept(client_ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(client_ssl);
            SSL_free(server_ssl);
            close(remote_sock);
            continue;
        }
        /*
        // demander pour le certificat en variable d'environnement
        // demander pour l'usurpation de l'identité
        while ((bytes = SSL_read(client_ssl, buffer, sizeof(buffer))) > 0) {
            buffer[bytes] = '\0';
            printf("%s", buffer);
        }
        SSL_free(server_ssl);
        close(remote_sock);
        continue;*/
        printf("CB\n");

        if (SSL_connect(server_ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(client_ssl);
            SSL_free(server_ssl);
            close(client_sock);
            close(remote_sock);
            continue;
        }

        printf("D\n");

        // Relayer les données entre le client et le serveur.
        while ((bytes = SSL_read(client_ssl, buffer, sizeof(buffer))) > 0) {
            buffer[bytes] = '\0';
            printf("%s", buffer);
            if (SSL_write(server_ssl, buffer, bytes) != bytes) {
                printf("SSL_write failed request\n");
                break;
            }
        }
        printf("\n------------------------------------------------------------------\n");
        while ((bytes = SSL_read(server_ssl, buffer, sizeof(buffer))) > 0) {
            buffer[bytes] = '\0';
            printf("%s", buffer);
            if (SSL_write(client_ssl, buffer, bytes) != bytes) {
                printf("SSL_write failed response\n");
                break;
            }
        }

        // Libérer les ressources et fermer les sockets.
        SSL_free(client_ssl);
        SSL_free(server_ssl);
        close(client_sock);
        close(remote_sock);
    }

    // Nettoyer OpenSSL.
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}