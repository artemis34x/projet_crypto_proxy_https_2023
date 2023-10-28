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
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>

//READ
#define PORT 443
#define BUFFER_SIZE 4096
#define CA_CERT_FILE "./ca_v2.crt"
#define CA_KEY_FILE "./ca_v2.key"
#define TARGET_URL "epita.it"
//WRITE
#define NEW_CERT_FILE "new_cert.pem"
#define NEW_KEY_FILE "new_key.pem"
#define TARGET_CERT_FILE_ "target.pem"


int get_certificate_from_server(char* host_target, int port_target,X509 **server_cert){
    int sockfd;
    struct hostent *server;
    struct sockaddr_in serv_addr;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        printf("Error creating SSL context.\n");
        return 1;
    }

    server = gethostbyname(host_target);
    if (server == NULL) {
        fprintf(stderr,"Error, no such host\n");
        return 1;
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(port_target);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) {
        printf("Error connecting to the target server.\n");
        return 1;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if (!SSL_set_tlsext_host_name(ssl, host_target)) {
        printf("Error setting SNI host name.\n");
        SSL_free(ssl);
        close(sockfd);
        return 1;
    }

    if (SSL_connect(ssl) != 1) {
        printf("Error creating SSL connection.\n");
        SSL_free(ssl);
        close(sockfd);
        return 1;
    }

    *server_cert = SSL_get_peer_certificate(ssl);

    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    return 0;
}

int copy_and_signe_cert(X509 *target_cert, char* ca_key_file, char* ca_cert_file, EVP_PKEY *public_key_new_cert, X509 **new_cert) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    BIO *certbio = BIO_new(BIO_s_file());
    BIO_read_filename(certbio, ca_cert_file);

    X509 *cacert = PEM_read_bio_X509(certbio, NULL, 0, NULL);
    if (cacert == NULL) {
        printf("Error loading CA cert.\n");
        BIO_free_all(certbio);
        return 1;
    }

    BIO *keybio = BIO_new(BIO_s_file());
    BIO_read_filename(keybio, ca_key_file);

    EVP_PKEY *cakey = PEM_read_bio_PrivateKey(keybio, NULL, 0, NULL);
    if (cakey == NULL) {
        printf("Error loading CA key.\n");
        BIO_free_all(certbio);
        BIO_free_all(keybio);
        return 1;
    }

    // Create a new certificate and copy information from the target certificate
    *new_cert = X509_new();
    if (new_cert == NULL) {
        printf("Error creating new certificate.\n");
        BIO_free_all(certbio);
        BIO_free_all(keybio);
        return 1;
    }

    // Set version, serial number, subject, issuer, notBefore, notAfter, public key
    X509_set_version(*new_cert, X509_get_version(target_cert));
    X509_set_serialNumber(*new_cert, X509_get_serialNumber(target_cert));
    X509_set_subject_name(*new_cert, X509_get_subject_name(target_cert));
    X509_set_issuer_name(*new_cert, X509_get_issuer_name(cacert));
    X509_set_notBefore(*new_cert, X509_get_notBefore(target_cert));
    X509_set_notAfter(*new_cert, X509_get_notAfter(target_cert));
    X509_set_pubkey(*new_cert, public_key_new_cert);

    // Copy extensions from target certificate
    int num_ext = X509_get_ext_count(target_cert);
    for (int i = 0; i < num_ext; i++) {
        X509_EXTENSION *ext = X509_get_ext(target_cert, i);
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);

        int nid = OBJ_obj2nid(obj);
        if (nid == NID_basic_constraints || nid == NID_key_usage || nid == NID_ext_key_usage ||
            nid == NID_subject_alt_name || nid == NID_certificate_policies || nid == NID_crl_distribution_points ||
            nid == NID_info_access) {
            X509_add_ext(*new_cert, ext, -1);
        }
    }
    // Sign the new certificate with our CA
    if (X509_sign(*new_cert, cakey, EVP_sha256()) <= 0) {
        printf("Error signing the new certificate.\n");
        BIO_free_all(certbio);
        BIO_free_all(keybio);
        return 1;
    }

    BIO_free_all(certbio);
    BIO_free_all(keybio);

    return 0;
}
char* ASN1_TIME_to_string(ASN1_TIME* time) {
    BIO *bio;
    char *buf;

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        return NULL;
    }

    if (!ASN1_TIME_print(bio, time)) {
        BIO_free(bio);
        return NULL;
    }

    buf = malloc(BIO_number_written(bio) + 1);
    if (buf == NULL) {
        BIO_free(bio);
        return NULL;
    }

    memset(buf, 0, BIO_number_written(bio) + 1);
    BIO_read(bio, buf, BIO_number_written(bio));
    BIO_free(bio);
    return buf;
}
void print_cert(X509 *cert) {
    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);

    printf("Subject: %s\n", subj);
    printf("Issuer: %s\n", issuer);

    ASN1_INTEGER *asn1_i = X509_get_serialNumber(cert);
    BIGNUM *bignum = ASN1_INTEGER_to_BN(asn1_i, NULL);
    char *serial = BN_bn2dec(bignum);

    printf("Serial Number: %s\n", serial);

    char *not_before = ASN1_TIME_to_string(X509_get_notBefore(cert));
    char *not_after = ASN1_TIME_to_string(X509_get_notAfter(cert));

    printf("Not Before: %s\n", not_before);
    printf("Not After: %s\n", not_after);

    BN_free(bignum);
    OPENSSL_free(subj);
    OPENSSL_free(issuer);
    OPENSSL_free(serial);
    OPENSSL_free(not_before);
    OPENSSL_free(not_after);
}

int write_cert_to_file(X509 *cert, const char* file_name) {
    FILE* fp = fopen(file_name, "wb");
    if (!fp) {
        printf("Error opening file %s\n", file_name);
        return -1;
    }

    int ret = PEM_write_X509(fp, cert);
    fclose(fp);

    if (ret != 1) {
        printf("Error writing cert to file\n");
        return -1;
    }

    return 0;
}

int resolve_dns(const char *hostname, char* ipstr, size_t ipstr_len) {
    struct addrinfo hints, *res;
    int status;
    char ip[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return -1;
    }

    void *addr;
    char *ipver;


    if (res->ai_family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
        addr = &(ipv4->sin_addr);
        ipver = "IPv4";
    } else {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)res->ai_addr;
        addr = &(ipv6->sin6_addr);
        ipver = "IPv6";
    }

    inet_ntop(res->ai_family, addr, ip, sizeof ip);
    printf("  %s: %s\n", ipver, ip);
    strncpy(ipstr, ip, ipstr_len);
    freeaddrinfo(res);

    return 0;
}

int generate_keypair(EVP_PKEY **pkey) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (pctx == NULL) {
        printf("Failed to create PKEY context.\n");
        return 1;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        printf("Failed to initialize keygen.\n");
        EVP_PKEY_CTX_free(pctx);
        return 1;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) {
        printf("Failed to set RSA key length.\n");
        EVP_PKEY_CTX_free(pctx);
        return 1;
    }

    if (EVP_PKEY_keygen(pctx, pkey) <= 0) {
        printf("Failed to generate key.\n");
        EVP_PKEY_CTX_free(pctx);
        return 1;
    }

    EVP_PKEY_CTX_free(pctx);
    return 0;
}

int save_private_key(EVP_PKEY *pkey, const char *file_name) {
    FILE *fp = fopen(file_name, "wb");
    if (fp == NULL) {
        printf("Failed to open file %s.\n", file_name);
        return 1;
    }

    if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL)) {
        printf("Failed to write private key to file.\n");
        ERR_print_errors_fp(stderr);
        fclose(fp);
        return 1;
    }

    fclose(fp);
    return 0;
}

int verify_cert(const char *cert_path, const char *ca_path) {
    FILE *cert_file = fopen(cert_path, "r");
    if (!cert_file) {
        printf("Failed to open certificate file %s.\n", cert_path);
        return 1;
    }

    FILE *ca_file = fopen(ca_path, "r");
    if (!ca_file) {
        printf("Failed to open CA file %s.\n", ca_path);
        fclose(cert_file);
        return 1;
    }

    X509 *cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    if (!cert) {
        printf("Failed to read certificate.\n");
        fclose(cert_file);
        fclose(ca_file);
        return 1;
    }

    X509 *ca = PEM_read_X509(ca_file, NULL, NULL, NULL);
    if (!ca) {
        printf("Failed to read CA.\n");
        X509_free(cert);
        fclose(cert_file);
        fclose(ca_file);
        return 1;
    }

    X509_STORE *store = X509_STORE_new();
    X509_STORE_add_cert(store, ca);

    X509_STORE_CTX *vrfy_ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(vrfy_ctx, store, cert, NULL);

    int result = X509_verify_cert(vrfy_ctx);
    if (result != 1) {
        printf("Verification failed\n");
    }

    X509_STORE_CTX_free(vrfy_ctx);
    X509_STORE_free(store);
    X509_free(cert);
    X509_free(ca);
    fclose(cert_file);
    fclose(ca_file);

    return !result;
}

int main(){
    if (access(CA_KEY_FILE, F_OK) == -1) {
        printf("CA key file %s does not exist.\n", CA_KEY_FILE);
        return 0;
    }

    if (access(CA_CERT_FILE, F_OK) == -1) {
        printf("CA cert file %s does not exist.\n", CA_CERT_FILE);
        return 0;
    }

    X509 *target_cert = NULL;
    if (get_certificate_from_server(TARGET_URL, PORT, &target_cert)) {
        printf("Error getting certificate.\n");
        return 0;
    }

    if (write_cert_to_file(target_cert, TARGET_CERT_FILE_)) {
        printf("Error writing certificate to file.\n");
        return 0;
    }

    EVP_PKEY *pkey = NULL;

    if(generate_keypair(&pkey)){
        printf("Error generating keypair.\n");
        return 0;
    }

    if(save_private_key(pkey, NEW_KEY_FILE)){
        printf("Error saving private key.\n");
        return 0;
    }

    X509 *new_cert = NULL;
    if(copy_and_signe_cert(target_cert, CA_KEY_FILE, CA_CERT_FILE, pkey, &new_cert)){
        printf("Error copying and signing certificate.\n");
        return 0;
    }
    print_cert(target_cert);
    printf("\n-------------------------\n");
    print_cert(new_cert);

    if(write_cert_to_file(new_cert, NEW_CERT_FILE)){
        printf("Error writing certificate to file.\n");
        return 0;
    }

    if (verify_cert(NEW_CERT_FILE, CA_CERT_FILE)) {
        printf("Error verifying certificate.\n");
        return 0;
    }

    printf("Everything is fine.\n");

    return 0;
}