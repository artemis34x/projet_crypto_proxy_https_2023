//
// Created by antoine on 12/06/23.
//

//http://www2.culture.gouv.fr/culture/inventai/patrimoine/
// sudo apt-get install libyara-dev 4.2.3

#include "yara.h"


YR_RULES* load_yara_rules(char* rules_directory)
{
    YR_COMPILER *compiler = NULL;
    YR_RULES* rules = NULL;
    struct dirent *dir;
    char rule_path[256];
    int errors;

    yr_initialize();

    if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
    {
        printf("Could not create YARA compiler\n");
        return NULL;
    }

    DIR* d = opendir(rules_directory);
    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            if (strstr(dir->d_name, ".yara") != NULL)
            {
                sprintf(rule_path, "%s/%s", rules_directory, dir->d_name);
                yr_compiler_add_file(compiler, rule_path, NULL, NULL);
            }
        }
        closedir(d);
    }

    errors = yr_compiler_get_rules(compiler, &rules);

    if (errors != 0)
    {
        printf("Compilation with %d errors\n", errors);
        return NULL;
    }

    yr_compiler_destroy(compiler);

    return rules;
}

int callback_function_yara(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data){

    if (message == CALLBACK_MSG_RULE_MATCHING){
        YR_RULE* rule = (YR_RULE*) message_data;
        printf("Rule %s matched\n", rule->identifier);
        char **identifier = (char **) user_data;
        *identifier = malloc(strlen(rule->identifier) + 1);
        strcpy(*identifier, rule->identifier);
        return CALLBACK_ABORT;
    }
    return CALLBACK_CONTINUE;
}

void scan_buffer(YR_RULES* rules, char* buffer,size_t size)
{
    char *identifier = NULL;
    yr_rules_scan_mem(rules,(const uint8_t *)buffer,size,0,callback_function_yara,&identifier,1000);
    if (identifier != NULL){
        printf("Rule %s matched\n", identifier);
        free(identifier);
    }
}

// pour les tests
int main(int argc, char** argv)
{


    YR_RULES* rules = load_yara_rules("yara/");

    if (rules == NULL)
    {
        printf("Could not load rules\n");
        return 1;
    }

    //

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

    server = gethostbyname(HOST);
    if (server == NULL) {
        fprintf(stderr,"Error, no such host\n");
        return 1;
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(PORT);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) {
        printf("Error connecting to the target server.\n");
        return 1;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if (!SSL_set_tlsext_host_name(ssl, HOST)) {
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
    printf("b\n");
    // Envoi d'une requête HTTP
    const char *request = "GET /fr/docs/Web/HTTP/Methods/TRACE HTTP/1.1\r\n"
                          "Host: developer.mozilla.org\r\n"
                          "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0\r\n"
                          "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,;q=0.8\r\n"
                          "Accept-Language: en-US,en;q=0.5\r\n"
                          "Accept-Encoding: identity\r\n"
                          "Connection: keep-alive\r\n"
                          "Upgrade-Insecure-Requests: 1\r\n"
                          "Sec-Fetch-Dest: document\r\n"
                          "Sec-Fetch-Mode: navigate\r\n"
                          "Sec-Fetch-Site: none\r\n"
                          "Sec-Fetch-User: ?1\r\n"
                          "\r\n";


    //
    yr_rules_destroy(rules);
    yr_finalize();

    return 0;
}
