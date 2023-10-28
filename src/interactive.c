#include "interactive.h"



int start_interactive(int port){
    int socket_desc , client_sock , c;
    struct sockaddr_in server , client;

    // Créer le socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        perror("Could not create socket");
        exit(6);
    }

    // Préparer le sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(port);

    // Bind
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("bind failed. Error");
        exit(6);
    }

    // Listen
    listen(socket_desc , 3);

    // Accepter les connexions entrantes
    c = sizeof(struct sockaddr_in);
    client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);

    if (client_sock < 0)
    {
        perror("accept failed");
        exit(6);
    }

    return client_sock;
}

void send_request_info_interactive(int sock_interactive, char *ip_server, unsigned int port_server){
    if (strlen(ip_server) > 15 && port_server > 65535){
        perror("ip_server or port_server is invalid");
        exit(1);
    }
    //Protocol custome pour une sur-couche d'HTTP pour donner plus d'info à l'outil: V1,REQUEST,IP_SERVER_WEB,PORT_SERVER_WEB,...(le packet http)
    char buffer[250];
    if(snprintf(buffer, 250, "V1,REQUEST,%s,%d,", ip_server, port_server)>250){
        perror("[INTERACTIVE]buffer is too small");
        exit(1);
    }
    send(sock_interactive, buffer, strlen(buffer), 0);
}

void send_response_info_interactive(int sock_interactive, char *ip_client, unsigned int port_client){
    if (strlen(ip_client) > 15 && port_client > 65535){
        perror("ip_client or port_client is invalid");
        exit(1);
    }
    //Protocol custome pour une sur-couche d'HTTP pour donner plus d'info à l'outil: V1,RESPONSE,IP_CLIENT_WEB,PORT_CLIENT_WEB,...(le packet http)
    char buffer[250];
    if(snprintf(buffer,250, "V1,RESPONSE,%s,%d,", ip_client, port_client)>250){
        perror("[INTERACTIVE]buffer is too small");
        exit(1);
    }
    send(sock_interactive, buffer, strlen(buffer), 0);
}