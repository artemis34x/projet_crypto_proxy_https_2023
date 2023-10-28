struct parse_header_args {
    SSL *ssl_sender;
    SSL *ssl_receiver;
    unsigned int buffer_length;
    int in_header;
    int is_first_line;
    int is_request;
    int method_id;
    long long content_length;
};


int parse_header(struct parse_header_args *args) {
    if(args->in_header){
        if (args->buffer_length+2 == BUFFER_SIZE) {
            printf("Error: buffer overflow.\n");
            return 1;
        }
        if(SSL_read(args->ssl_sender, buffer+args->buffer_length, 1) <= 0) {
            printf("Error reading from sender.\n");
            return 1;
        }
        printf("%c", buffer[args->buffer_length]);
        args->buffer_length++;
        if (args->buffer_length >= 2 && buffer[args->buffer_length-2] == '\r' && buffer[args->buffer_length-1] == '\n') {
            if (args->buffer_length == 2) {
                args->in_header = 0;
                if (args->is_request){
                    SSL_write(args->ssl_receiver, "Transfer-Encoding: identity\r\n", 29);
                    printf("Transfer-Encoding: identity\r\n");
                }
                SSL_write(args->ssl_receiver, buffer, args->buffer_length);
                buffer[args->buffer_length] = '\0';
                printf("%s", buffer);

                return args->is_request && args->method_id == 0;
            }
            else {
                if (args->is_first_line) {
                    args->is_first_line = 0;
                    args->content_length = -1;
                    if (buffer[0] == 'H' && buffer[1] == 'T') {
                        args->is_request = 0;
                    }
                    else {
                        args->is_request = 1;
                        char* pos;
                        if ((pos = strstr(buffer, "GET")) == 0) {
                            args->method_id = 0;
                        }
                        else if ((pos = strstr(buffer, "POST")) == 0) {
                            args->method_id = 1;
                        }
                        else if ((pos = strstr(buffer, "PUT")) == 0) {
                            args->method_id = 2;
                        }
                        else if ((pos = strstr(buffer, "DELETE")) == 0) {
                            args->method_id = 3;
                        }
                        else if ((pos = strstr(buffer, "HEAD")) == 0) {
                            args->method_id = 4;
                        }
                        else if ((pos = strstr(buffer, "OPTIONS")) == 0) {
                            args->method_id = 5;
                        }
                        else if ((pos = strstr(buffer, "TRACE")) == 0) {
                            args->method_id = 6;
                        }
                        else if ((pos = strstr(buffer, "CONNECT")) == 0) {
                            args->method_id = 7;
                        }
                        else {
                            printf("Unknown method.\n");
                            return 1;
                        }
                    }
                }
                int write_buffer = 1;
                char *pos;
                if((pos=strstr(buffer, "Content-Length: ")) != NULL) {
                    args->content_length = atoll(pos+16);
                }
                if (args->is_request) {
                    if(strstr(buffer, "Transfer-Encoding: ") != NULL) {
                        write_buffer = 0;
                    }
                }
                if (write_buffer) {
                    SSL_write(args->ssl_receiver, buffer, args->buffer_length);
                    buffer[args->buffer_length] = '\0';
                    printf("%s", buffer);
                }
                args->buffer_length = 0;
            }
        }
    }else{
        if (args->content_length == 0) {
            return 1;
        }
        int bytes;
        int max_bytes = args->content_length == -1 ? sizeof(buffer)-1 : (args->content_length < sizeof(buffer)-1 ? args->content_length : sizeof(buffer)-1);
        if (max_bytes < 1){
            return 1;
        }
        if((bytes = SSL_read(args->ssl_sender, buffer, max_bytes)) > 0) {
            buffer[bytes] = '\0';
            printf("%s", buffer);
            if (args->content_length != -1) {
                args->content_length -= bytes;
            }
            if(SSL_write(args->ssl_receiver, buffer, bytes) <= 0) {
                printf("Error writing to the target server.\n");
                return 1;
            }
        }
        else {
            printf("Error reading from sender.\n");
            return 1;
        }

    }
    return 0;
}

int ssl_socket_to_ssl_socket(SSL *ssl_sender, SSL *ssl_receiver) {
    fd_set readfds;
    int socket_sender = SSL_get_fd(ssl_sender);
    int result;

    struct parse_header_args args={ssl_sender, ssl_receiver, 0, 1, 1, 0, 0, -1};

    if(parse_header(&args)){
        return 1;
    }

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(socket_sender, &readfds);
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 100000; //

        result = select(socket_sender + 1, &readfds, NULL, NULL, &tv);

        if (result > 0 && FD_ISSET(socket_sender, &readfds)) {
            if (parse_header(&args)) {
                return 1;
            }
        } else if (result == 0) {
            printf("Nothing to read from the sender within the timeout.\n");
            return 0;
        } else {
            printf("Error with select().\n");
            return 1;
        }
    }
}

