//
// Created by antoine on 13/06/23.
//

#include "regex.h"
int regex_match(struct re_pattern_buffer *regex, char *buffer, int size){
    char t = buffer[size-1];
    buffer[size-1] = '\0';
    // Verification du buffer
    int flag = regexec(regex, buffer, 0, NULL, 0);
    buffer[size-1] = t;
    return flag == 0;
}

int init_regex_from_env(re_pattern_buffer_custom **regex, char *env_name){
    // Recuperation de la regex via la variable d'environnement
    char * regex_str = getenv(env_name);
    if (regex_str == NULL){
        return 1;
    }
    *regex = malloc(sizeof(re_pattern_buffer_custom));

    // Compilation de la regex
    int err = regcomp(*regex, regex_str, REG_EXTENDED);
    if (err != 0){
        return 2;
    }
    return 0;
}

void free_regex(struct re_pattern_buffer *regex){
    regfree(regex);
}