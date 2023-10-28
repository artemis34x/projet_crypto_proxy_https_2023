//
// Created by antoine on 13/06/23.
//

#ifndef PROJET_CRYPTO_REGEX_H
#define PROJET_CRYPTO_REGEX_H

#include <regex.h>
#include <stdlib.h>
#include <string.h>

typedef struct re_pattern_buffer re_pattern_buffer_custom;

int regex_match(re_pattern_buffer_custom *regex, char *buffer, int size);

int init_regex_from_env(re_pattern_buffer_custom **regex, char *env_name);

void free_regex(re_pattern_buffer_custom *regex);
#endif //PROJET_CRYPTO_REGEX_H
