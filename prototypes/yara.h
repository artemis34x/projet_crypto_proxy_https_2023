//
// Created by antoine on 13/06/23.
//

#ifndef PROJET_CRYPTO_YARA_H
#define PROJET_CRYPTO_YARA_H
#include <yara.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <openssl/err.h>


YR_RULES* load_yara_rules(char* rules_directory);
void scan_buffer(YR_RULES* rules, char* buffer,size_t size);

#endif //PROJET_CRYPTO_YARA_H
