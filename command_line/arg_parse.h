/*
 * arg_parse.h
 *
 * Copyright (c) 2021, Laurence Lundblade.
 *
 * Created by Laurence Lundblade on 1/29/21.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef arg_parse_h
#define arg_parse_h

#include "decode_token.h"
#include "ctoken_eat_labels.h"
#include "ctoken.h" // TODO: dependency issue


/**
 * @brief Main / initial parse of argv and put results into arguments stucture.
 *
 * @return 0 on success; 1 on failure
 *
 * free_arguments() must be called to deallocate memory that was allocated by this.
 */
int parse_arguments(int                      argc,
                    char                   **argv,
                    struct ctoken_arguments *arguments);


void free_arguments(struct ctoken_arguments *arguments);


/* Decodes submod:label:value or label:value, the value of the -claim option
   All returned strings are malloced
   return 0 on success, 1 on failure
   claim_number is 0 if claim label is a string, and non-zero if it is a number */
int parse_claim_argument(const char *claim_arg,
                         const char **submod_name,
                         const char **claim_label,
                         const char **claim_value,
                         int64_t    *claim_number);


/* pointer in q_useful_buf returned is malloced and must be freed */
struct q_useful_buf_c convert_to_binary(const char *string);


int convert_to_int64(const char *string, int64_t *value);



const char *cbor_label_to_json_name(int64_t cbor_label);

/* Returns 0 if there is no cbor label for the json name. */
int64_t json_name_to_cbor_label(const char *json_name);


enum ctoken_security_level_t parse_sec_level_value(const  char *sl);

enum ctoken_debug_level_t parse_debug_state(const char *d1);

enum ctoken_intended_use_t parse_intended_use(const char *use);

int parse_location_arg(const char *s, struct ctoken_location_t *location);


#endif /* arg_parse_h */
