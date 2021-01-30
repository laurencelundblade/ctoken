//
//  arg_parse.h
//  CToken
//
//  Created by Laurence Lundblade on 1/29/21.
//  Copyright © 2021 Laurence Lundblade. All rights reserved.
//

#ifndef arg_parse_h
#define arg_parse_h

#include "decode_token.h"
#include "ctoken_eat_labels.h"



int parse_arguments(int argc,
                    char **argv,
                    struct ctoken_arguments *arguments);

/* pointer in q_useful_buf is malloced and must be freed */
struct q_useful_buf_c convert_to_binary(const char *string);


int convert_to_int64(const char *string, int64_t *value);


/* Returns a malloced string */
const char *copy_up_to_colon(const char *input, size_t *amount_copied);




const char *cbor_label_to_json_name(int64_t cbor_label);

/* Returns 0 if there is no cbor label for the json name. */
int64_t json_name_to_cbor_label(const char *json_name);


enum ctoken_security_level_t parse_sec_level_value(const  char *sl);

enum ctoken_debug_level_t parse_debug_state(const char *d1);

enum ctoken_intended_use_t parse_intended_use(const char *use);


#endif /* arg_parse_h */
