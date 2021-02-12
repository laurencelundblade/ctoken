//
//  jtoken_encode.c
//  CToken
//
//  Created by Laurence Lundblade on 2/2/21.
//  Copyright © 2021 Laurence Lundblade. All rights reserved.
//

#include "jtoken_encode.h"
#include "base64.h"

#include <stdlib.h>



#define INDENTION_INCREMENT 2

static void indent(struct jtoken_encode_ctx *me)
{
    int indention_level = INDENTION_INCREMENT * me->indent_level;

    while(indention_level > 0) {
        fputc(' ', me->out_file);
        indention_level--;
    }
}



void jtoken_encode_int64(struct jtoken_encode_ctx *me, const char *claim_name, int64_t claim_value)
{
    indent(me);
    fprintf(me->out_file, "\"%s\": %lld\n", claim_name, claim_value);
}

void jtoken_encode_uint64(struct jtoken_encode_ctx *me, const char *claim_name, uint64_t claim_value)
{
    indent(me);
    fprintf(me->out_file, "\"%s\": %llu\n", claim_name, claim_value);
}

void jtoken_encode_double(struct jtoken_encode_ctx *me, const char *claim_name, double claim_value)
{
    indent(me);
    fprintf(me->out_file, "\"%s\": %f\n", claim_name, claim_value);
}

void jtoken_encode_text_string(struct jtoken_encode_ctx *me,
                               const char               *claim_name,
                               struct q_useful_buf_c     claim_value)
{
    indent(me);
    fprintf(me->out_file, "\"%s\":\"", claim_name);
    fwrite(claim_value.ptr, 1, claim_value.len, me->out_file);
    fprintf(me->out_file, "\"\n");
}



void jtoken_encode_byte_string(struct jtoken_encode_ctx *me,
                               const char               *claim_name,
                               struct q_useful_buf_c     claim_value)
{
    indent(me);
    fprintf(me->out_file, "\"%s\":\"", claim_name);

    size_t output_size;
    char *b64 = base64_encode(claim_value.ptr, claim_value.len, &output_size);

    fwrite(b64, 1, output_size, me->out_file);
    fprintf(me->out_file, "\"\n");

    free(b64);
}


void jtoken_encode_simple(struct jtoken_encode_ctx *me,
                          const char               *claim_name,
                          enum jtoken_simple_t      simple)
{
    indent(me);
    fprintf(me->out_file, "\"%s\":\"", claim_name);

    switch(simple) {
        case JSON_TRUE:  fprintf(me->out_file, "true");  break;
        case JSON_FALSE: fprintf(me->out_file, "false"); break;
        case JSON_NULL:  fprintf(me->out_file, "null");  break;
    }

    fprintf(me->out_file, "\"\n");
}


void jtoken_encode_bool(struct jtoken_encode_ctx *me,
                        const char               *claim_name,
                        bool                     value)
{
    indent(me);
    fprintf(me->out_file,
            "\"%s\":\"%s\"\n",
            claim_name,
            value ? "true" : "false");;
}


void jtoken_encode_null(struct jtoken_encode_ctx *me,
                        const char               *claim_name)
{
    indent(me);
    fprintf(me->out_file,
            "\"%s\":\"null\"\n",
            claim_name);;
}


/* outputs location claim in json format */
int jtoken_encode_location(struct jtoken_encode_ctx *me, const struct ctoken_location_t *location)
{
    indent(me);
    fprintf(me->out_file, "\"location\" : {\n");
    // TODO: spelling of lattitude in ctoken lib
    indent(me);
    fprintf(me->out_file, "   \"lattitude\": %f,\n", location->eat_loc_latitude);
    indent(me);
    fprintf(me->out_file, "   \"longitude\": %f\n", location->eat_loc_longitude);
    indent(me);
    fprintf(me->out_file, "}\n");

// TODO: the rest of parts

    return 0;
}

