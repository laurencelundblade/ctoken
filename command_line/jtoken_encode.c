/*
 * jtoken_encode.c
 *
 * Copyright (c) 2021, Laurence Lundblade.
 *
 * Created by Laurence Lundblade on 2/2/21.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

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

void jtoken_encode_start(struct jtoken_encode_ctx *me)
{
    fprintf(me->out_file, "{\n");
    me->indent_level = 1;
}

void jtoken_encode_finish(struct jtoken_encode_ctx *me)
{
    fprintf(me->out_file, "}\n");
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

struct integer_string_map_t {
    int64_t     cbor_label;
    const char *json_name;
};


static const struct integer_string_map_t sec_levels[] = {
    {JTOKEN_EAT_SL_UNRESTRICTED, "unrestricted"},
    {JTOKEN_EAT_SL_RESTRICTED, "restricted"},
    {JTOKEN_EAT_SL_SECURE_RESTRICTED, "secure_restricted"},
    {JTOKEN_EAT_SL_HARDWARE, "hardware"},
    {JTOKEN_EAT_SL_INVALID, NULL}
};


static const struct integer_string_map_t debug_states[] = {
    {JTOKEN_DEBUG_ENABLED, "enabled"},
    {JTOKEN_DEBUG_DISABLED, "disabled"},
    {JTOKEN_DEBUG_DISABLED_SINCE_BOOT, "disabled_since_boot"},
    {JTOKEN_DEBUG_DISABLED_PERMANENT, "disabled_permanent"},
    {JTOKEN_DEBUG_DISABLED_FULL_PERMANENT, "disabled_full_permanent"},
    {JTOKEN_DEBUG_INVALID, NULL}
};

/*
static const struct integer_string_map_t intended_uses[] = {
    {CTOKEN_USE_GENERAL, "general"},
    {CTOKEN_USE_REGISTRATION, "registration"},
    {CTOKEN_USE_PROVISIONING, "provisioning"},
    {CTOKEN_USE_CERTIFICATE_ISSUANCE, "certificate_issuance"},
    {CTOKEN_USE_PROOF_OF_POSSSION, "proof_of_possesion"},
    {CTOKEN_USE_INVALID, NULL}
};
*/

static const char *int_to_string(const struct integer_string_map_t *map, int64_t cbor_label)
{
    size_t i;

    for(i = 0; map[i].json_name != NULL; i++) {
        if(map[i].cbor_label == cbor_label) {
            return map[i].json_name;
        }
    }

    return NULL;
}


void
jtoken_encode_security_level(struct jtoken_encode_ctx    *me,
                             enum jtoken_security_level_t security_level)
{
    const char *sec_level_string = int_to_string(sec_levels, security_level);
    if(sec_level_string == NULL) {
        sec_level_string = "<<invalid security level";
    }
    jtoken_encode_text_string_z(me, "seclevel", sec_level_string);
}


void
jtoken_encode_debug_state(struct jtoken_encode_ctx  *me,
                          enum ctoken_debug_level_t  debug_state)
{
    const char *dbg_level_string = int_to_string(debug_states, debug_state);
    if(dbg_level_string == NULL) {
        dbg_level_string = "<<invalid debug state";
    }
    jtoken_encode_text_string_z(me, "dbgstate", dbg_level_string);
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


void jtoken_encode_start_submod_section(struct jtoken_encode_ctx *me)
{
    indent(me);
    fprintf(me->out_file, "\"submods\" : {\n");
    me->indent_level++;
}


void jtoken_encode_end_submod_section(struct jtoken_encode_ctx *me)
{
    indent(me);
    fprintf(me->out_file, "}\n");
    me->indent_level--;
}


void jtoken_encode_open_submod(struct jtoken_encode_ctx *me,
                               const char               *submod_name)
{
    indent(me);
    fprintf(me->out_file, "\"%s\" : {\n", submod_name);
    me->indent_level++;
}


void jtoken_encode_close_submod_section(struct jtoken_encode_ctx *me)
{
    indent(me);
    fprintf(me->out_file, "}\n");
    me->indent_level--;
}


