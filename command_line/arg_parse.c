//
//  arg_parse.c
//  CToken
//
//  Created by Laurence Lundblade on 1/29/21.
//  Copyright © 2021 Laurence Lundblade. All rights reserved.
//

#include "arg_parse.h"

#include <getopt.h>
#include <string.h>
#include <stdlib.h>

#include "decode_token.h"
#include "t_cose/q_useful_buf.h"

#include "useful_buf_malloc.h"

#include "ctoken_cwt_labels.h"



/* options descriptor */
enum arg_id_t {
    INPUT_FILE,
    OUTPUT_FILE,
    CLAIM,
    INPUT_FORMAT,
    OUTPUT_FORMAT,
    INPUT_PROTECTION,
    OUTPUT_PROTECTION,
    OUTPUT_TAGGING,
    NO_VERIFY
};

static const struct option longopts[] = {
    { "in",         required_argument,  NULL,  INPUT_FILE },
    { "out",        required_argument,  NULL,  OUTPUT_FILE },
    { "claim",      required_argument,  NULL,  CLAIM },
    { "in_form",    required_argument,  NULL,  INPUT_FORMAT },
    { "out_form",   required_argument,  NULL,  OUTPUT_FORMAT },
    { "in_prot",    required_argument,  NULL,  INPUT_PROTECTION },
    { "out_prot",   required_argument,  NULL,  OUTPUT_PROTECTION },
    { "out_tag",    required_argument,  NULL,  OUTPUT_TAGGING },
    { "no_verify",  no_argument,        NULL,  NO_VERIFY },
    { NULL,         0,                  NULL,  0 }
};

/*
 * @brief Parse argv and put results into arguments stucture.
 *
 * @return 0 on success; 1 on failure
 */
int parse_arguments(int argc, char **argv, struct ctoken_arguments *arguments)
{
    int return_value;
    int selected_opt;

    memset(arguments, 0, sizeof(*arguments));

    return_value = 0;

    while((selected_opt = getopt_long_only(argc, argv, "", longopts, NULL)) != EOF) {

        switch(selected_opt) {
            case INPUT_FILE:
                arguments->input_file = optarg;
                break;

            case OUTPUT_FILE:
                arguments->output_file = optarg;
                break;

            case CLAIM:
                if(arguments->claims) {
                    const char **i;
                    for(i = arguments->claims; *i; i++);
                    size_t count = i - arguments->claims;

                    arguments->claims = realloc(arguments->claims,
                                                (count + 2) * sizeof(char *));
                    arguments->claims[count] = optarg;
                    arguments->claims[count+1] = NULL;
                } else {
                    arguments->claims = malloc(2 * sizeof(char *));
                    arguments->claims[0] = optarg;
                    arguments->claims[1] = NULL;
                }
                break;

            case INPUT_FORMAT:
                if(!strcasecmp(optarg, "cbor")) {
                    arguments->input_format = IN_FORMAT_CBOR;
                } else if(!strcasecmp(optarg, "json")) {
                    arguments->input_format = IN_FORMAT_JSON;
                } else {
                    fprintf(stderr, "Invalid input format: \"%s\"\n", optarg);
                    return_value = 1;
                    goto Done;
                }
                break;

            case OUTPUT_FORMAT:
                if(!strcasecmp(optarg, "cbor")) {
                    arguments->output_format = OUT_FORMAT_CBOR;
                } else if(!strcasecmp(optarg, "json")) {
                    arguments->output_format = OUT_FORMAT_JSON;
                } else {
                    fprintf(stderr, "Invalid output format: \"%s\"\n", optarg);
                    return_value = 1;
                    goto Done;
                }
                break;

            case INPUT_PROTECTION:
                if(!strcasecmp(optarg, "detect")) {
                    arguments->input_protection = IN_PROT_DETECT;
                } else if(!strcasecmp(optarg, "none")) {
                     arguments->input_protection = IN_PROT_NONE;
                } else if(!strcasecmp(optarg, "sign")) {
                     arguments->input_protection = IN_PROT_SIGN;
                } else if(!strcasecmp(optarg, "mac")) {
                     arguments->input_protection = IN_PROT_MAC;
                } else if(!strcasecmp(optarg, "sign_encrypt")) {
                     arguments->input_protection = IN_PROT_SIGN_ENCRYPT;
                } else if(!strcasecmp(optarg, "mac_encrypt")) {
                     arguments->input_protection = IN_PROT_MAC_ENCRYPT;
                } else {
                    fprintf(stderr, "Invalid input protection: \"%s\"\n", optarg);
                    return_value = 1;
                    goto Done;
                }

            case OUTPUT_PROTECTION:
                if(!strcasecmp(optarg, "none")) {
                     arguments->output_protection = OUT_PROT_NONE;
                } else if(!strcasecmp(optarg, "sign")) {
                     arguments->output_protection = OUT_PROT_SIGN;
                } else if(!strcasecmp(optarg, "mac")) {
                     arguments->output_protection = OUT_PROT_MAC;
                } else if(!strcasecmp(optarg, "sign_encrypt")) {
                     arguments->output_protection = OUT_PROT_SIGN_ENCRYPT;
                } else if(!strcasecmp(optarg, "mac_encrypt")) {
                     arguments->output_protection = OUT_PROT_MAC_ENCRYPT;
                } else {
                    fprintf(stderr, "Invalid output protection: \"%s\"\n", optarg);
                    return_value = 1;
                    goto Done;
                }

            case OUTPUT_TAGGING:
                if(!strcasecmp(optarg, "cwt")) {
                    arguments->output_tagging = OUT_TAG_CWT;
                } else if(!strcasecmp(optarg, "cose")) {
                    arguments->output_tagging = OUT_TAG_COSE;
                } else if(!strcasecmp(optarg, "none")) {
                    arguments->output_tagging = OUT_TAG_NONE;
                } else {
                    fprintf(stderr, "Invalid output tagging: \"%s\"\n", optarg);
                    return_value = 1;
                    goto Done;
                }

            case NO_VERIFY:
                arguments->no_verify = true;
                break;

            default:
                fprintf(stderr, "Oops. Input parameter parsing went wrong\n");
                return_value = 1;
        }
    }

  Done:
    return return_value;
}




struct integer_string_map_t {
    int64_t     cbor_label;
    const char *json_name;
};


static const struct integer_string_map_t label_map[] = {
    {CTOKEN_CWT_LABEL_ISSUER, "iss"},
    {CTOKEN_CWT_LABEL_SUBJECT, "sub"},
    {CTOKEN_CWT_LABEL_AUDIENCE, "aud"},
    {CTOKEN_CWT_LABEL_EXPIRATION, "exp"},
    {CTOKEN_CWT_LABEL_NOT_BEFORE, "nbf"},
    {CTOKEN_CWT_LABEL_IAT, "iat"},
    {CTOKEN_CWT_LABEL_CTI, "cti"},

    // TODO: sort out the official definition vs the temporary
    {CTOKEN_EAT_LABEL_NONCE, "nonce"},
    {10, "nonce"},

    {CTOKEN_EAT_LABEL_UEID, "ueid"},
    {11, "ueid"},

    {CTOKEN_EAT_LABEL_OEMID, "oemid"},
    {13, "oemid"},

    {CTOKEN_EAT_LABEL_SECURITY_LEVEL, "seclevel"},
    {14, "seclevel"},

    {CTOKEN_EAT_LABEL_SECURE_BOOT, "secboot"},
    {15, "seclevel"},

    {CTOKEN_EAT_LABEL_DEBUG_STATE, "dbgstat"},
    {16, "dbgstat"},

    {CTOKEN_EAT_LABEL_LOCATION, "location"},
    {17, "location"},

    {CTOKEN_EAT_LABEL_SUBMODS, "submods"},
    {20, "submods"},

    {0, NULL}
};

static const struct integer_string_map_t sec_levels[] = {
    {EAT_SL_UNRESTRICTED, "unrestricted"},
    {EAT_SL_RESTRICTED, "restricted"},
    {EAT_SL_SECURE_RESTRICTED, "secure_restricted"},
    {EAT_SL_HARDWARE, "hardware"},
    {EAT_SL_INVALID, NULL}
};


static const struct integer_string_map_t dbg_states[] = {
    {CTOKEN_DEBUG_ENABLED, "enabled"},
    {CTOKEN_DEBUG_DISABLED, "disabled"},
    {CTOKEN_DEBUG_DISABLED_SINCE_BOOT, "disabled_since_boot"},
    {CTOKEN_DEBUG_DISABLED_PERMANENT, "disabled_permanent"},
    {CTOKEN_DEBUG_DISABLED_FULL_PERMANENT, "disabled_full_permanent"},
    {CTOKEN_DEBUG_INVALID, NULL}
};


static const char *int_to_string(const struct integer_string_map_t *map, int64_t cbor_label)
{
    size_t i;

    for(i = 0; map[i].json_name != NULL; i++) {
        if(label_map[i].cbor_label == cbor_label) {
            return label_map[i].json_name;
        }
    }

    return NULL;
}


/* Returns 0 if string was not found in map */
int64_t string_to_int(const struct integer_string_map_t *map, const char *string)
{
    size_t i;

    for(i = 0; map[i].json_name != NULL; i++) {
        if(!strcmp(string, map[i].json_name)) {
            return label_map[i].cbor_label;
        }
    }

    return 0;
}


const char *cbor_label_to_json_name(int64_t cbor_label)
{
    return int_to_string(label_map, cbor_label);
}

/* Returns 0 if there is no cbor label for the json name. */
int64_t json_name_to_cbor_label(const char *json_name)
{
    return string_to_int(label_map, json_name);
}

const char *sec_level_2(enum ctoken_security_level_t i)
{
    return int_to_string(sec_levels, i);
}


enum ctoken_security_level_t sec_level_x(const char *s)
{
    return (enum ctoken_security_level_t)string_to_int(sec_levels, s);
}





const char *copy_up_to_colon(const char *input, size_t *copied)
{
    const char *c = strchr(input, ':');

    if(c == NULL) {
        return NULL;
    }

    *copied = c - input;

    return strndup(input, c - input);
}


enum ctoken_security_level_t parse_sec_level_value(const  char *sl)
{
    long n;
    char *e;

    /* Try to convert to a number first */
    n = strtol(sl, &e, 10);

    if(*e == '\0') {
        /* Successfull converted. See if it is in range */
        if(n > EAT_SL_HARDWARE ||
           n < EAT_SL_UNRESTRICTED) {
            return EAT_SL_INVALID;
        } else {
            /* Successful integer security level */
            return (enum ctoken_security_level_t)n;
        }
    }

    /* Now try it as a string */
    return sec_level_x(sl);
}


enum ctoken_debug_level_t parse_dbg_x(const char *d1)
{
    return 0;

}



/* returns 4 binary bits corresponding to hex character or
 0xffff if character is not a hex character. */
static uint16_t hex_char(char c)
{
    if(c >= '0' && c <= '9') {
        return c - '0';
    } else if(c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if(c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    } else {
        return 0xffff;
    }
}

/* input is hex digits, e.g. 34a8b20f
   output is a malloced buffer with corresponding binary bytes. */
struct q_useful_buf_c convert_to_binary(const char *z)
{
    struct q_useful_buf b = useful_malloc(strlen(z)/2);

    UsefulOutBuf OB;

    UsefulOutBuf_Init(&OB, b);

    while(*z) {
        uint32_t v = (hex_char(*z) << 4) + hex_char(*(z+1));
        if(v > 0xff) {
            free(b.ptr);
            return NULL_Q_USEFUL_BUF_C;
        }

        UsefulOutBuf_AppendByte(&OB, (uint8_t)v);
        z += 2;
    }

    return UsefulOutBuf_OutUBuf(&OB);;
}


int convert_to_int64(const char *s, int64_t *v)
{
    char *end;
    *v = strtoll(s, &end, 10);
    return *end == '\0' ? 0 : 1;
}
