/*
 * arg_parse.c
 *
 * Copyright (c) 2021, Laurence Lundblade.
 *
 * Created by Laurence Lundblade on 1/29/21.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "arg_parse.h"

#include <getopt.h>
#include <string.h>
#include <stdlib.h>

#include "decode_token.h"
#include "t_cose/q_useful_buf.h"

#include "useful_buf_malloc.h"

#include "ctoken_cwt_labels.h"

#include "ctoken.h" // TODO: this should not be a dependency; issue is location



/* Command line option indexes used with getopt(). */
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


/* Description of the command line options for getopt(), particularly getopt_long_only(). */
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
 * Public function. See arg_parse.h
 */
int parse_arguments(int argc, char **argv, struct ctoken_arguments *arguments)
{
    int          return_value;
    int          selected_opt;
    const char **claim;
    size_t       claim_count;

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
                    /* Count up claims parsed so far */
                    for(claim = arguments->claims; *claim; claim++);
                    claim_count = claim - arguments->claims;

                    arguments->claims = realloc(arguments->claims,
                                                (claim_count + 2) * sizeof(char *));
                    arguments->claims[claim_count] = optarg;
                    arguments->claims[claim_count+1] = NULL;
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
    if(return_value) {
        free_arguments(arguments);
    }
    return return_value;
}


/*
 * Public function. See arg_parse.h
 */
void free_arguments(struct ctoken_arguments *arguments)
{
    if(arguments->claims) {
        free(arguments->claims);
        arguments->claims = NULL;
    }
}



/* Returned a malloced NULL-terminated string up
 that is the characters up to to the first ':' in input.
 Also return the amount copied.*/
static const char *copy_up_to_colon(const char *input, size_t *copied)
{
    const char *c = strchr(input, ':');

    if(c == NULL) {
        return NULL;
    }

    *copied = c - input;

    return strndup(input, c - input);
}



/*
 * Public function. See arg_parse.h
 */
int parse_claim_argument(const char *claim_arg,
                         const char **submod_name,
                         const char **claim_label,
                         const char **claim_value,
                         int64_t    *claim_number)
{
    char       *end;
    size_t      first_part_length;
    const char *remains;
    const char *second_part;

    *submod_name = NULL;
    *claim_label = NULL;
    *claim_value = NULL;

    /* decode into submod, label and value */
    const char *first_part = copy_up_to_colon(claim_arg, &first_part_length);
    if(first_part == NULL) {
        /* Something wrong with the claim */
        return 1;
    }

    remains = claim_arg + first_part_length + 1;

    second_part = copy_up_to_colon(remains, &first_part_length);

    if(second_part == NULL) {
        /* Format is label:value */
        *claim_label = first_part;
        *claim_value = strdup(remains);
    } else {
        /* format is submod:label:value */
        *submod_name = first_part;
        *claim_label = second_part;
        *claim_value = strdup(second_part + first_part_length + 1);
    }

    /* Is label a string or a number? */
    *claim_number = strtoll(*claim_label, &end, 10);
    if(*end != '\0') {
        /* label is a string. Try to look it up. */
        *claim_number = json_name_to_cbor_label(*claim_label);
    }

    return 0;
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


static const struct integer_string_map_t debug_states[] = {
    {CTOKEN_DEBUG_ENABLED, "enabled"},
    {CTOKEN_DEBUG_DISABLED, "disabled"},
    {CTOKEN_DEBUG_DISABLED_SINCE_BOOT, "disabled_since_boot"},
    {CTOKEN_DEBUG_DISABLED_PERMANENT, "disabled_permanent"},
    {CTOKEN_DEBUG_DISABLED_FULL_PERMANENT, "disabled_full_permanent"},
    {CTOKEN_DEBUG_INVALID, NULL}
};


static const struct integer_string_map_t intended_uses[] = {
    {CTOKEN_USE_GENERAL, "general"},
    {CTOKEN_USE_REGISTRATION, "registration"},
    {CTOKEN_USE_PROVISIONING, "provisioning"},
    {CTOKEN_USE_CERTIFICATE_ISSUANCE, "certificate_issuance"},
    {CTOKEN_USE_PROOF_OF_POSSSION, "proof_of_possesion"},
    {CTOKEN_USE_INVALID, NULL}
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
static int64_t string_to_int(const struct integer_string_map_t *map, const char *string)
{
    size_t i;

    for(i = 0; map[i].json_name != NULL; i++) {
        if(!strcmp(string, map[i].json_name)) {
            return label_map[i].cbor_label;
        }
    }

    return label_map[i].cbor_label;
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


static const char *sec_level_2(enum ctoken_security_level_t i)
{
    return int_to_string(sec_levels, i);
}


static enum ctoken_security_level_t sec_level_x(const char *s)
{
    return (enum ctoken_security_level_t)string_to_int(sec_levels, s);
}


static inline enum ctoken_debug_level_t debug_state_from_string(const char *s)
{
    return (enum ctoken_debug_level_t)string_to_int(debug_states, s);
}


static inline enum ctoken_intended_use_t intended_use_from_string(const char *s)
{
    return (enum ctoken_intended_use_t)string_to_int(intended_uses, s);
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


enum ctoken_debug_level_t parse_debug_state(const char *d1)
{
    long n;
    char *number_end;

    /* Try to convert to a number first */
    n = strtol(d1, &number_end, 10);

    if(*number_end == '\0') {
        if(n > CTOKEN_DEBUG_DISABLED_FULL_PERMANENT ||
           n < CTOKEN_DEBUG_ENABLED) {
            return CTOKEN_DEBUG_INVALID;
        } else {
            return (enum ctoken_debug_level_t)n;
        }
    } else {
        return debug_state_from_string(d1);
    }
}


enum ctoken_intended_use_t parse_intended_use(const char *use)
{
    long n;
    char *number_end;

    /* Try to convert to a number first */
    n = strtol(use, &number_end, 10);

    if(*number_end == '\0') {
        if(n > CTOKEN_USE_PROOF_OF_POSSSION ||
           n < CTOKEN_USE_GENERAL) {
            return CTOKEN_USE_INVALID;
        } else {
            return (enum ctoken_intended_use_t)n;
        }
    } else {
        return intended_use_from_string(use);
    }
}


/*

 4.5,6.5,8.7,A5555,T9999

 */
int parse_location_arg(const char *s, struct ctoken_location_t *location)
{
    char *end;
    size_t i = 0;
    int64_t l;

    while(1) {
        if(*s == 'A' || *s == 'T') {
            l = strtoll(s+1, &end, 10);
            if(*end != ',' && *end != '\0') {
                /* syntax error */
                return 1;
            }
            if(*s == 'A') {
                location->age = l;
            } else {
                location->time_stamp = l;
            }
        } else {
            location->items[i] = strtod(s, &end);
            if(*end != ',' && *end != '\0') {
                /* syntax error */
                return 1;
            }
            /* got a good double value */
            i++;
            location->item_flags |= (0x01 << i);
            if(i > 7) {
                return 1;
            }
        }
        if(*end == '\0') {
            /* successful exit */
            return 0;
        }
        s = end+1;
    }
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
