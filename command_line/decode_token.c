//
//  decode_token.c
//  CToken
//
//  Created by Laurence Lundblade on 1/11/21.
//  Copyright © 2021 Laurence Lundblade. All rights reserved.
//

#include "decode_token.h"
#include "t_cose/q_useful_buf.h"
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include "ctoken_decode.h"
#include <sys/errno.h>
#include "ctoken_encode.h"


#include <stdint.h>
#include <stdlib.h>


static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};

// https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
// See if this is really correct.
char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}

void build_decoding_table() {

    decoding_table = malloc(256);

    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}


unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length) {

    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}


void base64_cleanup() {
    free(decoding_table);
}


/*


 */



#define INDENTION_INCREMENT 2

void indent(FILE *output_file, int indention_level)
{
    indention_level *= INDENTION_INCREMENT;

    while(indention_level > 0) {
        fputc(' ', output_file);
        indention_level--;
    }
}


// outputs location claim in json format
int output_location_claim(FILE *output_file, int indention_level, const struct ctoken_location_t *location)
{
    indent(output_file, indention_level);
    fprintf(output_file, "\"location\" : {\n");
    // TODO: spelling of lattitude in ctoken lib
    indent(output_file, indention_level);
    fprintf(output_file, "   \"lattitude\": %f,\n", location->eat_loc_latitude);
    indent(output_file, indention_level);
    fprintf(output_file, "   \"longitude\": %f\n", location->eat_loc_longitude);
    indent(output_file, indention_level);
    fprintf(output_file, "}\n");

// TODO: the rest of parts

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


struct jwt_encode_ctx {
    FILE *out_file;
    int   indent_level;
};


struct output_context {
    int output_type;
    union {
        struct ctoken_encode_ctx ctoken;
        struct jwt_encode_ctx    jwt;
    } u;
};

int64_t string_to_int(const struct integer_string_map_t *map, const char *string)
{
    size_t i;

    for(i = 0; map[i].json_name != NULL; i++) {
        if(strcmp(string, map[i].json_name)) {
            return label_map[i].cbor_label;
        }
    }

    return 0;
}


static inline const char *cbor_label_to_json_name(int64_t cbor_label)
{
    return int_to_string(label_map, cbor_label);
}


static inline const char *sec_level_2(enum ctoken_security_level_t i)
{
    return int_to_string(sec_levels, i);
}


static inline enum ctoken_security_level_t sec_level_x(const char *s)
{
    return (enum ctoken_security_level_t)string_to_int(sec_levels, s);
}




void output_int64(FILE *output_file, int indention_level, const char *claim_name, int64_t claim_value)
{
    indent(output_file, indention_level);
    fprintf(output_file, "\"%s\": %lld\n", claim_name, claim_value);
}

void output_uint64(FILE *output_file, int indention_level, const char *claim_name, uint64_t claim_value)
{
    indent(output_file, indention_level);
    fprintf(output_file, "\"%s\": %llu\n", claim_name, claim_value);
}

void output_double(FILE *output_file, int indention_level, const char *claim_name, double claim_value)
{
    indent(output_file, indention_level);
    fprintf(output_file, "\"%s\": %f\n", claim_name, claim_value);
}

void output_text_string(FILE *output_file, int indention_level, const char *claim_name, struct q_useful_buf_c claim_value)
{
    indent(output_file, indention_level);
    fprintf(output_file, "\"%s\":\"", claim_name);
    fwrite(claim_value.ptr, 1, claim_value.len, output_file);
    fprintf(output_file, "\"\n");
}


void output_byte_string(FILE *output_file,
                        int indention_level,
                        const char *claim_name,
                        struct q_useful_buf_c claim_value)
{
    indent(output_file, indention_level);
    fprintf(output_file, "\"%s\":\"", claim_name);

    size_t output_size;
    char *b64 = base64_encode(claim_value.ptr, claim_value.len, &output_size);

    fwrite(b64, 1, output_size, output_file);
    fprintf(output_file, "\"\n");

    free(b64);
}


void output_byte_simple(FILE *output_file,
                        int indention_level,
                        const char *claim_name,
                        int simple)
{
    indent(output_file, indention_level);
    fprintf(output_file, "\"%s\":\"", claim_name);

    switch(simple) {
        case QCBOR_TYPE_TRUE:  fprintf(output_file, "true"); break;
        case QCBOR_TYPE_FALSE: fprintf(output_file, "false"); break;
        case QCBOR_TYPE_NULL:  fprintf(output_file, "null"); break;
    }

    fprintf(output_file, "\"\n");
}




void output_other_claim(FILE *output_file,
                        int indention_level,
                        struct ctoken_decode_ctx *decode_context,
                        int64_t cbor_label)
{
    struct ctoken_location_t loc;


    switch(cbor_label) {

        case CTOKEN_EAT_LABEL_LOCATION:
            ctoken_decode_location(decode_context, &loc);
            // TODO: error check
            output_location_claim(output_file, indention_level, &loc);
            break;

        default:
            // Claim is aggregate that is not known. Must walk
            // the CBOR and convert to JSON.
            break;

    }
}



int decode_cbor(FILE *output_file, struct q_useful_buf_c input_bytes, int output_format)
{
    struct ctoken_decode_ctx decode_context;
    enum ctoken_err_t        error;
    QCBORItem                claim_item;

    int indention_level = 0;

    ctoken_decode_init(&decode_context,
                       0,
                       0,
                       CTOKEN_PROTECTION_NONE);

    error = ctoken_decode_validate_token(&decode_context, input_bytes);
    if(error) {
        return -9;
    }

    while(1) {
        error = ctoken_decode_next_claim(&decode_context, &claim_item);

        if(error != CTOKEN_ERR_SUCCESS) {
            // TODO: handle errors better here
            break;
        }

        // TODO: make sure label is of the right type and/or handle alternate types
        const char *json_name = cbor_label_to_json_name(claim_item.label.int64);

        char substitue_json_name[20];
        snprintf(substitue_json_name, sizeof(substitue_json_name), "%lld", claim_item.label.int64);

        switch(claim_item.uDataType) {
            case QCBOR_TYPE_INT64:
                output_int64(output_file,
                             indention_level,
                             json_name ? json_name : substitue_json_name,
                             claim_item.val.int64);
                break;

            case QCBOR_TYPE_UINT64:
                output_uint64(output_file,
                             indention_level,
                             json_name ? json_name : substitue_json_name,
                             claim_item.val.uint64);
                break;

            case QCBOR_TYPE_DOUBLE:
                output_double(output_file,
                              indention_level,
                              json_name ? json_name : substitue_json_name,
                              claim_item.val.dfnum);
                break;

            case QCBOR_TYPE_TEXT_STRING:
                output_text_string(output_file,
                                   indention_level,
                                   json_name ? json_name : substitue_json_name,
                                   claim_item.val.string);
                break;

            case QCBOR_TYPE_BYTE_STRING:
                output_byte_string(output_file,
                                   indention_level,
                                   json_name ? json_name : substitue_json_name,
                                   claim_item.val.string);
                break;

            case QCBOR_TYPE_TRUE:
            case QCBOR_TYPE_FALSE:
            case QCBOR_TYPE_NULL:
                output_byte_simple(output_file,
                                   indention_level,
                                   json_name ? json_name : substitue_json_name,
                                   claim_item.uDataType);
                break;

            default:
                output_other_claim(output_file,
                                   indention_level,
                                   &decode_context,
                                   claim_item.label.int64);
        }
    }

    return 0;
}




/* Read the contents of a file into malloced buffer
 *
 *
 */
struct q_useful_buf_c read_file(int file_descriptor)
{
    char    input_buf[2048];
    char   *file_content;
    size_t  file_size;
    ssize_t amount_read;


    file_content = NULL;
    file_size    = 0;
    while(1) {
        amount_read = read(file_descriptor, input_buf, sizeof(input_buf));

        if(amount_read == 0) {
            /* normal exit */
            break;
        }

        if(amount_read < 0) {
            /* read error exit */
            return NULL_Q_USEFUL_BUF_C;
        }

        if(file_content == NULL) {
            file_content = malloc(amount_read);
            if(file_content == NULL) {
                return NULL_Q_USEFUL_BUF_C;
            }
        } else {
            file_content = realloc(file_content, amount_read + file_size);
        }

        memcpy(file_content + file_size, input_buf, amount_read);
        file_size += amount_read;
    }

    return (struct q_useful_buf_c){file_content, file_size};
}



static const char *copy_up_to_colon(const char *input, size_t *copied)
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


struct q_useful_buf_c convert_to_binary(const char *z)
{
    // TODO: fill this in
    return NULL_Q_USEFUL_BUF_C;
}


/* Decodes submod:label:value or label:value
   All returned strings are malloced
   return 0 on success, 1 on failure
   claim_number is 0 if claim label is a string, and non-zero if it is a number */
static int parse_claim_argument(const char *claim_arg,
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
        /* label is a string */
        *claim_number = 0;
    }

    return 0;
}

/* Free a pointer if not NULL even if it is const */
#define FREEIF(x) if(x != NULL){free((void *)x);}


int encode_claim(struct ctoken_encode_ctx *encode_ctx, const char *claim)
{
    const char *claim_label;
    const char *submod_name;
    const char *claim_value;
    int64_t     claim_number;
    int         error;

    error = parse_claim_argument(claim,
                                 &submod_name,
                                 &claim_label,
                                 &claim_value,
                                 &claim_number);

    if(error) {
        return error;
    }

    // TODO: handle submods (a lot of work!)


    enum ctoken_security_level_t sec_level;
    enum ctoken_debug_level_t    debug_level;
    struct q_useful_buf_c        binary_value;

    switch(claim_number) {
        case CTOKEN_EAT_LABEL_UEID:
            binary_value = convert_to_binary(claim_value);
            if(q_useful_buf_c_is_null(binary_value)) {
                fprintf(stderr, "bad ueid value \"%s\"\n", claim_value);
                return 1;
            }
            ctoken_encode_ueid(encode_ctx, binary_value);
            break;

        case CTOKEN_EAT_LABEL_NONCE:
            binary_value = convert_to_binary(claim_value);
            if(q_useful_buf_c_is_null(binary_value)) {
                fprintf(stderr, "bad nonce value \"%s\"\n", claim_value);
                return 1;
            }
            ctoken_encode_nonce(encode_ctx, binary_value);
            break;


        case CTOKEN_EAT_LABEL_SECURITY_LEVEL:
            sec_level = parse_sec_level_value(claim_value);
            if(sec_level == EAT_SL_INVALID) {
                fprintf(stderr, "bad security level \"%s\"\n", claim_value);
                return 1;
            }
            ctoken_encode_security_level(encode_ctx, sec_level);
            break;

        case CTOKEN_EAT_LABEL_DEBUG_STATE:
            debug_level = parse_dbg_x(claim_value);
            if(debug_level == CTOKEN_DEBUG_INVALID) {
                fprintf(stderr, "bad debug level \"%s\"\n", claim_value);
                return 1;
            }
            ctoken_encode_debug_state(encode_ctx, debug_level);
            break;

        case 0:
            // claim label is a string
            break;
    }

    FREEIF(submod_name);
    FREEIF(claim_label);
    FREEIF(claim_value);

    return 0;
}


int encode_claims2(struct ctoken_encode_ctx *encode_ctx, const char **claims)
{
    // try to map claim to a known integer label and call the right output
    // function for the claim

    // if claim is a string, error out

    // if claim is a number, proceeding is OK
    // try decoding value as an integer
    // next, try decoding value has a double
    // 





    return 0;
}


int write_bytes(FILE *out_file, struct q_useful_buf_c token)
{
    size_t x = fwrite(token.ptr, 1, token.len, out_file);

    return x == token.len ? 1 : 0;
}


int encode_claims(FILE *output, const char **claims)
{

    while(*claims != NULL) {
        const char *label;
        const char *value;
        const char *submod;


        // decode into submod, label and value
        // todo: strdup the value so all are malloced.
        size_t l;
        const char *x1 = copy_up_to_colon(*claims, &l);
        if(x1) {
            // Something wrong with the claim
            return -900;
        }

        const char *remains = *claims + l + 1;

        const char *x2 = copy_up_to_colon(remains, &l);

        if(x2 == NULL) {
            // Format is label:value
            label = x1;
            value = remains;
        } else {
            // format is submod:label:value
            submod = x1;
            label = x2;
            value = x2 + l + 1;
        }

        // Is label a string or a number?
        int64_t int_label;
        char *end;

        int_label = strtoll(label, &end, 10);
        if(*end != '\0') {
            // label is a string
        }

        



        // Is label something we understand?
        // If yes, then call the right encoder for it
        // If no, then generically encode it the best we can

        // Is





        claims++;
    }

    struct ctoken_encode_ctx encode_ctx;

    ctoken_encode_init(&encode_ctx, 0, 0, CTOKEN_PROTECTION_NONE, 0);

    struct q_useful_buf out_buf = (struct q_useful_buf){NULL, SIZE_MAX};
    struct q_useful_buf_c completed_token;


    // Loop only executes twice, once to compute size then to actually created token
    while(1) {
        ctoken_encode_start(&encode_ctx, out_buf);

        encode_claims2(&encode_ctx, claims);

        ctoken_encode_finish(&encode_ctx, &completed_token);

        if(out_buf.ptr != NULL) {
            // Normal exit from loop
            break;
        }

        out_buf.ptr = malloc(completed_token.len);
        out_buf.len = completed_token.len;
    }

    write_bytes(output, completed_token);

    free(out_buf.ptr);


    return 0;
}




int ctoken(const struct ctoken_arguments *arguments)
{
    struct q_useful_buf_c input_bytes = NULL_Q_USEFUL_BUF_C;
    FILE *output;

    if(arguments->output_file) {
        output = fopen(arguments->output_file, "r");
        if(output == NULL) {
            fprintf(stderr, "error opening output file \"%s\"\n", arguments->output_file);
            return -4;
        }
    } else {
        output = stdout;
    }

    if(arguments->input_file) {
        if(arguments->claims) {
            fprintf(stderr, "Can't give -in option and -claim option at the same time (yet)\n");
            return -9;
        }

        int file_descriptor;
        if(!strcmp(arguments->input_file, "-")) {
            file_descriptor = 0;
        } else {
            file_descriptor = open(arguments->input_file, O_RDONLY);
            if(file_descriptor < 0) {
                fprintf(stderr, "can't open input file \"%s\" (%d)\n", arguments->input_file, errno);
                return -1;
            }
        }
        input_bytes = read_file(file_descriptor);
        if(UsefulBuf_IsNULLC(input_bytes)) {
            fprintf(stderr, "error reading input file \"%s\"\n", arguments->input_file);
            return -2;
        }

        // TODO: need to handle JSON too.
        decode_cbor(output, input_bytes, arguments->output_format);

        return 0;
    } else {
        if(arguments->claims) {
            encode_claims(output, arguments->claims);

        } else {
            fprintf(stderr, "No input given (neither -in or -claim given)\n");
            return -88;
        }
    }


    return 0;
}



void ct_main()
{
    struct ctoken_arguments arguments;

    memset(&arguments, 0, sizeof(arguments));

    arguments.input_file = "token.cbor";

    ctoken(&arguments);

}
