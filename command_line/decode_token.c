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
#include "useful_buf_malloc.h"

#include "arg_parse.h"


#include <stdint.h>
#include <stdlib.h>

#include "base64.h"



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



void add_generic(struct ctoken_encode_ctx *encode_ctx,
                 int64_t                   claim_number,
                 const char               *claim_value)
{
    // TODO: fix type of label.
    // TODO: detect different type of claim_values
    ctoken_encode_add_tstr_z(encode_ctx, claim_number, claim_value);
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
    int64_t                      int64_value;
    enum ctoken_intended_use_t   intended_use;
    struct ctoken_location_t     location;

    switch(claim_number) {
        case CTOKEN_CWT_LABEL_ISSUER:
            ctoken_encode_issuer(encode_ctx, q_useful_buf_from_sz(claim_value));
            break;

        case CTOKEN_CWT_LABEL_SUBJECT:
            ctoken_encode_subject(encode_ctx, q_useful_buf_from_sz(claim_value));
            break;

        case CTOKEN_CWT_LABEL_AUDIENCE:
            ctoken_encode_audience(encode_ctx, q_useful_buf_from_sz(claim_value));
            break;

        case CTOKEN_CWT_LABEL_EXPIRATION:
            if(convert_to_int64(claim_value, &int64_value)) {
                fprintf(stderr, "Error in expiration format \"%s\"\n", claim_value);
                return 1;
            }
            ctoken_encode_expiration(encode_ctx, int64_value);
            break;

        case CTOKEN_CWT_LABEL_NOT_BEFORE:
            if(convert_to_int64(claim_value, &int64_value)) {
                fprintf(stderr, "Error in not-before format \"%s\"\n", claim_value);
                return 1;
            }
            ctoken_encode_not_before(encode_ctx, int64_value);
            break;

        case CTOKEN_CWT_LABEL_IAT:
             if(convert_to_int64(claim_value, &int64_value)) {
                 fprintf(stderr, "Error in issued-at format \"%s\"\n", claim_value);
                 return 1;
             }
             ctoken_encode_iat(encode_ctx, int64_value);
             break;

        case CTOKEN_CWT_LABEL_CTI:
             binary_value = convert_to_binary(claim_value);
             if(q_useful_buf_c_is_null(binary_value)) {
                 fprintf(stderr, "bad cti value \"%s\"\n", claim_value);
                 return 1;
             }
             ctoken_encode_cti(encode_ctx, binary_value);
             useful_buf_c_free(binary_value);
             break;

        case CTOKEN_EAT_LABEL_UEID:
            binary_value = convert_to_binary(claim_value);
            if(q_useful_buf_c_is_null(binary_value)) {
                fprintf(stderr, "bad ueid value \"%s\"\n", claim_value);
                return 1;
            }
            ctoken_encode_ueid(encode_ctx, binary_value);
            useful_buf_c_free(binary_value);
            break;

        case CTOKEN_EAT_LABEL_NONCE:
            binary_value = convert_to_binary(claim_value);
            if(q_useful_buf_c_is_null(binary_value)) {
                fprintf(stderr, "bad nonce value \"%s\"\n", claim_value);
                return 1;
            }
            ctoken_encode_nonce(encode_ctx, binary_value);
            useful_buf_c_free(binary_value);
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
            debug_level = parse_debug_state(claim_value);
            if(debug_level == CTOKEN_DEBUG_INVALID) {
                fprintf(stderr, "bad debug state \"%s\"\n", claim_value);
                return 1;
            }
            ctoken_encode_debug_state(encode_ctx, debug_level);
            break;

        case CTOKEN_EAT_LABEL_INTENDED_USE:
            intended_use = parse_intended_use(claim_value);
            if(intended_use == CTOKEN_USE_INVALID) {
                fprintf(stderr, "bad intended use \"%s\"\n", claim_value);
                return 1;
            }
            ctoken_encode_intended_use(encode_ctx, intended_use);
            break;

        case CTOKEN_EAT_LABEL_LOCATION:
            error = parse_location_arg(claim_value, &location);
            if(error) {
                fprintf(stderr, "bad location \"%s\"\n", claim_value);
                return 1;
            }
            ctoken_encode_location(encode_ctx, &location);

        default:
            add_generic(encode_ctx, claim_number, claim_value);
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
    int r;

    while(*claims) {
        r = encode_claim(encode_ctx, *claims);
        if(r) {
            return r;
        }
        claims++;
    }

    return 0;
}


/* returns 0 if write was successful, 1 if not */
int write_bytes(FILE *out_file, struct q_useful_buf_c token)
{
    size_t x = fwrite(token.ptr, 1, token.len, out_file);

    return x == token.len ? 1 : 0;
}


int encode_claims(FILE *output, const char **claims)
{
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

    /* Set up output file to which whatever is done will be written. */
    if(arguments->output_file) {
        output = fopen(arguments->output_file, "w");
        if(output == NULL) {
            fprintf(stderr, "error opening output file \"%s\"\n", arguments->output_file);
            return -4;
        }
    } else {
        output = stdout;
    }

    /* Figure out the input, either a file or some claim arguments (or both?)*/
    if(arguments->input_file) {

        /* Input is a file, not claim arguments */
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
            /* input is some claim arguments. */
            encode_claims(output, arguments->claims);

        } else {
            fprintf(stderr, "No input given (neither -in or -claim given)\n");
            return -88;
        }
    }

    fclose(output);

    return 0;
}



void ct_main()
{
    struct ctoken_arguments arguments;

    memset(&arguments, 0, sizeof(arguments));

    arguments.input_file = "token.cbor";

    ctoken(&arguments);

}
