//
//  decode_token.c
//  CToken
//
//  Created by Laurence Lundblade on 1/11/21.
//  Copyright © 2021 Laurence Lundblade. All rights reserved.
//

#include "decode_token.h"
#include "t_cose/q_useful_buf.h"
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

#include "file_io.h"

#include "jtoken_encode.h"



struct output_context {
    enum {OUT_JSON, OUT_CBOR} output_type;
    union {
        struct ctoken_encode_ctx ctoken;
        struct jtoken_encode_ctx jwt;
    } u;

    FILE *output_file;
};




int reencode_cbor_generic(struct output_context *me, QCBORItem claim_item)
{
    char substitue_json_name[20];
    const char *json_name;
    bool bool_value;

    if(me->output_type == OUT_JSON) {
        json_name = cbor_label_to_json_name(claim_item.label.int64);
        if(json_name == NULL) {
            snprintf(substitue_json_name, sizeof(substitue_json_name), "%lld", claim_item.label.int64);
            json_name = substitue_json_name;
        }
    }

    switch(claim_item.uDataType) {
        case QCBOR_TYPE_INT64:
            if(me->output_type == OUT_JSON) {
                jtoken_encode_int64(&(me->u.jwt), json_name, claim_item.val.int64);
            } else {
                ctoken_encode_add_integer(&(me->u.ctoken),
                                          claim_item.label.int64,
                                          claim_item.val.int64);
            }
            break;
/*
        case QCBOR_TYPE_UINT64:
            output_uint64(output_file,
                         indention_level,
                         json_name ? json_name : substitue_json_name,
                         claim_item.val.uint64);
            break;
*/
        case QCBOR_TYPE_DOUBLE:
             if(me->output_type == OUT_JSON) {
                jtoken_encode_double(&(me->u.jwt), json_name, claim_item.val.dfnum);
            } else {
                ctoken_encode_add_double(&(me->u.ctoken),
                                       claim_item.label.int64,
                                          claim_item.val.dfnum);
            }
            break;

        case QCBOR_TYPE_TEXT_STRING:
            if(me->output_type == OUT_JSON) {
                jtoken_encode_text_string(&(me->u.jwt), json_name, claim_item.val.string);
            } else {
                ctoken_encode_add_tstr(&(me->u.ctoken),
                                          claim_item.label.int64,
                                          claim_item.val.string);
            }
            break;

        case QCBOR_TYPE_BYTE_STRING:
             if(me->output_type == OUT_JSON) {
                jtoken_encode_byte_string(&(me->u.jwt), json_name, claim_item.val.string);
            } else {
                ctoken_encode_add_bstr(&(me->u.ctoken),
                                       claim_item.label.int64,
                                          claim_item.val.string);
            }
            break;

        case QCBOR_TYPE_TRUE:
        case QCBOR_TYPE_FALSE:
             bool_value = claim_item.uDataType == QCBOR_TYPE_TRUE;
             if(me->output_type == OUT_JSON) {
                jtoken_encode_byte_string(&(me->u.jwt), json_name, claim_item.val.string);
            } else {
                ctoken_encode_add_bool(&(me->u.ctoken),
                                         claim_item.label.int64,
                                         bool_value);
            }
            break;

        case QCBOR_TYPE_NULL:
             if(me->output_type == OUT_JSON) {
                jtoken_encode_null(&(me->u.jwt), json_name);
            } else {
                ctoken_encode_add_null(&(me->u.ctoken),
                                         claim_item.label.int64);
            }
            break;


        default:
            // TODO: some type that is not understood. Fix error code
            return 1;
            break;
    }


    return 0; // TODO: error handling

}




/* Decode CBOR-format input and re-encode it is JSON or CBOR. */
int reencode_cbor(struct output_context *me, struct q_useful_buf_c input_bytes)
{
    struct ctoken_decode_ctx decode_context;
    enum ctoken_err_t        error;
    QCBORItem                claim_item;

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

        // TODO: are type checks needed for these?
        switch(claim_item.label.int64) {

            case CTOKEN_CWT_LABEL_ISSUER:
                if(me->output_type == OUT_JSON) {
                    jtoken_encode_issuer(&(me->u.jwt), claim_item.val.string);
                } else {
                    ctoken_encode_issuer(&(me->u.ctoken), claim_item.val.string);
                }
                break;

            case CTOKEN_CWT_LABEL_SUBJECT:
                if(me->output_type == OUT_JSON) {
                    jtoken_encode_subject(&(me->u.jwt), claim_item.val.string);
                } else {
                    ctoken_encode_subject(&(me->u.ctoken), claim_item.val.string);
                }
                break;

            case CTOKEN_CWT_LABEL_AUDIENCE:
                if(me->output_type == OUT_JSON) {
                    jtoken_encode_audience(&(me->u.jwt), claim_item.val.string);
                } else {
                    ctoken_encode_audience(&(me->u.ctoken), claim_item.val.string);
                }
                break;

            case CTOKEN_CWT_LABEL_EXPIRATION:
                if(me->output_type == OUT_JSON) {
                    jtoken_encode_expiration(&(me->u.jwt), claim_item.val.int64);
                } else {
                    ctoken_encode_expiration(&(me->u.ctoken), claim_item.val.int64);
                }
                break;

            case CTOKEN_CWT_LABEL_NOT_BEFORE:
                 if(me->output_type == OUT_JSON) {
                     jtoken_encode_not_before(&(me->u.jwt), claim_item.val.int64);
                 } else {
                     ctoken_encode_not_before(&(me->u.ctoken), claim_item.val.int64);
                 }
                 break;

            case CTOKEN_CWT_LABEL_IAT:
                 if(me->output_type == OUT_JSON) {
                     jtoken_encode_iat(&(me->u.jwt), claim_item.val.int64);
                 } else {
                     ctoken_encode_iat(&(me->u.ctoken), claim_item.val.int64);
                 }
                 break;

            case CTOKEN_CWT_LABEL_CTI:
                if(me->output_type == OUT_JSON) {
                    jtoken_encode_jti(&(me->u.jwt), claim_item.val.string);
                } else {
                    ctoken_encode_cti(&(me->u.ctoken), claim_item.val.string);
                }
                break;

            case CTOKEN_EAT_LABEL_UEID:
                if(me->output_type == OUT_JSON) {
                    jtoken_encode_ueid(&(me->u.jwt), claim_item.val.string);
                } else {
                    ctoken_encode_ueid(&(me->u.ctoken), claim_item.val.string);
                }
                break;

            case CTOKEN_EAT_LABEL_NONCE:
                if(me->output_type == OUT_JSON) {
                    jtoken_encode_nonce(&(me->u.jwt), claim_item.val.string);
                } else {
                    ctoken_encode_nonce(&(me->u.ctoken), claim_item.val.string);
                }
                break;

            case CTOKEN_EAT_LABEL_SECURITY_LEVEL:
                if(out_ctx->output_type == 1) { // TODO: value
                     ctoken_encode_security_level(&(me->u.ctoken), sec_level);
                 } else {
                     // TODO: build check that ctoken and jtoken values are the same
                     jtoken_encode_security_level(&(me->u.jwt),
                                                  (enum jtoken_security_level_t)sec_level);
                 }
                break;

            default:
                reencode_cbor_generic(me, claim_item);
                break;
                
        }
    }
    return 0;
}





static inline void
encode_generic_claim_argument(struct output_context    *out_ctx,
                 int64_t                   claim_number,
                 const char               *claim_label,
                 const char               *claim_value)
{
    if(out_ctx->output_type == OUT_JSON) {
        jtoken_encode_text_string_z(&(out_ctx->u.jwt), claim_label, claim_value);

    } else {// TODO: value
        // TODO: detect different type of claim_values
        /* Claim types....
         if it converts to an integer output as an integer
         if it converts to a double, output as double
         if it is true or false output as simple
         if it matches diagnostic binary notation output as bstr
         finally output as a text string

         or could just decode the whole diagnostic notation
         which is kind of what the above is.


         */
        // TODO: fix type of label.
        ctoken_encode_add_tstr_z(&(out_ctx->u.ctoken), claim_number, claim_value);
    }
}



/* Free a pointer if not NULL even if it is const */
#define FREEIF(x) if(x != NULL){free((void *)x);}

/* Encode a claim given as a command line argument */
int encode_claim_argument(struct output_context *out_ctx, const char *claim)
{
    const char *claim_label;
    const char *submod_name;
    const char *claim_value;
    int64_t     claim_number;
    int         error;

    QCBORItem                claim_item;


    // TODO: make this work for jwt
    struct ctoken_encode_ctx *encode_ctx = &(out_ctx->u.ctoken);

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
            claim_item.label.int64 = CTOKEN_CWT_LABEL_ISSUER;
            claim_item.uDataType = QCBOR_TYPE_TEXT_STRING;
            claim_item.val.string = q_useful_buf_from_sz(claim_value);



            if(out_ctx->output_type == 1) { // TODO: value
                ctoken_encode_issuer(&(out_ctx->u.ctoken), q_useful_buf_from_sz(claim_value));
            } else {
                jtoken_encode_issuer(&(out_ctx->u.jwt), q_useful_buf_from_sz(claim_value));
            }
            break;

        case CTOKEN_CWT_LABEL_SUBJECT:
            if(out_ctx->output_type == 1) { // TODO: value
                ctoken_encode_subject(&(out_ctx->u.ctoken), q_useful_buf_from_sz(claim_value));
            } else {
                jtoken_encode_subject(&(out_ctx->u.jwt), q_useful_buf_from_sz(claim_value));
            }
            break;

        case CTOKEN_CWT_LABEL_AUDIENCE:
            if(out_ctx->output_type == 1) { // TODO: value
                ctoken_encode_audience(&(out_ctx->u.ctoken), q_useful_buf_from_sz(claim_value));
            } else {
                jtoken_encode_audience(&(out_ctx->u.jwt), q_useful_buf_from_sz(claim_value));
            }
            break;

        case CTOKEN_CWT_LABEL_EXPIRATION:
            if(convert_to_int64(claim_value, &int64_value)) {
                fprintf(stderr, "Error in expiration format \"%s\"\n", claim_value);
                return 1;
            }
            if(out_ctx->output_type == 1) { // TODO: value
                ctoken_encode_expiration(&(out_ctx->u.ctoken), int64_value);
            } else {
                jtoken_encode_expiration(&(out_ctx->u.jwt), int64_value);
            }
            break;

        case CTOKEN_CWT_LABEL_NOT_BEFORE:
            if(convert_to_int64(claim_value, &int64_value)) {
                fprintf(stderr, "Error in not-before format \"%s\"\n", claim_value);
                return 1;
            }
            if(out_ctx->output_type == 1) { // TODO: value
                ctoken_encode_not_before(&(out_ctx->u.ctoken), int64_value);
            } else {
                jtoken_encode_not_before(&(out_ctx->u.jwt), int64_value);
            }
            break;

        case CTOKEN_CWT_LABEL_IAT:
             if(convert_to_int64(claim_value, &int64_value)) {
                 fprintf(stderr, "Error in issued-at format \"%s\"\n", claim_value);
                 return 1;
             }
            if(out_ctx->output_type == 1) { // TODO: value
                ctoken_encode_iat(&(out_ctx->u.ctoken), int64_value);
            } else {
                jtoken_encode_iat(&(out_ctx->u.jwt), int64_value);
            }
            break;

        case CTOKEN_CWT_LABEL_CTI:
             binary_value = convert_to_binary(claim_value);
             if(q_useful_buf_c_is_null(binary_value)) {
                 fprintf(stderr, "bad cti value \"%s\"\n", claim_value);
                 return 1;
             }
             if(out_ctx->output_type == 1) { // TODO: value
                 ctoken_encode_cti(&(out_ctx->u.ctoken), binary_value);
             } else {
                 // TODO: text vs binary here
                 jtoken_encode_jti(&(out_ctx->u.jwt), q_useful_buf_from_sz(claim_value));
             }
             useful_buf_c_free(binary_value);
             break;

        case CTOKEN_EAT_LABEL_UEID:
            binary_value = convert_to_binary(claim_value);
            if(q_useful_buf_c_is_null(binary_value)) {
                fprintf(stderr, "bad ueid value \"%s\"\n", claim_value);
                return 1;
            }
            if(out_ctx->output_type == 1) { // TODO: value
                ctoken_encode_ueid(&(out_ctx->u.ctoken), binary_value);
            } else {
                jtoken_encode_ueid(&(out_ctx->u.jwt), binary_value);
            }
            useful_buf_c_free(binary_value);
            break;

        case CTOKEN_EAT_LABEL_NONCE:
            binary_value = convert_to_binary(claim_value);
            if(q_useful_buf_c_is_null(binary_value)) {
                fprintf(stderr, "bad nonce value \"%s\"\n", claim_value);
                return 1;
            }
            if(out_ctx->output_type == 1) { // TODO: value
                ctoken_encode_nonce(&(out_ctx->u.ctoken), binary_value);
            } else {
                jtoken_encode_nonce(&(out_ctx->u.jwt), binary_value);
            }
            useful_buf_c_free(binary_value);
            break;

        case CTOKEN_EAT_LABEL_SECURITY_LEVEL:
            sec_level = parse_sec_level_value(claim_value);
            if(sec_level == EAT_SL_INVALID) {
                fprintf(stderr, "bad security level \"%s\"\n", claim_value);
                return 1;
            }
            if(out_ctx->output_type == 1) { // TODO: value
                ctoken_encode_security_level(&(out_ctx->u.ctoken), sec_level);
            } else {
                // TODO: build check that ctoken and jtoken values are the same
                jtoken_encode_security_level(&(out_ctx->u.jwt),
                                             (enum jtoken_security_level_t)sec_level);
            }
            break;

        case CTOKEN_EAT_LABEL_DEBUG_STATE:
            debug_level = parse_debug_state(claim_value);
            if(debug_level == CTOKEN_DEBUG_INVALID) {
                fprintf(stderr, "bad debug state \"%s\"\n", claim_value);
                return 1;
            }
            if(out_ctx->output_type == 1) { // TODO: value
               ctoken_encode_debug_state(&(out_ctx->u.ctoken), debug_level);
            } else {
               jtoken_encode_debug_state(&(out_ctx->u.jwt),
                                         (enum jtoken_debug_level_t) debug_level);
            }
            break;

        case CTOKEN_EAT_LABEL_INTENDED_USE:
            intended_use = parse_intended_use(claim_value);
            if(intended_use == CTOKEN_USE_INVALID) {
                fprintf(stderr, "bad intended use \"%s\"\n", claim_value);
                return 1;
            }
            ctoken_encode_intended_use(&(out_ctx->u.ctoken), intended_use);
            break;

        case CTOKEN_EAT_LABEL_LOCATION:
            error = parse_location_arg(claim_value, &location);
            if(error) {
                fprintf(stderr, "bad location \"%s\"\n", claim_value);
                return 1;
            }
            ctoken_encode_location(encode_ctx, &location);

        default:
            encode_generic_claim_argument(out_ctx, claim_number, claim_label, claim_value);
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


int encode_claims2(struct output_context *out_ctx, const char **claims)
{
    int r;

    while(*claims) {
        r = encode_claim_argument(out_ctx, *claims);
        if(r) {
            return r;
        }
        claims++;
    }

    return 0;
}



int encode_claims_arguments(FILE *output, const char **claims)
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


int
reencode_cbor_to_file(FILE *output_file, int format , struct q_useful_buf_c input_bytes)
{
    struct output_context output;

    if(format == OUT_FORMAT_CBOR) {
        output.output_type = OUT_CBOR;
        ctoken_encode_init(&output.u.ctoken, 0, 0, CTOKEN_PROTECTION_NONE, 0);

        struct q_useful_buf out_buf = (struct q_useful_buf){NULL, SIZE_MAX};
        struct q_useful_buf_c completed_token;

        // Loop only executes twice, once to compute size then to actually created token
        while(1) {
            ctoken_encode_start(&output.u.ctoken, out_buf);

            reencode_cbor(&output, input_bytes);

            ctoken_encode_finish(&output.u.ctoken, &completed_token);

            if(out_buf.ptr != NULL) {
                // Normal exit from loop
                break;
            }

            out_buf.ptr = malloc(completed_token.len);
            out_buf.len = completed_token.len;
        }

        write_bytes(output_file, completed_token);

        free(out_buf.ptr);
        
    } else {
        output.output_type = OUT_JSON;
        jwt_encode_init(&output.u.jwt, output_file);

        reencode_cbor(&output, input_bytes);
    }

    return 0;
}




int ctoken(const struct ctoken_arguments *arguments)
{
    struct q_useful_buf_c input_bytes = NULL_Q_USEFUL_BUF_C;
    FILE *output_file;
    struct output_context output;


    /* Set up output file to which whatever is done will be written. */
    if(arguments->output_file) {
        output_file = fopen(arguments->output_file, "w");
        if(output_file == NULL) {
            fprintf(stderr, "error opening output file \"%s\"\n", arguments->output_file);
            return -4;
        }
    } else {
        output_file = stdout;
    }

    output.output_file = output_file;

    if(arguments->output_format == OUT_FORMAT_CBOR) {

    } else {

        
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

        // TODO: need to handle JSON too. This assumes file is CBOR
        // TODO: key material and options for decoding CBOR
        // TODO: actually set up output file for CBOR outputting
        reencode_cbor_to_file(output_file, arguments->output_format , input_bytes);

        return 0;
    } else {
        if(arguments->claims) {
            /* input is some claim arguments. */
            encode_claims_arguments(output_file, arguments->claims);

        } else {
            fprintf(stderr, "No input given (neither -in or -claim given)\n");
            return -88;
        }
    }

    fclose(output_file);

    return 0;
}



void ct_main()
{
    struct ctoken_arguments arguments;

    memset(&arguments, 0, sizeof(arguments));

    arguments.input_file = "token.cbor";

    ctoken(&arguments);
}


/*


open output file descriptor

encode into memory

 write to file descriptor


 does JSON encoder write to memory?








 */
