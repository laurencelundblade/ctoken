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

#include "jtoken_adapt.h"
#include "ctoken_adapt.h"

#include <stdint.h>
#include <stdlib.h>

#include "base64.h"

#include "file_io.h"

#include "jtoken_encode.h"


#include "xclaim.h"




int xclaim_processor(xclaim_decoder *decoder, xclaim_encode *encoder)
{
    struct q_useful_buf_c submod_name;
    struct q_useful_buf_c token;
    enum ctoken_type_t    type;
    int                   e;


    /* First output the regular claims */
    while(1) {
        struct xclaim claim;

        e = (decoder->next_claim)(decoder->ctx, &claim);
        if(e != 0) {
            break;
        }
        (encoder->output_claim)(encoder->ctx, &claim);
    }
    if(e != 99) {
        // Error out
        return e;
    }

    (encoder->start_submods_section)(encoder->ctx);
    /* Now the submodules */
    uint32_t index = 0;
    while(1) {
        e = (decoder->enter_submod(decoder->ctx, index, &submod_name));
        if(e == 0) {
            /* is a regular submodule, so recurse */
            //(o->open_submod)(o->ctx, submod_name); // TODO: fix this
            xclaim_processor(decoder, encoder);
            (encoder->close_submod)(encoder->ctx);
            (decoder->exit_submod)(decoder->ctx);
        } else if( e == 88) {
            /* Is a nested token. This can be processed as an opaque blob
             * or there can be recursion, but it recursion must be at a
             * larger level because it key material and such need to be
             * supplied. */
            (decoder->get_nested)(decoder->ctx, index, &type, &token);
            (encoder->output_nested)(encoder->ctx, token);
        } else if(e == 88) {
            // Normal exit from loop
            break;
        } else {
            return e;
        }
    }
    (encoder->end_submods_section)(encoder->ctx);

    return 0;
}




/* This drives the encoding of the input in CBOR using ctoken. */
int encode_as_cbor(xclaim_decoder *xclaim_decoder, FILE *output_file)
{
    xclaim_encode             xclaim_encoder;
    struct ctoken_encode_ctx  ctoken_encoder;
    struct q_useful_buf       out_buf;
    struct q_useful_buf_c     completed_token;


    /* Set up the ctoken encoder with all the necessary options.
       This is a lot. There is a lot of work to do. */
    // TODO: further set up needed.
    ctoken_encode_init(&ctoken_encoder, 0, 0, CTOKEN_PROTECTION_NONE, 0);

    /* Set up the xclaim decoder to work with ctoken. */
    xclaim_ctoken_encode_init(&xclaim_encoder, &ctoken_encoder);


    // Loop only executes twice, once to compute size then to actually created token
    out_buf = (struct q_useful_buf){NULL, SIZE_MAX};

    while(1) {
        ctoken_encode_start(&ctoken_encoder, out_buf);

        xclaim_processor(xclaim_decoder, &xclaim_encoder);

        ctoken_encode_finish(&ctoken_encoder, &completed_token);

        if(out_buf.ptr != NULL) {
            // Normal exit from loop
            break;
        }

        out_buf.ptr = malloc(completed_token.len);
        out_buf.len = completed_token.len;
    }

    write_bytes(output_file, completed_token);

    free(out_buf.ptr);

    return 0; // TODO:
}




int encode_as_json(xclaim_decoder *in, FILE *output_file)
{
    xclaim_encode output;
    struct jtoken_encode_ctx jo;

    jo.out_file = output_file;

    xclaim_jtoken_encode_init(&output, &jo);

    xclaim_processor(in, &output);

    // TODO: error handling

    return 0;
}




int init_ctoken_iclaims(xclaim_decoder           *xclaim_decoder,
                        struct ctoken_decode_ctx *ctx,
                        struct q_useful_buf_c     input_bytes)
{
    int error;

    ctoken_decode_init(ctx, 0, 0, CTOKEN_PROTECTION_NONE);

    error = ctoken_decode_validate_token(ctx, input_bytes);
    if(error) {
        return -9;
    }

    xclaim_ctoken_decode_init(xclaim_decoder, ctx);

    return 0;
}





int ctoken(const struct ctoken_arguments *arguments)
{
    struct q_useful_buf_c    input_bytes = NULL_Q_USEFUL_BUF_C;
    FILE                    *output_file;
    struct ctoken_decode_ctx cctx;
    struct parg parg;

    xclaim_decoder decoder;

    /* Set up the xlaim_decoder object first. The type of this object
       depends on the input type (e.g. CBOR or command line arguments
       (eventually JWT too)). The decoder object will be called by
     the outputter to iterate over all the claims. */
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
        if(init_ctoken_iclaims(&decoder, &cctx, input_bytes)) {
            return 1;
        }

    } else {
        if(arguments->claims) {
            /* input is some claim arguments. */
            if(setup1_parg_decode(&decoder, &parg, arguments->claims)) {
                return 1;
            }

        } else {
            fprintf(stderr, "No input given (neither -in or -claim given)\n");
            return -88;
        }
    }


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


    /* Call the outputter to do the actual work */
    if(arguments->output_format == OUT_FORMAT_CBOR) {
        encode_as_cbor(&decoder, output_file);

    } else {
        encode_as_json(&decoder, output_file);

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

#ifdef XXXXXX
/*


open output file descriptor

encode into memory

 write to file descriptor


 does JSON encoder write to memory?



 loop over arguments

 loop over read claims






 ctoken outputer
 jtoken outputer

These two work differently (at the moment)


 ctoken reader

 arg parser... not really a





 */




#if 0

int reencode_cbor_generic(struct output_context *me, QCBORItem claim_item)
{
    char substitue_json_name[20];
    const char *json_name;
    bool bool_value;
    oclaims *o = NULL;

    switch(claim_item.uDataType) {
        case QCBOR_TYPE_INT64:
            (o->output_int64)(o->ctx, claim_item.label.int64, claim_item.val.int64);
            break;

/*
        case QCBOR_TYPE_UINT64:
            output_uint64(output_file,
                         indention_level,
                         json_name ? json_name : substitue_json_name,
                         claim_item.val.uint64);
            break;
*/


        default:
            // TODO: some type that is not understood. Fix error code
            return 1;
            break;
    }

    return 0; // TODO: error handling
}

#endif


int xclaim_encode_generic(xclaim_encode *o, const QCBORItem *claim_item)
{
    bool bool_value;

    switch(claim_item->uDataType) {
        case QCBOR_TYPE_INT64:
            (o->output_int64)(o->ctx, claim_item->label.int64, claim_item->val.int64);
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
            (o->output_double)(o->ctx, claim_item->label.int64, claim_item->val.dfnum);
             break;

         case QCBOR_TYPE_TEXT_STRING:
             (o->output_text)(o->ctx, claim_item->label.int64, claim_item->val.string);
             break;

         case QCBOR_TYPE_BYTE_STRING:
             (o->output_byte_string)(o->ctx, claim_item->label.int64, claim_item->val.string);
             break;

         case QCBOR_TYPE_TRUE:
         case QCBOR_TYPE_FALSE:
              bool_value = claim_item->uDataType == QCBOR_TYPE_TRUE;
              (o->output_bool)(o->ctx, claim_item->label.int64, bool_value);
             break;

         case QCBOR_TYPE_NULL:
              (o->output_null)(o->ctx, claim_item->label.int64);
             break;

        default:
            // TODO: some type that is not understood. Fix error code
            return 1;
            break;
    }


    return 0; // TODO: error handling

}




#if 0

static void reencode_claim(const QCBORItem *claim_item, struct output_context *me)
{
    switch(claim_item->label.int64) {

        case CTOKEN_CWT_LABEL_ISSUER:
            if(me->output_type == OUT_JSON) {
                jtoken_encode_issuer(&(me->u.jwt), claim_item->val.string);
            } else {
                ctoken_encode_issuer(&(me->u.ctoken), claim_item->val.string);
            }
            break;

        case CTOKEN_CWT_LABEL_SUBJECT:
            if(me->output_type == OUT_JSON) {
                jtoken_encode_subject(&(me->u.jwt), claim_item->val.string);
            } else {
                ctoken_encode_subject(&(me->u.ctoken), claim_item->val.string);
            }
            break;

        case CTOKEN_CWT_LABEL_AUDIENCE:
            if(me->output_type == OUT_JSON) {
                jtoken_encode_audience(&(me->u.jwt), claim_item->val.string);
            } else {
                ctoken_encode_audience(&(me->u.ctoken), claim_item->val.string);
            }
            break;

        case CTOKEN_CWT_LABEL_EXPIRATION:
            if(me->output_type == OUT_JSON) {
                jtoken_encode_expiration(&(me->u.jwt), claim_item->val.int64);
            } else {
                ctoken_encode_expiration(&(me->u.ctoken), claim_item->val.int64);
            }
            break;

        case CTOKEN_CWT_LABEL_NOT_BEFORE:
            if(me->output_type == OUT_JSON) {
                jtoken_encode_not_before(&(me->u.jwt), claim_item->val.int64);
            } else {
                ctoken_encode_not_before(&(me->u.ctoken), claim_item->val.int64);
            }
            break;

        case CTOKEN_CWT_LABEL_IAT:
            if(me->output_type == OUT_JSON) {
                jtoken_encode_iat(&(me->u.jwt), claim_item->val.int64);
            } else {
                ctoken_encode_iat(&(me->u.ctoken), claim_item->val.int64);
            }
            break;

        case CTOKEN_CWT_LABEL_CTI:
            if(me->output_type == OUT_JSON) {
                jtoken_encode_jti(&(me->u.jwt), claim_item->val.string);
            } else {
                ctoken_encode_cti(&(me->u.ctoken), claim_item->val.string);
            }
            break;

        case CTOKEN_EAT_LABEL_UEID:
            if(me->output_type == OUT_JSON) {
                jtoken_encode_ueid(&(me->u.jwt), claim_item->val.string);
            } else {
                ctoken_encode_ueid(&(me->u.ctoken), claim_item->val.string);
            }
            break;

        case CTOKEN_EAT_LABEL_NONCE:
            if(me->output_type == OUT_JSON) {
                jtoken_encode_nonce(&(me->u.jwt), claim_item->val.string);
            } else {
                ctoken_encode_nonce(&(me->u.ctoken), claim_item->val.string);
            }
            break;

        case CTOKEN_EAT_LABEL_SECURITY_LEVEL:
            if(me->output_type == OUT_JSON) {
                ctoken_encode_security_level(&(me->u.ctoken), 1);
            } else {
                // TODO: build check that ctoken and jtoken values are the same
                jtoken_encode_security_level(&(me->u.jwt),
                                             (enum jtoken_security_level_t)1);
            }
            break;

        default:
            reencode_cbor_generic(me, *claim_item); // TODO: make a pointer
            break;

    }
}
#endif






#if 0
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
        reencode_claim(&claim_item, me);
    }
    return 0;
}
#endif




int
reencode_cbor_to_file(FILE *output_file, int format, struct q_useful_buf_c input_bytes)
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



static void reencode_claim_new(const QCBORItem *claim_item, xclaim_encode *out)
{
    switch(claim_item->label.int64) {

        case CTOKEN_CWT_LABEL_ISSUER:
            (out->output_issuer)(out->ctx, claim_item->val.string);
            break;
/*
        case CTOKEN_CWT_LABEL_SUBJECT:
            if(me->output_type == OUT_JSON) {
                jtoken_encode_subject(&(me->u.jwt), claim_item->val.string);
            } else {
                ctoken_encode_subject(&(me->u.ctoken), claim_item->val.string);
            }
            break;

        case CTOKEN_CWT_LABEL_AUDIENCE:
            if(me->output_type == OUT_JSON) {
                jtoken_encode_audience(&(me->u.jwt), claim_item->val.string);
            } else {
                ctoken_encode_audience(&(me->u.ctoken), claim_item->val.string);
            }
            break;

        case CTOKEN_CWT_LABEL_EXPIRATION:
            if(me->output_type == OUT_JSON) {
                jtoken_encode_expiration(&(me->u.jwt), claim_item->val.int64);
            } else {
                ctoken_encode_expiration(&(me->u.ctoken), claim_item->val.int64);
            }
            break;

        case CTOKEN_CWT_LABEL_NOT_BEFORE:
            if(me->output_type == OUT_JSON) {
                jtoken_encode_not_before(&(me->u.jwt), claim_item->val.int64);
            } else {
                ctoken_encode_not_before(&(me->u.ctoken), claim_item->val.int64);
            }
            break;

        case CTOKEN_CWT_LABEL_IAT:
            if(me->output_type == OUT_JSON) {
                jtoken_encode_iat(&(me->u.jwt), claim_item->val.int64);
            } else {
                ctoken_encode_iat(&(me->u.ctoken), claim_item->val.int64);
            }
            break;

        case CTOKEN_CWT_LABEL_CTI:
            if(me->output_type == OUT_JSON) {
                jtoken_encode_jti(&(me->u.jwt), claim_item->val.string);
            } else {
                ctoken_encode_cti(&(me->u.ctoken), claim_item->val.string);
            }
            break;

        case CTOKEN_EAT_LABEL_UEID:
            if(me->output_type == OUT_JSON) {
                jtoken_encode_ueid(&(me->u.jwt), claim_item->val.string);
            } else {
                ctoken_encode_ueid(&(me->u.ctoken), claim_item->val.string);
            }
            break;

        case CTOKEN_EAT_LABEL_NONCE:
            if(me->output_type == OUT_JSON) {
                jtoken_encode_nonce(&(me->u.jwt), claim_item->val.string);
            } else {
                ctoken_encode_nonce(&(me->u.ctoken), claim_item->val.string);
            }
            break;

        case CTOKEN_EAT_LABEL_SECURITY_LEVEL:
            if(me->output_type == OUT_JSON) {
                ctoken_encode_security_level(&(me->u.ctoken), 1);
            } else {
                // TODO: build check that ctoken and jtoken values are the same
                jtoken_encode_security_level(&(me->u.jwt),
                                             (enum jtoken_security_level_t)1);
            }
            break;
*/
        default:
            xclaim_encode_generic(out, claim_item);
            break;

    }
}


#endif
