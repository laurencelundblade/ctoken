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

#include "arg_parse.h"

#include "jtoken_adapt.h"
#include "ctoken_adapt.h"

#include <stdint.h>

#include "useful_file_io.h"

#include "xclaim.h"




int xclaim_processor(xclaim_decoder *decoder, xclaim_encode *encoder)
{
    struct q_useful_buf_c submod_name;
    struct q_useful_buf_c token;
    enum ctoken_type_t    type;
    int                   e;
    struct                xclaim claim;
    uint32_t              index;


    /* First output the regular claims */
    (decoder->rewind)(decoder->ctx);

    while(1) {
        e = (decoder->next_claim)(decoder->ctx, &claim);
        if(e != 0) {
            break;
        }
        (encoder->output_claim)(encoder->ctx, &claim);
    }
    if(e != CTOKEN_ERR_NO_MORE_CLAIMS) {
        // Error out
        return e;
    }
    
#if 0
    (encoder->start_submods_section)(encoder->ctx);
    /* Now the submodules */
    index = 0;
    while(1) {
        e = (decoder->enter_submod(decoder->ctx, index, &submod_name));
        if(e == 0) {
            /* is a regular submodule, so recurse */
            //(o->open_submod)(o->ctx, submod_name); // TODO: fix this
            xclaim_processor(decoder, encoder);
            (encoder->close_submod)(encoder->ctx);
            (decoder->exit_submod)(decoder->ctx);
        } else if( e == 88) {
            /* It is a nested token. This can be processed as an opaque blob
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
#endif

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

    return 0; // TODO: error code
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
