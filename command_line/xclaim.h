/*
* xclaim.h
*
* Copyright (c) 2021, Laurence Lundblade.
*
* Created by Laurence Lundblade on 2/17/21.
*
* SPDX-License-Identifier: BSD-3-Clause
*
* See BSD-3-Clause license in README.md
*/

#ifndef xclaim_h
#define xclaim_h

#include "ctoken.h"
#include "qcbor/qcbor_decode.h"

/*
This is an abstract base class for iterating over the claims in a token
including the submodules.

This is design to be implemented over different claim decoders and
parsers like the ctoken CWT decoder and the command line argument
parser for the ctoken command line.

*/



struct xclaim {
    QCBORItem  qcbor_item;
    union {
        struct ctoken_location_t location_claim;
    } u;
};


enum xclaim_errors_t {
    XCLAIM_SUCCESS = 0,

    XCLAIM_NO_MORE = 1,

    XCLAIM_SUBMOD_IS_TOKEN = 2,

    XCLAIM_CTOKEN_ERROR_BASE = 100,

    XCLAIM_JTOKEN_ERROR_BASE = 200,

    XCLAIM_ARG_ERROR_BASE = 300
};




typedef struct {
    /* vtable */
    void (*rewind)(void *ctx);
    int (*next_claim)(void *ctx, struct xclaim *claim);
    int (*enter_submod)(void *ctx,uint32_t index, struct q_useful_buf_c *name);
    int (*exit_submod)(void *ctx);
    int (*get_nested)(void *ctx, uint32_t index, enum ctoken_type_t *type, struct q_useful_buf_c *token);

    void *ctx;
} xclaim_decoder;




typedef struct  {
    /* vtable */
    int (*output_claim)(void *ctx, const struct xclaim *claim);
    int (*start_submods_section)(void *ctx);
    int (*end_submods_section)(void *ctx);
    int (*open_submod)(void *ctx, const char *submod_name);
    int (*close_submod)(void *ctx);
    int (*output_nested)(void *ctx, struct q_useful_buf_c token);

    void *ctx;
} xclaim_encoder;


int xclaim_processor(xclaim_decoder *decoder, xclaim_encoder *encoder);


#endif /* xclaim_h */
