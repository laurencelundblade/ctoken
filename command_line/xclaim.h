//
//  xclaim.h
//  CToken
//
//  Created by Laurence Lundblade on 2/14/21.
//  Copyright © 2021 Laurence Lundblade. All rights reserved.
//

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
        struct ctoken_location_t  location_claim;
    } u;
};

typedef struct iclaims xclaim_decoder;


struct iclaims {
    /* A vtable */
    int (*next_claim)(void *ctx, struct xclaim *claim);
    int (*enter_submod)(void *ctx,uint32_t index, struct q_useful_buf_c *name);
    int (*exit_submod)(void *ctx);
    int (*get_nested)(void *ctx, uint32_t index, enum ctoken_type_t *type, struct q_useful_buf_c *token);

    void *ctx;
};



typedef struct oclaims xclaim_encode;

struct oclaims {
    /* A vtable */
    int (*output_claim)(void *ctx, const struct xclaim *claim);
    int (*start_submods_section)(void *ctx);
    int (*end_submods_section)(void *ctx);
    int (*open_submod)(void *ctx, const char *submod_name);
    int (*close_submod)(void *ctx);
    int (*output_nested)(void *ctx, struct q_useful_buf_c token);

    void *ctx;
};


#endif /* xclaim_h */
