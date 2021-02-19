/*
 * xclaim.c
 *
 * Copyright (c) 2021, Laurence Lundblade.
 *
 * Created by Laurence Lundblade on 2/17/21.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "xclaim.h"



int xclaim_processor(xclaim_decoder *decoder, xclaim_encoder *encoder)
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

    index = 0;
    e = (decoder->enter_submod(decoder->ctx, index, &submod_name));
    if(e == 0 || e == 88) {
        /* There are submods */
        (encoder->start_submods_section)(encoder->ctx);
        do {
            if(e == 88) {
                /* It is a nested token. This can be processed as an opaque blob
                 * or there can be recursion, but it recursion must be at a
                 * larger level because it key material and such need to be
                 * supplied. */
                // TODO: this should include submod name
                (decoder->get_nested)(decoder->ctx, index, &type, &token);
                (encoder->output_nested)(encoder->ctx, token);
            } else {
                //(encoder->open_submod)(encoder->ctx, submod_name); // TODO: fix this
                xclaim_processor(decoder, encoder);
                (encoder->close_submod)(encoder->ctx);
                (decoder->exit_submod)(decoder->ctx);
            }

            index++;
            e = (decoder->enter_submod(decoder->ctx, index, &submod_name));
        } while (e == 0 || e == 88);
        (encoder->end_submods_section)(encoder->ctx);
    }

    if(e != CTOKEN_ERR_NO_MORE_CLAIMS) {
        // Error out
        return e;
    } else {
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

