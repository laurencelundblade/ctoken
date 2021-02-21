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
    int                   xclaim_error;
    struct                xclaim claim;
    uint32_t              submod_index;


    /* First output the regular claims */
    (decoder->rewind)(decoder->ctx);

    while(1) {
        xclaim_error = (decoder->next_claim)(decoder->ctx, &claim);
        if(xclaim_error != XCLAIM_SUCCESS) {
            break;
        }
        (encoder->output_claim)(encoder->ctx, &claim);
    }
    if(xclaim_error != XCLAIM_NO_MORE) {
        // Error out
        return xclaim_error;
    }

    submod_index = 0;
    xclaim_error = (decoder->enter_submod(decoder->ctx, submod_index, &submod_name));
    if(xclaim_error == XCLAIM_SUCCESS || xclaim_error == XCLAIM_SUBMOD_IS_TOKEN) {
        /* There are submods */
        (encoder->start_submods_section)(encoder->ctx);
        do {
            if(xclaim_error == XCLAIM_SUBMOD_IS_TOKEN) {
                /* It is a nested token. This can be processed as an opaque blob
                 * or there can be recursion, but it recursion must be at a
                 * larger level because it key material and such need to be
                 * supplied. */
                // TODO: this should include submod name
                (decoder->get_nested)(decoder->ctx, submod_index, &type, &token);
                (encoder->output_nested)(encoder->ctx, token);
            } else {
                (encoder->open_submod)(encoder->ctx, "submod_name"); // TODO: fix this
                xclaim_error = xclaim_processor(decoder, encoder);
                if(xclaim_error != XCLAIM_SUCCESS) {
                    break;
                }
                (encoder->close_submod)(encoder->ctx);
                (decoder->exit_submod)(decoder->ctx);
            }

            submod_index++;
            xclaim_error = (decoder->enter_submod(decoder->ctx, submod_index, &submod_name));
        } while (xclaim_error == XCLAIM_SUCCESS || xclaim_error == XCLAIM_SUBMOD_IS_TOKEN);
        (encoder->end_submods_section)(encoder->ctx);
    } else if(xclaim_error == XCLAIM_NO_MORE) {
        xclaim_error = XCLAIM_SUCCESS;
    }

    return xclaim_error;
}

