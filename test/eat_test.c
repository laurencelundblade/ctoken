/*
 * eat_test.c
 *
 * Copyright (c) 2020 Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 2/13/20.
 */


#include "eat_test.h"
#include "ctoken_eat_encode.h"
#include "ctoken_eat_decode.h"


int32_t basic_eat_test(void)
{
    struct ctoken_encode_ctx  encode_ctx;
    MakeUsefulBufOnStack(     token_out_buffer, 200);
    struct q_useful_buf_c     completed_token;
    enum ctoken_err_t         result;
    struct ctoken_eat_location_t location;

    /* Set up the encoder to use short-circuit signing. It doesn't require a
     * key, so it is easy to get going with.  Must tell it a valid algorithm
     * ID even though it doesn't use it. This context can be used to create
     * one or more tokens.
     */
    ctoken_encode_init(&encode_ctx,
                       T_COSE_OPT_SHORT_CIRCUIT_SIG,
                       0,
                       T_COSE_ALGORITHM_ES256);

    /* Get started on a particular token by giving an out buffer.
     */
    result = ctoken_encode_start(&encode_ctx, token_out_buffer);
    if(result) {
        return 100 + (int32_t)result;
    }

    /* --- Add the claims --- */
    location.eat_loc_latitude = 34.88;
    location.eat_loc_longitude = 9.54;
    location.item_flags = 0x3;

    ctoken_eat_encode_location(&encode_ctx, &location);


    /* --- Done adding the claims --- */

    /* Finsh up the token. This is when the signing happens. The pointer
     * and length of the completed token are returned
     */
    result = ctoken_encode_finish(&encode_ctx, &completed_token);
    if(result) {
        return 200 + (int32_t)result;
    }

    struct ctoken_decode_cxt decode_context;
    /* Set up to verify and decode the token */

    /* Initialize the decoder / verifier context. No options are set
     * so two 0's are passed
     */
    ctoken_decode_init(&decode_context, T_COSE_OPT_ALLOW_SHORT_CIRCUIT, 0);

    /* Pass in the token and have it validated. If the token was corrupt
     * or the signature check failed, it will be returned here
     */
    result = ctoken_decode_validate_token(&decode_context, completed_token);
    if(result) {
        return 300 + (int32_t)result;
    }

    memset(&location, 0, sizeof(location));

    result = ctoken_eat_decode_location(&decode_context,
                                        &location);
    if(result) {
        return 400 + (int32_t)result;
    }

    if(location.eat_loc_longitude != 9.54 || location.eat_loc_latitude != 34.88) {
        return 500;
    }

    return 0;
}

