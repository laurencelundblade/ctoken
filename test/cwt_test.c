/*
 * cwt_test.c
 *
 * Copyright (c) 2020 Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 2/8/20.
 */


#include "cwt_test.h"


#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_sign1_sign.h"

#include "ctoken_encode.h"
#include "ctoken_decode.h"



int32_t cwt_test()
{
    struct ctoken_encode_ctx  encode_ctx;
    MakeUsefulBufOnStack(     token_out_buffer, 200);
    struct q_useful_buf_c     completed_token;
    enum ctoken_err_t         result;

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

    ctoken_encode_expiration(&encode_ctx, 9999);

    /* --- Done adding the claims --- */

    /* Finsh up the token. This is when the signing happens. The pointer
     * and length of the completed token are returned
     */
    result = ctoken_encode_finish(&encode_ctx, &completed_token);
    if(result) {
        return 200 + (int32_t)result;
    }



    struct ctoken_decode_ctx decode_context;
    int64_t expiration;
    /* Set up to verify and decode the token */

    /* Initialize the decoder / verifier context. 
     */
    ctoken_decode_init(&decode_context, T_COSE_OPT_ALLOW_SHORT_CIRCUIT, 0);

    /* Pass in the token and have it validated. If the token was corrupt
     * or the signature check failed, it will be returned here
     */
    result = ctoken_decode_validate_token(&decode_context, completed_token);
    if(result) {
        return 300 + (int32_t)result;
    }

    /* Get the expiration and see that it is what was expected */
    result = ctoken_decode_expiration(&decode_context, &expiration);
    if(result) {
        return 400 +(int32_t)result;
    }

    if(expiration != 9999) {
        return 500;
    }

    /* Success! */
    return 0;
}
