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

#include "cwt_encode.h"
#include "cwt_decode.h"

#include "t_cose_common.h"
#include "t_cose_sign1_sign.h"


int32_t cwt_test()
{
    struct attest_token_encode_ctx encode_ctx;
    MakeUsefulBufOnStack(          token_out_buffer, 200);
    struct q_useful_buf_c          completed_token;
    enum attest_token_err_t        result;

    /* Set up the encoder to use short-circuit signing. It doesn't require a
     * key, so it is easy to get going with.  Must tell it a valid algorithm
     * ID even though it doesn't use it. This context can be used to create
     * one or more tokens.
     */
    attest_token_encode_init(&encode_ctx,
                             T_COSE_OPT_SHORT_CIRCUIT_SIG,
                             0,
                             T_COSE_ALGORITHM_ES256);

    /* Get started on a particular token by giving an out buffer.
     */
    result = attest_token_encode_start(&encode_ctx, &token_out_buffer);
    if(result) {
        return -9; // TODO: better error code
    }

    /* --- Add the claims --- */

    attest_token_encode_cwt_expiration(&encode_ctx, 9999);

    /* --- Done adding the claims --- */

    /* Finsh up the token. This is when the signing happens. The pointer
     * and length of the completed token are returned
     */
    result = attest_token_encode_finish(&encode_ctx, &completed_token);
    if(result) {
        return -99; // TODO: better error code
    }



    struct attest_token_decode_context decode_context;
    int64_t expiration;
    /* Set up to verify and decode the token */

    /* Initialize the decoder / verifier context. No options are set
     * so two 0's are passed
     */
    attest_token_decode_init(&decode_context, 0, 0);

    /* Pass in the token and have it validated. If the token was corrupt
     * or the signature check failed, it will be returned here
     */
    result = attest_token_decode_validate_token(&decode_context, completed_token);
    if(result) {
        return -199; // TODO: better error code
    }

    /* Get the expiration and see that it is what was expected */
    result = attest_token_decode_cwt_expiration(&decode_context, &expiration);
    if(result) {
        return -199; // TODO: better error code
    }

    if(expiration != 9999) {
        return -99;
    }

    /* Success! */
    return 0;
}
