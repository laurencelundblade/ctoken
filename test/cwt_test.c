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
                       CTOKEN_PROTECTION_COSE_SIGN1,
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
    ctoken_decode_init(&decode_context,
                       T_COSE_OPT_ALLOW_SHORT_CIRCUIT,
                       0,
                       CTOKEN_PROTECTION_BY_TAG);

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




#define C_ARRAY_COUNT(array,type) (sizeof(array)/sizeof(type))


struct encode_tag_test {
    uint32_t                  test_number;
    uint32_t                  top_level_tag;
    uint32_t                  cose_tag;
    enum ctoken_protection_t  protection_type;
    struct q_useful_buf_c     first_bytes;
};

struct encode_tag_test encode_tag_tests[] =  {
    {1, 0,                            0, CTOKEN_PROTECTION_NONE,       {(uint8_t[]){0xD9, 0x02, 0x59, 0xA1}, 4}},
    {2, CTOKEN_OPT_TOP_LEVEL_NOT_TAG, 0, CTOKEN_PROTECTION_NONE,       {(uint8_t[]){0xA1}, 1}},
    {3, 0,                            0, CTOKEN_PROTECTION_COSE_SIGN1, {(uint8_t[]){0xD8, 0x3D, 0xD2, 0x84}, 4}},
    {4, CTOKEN_OPT_TOP_LEVEL_NOT_TAG, 0, CTOKEN_PROTECTION_COSE_SIGN1, {(uint8_t[]){0xD2, 0x84}, 2}},

    {5, 0,                            T_COSE_OPT_OMIT_CBOR_TAG, CTOKEN_PROTECTION_NONE,       {(uint8_t[]){0xD9, 0x02, 0x59, 0xA1}, 4}},
    {6, CTOKEN_OPT_TOP_LEVEL_NOT_TAG, T_COSE_OPT_OMIT_CBOR_TAG, CTOKEN_PROTECTION_NONE,       {(uint8_t[]){0xA1}, 1}},
    {7, 0,                            T_COSE_OPT_OMIT_CBOR_TAG, CTOKEN_PROTECTION_COSE_SIGN1, {(uint8_t[]){0xD8, 0x3D, 0xD2, 0x84}, 4}},
    {8, CTOKEN_OPT_TOP_LEVEL_NOT_TAG, T_COSE_OPT_OMIT_CBOR_TAG, CTOKEN_PROTECTION_COSE_SIGN1, {(uint8_t[]){0x84}, 1}},
};



/* Return code is
 xxxyyyzzz where zz is the error code, yy is the test number and zz is
 check being performed
 */
static inline int32_t test_result_code(uint32_t           test_case,
                                        uint32_t           test_number,
                                        enum ctoken_err_t  error_code)
{
    return (test_case * 1000000) + (test_number * 1000) + (int32_t)error_code;
}


int32_t cwt_tags_test()
{
    enum ctoken_err_t         result;
    MakeUsefulBufOnStack(     token_out_buffer, 200);
    struct q_useful_buf_c     completed_token;
    struct ctoken_encode_ctx  encode_context;
    struct q_useful_buf_c     token_head;

    for(int i = 0; i < C_ARRAY_COUNT(encode_tag_tests, struct encode_tag_test); i++) {
        if(encode_tag_tests[i].test_number == 7) {
            // Does nothing. Allows setting break point for particular test.
            result = 0;
        }

        ctoken_encode_init(&encode_context,
                           encode_tag_tests[i].cose_tag | T_COSE_OPT_SHORT_CIRCUIT_SIG,
                           encode_tag_tests[i].top_level_tag,
                           encode_tag_tests[i].protection_type,
                           T_COSE_ALGORITHM_ES256);

        result = ctoken_encode_start(&encode_context, token_out_buffer);
        if(encode_tag_tests[i].test_number == 7) {
            /* Special case for test number 7 that should return an error */
            if(result != CTOKEN_ERR_TAG_COMBO_NOT_ALLOWED) {
                return test_result_code(4, encode_tag_tests[i].test_number, result);
            } else {
                continue;
            }
        }

        if(result) {
            return test_result_code(1, encode_tag_tests[i].test_number, result);
        }

        ctoken_encode_expiration(&encode_context, 9999);

        result = ctoken_encode_finish(&encode_context, &completed_token);
        if(result) {
            return test_result_code(2, encode_tag_tests[i].test_number, result);
        }

        token_head = q_useful_buf_head(completed_token, encode_tag_tests[i].first_bytes.len);

        if(q_useful_buf_compare(token_head, encode_tag_tests[i].first_bytes)) {
            return test_result_code(3, encode_tag_tests[i].test_number, result);
        }
    }
    
    return 0;
}
