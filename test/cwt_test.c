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

#include "ctoken/ctoken_encode.h"
#include "ctoken/ctoken_decode.h"



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




struct encode_tag_test {
    uint32_t                  test_number;
    uint32_t                  top_level_tag;
    uint32_t                  cose_tag;
    enum ctoken_protection_t  protection_type;
    struct q_useful_buf_c     first_bytes;
};

static const struct encode_tag_test encode_tag_tests[] =  {
    {1, 0,                            0, CTOKEN_PROTECTION_NONE,       {(uint8_t[]){0xD9, 0x02, 0x59, 0xA1}, 4}},
    {2, CTOKEN_OPT_TOP_LEVEL_NOT_TAG, 0, CTOKEN_PROTECTION_NONE,       {(uint8_t[]){0xA1}, 1}},
    {3, 0,                            0, CTOKEN_PROTECTION_COSE_SIGN1, {(uint8_t[]){0xD8, 0x3D, 0xD2, 0x84}, 4}},
    {4, CTOKEN_OPT_TOP_LEVEL_NOT_TAG, 0, CTOKEN_PROTECTION_COSE_SIGN1, {(uint8_t[]){0xD2, 0x84}, 2}},

    {5, 0,                            T_COSE_OPT_OMIT_CBOR_TAG, CTOKEN_PROTECTION_NONE,       {(uint8_t[]){0xD9, 0x02, 0x59, 0xA1}, 4}},
    {6, CTOKEN_OPT_TOP_LEVEL_NOT_TAG, T_COSE_OPT_OMIT_CBOR_TAG, CTOKEN_PROTECTION_NONE,       {(uint8_t[]){0xA1}, 1}},
    {7, 0,                            T_COSE_OPT_OMIT_CBOR_TAG, CTOKEN_PROTECTION_COSE_SIGN1, {(uint8_t[]){0xD8, 0x3D, 0xD2, 0x84}, 4}},
    {8, CTOKEN_OPT_TOP_LEVEL_NOT_TAG, T_COSE_OPT_OMIT_CBOR_TAG, CTOKEN_PROTECTION_COSE_SIGN1, {(uint8_t[]){0x84}, 1}},
};

static const uint8_t bare_uccs[] = {
    0xA1, 0x04, 0x19, 0x27, 0x0F};

static const uint8_t uccs_tag[] = {
    0xD9, 0x02, 0x59, 0xA1, 0x04, 0x19, 0x27, 0x0F};

static const uint8_t cwt_cose_tag[] = {
    0xD8, 0x3D, 0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26,
    0xA1, 0x04, 0x58, 0x20, 0xEF, 0x95, 0x4B, 0x4B,
    0xD9, 0xBD, 0xF6, 0x70, 0xD0, 0x33, 0x60, 0x82,
    0xF5, 0xEF, 0x15, 0x2A, 0xF8, 0xF3, 0x5B, 0x6A,
    0x6C, 0x00, 0xEF, 0xA6, 0xA9, 0xA7, 0x1F, 0x49,
    0x51, 0x7E, 0x18, 0xC6, 0x45, 0xA1, 0x04, 0x19,
    0x27, 0x0F, 0x58, 0x40, 0x2C, 0x70, 0xDD, 0xAE,
    0x8E, 0x68, 0xB5, 0x20, 0x73, 0xE8, 0xC6, 0xD8,
    0xFA, 0xB6, 0xD0, 0xB8, 0x43, 0x97, 0xC9, 0xAE,
    0x7D, 0x21, 0x08, 0xB8, 0xA6, 0x4A, 0x72, 0xB0,
    0xFA, 0xD8, 0x88, 0x75, 0x2C, 0x70, 0xDD, 0xAE,
    0x8E, 0x68, 0xB5, 0x20, 0x73, 0xE8, 0xC6, 0xD8,
    0xFA, 0xB6, 0xD0, 0xB8, 0x43, 0x97, 0xC9, 0xAE,
    0x7D, 0x21, 0x08, 0xB8, 0xA6, 0x4A, 0x72, 0xB0,
    0xFA, 0xD8, 0x88, 0x75};

static const uint8_t bare_cwt_cose_tag[] = {
    0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26,
    0xA1, 0x04, 0x58, 0x20, 0xEF, 0x95, 0x4B, 0x4B,
    0xD9, 0xBD, 0xF6, 0x70, 0xD0, 0x33, 0x60, 0x82,
    0xF5, 0xEF, 0x15, 0x2A, 0xF8, 0xF3, 0x5B, 0x6A,
    0x6C, 0x00, 0xEF, 0xA6, 0xA9, 0xA7, 0x1F, 0x49,
    0x51, 0x7E, 0x18, 0xC6, 0x45, 0xA1, 0x04, 0x19,
    0x27, 0x0F, 0x58, 0x40, 0x2C, 0x70, 0xDD, 0xAE,
    0x8E, 0x68, 0xB5, 0x20, 0x73, 0xE8, 0xC6, 0xD8,
    0xFA, 0xB6, 0xD0, 0xB8, 0x43, 0x97, 0xC9, 0xAE,
    0x7D, 0x21, 0x08, 0xB8, 0xA6, 0x4A, 0x72, 0xB0,
    0xFA, 0xD8, 0x88, 0x75, 0x2C, 0x70, 0xDD, 0xAE,
    0x8E, 0x68, 0xB5, 0x20, 0x73, 0xE8, 0xC6, 0xD8,
    0xFA, 0xB6, 0xD0, 0xB8, 0x43, 0x97, 0xC9, 0xAE,
    0x7D, 0x21, 0x08, 0xB8, 0xA6, 0x4A, 0x72, 0xB0,
    0xFA, 0xD8, 0x88, 0x75};

static const uint8_t bare_cwt[] = {
    0x84, 0x43, 0xA1, 0x01, 0x26,
    0xA1, 0x04, 0x58, 0x20, 0xEF, 0x95, 0x4B, 0x4B,
    0xD9, 0xBD, 0xF6, 0x70, 0xD0, 0x33, 0x60, 0x82,
    0xF5, 0xEF, 0x15, 0x2A, 0xF8, 0xF3, 0x5B, 0x6A,
    0x6C, 0x00, 0xEF, 0xA6, 0xA9, 0xA7, 0x1F, 0x49,
    0x51, 0x7E, 0x18, 0xC6, 0x45, 0xA1, 0x04, 0x19,
    0x27, 0x0F, 0x58, 0x40, 0x2C, 0x70, 0xDD, 0xAE,
    0x8E, 0x68, 0xB5, 0x20, 0x73, 0xE8, 0xC6, 0xD8,
    0xFA, 0xB6, 0xD0, 0xB8, 0x43, 0x97, 0xC9, 0xAE,
    0x7D, 0x21, 0x08, 0xB8, 0xA6, 0x4A, 0x72, 0xB0,
    0xFA, 0xD8, 0x88, 0x75, 0x2C, 0x70, 0xDD, 0xAE,
    0x8E, 0x68, 0xB5, 0x20, 0x73, 0xE8, 0xC6, 0xD8,
    0xFA, 0xB6, 0xD0, 0xB8, 0x43, 0x97, 0xC9, 0xAE,
    0x7D, 0x21, 0x08, 0xB8, 0xA6, 0x4A, 0x72, 0xB0,
    0xFA, 0xD8, 0x88, 0x75};


struct decode_tag_test {
    uint32_t                  test_number;
    uint32_t                  top_level_tag;
    uint32_t                  cose_tag;
    enum ctoken_protection_t  protection_type;
    struct q_useful_buf_c     token_to_decode;
    enum ctoken_err_t         expected_error;
    enum ctoken_protection_t  expected_protection_type;

};


/* Use a function to initialize this array to not rely on the linker/loader
 to know how to initialize a pointer in one static data structure to
 other static data.
 */
static inline void init_decode_tag_tests(struct decode_tag_test test[])
{
    test[0] = (struct decode_tag_test) {
        .test_number     = 1,
        .top_level_tag   = CTOKEN_OPT_PROHIBIT_TOP_LEVEL_TAG,
        .cose_tag        = 0,
        .protection_type = CTOKEN_PROTECTION_NONE,
        .token_to_decode = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(bare_uccs),
        .expected_error  = CTOKEN_ERR_SUCCESS,
        .expected_protection_type = CTOKEN_PROTECTION_NONE
    };

    test[1] = (struct decode_tag_test) {
        .test_number     = 2,
        .top_level_tag   = CTOKEN_OPT_REQUIRE_TOP_LEVEL_TAG,
        .cose_tag        = 0,
        .protection_type = CTOKEN_PROTECTION_NONE,
        .token_to_decode = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(uccs_tag),
        .expected_error  = CTOKEN_ERR_SUCCESS,
        .expected_protection_type = CTOKEN_PROTECTION_NONE
    };

    test[2] = (struct decode_tag_test) {
        .test_number     = 3,
        .top_level_tag   = CTOKEN_OPT_PROHIBIT_TOP_LEVEL_TAG,
        .cose_tag        = 0,
        .protection_type = CTOKEN_PROTECTION_NONE,
        .token_to_decode = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(uccs_tag),
        .expected_error  = CTOKEN_ERR_SHOULD_NOT_BE_TAG
    };

    test[3] = (struct decode_tag_test) {
        .test_number     = 4,
        .top_level_tag   = CTOKEN_OPT_REQUIRE_TOP_LEVEL_TAG,
        .cose_tag        = 0,
        .protection_type = CTOKEN_PROTECTION_NONE,
        .token_to_decode = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(bare_uccs),
        .expected_error  = CTOKEN_ERR_SHOULD_BE_TAG
    };

    test[4] = (struct decode_tag_test) {
        .test_number     = 5,
        .top_level_tag   = 0,
        .cose_tag        = 0,
        .protection_type = CTOKEN_PROTECTION_BY_TAG,
        .token_to_decode = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(bare_uccs),
        .expected_error  = CTOKEN_ERR_UNDETERMINED_PROTECTION_TYPE
    };

    test[5] = (struct decode_tag_test) {
        .test_number     = 6,
        .top_level_tag   = 0,
        .cose_tag        = 0,
        .protection_type = CTOKEN_PROTECTION_BY_TAG,
        .token_to_decode = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(cwt_cose_tag),
        .expected_error  = CTOKEN_ERR_SUCCESS,
        .expected_protection_type = CTOKEN_PROTECTION_COSE_SIGN1
    };

    test[6] = (struct decode_tag_test) {
        .test_number     = 7,
        .top_level_tag   = 0,
        .cose_tag        = T_COSE_OPT_TAG_PROHIBITED,
        .protection_type = CTOKEN_PROTECTION_BY_TAG,
        .token_to_decode = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(cwt_cose_tag),
        .expected_error  = CTOKEN_ERROR_COSE_TAG
    };

    test[7] = (struct decode_tag_test) {
        .test_number     = 8,
        .top_level_tag   = 0,
        .cose_tag        = 0,
        .protection_type = CTOKEN_PROTECTION_NONE,
        .token_to_decode = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(cwt_cose_tag),
        .expected_error  = CTOKEN_ERR_SUCCESS,
        .expected_protection_type = CTOKEN_PROTECTION_COSE_SIGN1
    };

    test[8] = (struct decode_tag_test) {
        .test_number     = 9,
        .top_level_tag   = 0,
        .cose_tag        = 0,
        .protection_type = CTOKEN_PROTECTION_BY_TAG,
        .token_to_decode = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(bare_cwt_cose_tag),
        .expected_error  = CTOKEN_ERR_SUCCESS,
        .expected_protection_type = CTOKEN_PROTECTION_COSE_SIGN1
    };

    test[9] = (struct decode_tag_test) {
        .test_number     = 10,
        .top_level_tag   = 0,
        .cose_tag        = 0,
        .protection_type = CTOKEN_PROTECTION_BY_TAG,
        .token_to_decode = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(bare_cwt),
        .expected_error  = CTOKEN_ERR_UNDETERMINED_PROTECTION_TYPE,
    };

    test[10] = (struct decode_tag_test) {
        .test_number     = 11,
        .top_level_tag   = 0,
        .cose_tag        = 0,
        .protection_type = CTOKEN_PROTECTION_COSE_SIGN1,
        .token_to_decode = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(bare_cwt),
        .expected_error  = CTOKEN_ERR_SUCCESS,
        .expected_protection_type = CTOKEN_PROTECTION_COSE_SIGN1
    };

    test[11] = (struct decode_tag_test) {
        .test_number     = 12,
        .top_level_tag   = CTOKEN_OPT_REQUIRE_TOP_LEVEL_TAG,
        .cose_tag        = 0,
        .protection_type = CTOKEN_PROTECTION_COSE_SIGN1,
        .token_to_decode = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(bare_cwt),
        .expected_error  = CTOKEN_ERR_SHOULD_BE_TAG,
        .expected_protection_type = CTOKEN_PROTECTION_COSE_SIGN1
    };

    test[12] = (struct decode_tag_test) {
        .test_number     = 13,
        .top_level_tag   = CTOKEN_OPT_REQUIRE_TOP_LEVEL_TAG,
        .cose_tag        = 0,
        .protection_type = CTOKEN_PROTECTION_COSE_SIGN1,
        .token_to_decode = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(bare_cwt_cose_tag),
        .expected_error  = CTOKEN_ERR_SHOULD_BE_TAG,
        .expected_protection_type = CTOKEN_PROTECTION_COSE_SIGN1
    };

    test[13] = (struct decode_tag_test) {
        .test_number     = 1000,
        .top_level_tag   = 0,
        .cose_tag        = 0,
        .protection_type = CTOKEN_PROTECTION_NONE,
        .token_to_decode = NULL_Q_USEFUL_BUF_C,
        .expected_error  = CTOKEN_ERR_SUCCESS
    };
}

/* Return code is
 xxxyyyzzz where zz is the error code, yy is the test number and zz is
 check being performed
 */
static inline int32_t test_result_code(uint32_t            test_case,
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
    struct ctoken_decode_ctx  decode_context;
    struct q_useful_buf_c     token_head;

    for(int i = 0; i < C_ARRAY_COUNT(encode_tag_tests, struct encode_tag_test); i++) {
        if(encode_tag_tests[i].test_number == 3) {
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

    struct decode_tag_test decode_tag_tests[14];

    init_decode_tag_tests(decode_tag_tests);

    for(int i = 0; ; i++) {
        const struct decode_tag_test *test = &decode_tag_tests[i];

        /* End of list */
        if(q_useful_buf_c_is_null(test->token_to_decode)) {
            break;
        }

        /* Does nothing; just for setting break point on particular test */
        if(test->test_number == 7) {
            result = 0;
        }
        ctoken_decode_init(&decode_context,
                           test->cose_tag | T_COSE_OPT_ALLOW_SHORT_CIRCUIT,
                           test->top_level_tag,
                           test->protection_type);

        result = ctoken_decode_validate_token(&decode_context, test->token_to_decode);

        if(result != test->expected_error) {
            return test_result_code(5, test->test_number, result);
        }

        if(result == CTOKEN_ERR_SUCCESS &&
           ctoken_decode_get_protection_type(&decode_context) != test->expected_protection_type) {
            return test_result_code(6, test->test_number, result);
        }

        // TODO: add tests for returned unprocessed tag numbers
    }

    return 0;
}
