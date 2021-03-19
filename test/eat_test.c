/*
 * eat_test.c
 *
 * Copyright (c) 2020-2021 Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 2/13/20.
 */


#include "eat_test.h"
#include "ctoken/ctoken_encode.h"
#include "ctoken/ctoken_decode.h"
#include "eat_test_tokens.h"


#define TUB(xxx) ((struct q_useful_buf_c){xxx##_token, xxx##_SIZE})


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


static inline int
ub_compare_sz(const char *string, const struct q_useful_buf_c buf1)
{
    return q_useful_buf_compare(q_useful_buf_from_sz(string), buf1);
}


int32_t basic_eat_test(void)
{
    struct ctoken_encode_ctx     encode_ctx;
    MakeUsefulBufOnStack(        token_out_buffer, 400);
    struct q_useful_buf_c        completed_token;
    enum ctoken_err_t            result;
    struct q_useful_buf_c        nonce;
    struct q_useful_buf_c        ueid;
    struct q_useful_buf_c        oemid;
    struct q_useful_buf_c        origination;
    enum ctoken_security_level_t security_level;
    bool                         secure_boot;
    enum ctoken_debug_level_t debug_level;
    struct ctoken_location_t location;
    uint64_t                     uptime;
    enum ctoken_intended_use_t   use;

    uint8_t test_nonce_bytes[] = {0x05, 0x08, 0x33, 0x99};
    const struct q_useful_buf_c test_nonce = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(test_nonce_bytes);

    uint8_t test_ueid_bytes[] = {0xa4, 0x68, 0x23, 0x99, 0x00, 0x01};
    const struct q_useful_buf_c test_ueid = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(test_ueid_bytes);

    uint8_t test_oemid_bytes[] = {0x14, 0x18, 0x13, 0x19, 0x10, 0x01};
    const struct q_useful_buf_c test_oemid = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(test_oemid_bytes);

    const struct q_useful_buf_c test_origination = Q_USEFUL_BUF_FROM_SZ_LITERAL("Acme TEE");


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
    /* Values are just made up for test */

    ctoken_encode_nonce(&encode_ctx,test_nonce);

    ctoken_encode_ueid(&encode_ctx, test_ueid);

    ctoken_encode_oemid(&encode_ctx, test_oemid);

    ctoken_encode_origination(&encode_ctx, test_origination);

    ctoken_encode_security_level(&encode_ctx, EAT_SL_SECURE_RESTRICTED);

    ctoken_encode_secure_boot(&encode_ctx, true);

    ctoken_encode_debug_state(&encode_ctx, CTOKEN_DEBUG_ENABLED);

    location.eat_loc_latitude = 34.88;
    location.eat_loc_longitude = 9.54;
    location.item_flags = 0x3;
    ctoken_encode_location(&encode_ctx, &location);

    ctoken_encode_uptime(&encode_ctx, 886688);

    ctoken_encode_intended_use(&encode_ctx, CTOKEN_USE_REGISTRATION);

    ctoken_encode_start_submod_section(&encode_ctx);

    ctoken_encode_open_submod(&encode_ctx, Q_USEFUL_BUF_FROM_SZ_LITERAL("a submodule"));

    ctoken_encode_uptime(&encode_ctx, 5);

    ctoken_encode_close_submod(&encode_ctx);

    ctoken_encode_end_submod_section(&encode_ctx);


    /* --- Done adding the claims --- */

    /* Finsh up the token. This is when the signing happens. The pointer
     * and length of the completed token are returned
     */
    result = ctoken_encode_finish(&encode_ctx, &completed_token);
    if(result) {
        return 200 + (int32_t)result;
    }

    struct ctoken_decode_ctx decode_context;
    /* Set up to verify and decode the token */

    /* Initialize the decoder / verifier context. No options are set
     * so two 0's are passed
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

    result = ctoken_decode_nonce(&decode_context, &nonce);
    if(result) {
        return 400 + (int32_t)result;
    }
    if(q_useful_buf_compare(nonce, test_nonce)) {
        return 499;
    }

    result = ctoken_decode_ueid(&decode_context, &ueid);
    if(result) {
        return 500 + (int32_t)result;
    }
    if(q_useful_buf_compare(ueid, test_ueid)) {
        return 599;
    }

    result = ctoken_decode_oemid(&decode_context, &oemid);
    if(result) {
        return 600 + (int32_t)result;
    }
    if(q_useful_buf_compare(oemid, test_oemid)) {
        return 699;
    }

    result = ctoken_decode_origination(&decode_context, &origination);
    if(result) {
        return 700 + (int32_t)result;
    }
    if(q_useful_buf_compare(origination, test_origination)) {
        return 799;
    }

    result = ctoken_decode_security_level(&decode_context, &security_level);
    if(result) {
        return 800 + (int32_t)result;
    }
    if(security_level != EAT_SL_SECURE_RESTRICTED) {
        return 899;
    }

    result = ctoken_decode_secure_boot(&decode_context, &secure_boot);
    if(result) {
        return 900 + (int32_t)result;
    }
    if(secure_boot != true) {
        return 999;
    }

    result = ctoken_decode_debug_state(&decode_context, &debug_level);
    if(result) {
        return 900 + (int32_t)result;
    }
    if(debug_level != CTOKEN_DEBUG_ENABLED) {
        return 999;
    }


    /* zero out to make sure results are tested correctly */
    memset(&location, 0, sizeof(location));

    result = ctoken_decode_location(&decode_context,
                                        &location);
    if(result) {
        return 1000 + (int32_t)result;
    }

    if(location.eat_loc_longitude != 9.54 ||
       location.eat_loc_latitude != 34.88 ||
       location.item_flags != 0x03 ) {
        return 1099;
    }


    result = ctoken_decode_uptime(&decode_context, &uptime);
    if(result) {
        return 1200 + (int32_t)result;
    }
    if(uptime != 886688) {
        return 1299;
    }

    result = ctoken_decode_intended_use(&decode_context, &use);
    if(result) {
        return 1500 + (int32_t)result;
    }
    if(use != CTOKEN_USE_REGISTRATION) {
        return 1599;
    }

    struct q_useful_buf_c submod_name;
    result = ctoken_decode_enter_nth_submod(&decode_context, 0, &submod_name);
    if(result) {
        return 1300 + (uint32_t)result;
    }

    ctoken_decode_uptime(&decode_context, &uptime);
    if(uptime != 5) {
        return 1399;
    }

    result = ctoken_decode_exit_submod(&decode_context);
    if(result) {
        return 1400 + (uint32_t)result;
    }


    return 0;
}


int32_t submods_test(void)
{
    struct ctoken_encode_ctx     encode_ctx;
    MakeUsefulBufOnStack(        token_out_buffer, 400);
    struct q_useful_buf_c        completed_token;
    enum ctoken_err_t            result;
    enum ctoken_err_t            ctoken_result;

    struct q_useful_buf_c        nonce;
    struct q_useful_buf_c        ueid;
    struct q_useful_buf_c        oemid;

    enum ctoken_type_t           type;
    struct q_useful_buf_c        submod_token;
    struct q_useful_buf_c        submod_name;
    uint32_t                     num_submods;

    struct ctoken_decode_ctx     decode_context;


    uint8_t test_nonce_bytes[] = {0x05, 0x08, 0x33, 0x99};
    const struct q_useful_buf_c test_nonce = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(test_nonce_bytes);

    uint8_t test_ueid_bytes[] = {0xa4, 0x68, 0x23, 0x99, 0x00, 0x01};
    const struct q_useful_buf_c test_ueid = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(test_ueid_bytes);

    uint8_t test_oemid_bytes[] = {0x14, 0x18, 0x13, 0x19, 0x10, 0x01};
    const struct q_useful_buf_c test_oemid = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(test_oemid_bytes);


    /* --- Make a token with submods --- */
    ctoken_encode_init(&encode_ctx,
                       T_COSE_OPT_SHORT_CIRCUIT_SIG,
                       0,
                       CTOKEN_PROTECTION_COSE_SIGN1,
                       T_COSE_ALGORITHM_ES256);


    result = ctoken_encode_start(&encode_ctx, token_out_buffer);
    if(result != CTOKEN_ERR_SUCCESS) {
        return 100 + (int32_t)result;
    }

    /* Add some claim values that are just made up for test */

    ctoken_encode_nonce(&encode_ctx, test_nonce);

    ctoken_encode_start_submod_section(&encode_ctx);

      ctoken_encode_open_submod(&encode_ctx, Q_USEFUL_BUF_FROM_SZ_LITERAL("sub1"));

        ctoken_encode_ueid(&encode_ctx, test_ueid);

        ctoken_encode_start_submod_section(&encode_ctx);

          ctoken_encode_nested_token(&encode_ctx,
                                     CTOKEN_TYPE_JSON,
                                     Q_USEFUL_BUF_FROM_SZ_LITERAL("json"),
                                     UsefulBuf_FromSZ("{ \"ueid\", \"xyz\"}"));

          ctoken_encode_open_submod(&encode_ctx, Q_USEFUL_BUF_FROM_SZ_LITERAL("subsub"));

            ctoken_encode_oemid(&encode_ctx, test_oemid);

          ctoken_encode_close_submod(&encode_ctx);

        ctoken_encode_end_submod_section(&encode_ctx);

      ctoken_encode_close_submod(&encode_ctx);

    ctoken_encode_end_submod_section(&encode_ctx);


    ctoken_result = ctoken_encode_finish(&encode_ctx, &completed_token);


     /* --- Validate and decode the token and all the claims in it --- */

     /* Initialize the decoder / verifier context. No options are set
      * so two 0's are passed
      */
     ctoken_decode_init(&decode_context,
                        T_COSE_OPT_ALLOW_SHORT_CIRCUIT,
                        CTOKEN_PROTECTION_BY_TAG,
                        0);

     result = ctoken_decode_validate_token(&decode_context, completed_token);
     if(result) {
         return 300 + (int32_t)result;
     }

     result = ctoken_decode_nonce(&decode_context, &nonce);
     if(result) {
         return 400 + (int32_t)result;
     }
     if(q_useful_buf_compare(nonce, test_nonce)) {
         return 499;
     }

    ctoken_decode_enter_named_submod(&decode_context, "sub1");

    result = ctoken_decode_ueid(&decode_context, &ueid);
    if(result) {
        return 500 + (int32_t)result;
    }
    if(q_useful_buf_compare(ueid, test_ueid)) {
        return 599;
    }

    ctoken_result = ctoken_decode_get_named_nested_token(&decode_context,
                                                         Q_USEFUL_BUF_FROM_SZ_LITERAL("json"),
                                                         &type,
                                                         &submod_token);
    if(ctoken_result != CTOKEN_ERR_SUCCESS ||
       ub_compare_sz("{ \"ueid\", \"xyz\"}", submod_token) ||
       type != CTOKEN_TYPE_JSON) {
        return 550;
    }

    ctoken_result = ctoken_decode_enter_named_submod(&decode_context, "json");
    if(ctoken_result != CTOKEN_ERR_SUBMOD_IS_A_TOKEN) {
        return 555;
    }

    ctoken_result = ctoken_decode_enter_nth_submod(&decode_context, 0, &submod_name);
    if(ctoken_result != CTOKEN_ERR_SUBMOD_IS_A_TOKEN) {
        return 556;
    }

    ctoken_decode_get_num_submods(&decode_context, &num_submods);
    if(num_submods != 2) {
        return 560;
    }

    ctoken_decode_enter_nth_submod(&decode_context, 1, &submod_name);
    if(ub_compare_sz("subsub", submod_name)) {
        return 540;
    }

    result = ctoken_decode_oemid(&decode_context, &oemid);
    if(result) {
        return 600 + (int32_t)result;
    }
    if(q_useful_buf_compare(oemid, test_oemid)) {
        return 699;
    }

    ctoken_decode_exit_submod(&decode_context);

    ctoken_decode_exit_submod(&decode_context);
    

    /* Get nonce against to know we are back at the top level */
    result = ctoken_decode_nonce(&decode_context, &nonce);
    if(result) {
        return 400 + (int32_t)result;
    }
    if(q_useful_buf_compare(nonce, test_nonce)) {
        return 499;
    }

    return 0;
}



int32_t submods_encode_errors_test(void)
{
    struct ctoken_encode_ctx     encode_ctx;
    MakeUsefulBufOnStack(        token_out_buffer, 400);
    enum ctoken_err_t            result;
    struct q_useful_buf_c        completed_token;


    ctoken_encode_init(&encode_ctx,
                       T_COSE_OPT_SHORT_CIRCUIT_SIG,
                       0,
                       CTOKEN_PROTECTION_COSE_SIGN1,
                       T_COSE_ALGORITHM_ES256);

    result = ctoken_encode_start(&encode_ctx, token_out_buffer);
    if(result) {
        return 100 + (int32_t)result;
    }


    ctoken_encode_open_submod(&encode_ctx, Q_USEFUL_BUF_FROM_SZ_LITERAL("foo"));

    result = ctoken_encode_finish(&encode_ctx, &completed_token);
    if(result != CTOKEN_ERR_NO_SUBMOD_SECTION_STARTED) {
        return 200 + (int32_t)result;
    }


    ctoken_encode_init(&encode_ctx,
                       T_COSE_OPT_SHORT_CIRCUIT_SIG,
                       0,
                       CTOKEN_PROTECTION_COSE_SIGN1,
                       T_COSE_ALGORITHM_ES256);

    result = ctoken_encode_start(&encode_ctx, token_out_buffer);
    if(result) {
        return 300 + (int32_t)result;
    }

    ctoken_encode_close_submod(&encode_ctx);

    result = ctoken_encode_finish(&encode_ctx, &completed_token);
    if(result != CTOKEN_ERR_NO_SUBMOD_OPEN) {
        return 400 + (int32_t)result;
    }


    ctoken_encode_init(&encode_ctx,
                       T_COSE_OPT_SHORT_CIRCUIT_SIG,
                       0,
                       CTOKEN_PROTECTION_COSE_SIGN1,
                       T_COSE_ALGORITHM_ES256);

    result = ctoken_encode_start(&encode_ctx, token_out_buffer);
    if(result) {
        return 500 + (int32_t)result;
    }

    ctoken_encode_end_submod_section(&encode_ctx);

    result = ctoken_encode_finish(&encode_ctx, &completed_token);
    if(result != CTOKEN_ERR_NO_SUBMOD_SECTION_STARTED) {
        return 600 + (int32_t)result;
    }


    ctoken_encode_init(&encode_ctx,
                       T_COSE_OPT_SHORT_CIRCUIT_SIG,
                       0,
                       CTOKEN_PROTECTION_COSE_SIGN1,
                       T_COSE_ALGORITHM_ES256);

    result = ctoken_encode_start(&encode_ctx, token_out_buffer);
    if(result) {
        return 700 + (int32_t)result;
    }

    ctoken_encode_nested_token(&encode_ctx,
                               CTOKEN_TYPE_JSON,
                               Q_USEFUL_BUF_FROM_SZ_LITERAL("jason"),
                               UsefulBuf_FROM_SZ_LITERAL("{}"));

    result = ctoken_encode_finish(&encode_ctx, &completed_token);
    if(result != CTOKEN_ERR_CANT_MAKE_SUBMOD_IN_SUBMOD) {
        return 800 + (int32_t)result;
    }


    ctoken_encode_init(&encode_ctx,
                       T_COSE_OPT_SHORT_CIRCUIT_SIG,
                       0,
                       CTOKEN_PROTECTION_COSE_SIGN1,
                       T_COSE_ALGORITHM_ES256);

    result = ctoken_encode_start(&encode_ctx, token_out_buffer);
    if(result) {
        return 900 + (int32_t)result;
    }


    ctoken_encode_start_submod_section(&encode_ctx);
    ctoken_encode_close_submod(&encode_ctx);

    result = ctoken_encode_finish(&encode_ctx, &completed_token);
    if(result != CTOKEN_ERR_NO_SUBMOD_OPEN) {
        return 1000 + (int32_t)result;
    }


    ctoken_encode_init(&encode_ctx,
                       T_COSE_OPT_SHORT_CIRCUIT_SIG,
                       0,
                       CTOKEN_PROTECTION_COSE_SIGN1,
                       T_COSE_ALGORITHM_ES256);

     result = ctoken_encode_start(&encode_ctx, token_out_buffer);
     if(result) {
         return 1100 + (int32_t)result;
     }

    for(char i = '1'; i < '7'; i++) {
        char ii[2];
        ii[0] = i;
        ii[0] = 0;
        ctoken_encode_start_submod_section(&encode_ctx);
        ctoken_encode_open_submod(&encode_ctx, q_useful_buf_from_sz(ii));
    }

    ctoken_encode_uptime(&encode_ctx, 55);

    for(char i = '1'; i < '7'; i++) {
         ctoken_encode_close_submod(&encode_ctx);
         ctoken_encode_end_submod_section(&encode_ctx);
     }

     result = ctoken_encode_finish(&encode_ctx, &completed_token);
     if(result != CTOKEN_ERR_SUCCESS) {
         return 1200 + (int32_t)result;
     }


    ctoken_encode_init(&encode_ctx,
                       T_COSE_OPT_SHORT_CIRCUIT_SIG,
                       0,
                       CTOKEN_PROTECTION_COSE_SIGN1,
                       T_COSE_ALGORITHM_ES256);

     result = ctoken_encode_start(&encode_ctx, token_out_buffer);
     if(result) {
         return 1300 + (int32_t)result;
     }

    for(char i = '1'; i < '8'; i++) {
        char ii[2];
        ii[0] = i;
        ii[0] = 0;
        ctoken_encode_start_submod_section(&encode_ctx);
        ctoken_encode_open_submod(&encode_ctx, q_useful_buf_from_sz(ii));
    }

    ctoken_encode_uptime(&encode_ctx, 55);

    for(char i = '1'; i < '8'; i++) {
         ctoken_encode_close_submod(&encode_ctx);
         ctoken_encode_end_submod_section(&encode_ctx);
     }

     result = ctoken_encode_finish(&encode_ctx, &completed_token);
     if(result != CTOKEN_ERR_NESTING_TOO_DEEP) {
         return 1400 + (int32_t)result;
     }

    return 0;
}



int32_t sign_cbor(struct q_useful_buf_c  cbor_input,
                  struct q_useful_buf    out_buf,
                  struct q_useful_buf_c *completed_token)
{
    struct ctoken_encode_ctx encode_ctx;

    ctoken_encode_init(&encode_ctx,
                       T_COSE_OPT_SHORT_CIRCUIT_SIG,
                       0,
                       CTOKEN_PROTECTION_COSE_SIGN1,
                       T_COSE_ALGORITHM_ES256);

    ctoken_encode_one_shot(&encode_ctx, out_buf, cbor_input, completed_token);


    return 0;
}


/* Need
 a submods section of the wrong type
 a token with no submod section
    - try various functions on it
 Try to enter submods that are too deeply nested
 submods section is not-well-formed
    - try with various methods
 a submod is not well formed -- Peek fails
 a submod that is of the wrong type     if(item.uDataType != QCBOR_TYPE_MAP) { fails
 A nested token with label that is not a text string






 */


/*
 {
  -76000: {         / The submodules section /
       "empty": { }, / An empty submodule (this is legal) /
       6: {          / A submodule with an integer name (not allowed) /
           -75000: 10

       },
       "bad-sub-mod": {
            -76000: {
                0: 0, / Integer label and content, both of which are illegal /
                "s": 0("November 11"), / content is date tag, which is illegal /
                "notmap" : [ 0 ],  / content is an array which is illegal /
                "notbs" : 0("hi"), / content is a date string which is illegal /
                "nest1": {
                     -76000: {
                         "nest2": {
                             -76000: {
                                 "nest3": {
                                     -76000: {
                                         -76006: 0
                                     }
                                  }
                               }
                            }
                         }
                      }
                   }
                }
  }
}
 */
static const char some_bad_submods[] = {
    0xa1, 0x3a, 0x00, 0x01, 0x28, 0xdf, 0xa3, 0x65,
    0x65, 0x6d, 0x70, 0x74, 0x79, 0xa0, 0x06, 0xa1,
    0x3a, 0x00, 0x01, 0x24, 0xf7, 0x0a, 0x6b, 0x62,
    0x61, 0x64, 0x2d, 0x73, 0x75, 0x62, 0x2d, 0x6d,
    0x6f, 0x64, 0xa1, 0x3a, 0x00, 0x01, 0x28, 0xdf,
    0xa5, 0x00, 0x00, 0x61, 0x73, 0xc0, 0x6b, 0x4e,
    0x6f, 0x76, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x20,
    0x31, 0x31, 0x66, 0x6e, 0x6f, 0x74, 0x6d, 0x61,
    0x70, 0x81, 0x00, 0x65, 0x6e, 0x6f, 0x74, 0x62,
    0x73, 0xc0, 0x62, 0x68, 0x69, 0x65, 0x6e, 0x65, 0x73,
    0x74, 0x31, 0xa1, 0x3a, 0x00, 0x01, 0x28, 0xdf,
    0xa1, 0x65, 0x6e, 0x65, 0x73, 0x74, 0x32, 0xa1,
    0x3a, 0x00, 0x01, 0x28, 0xdf, 0xa1, 0x65, 0x6e,
    0x65, 0x73, 0x74, 0x33, 0xa1, 0x3a, 0x00, 0x01,
    0x28, 0xdf, 0xa1, 0x3a, 0x00, 0x01, 0x28, 0xe5,
    0x00};






struct decode_submod_test_config {
    uint32_t              test_number;
    struct q_useful_buf_c token;

    enum ctoken_err_t expected_enter_0th;
    enum ctoken_err_t expected_exit_0th;
    enum ctoken_err_t expected_nested_0th;
    enum ctoken_err_t expected_enter_named;
    enum ctoken_err_t expected_exit_named;
    enum ctoken_err_t expected_named_nested;
    enum ctoken_err_t expected_validate;
    enum ctoken_err_t expected_enter_1st;
    enum ctoken_err_t expected_exit_1st;
    enum ctoken_err_t expected_nested_1st;
};

static const struct decode_submod_test_config tt[] = {
    {
        1,
        {completely_empty_token, completely_empty_SIZE},
        CTOKEN_ERR_SUBMOD_NOT_FOUND, /* expected_enter_0th */
        0, /* expected_exit_0th */
        CTOKEN_ERR_SUBMOD_NOT_FOUND, /* expected_nested_0th */
        CTOKEN_ERR_SUBMOD_NOT_FOUND, /* expected_enter_named */
        0, /* expected_exit_named */
        CTOKEN_ERR_SUBMOD_NOT_FOUND, /* expected_named_nested */
        0, /* expected_validate */
        CTOKEN_ERR_SUBMOD_NOT_FOUND, /* expected_enter_1st */
        0, /* expected_exit_1st */
        CTOKEN_ERR_SUBMOD_NOT_FOUND, /* expected_nested_1st */
   },

    {
        2,
        {not_well_formed_submod_section, not_well_formed_submod_section_SIZE},
        CTOKEN_ERR_CBOR_NOT_WELL_FORMED, /* expected_enter_0th */
        0, /* expected_exit_0th */
        CTOKEN_ERR_CBOR_NOT_WELL_FORMED, /* expected_nested_0th */
        CTOKEN_ERR_CBOR_NOT_WELL_FORMED, /* expected_enter_named */
        0, /* expected_exit_named */
        CTOKEN_ERR_CBOR_NOT_WELL_FORMED, /* expected_named_nested */
        0, /* expected_validate */
        CTOKEN_ERR_CBOR_NOT_WELL_FORMED, /* expected_enter_1st */
        0, /* expected_exit_1st */
        CTOKEN_ERR_CBOR_NOT_WELL_FORMED, /* expected_nested_1st */
    },

    {
        3,
        {minimal_submod_token, minimal_submod_SIZE},
        CTOKEN_ERR_SUCCESS, /* expected_enter_0th */
        CTOKEN_ERR_SUCCESS, /* expected_exit_0th */
        CTOKEN_ERR_SUBMOD_TYPE, /* expected_nested_0th */
        CTOKEN_ERR_SUCCESS, /* expected_enter_named */
        CTOKEN_ERR_SUCCESS, /* expected_exit_named */
        CTOKEN_ERR_SUCCESS, /* expected_named_nested */
        CTOKEN_ERR_SUCCESS, /* expected_validate */
        CTOKEN_ERR_SUBMOD_IS_A_TOKEN, /* expected_enter_1st */
        CTOKEN_ERR_SUCCESS, /* expected_exit_1st */
        CTOKEN_ERR_SUCCESS, /* expected_nested_1st */
    },

    {
        1,
        NULL_Q_USEFUL_BUF_C,
        0, /* expected_enter_0th */
        0, /* expected_exit_0th */
        0, /* expected_nested_0th */
        0, /* expected_enter_named */
        0, /* expected_exit_named */
        0, /* expected_named_nested */
        0, /* expected_validate */
        0, /* expected_enter_1st */
        0, /* expected_exit_1st */
        0, /* expected_nested_1st */
    }

};

/*

  A token with no submods

  A token with an empty submods section

  A token


 */



int32_t one_decode_errors_test_case(const struct decode_submod_test_config *t)
{
    struct ctoken_decode_ctx  decode_context;
    enum ctoken_err_t         ctoken_result;
    struct q_useful_buf_c     name;
    struct q_useful_buf_c     token;
    enum ctoken_type_t        nested_token_type;

    ctoken_decode_init(&decode_context,
                       T_COSE_OPT_ALLOW_SHORT_CIRCUIT,
                       0,
                       CTOKEN_PROTECTION_NONE);

    ctoken_result = ctoken_decode_validate_token(&decode_context, t->token);
    if(ctoken_result) {
        return test_result_code(0, t->test_number, ctoken_result);
    }

    ctoken_result = ctoken_decode_enter_nth_submod(&decode_context, 0, &name);
    if(ctoken_result != t->expected_enter_0th) {
        return test_result_code(1, t->test_number, ctoken_result);
    }

    if(ctoken_result == CTOKEN_ERR_SUCCESS) {
        ctoken_result = ctoken_decode_exit_submod(&decode_context);
        if(ctoken_result != t->expected_exit_0th) {
            return test_result_code(2, t->test_number, ctoken_result);
        }
    }

    ctoken_result = ctoken_decode_get_nth_nested_token(&decode_context, 0, &nested_token_type, &name, &token);
    if(ctoken_result != t->expected_nested_0th) {
        return test_result_code(3, t->test_number, ctoken_result);
    }

    ctoken_result = ctoken_decode_enter_named_submod(&decode_context, "submod");
    if(ctoken_result != t->expected_enter_named) {
        return test_result_code(4, t->test_number, ctoken_result);
    }

    if(ctoken_result == CTOKEN_ERR_SUCCESS) {
        ctoken_result = ctoken_decode_exit_submod(&decode_context);
        if(ctoken_result != t->expected_exit_named) {
            return test_result_code(5, t->test_number, ctoken_result);
        }
    }

    ctoken_result = ctoken_decode_get_named_nested_token(&decode_context,
                                                         Q_USEFUL_BUF_FROM_SZ_LITERAL("nested"),
                                                         &nested_token_type,
                                                         &token);
    if(ctoken_result != t->expected_named_nested) {
        return test_result_code(6, t->test_number, ctoken_result);
    }

    ctoken_result = ctoken_decode_enter_nth_submod(&decode_context, 1, &name);
    if(ctoken_result != t->expected_enter_1st) {
        return test_result_code(7, t->test_number, ctoken_result);
    }

    if(ctoken_result == CTOKEN_ERR_SUCCESS) {
        ctoken_result = ctoken_decode_exit_submod(&decode_context);
        if(ctoken_result != t->expected_exit_1st) {
            return test_result_code(8, t->test_number, ctoken_result);
        }
    }

    ctoken_result = ctoken_decode_get_nth_nested_token(&decode_context, 1, &nested_token_type, &name, &token);
    if(ctoken_result != t->expected_nested_1st) {
        return test_result_code(9, t->test_number, ctoken_result);
    }

    return 0;
}






int32_t submod_decode_errors_test()
{
    struct ctoken_decode_ctx  decode_context;
    enum ctoken_err_t         ctoken_result;
    enum ctoken_type_t        type;
    struct q_useful_buf_c     token;
    struct q_useful_buf_c     name;
    UsefulBuf_MAKE_STACK_UB(  out, 400);
    uint32_t                  num_submods;
    uint64_t                  uptime;
    int32_t                   test_result;


    const struct decode_submod_test_config *test_case = tt;

    while(!q_useful_buf_c_is_null(test_case->token)) {
        if(test_case->test_number == 2) {
            test_result = 44; // just for a break point
        }
        test_result = one_decode_errors_test_case(test_case);
        if(test_result) {
            return test_result;
        }
        test_case++;
    }

    ctoken_decode_init(&decode_context,
                       T_COSE_OPT_ALLOW_SHORT_CIRCUIT,
                       0,
                       CTOKEN_PROTECTION_NONE);

    ctoken_result = ctoken_decode_validate_token(&decode_context, TUB(deeply_nested_submods));
    if(ctoken_result) {
        return 100 + (int32_t)ctoken_result;
    }

    struct q_useful_buf_c nonce;
    ctoken_result = ctoken_decode_nonce(&decode_context, &nonce);

    if(ctoken_result != CTOKEN_ERR_NESTING_TOO_DEEP) {
        return 888;
    }

#if 0
    // Need better strategy to test this without triggering QCBOR's max nest dept
    int i;
    for(i = 0; i < 20; i++) {
        struct q_useful_buf_c nonce;
        struct q_useful_buf_c name;
        ctoken_result = ctoken_decode_nonce(&decode_context, &nonce);
        if(ctoken_result) {
            break;
        }
        if(*(uint8_t *)nonce.ptr != 0) {
            return 2;
        }
        ctoken_result = ctoken_decode_enter_nth_submod(&decode_context, 0, &name);
        if(ctoken_result) {
            break;
        }
    }

    if(i != 5) {
        return 77;
    }
#endif


    ctoken_result = ctoken_decode_validate_token(&decode_context, TUB(some_submods));
    if(ctoken_result) {
        return 100 + (int32_t)ctoken_result;
    }

    /* Try to enter a named submod that doesn't exist */
    ctoken_result = ctoken_decode_enter_named_submod(&decode_context, "foobar");
    if(ctoken_result != CTOKEN_ERR_SUBMOD_NOT_FOUND) {
        return 200 + (int32_t)ctoken_result;
    }

    /* Try to enter a submod by index that doesn't exist */
    ctoken_result = ctoken_decode_enter_nth_submod(&decode_context, 6, &name);
    if(ctoken_result != CTOKEN_ERR_SUBMOD_NOT_FOUND) {
        return 300 + (int32_t)ctoken_result;
    }

    /* Try to get a nested token by index that doesn't exist */
    ctoken_result = ctoken_decode_get_nth_nested_token(&decode_context, 6, &type, &name, &token);
    if(ctoken_result != CTOKEN_ERR_SUBMOD_NOT_FOUND) {
        return 400 + (int32_t)ctoken_result;
    }

    /* Try to get a named nested token that doesn't exist */
    ctoken_result = ctoken_decode_get_named_nested_token(&decode_context,
                                                         Q_USEFUL_BUF_FROM_SZ_LITERAL("foobar"),
                                                         &type,
                                                         &token);
    if(ctoken_result != CTOKEN_ERR_SUBMOD_NOT_FOUND) {
        return 500 + (int32_t)ctoken_result;
    }


    /* Make a token with some bad submodules for tests below and validate it */
    sign_cbor(UsefulBuf_FROM_BYTE_ARRAY_LITERAL(some_bad_submods), out, &token);
    ctoken_decode_init(&decode_context,
                       T_COSE_OPT_ALLOW_SHORT_CIRCUIT,
                       CTOKEN_PROTECTION_BY_TAG,
                       0);

    ctoken_result = ctoken_decode_validate_token(&decode_context, token);
    if(ctoken_result) {
        return 600 + (int32_t)ctoken_result;
    }

    /* Enter an empty submodule and succeed */
    ctoken_result = ctoken_decode_enter_named_submod(&decode_context, "empty");
    if(ctoken_result != CTOKEN_ERR_SUCCESS) {
        return 700 + (int32_t)ctoken_result;
    }

    /* Get number of submodules in then empty submodule and get 0 */
    ctoken_result = ctoken_decode_get_num_submods(&decode_context, &num_submods);
    if(ctoken_result != CTOKEN_ERR_SUCCESS || num_submods != 0) {
        return 800 + (int32_t)ctoken_result;
    }

    /* Try to get a nested token by name from the empty submodule and fail */
    ctoken_result = ctoken_decode_get_named_nested_token(&decode_context,
                                                         Q_USEFUL_BUF_FROM_SZ_LITERAL("subsub"),
                                                         &type, &token);
    if(ctoken_result != CTOKEN_ERR_SUBMOD_NOT_FOUND) {
        return 900 + (int32_t)ctoken_result;
    }

    /* Done with empty submodule. Exit successfully and go on despite above errors */
    ctoken_result = ctoken_decode_exit_submod(&decode_context);
    if(ctoken_result != CTOKEN_ERR_SUCCESS) {
        return 1000 + (int32_t)ctoken_result;
    }

    /* Try to enter submodule with an integer name and fail */
    ctoken_result = ctoken_decode_enter_nth_submod(&decode_context, 1, &name);
    if(ctoken_result != CTOKEN_ERR_SUBMOD_NAME_NOT_A_TEXT_STRING) {
        return 1100 + (int32_t)ctoken_result;
    }

    /* Enter a submodule with some more bad stuff and succeed */
    ctoken_result = ctoken_decode_enter_named_submod(&decode_context, "bad-sub-mod");
    if(ctoken_result != CTOKEN_ERR_SUCCESS) {
        return 1200 + (int32_t)ctoken_result;
    }

    /* submodule is an array and should have been a map */
    ctoken_result = ctoken_decode_enter_named_submod(&decode_context, "notmap");
    if(ctoken_result != CTOKEN_ERR_CBOR_TYPE) {
        return 1300 + (int32_t)ctoken_result;
    }

    /* submodule is time string and should have been a map */
    ctoken_result = ctoken_decode_enter_named_submod(&decode_context, "notbs");
    if(ctoken_result != CTOKEN_ERR_CBOR_TYPE) {
        return 1350 + (int32_t)ctoken_result;
    }

    /* Try to get a nested token that is not of the right type and fail */
    ctoken_result = ctoken_decode_get_named_nested_token(&decode_context,
                                                         Q_USEFUL_BUF_FROM_SZ_LITERAL("notmap"),
                                                         &type, &token);
    if(ctoken_result != CTOKEN_ERR_SUBMOD_TYPE) {
        return 1400 + (int32_t)ctoken_result;
    }

    /* Try to get a nested token that is also not of the right type and fail */
    ctoken_result = ctoken_decode_get_named_nested_token(&decode_context,
                                                         Q_USEFUL_BUF_FROM_SZ_LITERAL("notbs"),
                                                         &type, &token);
    if(ctoken_result != CTOKEN_ERR_SUBMOD_TYPE) {
        return 1400 + (int32_t)ctoken_result;
    }

    /* Try to get a nested token that is not of the right type and fail */
    ctoken_result = ctoken_decode_get_named_nested_token(&decode_context,
                                                         Q_USEFUL_BUF_FROM_SZ_LITERAL("nest1"),
                                                         &type, &token);
    if(ctoken_result != CTOKEN_ERR_SUBMOD_TYPE) {
        return 1400 + (int32_t)ctoken_result;
    }



    /* Create and validate a token with some not-well-formed parts of a submod */
    sign_cbor((struct q_useful_buf_c){not_well_formed_submod, not_well_formed_submod_SIZE}, out, &token);
    ctoken_decode_init(&decode_context,
                       T_COSE_OPT_ALLOW_SHORT_CIRCUIT,
                       CTOKEN_PROTECTION_BY_TAG,
                       0);
    ctoken_result = ctoken_decode_validate_token(&decode_context, token);
    if(ctoken_result) {
        return 1500 + (int32_t)ctoken_result;
    }

    /* The uptime claim is OK */
    ctoken_result = ctoken_decode_uptime(&decode_context, &uptime);
    if(ctoken_result != CTOKEN_ERR_SUCCESS) {
        return 1600 + (int32_t)ctoken_result;
    }

    /* The "jj" claim is OK and can be found. */
    ctoken_result = ctoken_decode_get_named_nested_token(&decode_context,
                                                         Q_USEFUL_BUF_FROM_SZ_LITERAL("jj"),
                                                         &type, &token);
    if(ctoken_result != CTOKEN_ERR_SUCCESS) {
        return 1700 + (int32_t)ctoken_result;
    }

    /* The "bad" submodule is not-well formed */
    ctoken_result = ctoken_decode_get_named_nested_token(&decode_context,
                                                         Q_USEFUL_BUF_FROM_SZ_LITERAL("bad"),
                                                         &type, &token);
    if(ctoken_result != CTOKEN_ERR_CBOR_NOT_WELL_FORMED) {
        return 1800 + (int32_t)ctoken_result;
    }

    return 0;
}


/* Create a token with the given payload and set up a decoder context
 * for it so everything is ready to for testing the decode methods.
 */
int32_t setup_decode_test(struct q_useful_buf_c     cbor_input,
                          UsefulBuf                 out_buf,
                          struct ctoken_decode_ctx *decode_context)
{
    struct ctoken_encode_ctx encode_ctx;
    struct q_useful_buf_c    completed_token;
    enum ctoken_err_t        ctoken_result;

    ctoken_encode_init(&encode_ctx,
                       T_COSE_OPT_SHORT_CIRCUIT_SIG,
                       0,
                       CTOKEN_PROTECTION_COSE_SIGN1,
                       T_COSE_ALGORITHM_ES256);

    ctoken_encode_one_shot(&encode_ctx, out_buf, cbor_input, &completed_token);


    ctoken_decode_init(decode_context,
                       T_COSE_OPT_ALLOW_SHORT_CIRCUIT,
                       CTOKEN_PROTECTION_BY_TAG,
                       0);

     ctoken_result = ctoken_decode_validate_token(decode_context, completed_token);
     if(ctoken_result) {
         return 1;
     }

    return 0;
}



/* Location claim that is a byte string, not a map */
static const uint8_t bad_location[] = {
    0xa1,
    0x3a, 0x00, 0x01, 0x28, 0xE3,
    0x40
};

static const uint8_t no_location[] = {
    0xa1,
    0x3a, 0x00, 0x01, 0x28, 0xE0,
    0x40
};


static const uint8_t empty_location[] = {
    0xa1,
    0x3a, 0x00, 0x01, 0x28, 0xE3,
    0xa0
};

static const uint8_t location_not_well_formed[] = {
    0xa1,
    0x3a, 0x00, 0x01, 0x28, 0xE3,
    0xa1, 0x01, 0x1d, 0x02, 0x3d
};

/*
 The payload part of this token:
 {-17: {1: 1.1, 2: 2.2, 3: 3.3, 4: 4.4, 5: 5.5, 6: 6.6, 7: 7.7, 8: 880000, 9: 9900}}
 */
static const uint8_t expected_full_location[] = {
    0xD8, 0x3D, 0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26,
    0xA1, 0x04, 0x58, 0x20, 0xEF, 0x95, 0x4B, 0x4B,
    0xD9, 0xBD, 0xF6, 0x70, 0xD0, 0x33, 0x60, 0x82,
    0xF5, 0xEF, 0x15, 0x2A, 0xF8, 0xF3, 0x5B, 0x6A,
    0x6C, 0x00, 0xEF, 0xA6, 0xA9, 0xA7, 0x1F, 0x49,
    0x51, 0x7E, 0x18, 0xC6, 0x58, 0x4D, 0xA1, 0x11,
    0xA9, 0x01, 0xFB, 0x3F, 0xF1, 0x99, 0x99, 0x99,
    0x99, 0x99, 0x9A, 0x02, 0xFB, 0x40, 0x01, 0x99,
    0x99, 0x99, 0x99, 0x99, 0x9A, 0x03, 0xFB, 0x40,
    0x0A, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x04,
    0xFB, 0x40, 0x11, 0x99, 0x99, 0x99, 0x99, 0x99,
    0x9A, 0x05, 0xF9, 0x45, 0x80, 0x06, 0xFB, 0x40,
    0x1A, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x07,
    0xFB, 0x40, 0x1E, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCD, 0x08, 0x1A, 0x00, 0x0D, 0x6D, 0x80, 0x09,
    0x19, 0x26, 0xAC, 0x58, 0x40, 0xE5, 0xE9, 0x68,
    0xED, 0x64, 0xF0, 0xE0, 0x36, 0x81, 0xA3, 0xB8,
    0x77, 0x07, 0x0C, 0x58, 0x4C, 0xF4, 0x87, 0x0C,
    0xBF, 0x60, 0x9C, 0xE4, 0xD9, 0x45, 0xDC, 0x4E,
    0xB8, 0xEE, 0x40, 0x93, 0xA5, 0xE5, 0xE9, 0x68,
    0xED, 0x64, 0xF0, 0xE0, 0x36, 0x81, 0xA3, 0xB8,
    0x77, 0x07, 0x0C, 0x58, 0x4C, 0xF4, 0x87, 0x0C,
    0xBF, 0x60, 0x9C, 0xE4, 0xD9, 0x45, 0xDC, 0x4E,
    0xB8, 0xEE, 0x40, 0x93, 0xA5};

int32_t location_test()
{
    struct ctoken_decode_ctx  decode_context;
    UsefulBuf_MAKE_STACK_UB(  out, 400);
    struct ctoken_location_t  location;
    enum ctoken_err_t         error;
    struct ctoken_encode_ctx  encode_context;
    struct q_useful_buf_c     completed_token;


    /* Test todo list:
     - encode a full location claim
     - decode a full location claim
     - */

    setup_decode_test(UsefulBuf_FROM_BYTE_ARRAY_LITERAL(bad_location),  out, &decode_context);

    error = ctoken_decode_location(&decode_context, &location);
    if(error != CTOKEN_ERR_CBOR_TYPE) {
        return test_result_code(1, 0, error);
    }


    setup_decode_test(UsefulBuf_FROM_BYTE_ARRAY_LITERAL(no_location),  out, &decode_context);

    error = ctoken_decode_location(&decode_context, &location);
    if(error != CTOKEN_ERR_CLAIM_NOT_PRESENT) {
        return test_result_code(1, 1, error);
    }


    setup_decode_test(UsefulBuf_FROM_BYTE_ARRAY_LITERAL(empty_location),  out, &decode_context);

    error = ctoken_decode_location(&decode_context, &location);
    if(error != CTOKEN_ERR_CLAIM_FORMAT) {
        return test_result_code(1, 2, error);
    }


    setup_decode_test(UsefulBuf_FROM_BYTE_ARRAY_LITERAL(location_not_well_formed),  out, &decode_context);

    error = ctoken_decode_location(&decode_context, &location);
    if(error != CTOKEN_ERR_CBOR_NOT_WELL_FORMED) {
        return test_result_code(1, 3, error);
    }


    /* Longitude field is missing */
    location.item_flags = 01;
    location.eat_loc_latitude = 5.6;

    ctoken_encode_init(&encode_context,
                       T_COSE_OPT_SHORT_CIRCUIT_SIG,
                       0,
                       CTOKEN_PROTECTION_COSE_SIGN1,
                       T_COSE_ALGORITHM_ES256);

    /* Get started on a particular token by giving an out buffer.
     */
    error = ctoken_encode_start(&encode_context, out);
    if(error) {
        return test_result_code(2, 1, error);
    }

    ctoken_encode_location(&encode_context, &location);
    error = ctoken_encode_finish(&encode_context, &completed_token);
    if(error != CTOKEN_ERR_LAT_LONG_REQUIRED) {
        return test_result_code(2, 2, error);
    }

    location.eat_loc_latitude = 1.1;
    location.eat_loc_longitude = 2.2;
    location.eat_loc_altitude = 3.3;
    location.eat_loc_accuracy = 4.4;
    location.eat_loc_altitude_accuracy = 5.5;
    location.eat_loc_heading = 6.6;
    location.eat_loc_speed = 7.7;
    location.time_stamp = 880000;
    location.age = 9900;
    ctoken_location_mark_item_present(&location, CTOKEN_EAT_LABEL_LATITUDE);
    ctoken_location_mark_item_present(&location, CTOKEN_EAT_LABEL_LONGITUDE);
    ctoken_location_mark_item_present(&location, CTOKEN_EAT_LABEL_ALTITUDE);
    ctoken_location_mark_item_present(&location, CTOKEN_EAT_LABEL_ACCURACY);
    ctoken_location_mark_item_present(&location, CTOKEN_EAT_LABEL_ALTITUDE_ACCURACY);
    ctoken_location_mark_item_present(&location, CTOKEN_EAT_LABEL_HEADING);
    ctoken_location_mark_item_present(&location, CTOKEN_EAT_LABEL_SPEED);
    ctoken_location_mark_item_present(&location, CTOKEN_EAT_LABEL_TIME_STAMP);
    ctoken_location_mark_item_present(&location, CTOKEN_EAT_LABEL_AGE);

    ctoken_encode_init(&encode_context,
                       T_COSE_OPT_SHORT_CIRCUIT_SIG,
                       0,
                       CTOKEN_PROTECTION_COSE_SIGN1,
                       T_COSE_ALGORITHM_ES256);

    error = ctoken_encode_start(&encode_context, out);
    if(error) {
        return test_result_code(2, 3, error);
    }

    ctoken_encode_location(&encode_context, &location);
    error = ctoken_encode_finish(&encode_context, &completed_token);
    if(error != CTOKEN_ERR_SUCCESS) {
        return test_result_code(2, 4, error);
    }
    if(q_useful_buf_compare(completed_token, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(expected_full_location))) {
        return test_result_code(2, 5, error);
    }

    ctoken_decode_init(&decode_context,
                       T_COSE_OPT_ALLOW_SHORT_CIRCUIT,
                       CTOKEN_PROTECTION_BY_TAG,
                       0);

    error = ctoken_decode_validate_token(&decode_context, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(expected_full_location));
    if(error) {
        return test_result_code(3, 0, error);
    }
    memset(&location, 0x44, sizeof(struct ctoken_location_t)); /* initialize to something incorrect */
    error = ctoken_decode_location(&decode_context, &location);
    if(error != CTOKEN_ERR_SUCCESS ||
       !ctoken_location_is_item_present(&location, CTOKEN_EAT_LABEL_LATITUDE) ||
       !ctoken_location_is_item_present(&location, CTOKEN_EAT_LABEL_LONGITUDE) ||
       !ctoken_location_is_item_present(&location, CTOKEN_EAT_LABEL_ALTITUDE) ||
       !ctoken_location_is_item_present(&location, CTOKEN_EAT_LABEL_ACCURACY) ||
       !ctoken_location_is_item_present(&location, CTOKEN_EAT_LABEL_ALTITUDE_ACCURACY) ||
       !ctoken_location_is_item_present(&location, CTOKEN_EAT_LABEL_HEADING) ||
       !ctoken_location_is_item_present(&location, CTOKEN_EAT_LABEL_SPEED) ||
       !ctoken_location_is_item_present(&location, CTOKEN_EAT_LABEL_TIME_STAMP) ||
       !ctoken_location_is_item_present(&location, CTOKEN_EAT_LABEL_AGE) ||
       location.eat_loc_latitude != 1.1 ||
       location.eat_loc_longitude != 2.2 ||
       location.eat_loc_altitude != 3.3 ||
       location.eat_loc_accuracy != 4.4 ||
       location.eat_loc_altitude_accuracy != 5.5 ||
       location.eat_loc_heading != 6.6 ||
       location.eat_loc_speed != 7.7 ||
       location.time_stamp != 880000 ||
       location.age != 9900) {
        return test_result_code(4, 0, error);
    }

    return 0;
}


/* Payload of token is {16: 2, 15: true}. It is using standard labels */
static const uint8_t expected_boot_and_debug[] = {
    0xD8, 0x3D, 0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26,
    0xA1, 0x04, 0x58, 0x20, 0xEF, 0x95, 0x4B, 0x4B,
    0xD9, 0xBD, 0xF6, 0x70, 0xD0, 0x33, 0x60, 0x82,
    0xF5, 0xEF, 0x15, 0x2A, 0xF8, 0xF3, 0x5B, 0x6A,
    0x6C, 0x00, 0xEF, 0xA6, 0xA9, 0xA7, 0x1F, 0x49,
    0x51, 0x7E, 0x18, 0xC6, 0x45, 0xA2, 0x10, 0x02,
    0x0F, 0xF5, 0x58, 0x40, 0x6A, 0xE7, 0x0C, 0xDF,
    0xFF, 0x22, 0xCB, 0x9C, 0xD5, 0xDC, 0x18, 0xE4,
    0x98, 0x95, 0xCF, 0x98, 0x4A, 0x99, 0x78, 0x90,
    0x30, 0xC3, 0x5D, 0x9E, 0x5A, 0xD0, 0x0C, 0xFF,
    0xD7, 0xA0, 0x68, 0x61, 0x6A, 0xE7, 0x0C, 0xDF,
    0xFF, 0x22, 0xCB, 0x9C, 0xD5, 0xDC, 0x18, 0xE4,
    0x98, 0x95, 0xCF, 0x98, 0x4A, 0x99, 0x78, 0x90,
    0x30, 0xC3, 0x5D, 0x9E, 0x5A, 0xD0, 0x0C, 0xFF,
    0xD7, 0xA0, 0x68, 0x61};

static const uint8_t bad_debug1[] = {
0xa1, 0x3a, 0x00, 0x01, 0x28, 0xe7, 0x62, 0x68, 0x69
};

static const uint8_t bad_debug2[] = {
    0xa1, 0x3a, 0x00, 0x01, 0x28, 0xe7, 0x1c
};

static const uint8_t bad_debug3[] = {
    0xa1, 0x3a, 0x00, 0x01, 0x28, 0xe7, 0x05
};

static const uint8_t bad_secure_boot1[] = {
    0xa1, 0x3a, 0x00, 0x01, 0x28, 0xe6, 0xf6
};

static const uint8_t bad_secure_boot2[] = {
    0xa1, 0x3a, 0x00, 0x01, 0x28, 0xe6, 0x1d
};


int32_t debug_and_boot_test()
{
    struct ctoken_decode_ctx  decode_context;
    UsefulBuf_MAKE_STACK_UB(  out, 400);
    enum ctoken_err_t         error;
    struct ctoken_encode_ctx  encode_context;
    struct q_useful_buf_c     completed_token;
    bool                      secure_boot;
    enum ctoken_debug_level_t debug_state;

    /* --- simple test encoding boot and debug state --- */
    ctoken_encode_init(&encode_context,
                       T_COSE_OPT_SHORT_CIRCUIT_SIG,
                       0,
                       CTOKEN_PROTECTION_COSE_SIGN1,
                       T_COSE_ALGORITHM_ES256);
    error = ctoken_encode_start(&encode_context, out);
    if(error) {
        return 100 + (int32_t)error;
    }

    ctoken_encode_debug_state(&encode_context, CTOKEN_DEBUG_DISABLED_SINCE_BOOT);

    ctoken_encode_secure_boot(&(encode_context), true);

    error = ctoken_encode_finish(&encode_context, &completed_token);
    if(error != CTOKEN_ERR_SUCCESS) {
        return 200 + (int32_t)error;
    }
    if(q_useful_buf_compare(completed_token, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(expected_boot_and_debug))) {
        return 300;
    }

    /* --- simple test decoding boot and debug state --- */
    ctoken_decode_init(&decode_context,
                       T_COSE_OPT_ALLOW_SHORT_CIRCUIT,
                       CTOKEN_PROTECTION_BY_TAG,
                       0);
    error = ctoken_decode_validate_token(&decode_context, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(expected_boot_and_debug));
    if(error != CTOKEN_ERR_SUCCESS) {
        return 400 + (int32_t)error;
    }

    error = ctoken_decode_secure_boot(&decode_context, &secure_boot);
    if(error != CTOKEN_ERR_SUCCESS || secure_boot != true) {
        return 500 + (int32_t)error;
    }

    error = ctoken_decode_debug_state(&decode_context, &debug_state);
    if(error != CTOKEN_ERR_SUCCESS || debug_state != CTOKEN_DEBUG_DISABLED_SINCE_BOOT) {
        return 600 + (int32_t)error;
    }


    /* --- try to encode erroneous debug state and see error --- */
    ctoken_encode_init(&encode_context,
                       T_COSE_OPT_SHORT_CIRCUIT_SIG,
                       0,
                       CTOKEN_PROTECTION_COSE_SIGN1,
                       T_COSE_ALGORITHM_ES256);
    error = ctoken_encode_start(&encode_context, out);
    if(error) {
        return 700 + (int32_t)error;
    }

    ctoken_encode_debug_state(&encode_context, -1);

    error = ctoken_encode_finish(&encode_context, &completed_token);
    if(error != CTOKEN_ERR_CLAIM_RANGE) {
        return 800 + (int32_t)error;
    }

    /* --- try to encode another erroneous debug state and see error --- */
    ctoken_encode_init(&encode_context,
                       T_COSE_OPT_SHORT_CIRCUIT_SIG,
                       0,
                       CTOKEN_PROTECTION_COSE_SIGN1,
                       T_COSE_ALGORITHM_ES256);
    error = ctoken_encode_start(&encode_context, out);
    if(error) {
        return 900 + (int32_t)error;
    }

    ctoken_encode_debug_state(&encode_context, 5);

    error = ctoken_encode_finish(&encode_context, &completed_token);
    if(error != CTOKEN_ERR_CLAIM_RANGE) {
        return 1000 + (int32_t)error;
    }


    /* --- decode debug state that is wrong type --- */
    setup_decode_test(UsefulBuf_FROM_BYTE_ARRAY_LITERAL(bad_debug1),  out, &decode_context);
    error = ctoken_decode_debug_state(&decode_context, &debug_state);
    if(error != CTOKEN_ERR_CBOR_TYPE) {
        return 1100 + (int32_t)error;
    }

    /* --- decode debug state that is not well formed --- */
    setup_decode_test(UsefulBuf_FROM_BYTE_ARRAY_LITERAL(bad_debug2),  out, &decode_context);
    error = ctoken_decode_debug_state(&decode_context, &debug_state);
    if(error != CTOKEN_ERR_CBOR_NOT_WELL_FORMED) {
        return 1200 + (int32_t)error;
    }


    /* --- decode debug state that is not a valid value --- */
    setup_decode_test(UsefulBuf_FROM_BYTE_ARRAY_LITERAL(bad_debug3),  out, &decode_context);
    error = ctoken_decode_debug_state(&decode_context, &debug_state);
    if(error != CTOKEN_ERR_CLAIM_RANGE) {
        return 1300 + (int32_t)error;
    }


    /* --- decode secure boot that is not a valid value --- */
    setup_decode_test(UsefulBuf_FROM_BYTE_ARRAY_LITERAL(bad_secure_boot1),  out, &decode_context);
    error = ctoken_decode_secure_boot(&decode_context, &secure_boot);
    if(error != CTOKEN_ERR_CBOR_TYPE) {
        return 1400 + (int32_t)error;
    }


    /* --- decode secure boot that is not well formed --- */
    setup_decode_test(UsefulBuf_FROM_BYTE_ARRAY_LITERAL(bad_secure_boot2),  out, &decode_context);
    error = ctoken_decode_secure_boot(&decode_context, &secure_boot);
    /* Only check for fail as QCBOR error codes for getting bool needs work */
    if(error == CTOKEN_ERR_SUCCESS) {
        return 1500 + (int32_t)error;
    }

    return 0;
}



/*

 {10: h'948F8860D13A463E8E',
  11: h'0198F50A4FF6C05861C8860D13A638EA4FE2FA',
  15: true,
  16: 3,
  6: 1(1526542894),
  14: 3,
  -76000: {
      "Android App Foo":
          {14: 1},
      "Secure Element Eat": h'420123',
      "Linux Android":
          {14: 1}
    }
  }

 */
static const uint8_t submods_uccs[] = {
    0xa7, 0x0a, 0x49, 0x94, 0x8f, 0x88, 0x60, 0xd1,
    0x3a, 0x46, 0x3e, 0x8e, 0x0b, 0x53, 0x01, 0x98,
    0xf5, 0x0a, 0x4f, 0xf6, 0xc0, 0x58, 0x61, 0xc8,
    0x86, 0x0d, 0x13, 0xa6, 0x38, 0xea, 0x4f, 0xe2,
    0xfa, 0x0f, 0xf5, 0x10, 0x03, 0x06, 0xc1, 0x1a,
    0x5a, 0xfd, 0x32, 0x2e, 0x0e, 0x03, 0x3a, 0x00,
    0x01, 0x28, 0xdf, 0xa3, 0x6f, 0x41, 0x6e, 0x64,
    0x72, 0x6f, 0x69, 0x64, 0x20, 0x41, 0x70, 0x70,
    0x20, 0x46, 0x6f, 0x6f, 0xa1, 0x0e, 0x01, 0x72,
    0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x20, 0x45,
    0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x45,
    0x61, 0x74, 0x43, 0x42, 0x01, 0x23, 0x6d, 0x4c,
    0x69, 0x6e, 0x75, 0x78, 0x20, 0x41, 0x6e, 0x64,
    0x72, 0x6f, 0x69, 0x64, 0xa1, 0x0e, 0x01
};

static const uint8_t expected_nonce[] = {
    0x94, 0x8F, 0x88, 0x60, 0xD1, 0x3A, 0x46, 0x3E, 0x8E
};


int32_t get_next_test()
{
    struct ctoken_decode_ctx  decode_context;
    QCBORItem                 claim;
    enum ctoken_err_t         result;
    uint32_t                  num_sub_mods;
    struct q_useful_buf_c     submod_name;


    ctoken_decode_init(&decode_context,
                       0,
                       0,
                       CTOKEN_PROTECTION_NONE);

    result = ctoken_decode_validate_token(&decode_context,
                                 Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(submods_uccs));
    if(result) {
        return test_result_code(1, 0, result);;
    }

    result = ctoken_decode_next_claim(&decode_context, &claim);
    if(result != CTOKEN_ERR_SUCCESS ||
       claim.uLabelType != QCBOR_TYPE_INT64 ||
       claim.label.int64 != 10 ||
       claim.uDataType != QCBOR_TYPE_BYTE_STRING ||
       q_useful_buf_compare(claim.val.string, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(expected_nonce))) {
        return test_result_code(2, 0, result);
    }

    result = ctoken_decode_next_claim(&decode_context, &claim);
    if(result != CTOKEN_ERR_SUCCESS ||
       claim.uLabelType != QCBOR_TYPE_INT64 ||
       claim.label.int64 != 11 ||
       claim.uDataType != QCBOR_TYPE_BYTE_STRING) {
        return test_result_code(3, 0, result);
    }

    result = ctoken_decode_next_claim(&decode_context, &claim);
    if(result != CTOKEN_ERR_SUCCESS ||
       claim.uLabelType != QCBOR_TYPE_INT64 ||
       claim.label.int64 != 15 ||
       claim.uDataType != QCBOR_TYPE_TRUE) {
        return test_result_code(4, 0, result);
    }

    result = ctoken_decode_next_claim(&decode_context, &claim);
    if(result != CTOKEN_ERR_SUCCESS ||
       claim.uLabelType != QCBOR_TYPE_INT64 ||
       claim.label.int64 != 16 ||
       claim.uDataType != QCBOR_TYPE_INT64 ||
       claim.val.int64 != 3) {
        return test_result_code(5, 0, result);
    }

    result = ctoken_decode_next_claim(&decode_context, &claim);
    if(result != CTOKEN_ERR_SUCCESS ||
       claim.uLabelType != QCBOR_TYPE_INT64 ||
       claim.label.int64 != 6 ||
       claim.uDataType != QCBOR_TYPE_DATE_EPOCH||
       claim.val.epochDate.nSeconds != 1526542894) {
        return test_result_code(6, 0, result);
    }

    result = ctoken_decode_next_claim(&decode_context, &claim);
    if(result != CTOKEN_ERR_SUCCESS ||
       claim.uLabelType != QCBOR_TYPE_INT64 ||
       claim.label.int64 != 14 ||
       claim.uDataType != QCBOR_TYPE_INT64 ||
       claim.val.int64 != 3) {
        return test_result_code(7, 0, result);
    }

    result = ctoken_decode_next_claim(&decode_context, &claim);
    if(result != CTOKEN_ERR_NO_MORE_CLAIMS) {
        return test_result_code(8, 0, result);
    }

    result = ctoken_decode_get_num_submods(&decode_context, &num_sub_mods);
    if(result != CTOKEN_ERR_SUCCESS ||
       num_sub_mods != 3) {
       return test_result_code(9, 0, result);
    }

    result = ctoken_decode_enter_nth_submod(&decode_context, 0, &submod_name);
    if(result != CTOKEN_ERR_SUCCESS) {
        return test_result_code(10, 0, result);
    }

    if(ub_compare_sz("Android App Foo", submod_name)) {
        return test_result_code(110, 0, 0);
    }

    result = ctoken_decode_next_claim(&decode_context, &claim);
    if(result != CTOKEN_ERR_SUCCESS ||
       claim.uLabelType != QCBOR_TYPE_INT64 ||
       claim.label.int64 != 14 ||
       claim.uDataType != QCBOR_TYPE_INT64 ||
       claim.val.int64 != 1) {
        return test_result_code(11, 0, result);
    }

    result = ctoken_decode_next_claim(&decode_context, &claim);
    if(result != CTOKEN_ERR_NO_MORE_CLAIMS) {
        return test_result_code(12, 0, result);
    }

    result = ctoken_decode_exit_submod(&decode_context);
    if(result != CTOKEN_ERR_SUCCESS) {
         return test_result_code(14, 0, result);
     }

     result = ctoken_decode_enter_nth_submod(&decode_context, 1, &submod_name);
     if(result != CTOKEN_ERR_SUBMOD_IS_A_TOKEN) {
         return test_result_code(15, 0, result);
     }

    result = ctoken_decode_enter_nth_submod(&decode_context, 2, &submod_name);
    if(result != CTOKEN_ERR_SUCCESS) {
        return test_result_code(16, 0, result);
    }

    if(ub_compare_sz("Linux Android", submod_name)) {
         return test_result_code(111, 0, 0);
     }

    result = ctoken_decode_next_claim(&decode_context, &claim);
    if(result != CTOKEN_ERR_SUCCESS ||
       claim.uLabelType != QCBOR_TYPE_INT64 ||
       claim.label.int64 != 14 ||
       claim.uDataType != QCBOR_TYPE_INT64 ||
       claim.val.int64 != 1) {
        return test_result_code(17, 0, result);
    }

    result = ctoken_decode_next_claim(&decode_context, &claim);
    if(result != CTOKEN_ERR_NO_MORE_CLAIMS) {
        return test_result_code(18, 0, result);
    }

    result = ctoken_decode_exit_submod(&decode_context);
    if(result != CTOKEN_ERR_SUCCESS) {
          return test_result_code(19, 0, result);
    }

    result = ctoken_decode_next_claim(&decode_context, &claim);
    if(result != CTOKEN_ERR_NO_MORE_CLAIMS) {
        return test_result_code(20, 0, result);
    }

    return 0;
}
