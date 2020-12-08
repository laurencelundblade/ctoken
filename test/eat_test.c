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
#include "ctoken_encode.h"
#include "ctoken_decode.h"




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

    ctoken_encode_boot_state(&encode_ctx, true, EAT_DL_DISABLED_SINCE_BOOT);

    location.eat_loc_latitude = 34.88;
    location.eat_loc_longitude = 9.54;
    location.item_flags = 0x3;
    ctoken_encode_location(&encode_ctx, &location);

    ctoken_encode_uptime(&encode_ctx, 886688);

    ctoken_encode_start_submod_section(&encode_ctx);

    ctoken_encode_open_submod(&encode_ctx, "a submodule");

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
    ctoken_decode_init(&decode_context, T_COSE_OPT_ALLOW_SHORT_CIRCUIT, 0);

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

    result = ctoken_decode_boot_state(&decode_context, &secure_boot, &debug_level);
    if(result) {
        return 900 + (int32_t)result;
    }
    if(secure_boot != true || debug_level != EAT_DL_DISABLED_SINCE_BOOT) {
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

    struct ctoken_decode_ctx     decode_context;


    uint8_t test_nonce_bytes[] = {0x05, 0x08, 0x33, 0x99};
    const struct q_useful_buf_c test_nonce = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(test_nonce_bytes);

    uint8_t test_ueid_bytes[] = {0xa4, 0x68, 0x23, 0x99, 0x00, 0x01};
    const struct q_useful_buf_c test_ueid = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(test_ueid_bytes);

    uint8_t test_oemid_bytes[] = {0x14, 0x18, 0x13, 0x19, 0x10, 0x01};
    const struct q_useful_buf_c test_oemid = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(test_oemid_bytes);

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
    /* Values are just made up for test */

    ctoken_encode_nonce(&encode_ctx, test_nonce);

    ctoken_encode_start_submod_section(&encode_ctx);

      ctoken_encode_open_submod(&encode_ctx, "sub1");

        ctoken_encode_ueid(&encode_ctx, test_ueid);

        ctoken_encode_start_submod_section(&encode_ctx);

          ctoken_encode_nested_token(&encode_ctx, CTOKEN_TYPE_JSON, "json", UsefulBuf_FromSZ( "{ \"ueid\", \"xyz\"" ));

          ctoken_encode_open_submod(&encode_ctx, "subsub");

            ctoken_encode_oemid(&encode_ctx, test_oemid);

          ctoken_encode_close_submod(&encode_ctx);

        ctoken_encode_end_submod_section(&encode_ctx);

      ctoken_encode_close_submod(&encode_ctx);

    ctoken_encode_end_submod_section(&encode_ctx);


    ctoken_result = ctoken_encode_finish(&encode_ctx, &completed_token);


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

     result = ctoken_decode_nonce(&decode_context, &nonce);
     if(result) {
         return 400 + (int32_t)result;
     }
     if(q_useful_buf_compare(nonce, test_nonce)) {
         return 499;
     }

    ctoken_decode_enter_submod_sz(&decode_context, "sub1");

    result = ctoken_decode_ueid(&decode_context, &ueid);
    if(result) {
        return 500 + (int32_t)result;
    }
    if(q_useful_buf_compare(ueid, test_ueid)) {
        return 599;
    }

    enum ctoken_type type;
    struct q_useful_buf_c token;

    ctoken_decode_get_nested_token_sz(&decode_context, "json", &type, &token);

    uint32_t num_submods;
    ctoken_decode_get_num_submods(&decode_context, &num_submods);
    if(num_submods != 2) {
        return 99;
    }

    ctoken_decode_enter_nth_submod(&decode_context, 1, NULL);

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



int32_t submods_errors_test(void)
{
    struct ctoken_encode_ctx     encode_ctx;
    MakeUsefulBufOnStack(        token_out_buffer, 400);
    enum ctoken_err_t            result;
    struct q_useful_buf_c        completed_token;


    ctoken_encode_init(&encode_ctx,
                       T_COSE_OPT_SHORT_CIRCUIT_SIG,
                       0,
                       T_COSE_ALGORITHM_ES256);

    result = ctoken_encode_start(&encode_ctx, token_out_buffer);
    if(result) {
        return 100 + (int32_t)result;
    }


    ctoken_encode_open_submod(&encode_ctx, "foo");

    result = ctoken_encode_finish(&encode_ctx, &completed_token);
    if(result != CTOKEN_ERR_NO_SUBMOD_SECTION_STARTED) {
        return 200 + (int32_t)result;
    }


    ctoken_encode_init(&encode_ctx,
                       T_COSE_OPT_SHORT_CIRCUIT_SIG,
                       0,
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
                       T_COSE_ALGORITHM_ES256);

    result = ctoken_encode_start(&encode_ctx, token_out_buffer);
    if(result) {
        return 700 + (int32_t)result;
    }

    ctoken_encode_nested_token(&encode_ctx,
                            CTOKEN_TYPE_JSON,
                            "jason",
                            UsefulBuf_FROM_SZ_LITERAL("{}"));

    result = ctoken_encode_finish(&encode_ctx, &completed_token);
    if(result != CTOKEN_ERR_CANT_MAKE_SUBMOD_IN_SUBMOD) {
        return 800 + (int32_t)result;
    }


    ctoken_encode_init(&encode_ctx,
                       T_COSE_OPT_SHORT_CIRCUIT_SIG,
                       0,
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
        ctoken_encode_open_submod(&encode_ctx, ii);
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
        ctoken_encode_open_submod(&encode_ctx, ii);
    }

    ctoken_encode_uptime(&encode_ctx, 55);

    for(char i = '1'; i < '8'; i++) {
         ctoken_encode_close_submod(&encode_ctx);
         ctoken_encode_end_submod_section(&encode_ctx);
     }

     result = ctoken_encode_finish(&encode_ctx, &completed_token);
     if(result != CTOKEN_ERR_SUBMOD_NESTING_TOO_DEEP) {
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
                       T_COSE_ALGORITHM_ES256);

    ctoken_encode_one_shot(&encode_ctx, out_buf, cbor_input, completed_token);


    return 0;
}


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



/*
This a fully signed token with the following payload
{
    -75008: h'05083399',
    -76000: {
        "sub1": {
            -75009: h'A46823990001',
            -76000: {
                "json": "{ \"ueid\", \"xyz\"",
                "subsub": {
                    -76001: h'141813191001'
                }
             }
         }
    }
}
 */
static const char some_good_submods[] = {
    0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA1, 0x04, 0x58,
    0x20, 0xEF, 0x95, 0x4B, 0x4B, 0xD9, 0xBD, 0xF6, 0x70,
    0xD0, 0x33, 0x60, 0x82, 0xF5, 0xEF, 0x15, 0x2A, 0xF8,
    0xF3, 0x5B, 0x6A, 0x6C, 0x00, 0xEF, 0xA6, 0xA9, 0xA7,
    0x1F, 0x49, 0x51, 0x7E, 0x18, 0xC6, 0x58, 0x52, 0xA2,
    0x3A, 0x00, 0x01, 0x24, 0xFF, 0x44, 0x05, 0x08, 0x33,
    0x99, 0x3A, 0x00, 0x01, 0x28, 0xDF, 0xA1, 0x64, 0x73,
    0x75, 0x62, 0x31, 0xA2, 0x3A, 0x00, 0x01, 0x25, 0x00,
    0x46, 0xA4, 0x68, 0x23, 0x99, 0x00, 0x01, 0x3A, 0x00,
    0x01, 0x28, 0xDF, 0xA2, 0x64, 0x6A, 0x73, 0x6F, 0x6E,
    0x6F, 0x7B, 0x20, 0x22, 0x75, 0x65, 0x69, 0x64, 0x22,
    0x2C, 0x20, 0x22, 0x78, 0x79, 0x7A, 0x22, 0x66, 0x73,
    0x75, 0x62, 0x73, 0x75, 0x62, 0xA1, 0x3A, 0x00, 0x01,
    0x28, 0xE0, 0x46, 0x14, 0x18, 0x13, 0x19, 0x10, 0x01,
    0x58, 0x40, 0xF9, 0x43, 0xB7, 0xB3, 0x33, 0x29, 0x3A,
    0x15, 0xEB, 0x87, 0x8E, 0x5F, 0xC1, 0x05, 0x17, 0xEA,
    0x64, 0x0D, 0xA9, 0x5A, 0x40, 0xD4, 0x47, 0x8F, 0xE8,
    0xF1, 0x0E, 0x63, 0x40, 0xEF, 0x6F, 0x10, 0xF9, 0x43,
    0xB7, 0xB3, 0x33, 0x29, 0x3A, 0x15, 0xEB, 0x87, 0x8E,
    0x5F, 0xC1, 0x05, 0x17, 0xEA, 0x64, 0x0D, 0xA9, 0x5A,
    0x40, 0xD4, 0x47, 0x8F, 0xE8, 0xF1, 0x0E, 0x63, 0x40,
    0xEF, 0x6F, 0x10};


/*
{
    -76006: 10,
    -76000: {
        "jj": "{ uptime: 40}",
        "bad": {
            -76006: NOT-WELL FORMED simple(01)
        }
    }
}
 */
static const char nwf_submod[] = {
    0xa2, 0x3a, 0x00, 0x01, 0x28, 0xe5, 0x0a, 0x3a,
    0x00, 0x01, 0x28, 0xdf, 0xa2, 0x62, 0x6a, 0x6a,
    0x6d, 0x7b, 0x20, 0x75, 0x70, 0x74, 0x69, 0x6d,
    0x65, 0x3a, 0x20, 0x34, 0x30, 0x7d, 0x63, 0x62,
    0x61, 0x64, 0xf8, 0x01};


int32_t submod_decode_errors_test()
{
    struct ctoken_decode_ctx  decode_context;
    enum ctoken_err_t         ctoken_result;
    enum ctoken_type          type;
    struct q_useful_buf_c     token;
    UsefulBuf_MAKE_STACK_UB(  out, 400);
    uint32_t uNum;


    ctoken_decode_init(&decode_context, T_COSE_OPT_ALLOW_SHORT_CIRCUIT, 0);

    ctoken_result = ctoken_decode_validate_token(&decode_context, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(some_good_submods));
    if(ctoken_result) {
        return 100 + (int32_t)ctoken_result;
    }

    ctoken_result = ctoken_decode_enter_submod_sz(&decode_context, "foobar");
    if(ctoken_result != CTOKEN_ERR_NAMED_SUBMOD_NOT_FOUND) {
        return 200 + (int32_t)ctoken_result;
    }

    ctoken_result = ctoken_decode_enter_nth_submod(&decode_context, 6, NULL);
    if(ctoken_result != CTOKEN_ERR_SUBMOD_INDEX_TOO_LARGE) {
        return 300 + (int32_t)ctoken_result;
    }

    ctoken_result = ctoken_decode_get_nth_nested_token(&decode_context, 6, &type, &token);
    if(ctoken_result != CTOKEN_ERR_SUBMOD_INDEX_TOO_LARGE) {
        return 400 + (int32_t)ctoken_result;
    }

    ctoken_result = ctoken_decode_get_nested_token_sz(&decode_context, "foobar", &type, &token);
    if(ctoken_result != CTOKEN_ERR_NAMED_SUBMOD_NOT_FOUND) {
        return 500 + (int32_t)ctoken_result;
    }


    sign_cbor(UsefulBuf_FROM_BYTE_ARRAY_LITERAL(some_bad_submods), out, &token);

    ctoken_decode_init(&decode_context, T_COSE_OPT_ALLOW_SHORT_CIRCUIT, 0);

    ctoken_result = ctoken_decode_validate_token(&decode_context, token);
    if(ctoken_result) {
        return 600 + (int32_t)ctoken_result;
    }

    /* An empty submodule */
    ctoken_result = ctoken_decode_enter_submod_sz(&decode_context, "empty");
    if(ctoken_result != CTOKEN_ERR_SUCCESS) {
        return 700 + (int32_t)ctoken_result;
    }

    ctoken_result = ctoken_decode_get_num_submods(&decode_context, &uNum);
    if(ctoken_result != CTOKEN_ERR_SUBMOD_SECTION) {
        return 800 + (int32_t)ctoken_result;
    }

    ctoken_result = ctoken_decode_get_nested_token_sz(&decode_context, "subsub", &type, &token);
    if(ctoken_result != CTOKEN_ERR_SUBMOD_SECTION) {
        return 900 + (int32_t)ctoken_result;
    }

    ctoken_result = ctoken_decode_exit_submod(&decode_context);
    if(ctoken_result != CTOKEN_ERR_SUCCESS) {
        return 1000 + (int32_t)ctoken_result;
    }

    /* A submodule with an integer name */
    struct q_useful_buf_c name;
    ctoken_result = ctoken_decode_enter_nth_submod(&decode_context, 1, &name);
    if(ctoken_result != CTOKEN_ERR_SUBMOD_NAME_NOT_A_TEXT_STRING) {
        return 1100 + (int32_t)ctoken_result;
    }

    ctoken_result = ctoken_decode_enter_submod_sz(&decode_context, "bad-sub-mod");
    if(ctoken_result != CTOKEN_ERR_SUCCESS) {
        return 1200 + (int32_t)ctoken_result;
    }

    /* submodule is a array and should have been a map */
    ctoken_result = ctoken_decode_enter_submod_sz(&decode_context, "notmap");
    if(ctoken_result != CTOKEN_ERR_SUBMOD_TYPE) {
        return 1300 + (int32_t)ctoken_result;
    }

    /* submodule is time string and should have been a map */
    ctoken_result = ctoken_decode_enter_submod_sz(&decode_context, "notbs");
    if(ctoken_result != CTOKEN_ERR_SUBMOD_TYPE) {
        return 1300 + (int32_t)ctoken_result;
    }

    /* Try to get a submod token that is not of the right type */
    ctoken_result = ctoken_decode_get_nested_token_sz(&decode_context, "notmap", &type, &token);
    if(ctoken_result != CTOKEN_ERR_SUBMOD_TYPE) {
        return 1400 + (int32_t)ctoken_result;
    }

    /* Try to get a submod token that is not of the right type */
    ctoken_result = ctoken_decode_get_nested_token_sz(&decode_context, "notbs", &type, &token);
    if(ctoken_result != CTOKEN_ERR_SUBMOD_TYPE) {
        return 1400 + (int32_t)ctoken_result;
    }

    /* Try to get a submod token that is not of the right type */
    ctoken_result = ctoken_decode_get_nested_token_sz(&decode_context, "nest1", &type, &token);
    if(ctoken_result != CTOKEN_ERR_SUBMOD_TYPE) {
        return 1400 + (int32_t)ctoken_result;
    }


    /* A not-well-formed submodule */
    sign_cbor(UsefulBuf_FROM_BYTE_ARRAY_LITERAL(nwf_submod), out, &token);

    ctoken_decode_init(&decode_context, T_COSE_OPT_ALLOW_SHORT_CIRCUIT, 0);

    ctoken_result = ctoken_decode_validate_token(&decode_context, token);
    if(ctoken_result) {
        return 1500 + (int32_t)ctoken_result;
    }

    uint64_t x;
    ctoken_result = ctoken_decode_uptime(&decode_context, &x);
    if(ctoken_result != CTOKEN_ERR_SUCCESS) {
        return 1600 + (int32_t)ctoken_result;
    }

    ctoken_result = ctoken_decode_get_nested_token_sz(&decode_context, "jj", &type, &token);
    if(ctoken_result != CTOKEN_ERR_SUCCESS) {
        return 1700 + (int32_t)ctoken_result;
    }

    ctoken_result = ctoken_decode_get_nested_token_sz(&decode_context, "bad", &type, &token);
    if(ctoken_result != CTOKEN_ERR_CBOR_NOT_WELL_FORMED) {
        return 1800 + (int32_t)ctoken_result;
    }

    return 0;
}
