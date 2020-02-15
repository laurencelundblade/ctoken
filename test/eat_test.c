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
    struct ctoken_encode_ctx     encode_ctx;
    MakeUsefulBufOnStack(        token_out_buffer, 400);
    struct q_useful_buf_c        completed_token;
    enum ctoken_err_t            result;
    struct q_useful_buf_c        nonce;
    struct q_useful_buf_c        ueid;
    struct q_useful_buf_c        oemid;
    struct q_useful_buf_c        origination;
    enum ctoken_eat_security_level_t security_level;
    bool                         secure_boot;
    enum ctoken_eat_debug_level_t debug_level;
    struct ctoken_eat_location_t location;
    uint64_t                     age;
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

    ctoken_eat_encode_nonce(&encode_ctx,test_nonce);

    ctoken_eat_encode_ueid(&encode_ctx, test_ueid);

    ctoken_eat_encode_oemid(&encode_ctx, test_oemid);

    ctoken_eat_encode_origination(&encode_ctx, test_origination);

    ctoken_eat_encode_security_level(&encode_ctx, EAT_SL_SECURE_RESTRICTED);

    ctoken_eat_encode_boot_state(&encode_ctx, true, EAT_DL_DISABLED_SINCE_BOOT);

    location.eat_loc_latitude = 34.88;
    location.eat_loc_longitude = 9.54;
    location.item_flags = 0x3;
    ctoken_eat_encode_location(&encode_ctx, &location);

    ctoken_eat_encode_age(&encode_ctx, 987654321);

    ctoken_eat_encode_uptime(&encode_ctx, 886688);

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

    result = ctoken_eat_decode_nonce(&decode_context, &nonce);
    if(result) {
        return 400 + (int32_t)result;
    }
    if(q_useful_buf_compare(nonce, test_nonce)) {
        return 499;
    }

    result = ctoken_eat_decode_ueid(&decode_context, &ueid);
    if(result) {
        return 500 + (int32_t)result;
    }
    if(q_useful_buf_compare(ueid, test_ueid)) {
        return 599;
    }

    result = ctoken_eat_decode_oemid(&decode_context, &oemid);
    if(result) {
        return 600 + (int32_t)result;
    }
    if(q_useful_buf_compare(oemid, test_oemid)) {
        return 699;
    }

    result = ctoken_eat_decode_origination(&decode_context, &origination);
    if(result) {
        return 700 + (int32_t)result;
    }
    if(q_useful_buf_compare(origination, test_origination)) {
        return 799;
    }

    result = ctoken_eat_decode_security_level(&decode_context, &security_level);
    if(result) {
        return 800 + (int32_t)result;
    }
    if(security_level != EAT_SL_SECURE_RESTRICTED) {
        return 899;
    }

    result = ctoken_eat_decode_boot_state(&decode_context, &secure_boot, &debug_level);
    if(result) {
        return 900 + (int32_t)result;
    }
    if(secure_boot != true || debug_level != EAT_DL_DISABLED_SINCE_BOOT) {
        return 999;
    }

    /* zero out to make sure results are tested correctly */
    memset(&location, 0, sizeof(location));

    result = ctoken_eat_decode_location(&decode_context,
                                        &location);
    if(result) {
        return 1000 + (int32_t)result;
    }

    if(location.eat_loc_longitude != 9.54 ||
       location.eat_loc_latitude != 34.88 ||
       location.item_flags != 0x03 ) {
        return 1099;
    }

    result = ctoken_eat_decode_age(&decode_context, &age);
    if(result) {
        return 1100 + (int32_t)result;
    }
    if(age != 987654321) {
        return 1199;
    }

    result = ctoken_eat_decode_uptime(&decode_context, &uptime);
    if(result) {
        return 1200 + (int32_t)result;
    }
    if(age != 987654321) {
        return 1299;
    }

    return 0;
}

