/*
 * ctoken_decode.c (formerly attest_token_decode.c)
 *
 * Copyright (c) 2019-2020, Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "ctoken_decode.h"
#include "t_cose_sign1_verify.h"
#include "q_useful_buf.h"
#include "qcbor_util.h"


/**
 * \file ctoken_decode.c
 *
 * \brief CBOR token decoder.
 *
 * This decodes and verifies a CBOR token giving access to the
 * data items in the token. The data items are also known as claims.
 *
 * This is written primarily as tests for the token encoder, though it
 * close to a full commercial token decoder. The main thing missing is
 * a thorough test suite for it. Test before commercial use is
 * important as this is a parser / decoder and thus subject to attack
 * by malicious input. It does however, use QCBOR for most base
 * parsing, and QCBOR is thoroughly tested and commercial.
 * *
 * \c uint_fast8_t is used for type and nest levels. They are
 * 8-bit quantities, but making using uint8_t variables
 * and parameters can result in bigger, slower code.
 * \c uint_fast8_t is part of \c <stdint.h>. It is not
 * used in structures where it is more important to keep
 * the size smaller.
 */



/*
 * Public function. See ctoken_decode.h
 */
void ctoken_decode_init(struct ctoken_decode_context *me,
                              uint32_t                t_cose_options,
                              uint32_t                options)
{
    memset(me, 0, sizeof(struct ctoken_decode_context));
    me->options    = options;
    me->last_error = CTOKEN_ERR_NO_VALID_TOKEN;

    t_cose_sign1_verify_init(&(me->verify_context), t_cose_options);
}




static enum ctoken_err_t t_cose_verify_error_map[] = {
    /*     T_COSE_SUCCESS = 0 */
    CTOKEN_ERR_SUCCESS,
    /*     T_COSE_ERR_UNSUPPORTED_SIGNING_ALG */
    CTOKEN_ERR_UNSUPPORTED_SIG_ALG,
    /*     T_COSE_ERR_PROTECTED_HEADERS */
    CTOKEN_ERR_GENERAL,
    /*     T_COSE_ERR_UNSUPPORTED_HASH */
    CTOKEN_ERR_HASH_UNAVAILABLE,
    /*     T_COSE_ERR_HASH_GENERAL_FAIL */
    CTOKEN_ERR_GENERAL,
    /*     T_COSE_ERR_HASH_BUFFER_SIZE */
    CTOKEN_ERR_GENERAL,
    /*     T_COSE_ERR_SIG_BUFFER_SIZE */
    CTOKEN_ERR_GENERAL,
    /*     T_COSE_ERR_KEY_BUFFER_SIZE */
    CTOKEN_ERR_GENERAL,
    /*     T_COSE_ERR_SIGN1_FORMAT */
    CTOKEN_ERR_COSE_SIGN1_FORMAT,
    /*     T_COSE_ERR_CBOR_NOT_WELL_FORMED */
    CTOKEN_ERR_CBOR_NOT_WELL_FORMED,
    /*     T_COSE_ERR_NO_ALG_ID */
    CTOKEN_ERR_COSE_SIGN1_FORMAT,
    /*     T_COSE_ERR_NO_KID */
    CTOKEN_ERR_COSE_SIGN1_FORMAT,
    /*     T_COSE_ERR_SIG_VERIFY */
    CTOKEN_ERR_COSE_SIGN1_VALIDATION,
    /*     T_COSE_ERR_BAD_SHORT_CIRCUIT_KID */
    CTOKEN_ERR_COSE_SIGN1_FORMAT,
    /*     T_COSE_ERR_INVALID_ARGUMENT */
    CTOKEN_ERR_GENERAL,
    /*     T_COSE_ERR_INSUFFICIENT_MEMORY */
    CTOKEN_ERR_INSUFFICIENT_MEMORY,
    /*     T_COSE_ERR_FAIL */
    CTOKEN_ERR_GENERAL,
    /*     T_COSE_ERR_TAMPERING_DETECTED */
    CTOKEN_ERR_TAMPERING_DETECTED,
    /*     T_COSE_ERR_UNKNOWN_KEY */
    CTOKEN_ERR_VERIFICATION_KEY,
    /*     T_COSE_ERR_WRONG_TYPE_OF_KEY */
    CTOKEN_ERR_VERIFICATION_KEY,
    /*     T_COSE_ERR_SIG_STRUCT */
    CTOKEN_ERR_COSE_SIGN1_FORMAT,
    /*     T_COSE_ERR_SHORT_CIRCUIT_SIG */
    CTOKEN_ERR_COSE_SIGN1_VALIDATION
};

/**

 \brief Map t_cose errors into ctoken errors

 \param[in] t_cose_error  The t_cose error to map

 \return The ctoken error.
 */
static inline enum ctoken_err_t
map_t_cose_errors(enum t_cose_err_t t_cose_error)
{
    /*
     * Object code is smaller by using the mapping array, assuming
     * compiler makes enums as small as possible.
     */
    enum ctoken_err_t return_value;
    const size_t map_size = sizeof(t_cose_verify_error_map) /  sizeof(enum ctoken_err_t);

    if(t_cose_error >= map_size) {
        return_value = CTOKEN_ERR_GENERAL;
    } else {
        return_value = t_cose_verify_error_map[t_cose_error];
    }

    return return_value;
}


enum ctoken_err_t
ctoken_decode_get_kid(struct ctoken_decode_context *me,
                            struct q_useful_buf_c   token,
                            struct q_useful_buf_c  *kid)
{
    struct q_useful_buf_c     payload;
    struct t_cose_parameters  parameters;
    enum t_cose_err_t         t_cose_error;

    // TODO: how to handle combined options here?
    t_cose_sign1_verify_init(&(me->verify_context), T_COSE_OPT_DECODE_ONLY);
    t_cose_error = t_cose_sign1_verify(&(me->verify_context), token, &payload, &parameters);

    if(t_cose_error) {
        return 99;
    }

    *kid = parameters.kid;

    return 0;
}


/*
 * Public function. See ctoken_decode.h
 */
enum ctoken_err_t
ctoken_decode_validate_token(struct ctoken_decode_context *me,
                             struct q_useful_buf_c         token)
{
    enum t_cose_err_t t_cose_error;
    enum ctoken_err_t return_value;

    /*
     * FIXME: check for CWT/EAT CBOR tag if requested
     */
    
    t_cose_error = t_cose_sign1_verify(&(me->verify_context), token, &me->payload, NULL);
    return_value = map_t_cose_errors(t_cose_error);
    me->last_error = return_value;

    return return_value;
}


/*
 * Public function. See ctoken_decode.h
 */
enum ctoken_err_t
ctoken_decode_get_map(struct ctoken_decode_context *me,
                            int32_t                 label,
                            QCBORItem              *item)
{
    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        item->uDataType = QCBOR_TYPE_NONE;
        return me->last_error;
    }

    return qcbor_util_get_top_level_item_in_map(me->payload,
                                                label,
                                                QCBOR_TYPE_MAP,
                                                item);
}


/*
 * Public function. See ctoken_decode.h
 */
enum ctoken_err_t
ctoken_decode_get_bstr(struct ctoken_decode_context *me,
                             int32_t                 label,
                             struct q_useful_buf_c  *claim)
{
    enum ctoken_err_t return_value;
    QCBORItem         item;

    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return_value = me->last_error;
        *claim = NULL_Q_USEFUL_BUF_C;
        goto Done;
    }

    return_value = qcbor_util_get_top_level_item_in_map(me->payload,
                                                        label,
                                                        QCBOR_TYPE_BYTE_STRING,
                                                        &item);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    *claim = item.val.string;

Done:
    return return_value;
}


/*
 * Public function. See ctoken_decode.h
 */
enum ctoken_err_t
ctoken_decode_get_tstr(struct ctoken_decode_context *me,
                       int32_t                       label,
                       struct q_useful_buf_c        *claim)
{
    enum ctoken_err_t return_value;
    QCBORItem         item;

    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return_value = me->last_error;
        *claim = NULL_Q_USEFUL_BUF_C;
        goto Done;
    }

    return_value = qcbor_util_get_top_level_item_in_map(me->payload,
                                                        label,
                                                        QCBOR_TYPE_TEXT_STRING,
                                                        &item);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    *claim = item.val.string;

Done:
    return return_value;
}


/*
 * Public function. See ctoken_decode.h
 */
enum ctoken_err_t
ctoken_decode_get_int(struct ctoken_decode_context *me,
                      int32_t                       label,
                      int64_t                      *integer)
{
    enum ctoken_err_t   return_value;
    QCBORItem           item;
    QCBORDecodeContext  decode_context;

    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return_value = me->last_error;
        *integer = 0;
        goto Done;
    }

    QCBORDecode_Init(&decode_context, me->payload, 0);

    return_value = qcbor_util_get_item_in_map(&decode_context,
                                               label,
                                              &item);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    if(QCBORDecode_Finish(&decode_context)) {
        return_value = CTOKEN_ERR_CBOR_STRUCTURE;
    }

    if(item.uDataType == QCBOR_TYPE_INT64) {
        *integer = item.val.int64;
    } else if(item.uDataType == QCBOR_TYPE_UINT64) {
        if(item.val.uint64 < INT64_MAX) {
            *integer = (int64_t)item.val.uint64;
        } else {
            return_value = CTOKEN_ERR_INTEGER_VALUE;
        }
    } else {
        return_value = CTOKEN_ERR_CBOR_TYPE;
    }

Done:
    return return_value;
}


/*
 * Public function. See ctoken_decode.h
 */
enum ctoken_err_t
ctoken_decode_get_uint(struct ctoken_decode_context *me,
                       int32_t                       label,
                       uint64_t                     *integer)
{
    enum ctoken_err_t   return_value;
    QCBORItem           item;
    QCBORDecodeContext  decode_context;

    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return_value = me->last_error;
        *integer = 0;
        goto Done;
    }

    QCBORDecode_Init(&decode_context, me->payload, 0);

    return_value = qcbor_util_get_item_in_map(&decode_context,
                                             label,
                                             &item);
    if(return_value != 0) {
        goto Done;
    }

    if(QCBORDecode_Finish(&decode_context)) {
        return_value = CTOKEN_ERR_CBOR_STRUCTURE;
    }

    if(item.uDataType == QCBOR_TYPE_UINT64) {
        *integer = item.val.uint64;
    } else if(item.uDataType == QCBOR_TYPE_INT64) {
        if(item.val.int64 >= 0) {
            *integer = (uint64_t)item.val.int64;
        } else {
            return_value = CTOKEN_ERR_INTEGER_VALUE;
        }
    } else {
        return_value = CTOKEN_ERR_CBOR_TYPE;
    }

Done:
    return return_value;
}


/*
 * Public function. See ctoken_decode.h
 */
enum ctoken_err_t
ctoken_decode_get_payload(struct ctoken_decode_context *me,
                          struct q_useful_buf_c        *payload)
{
    enum ctoken_err_t return_value;

    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return_value = me->last_error;
        *payload = NULL_Q_USEFUL_BUF_C;
        goto Done;
    }

    if(q_useful_buf_c_is_null_or_empty(me->payload)) {
        return_value = CTOKEN_ERR_NO_VALID_TOKEN;
        goto Done;
    }

    *payload = me->payload;
    return_value = CTOKEN_ERR_SUCCESS;

Done:
    return return_value;
}


