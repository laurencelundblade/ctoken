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
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/q_useful_buf.h"
#include "qcbor/qcbor_spiffy_decode.h"


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
void ctoken_decode_init(struct ctoken_decode_ctx *me,
                        uint32_t                  t_cose_options,
                        uint32_t                  options)
{
    memset(me, 0, sizeof(struct ctoken_decode_ctx));
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



static inline enum ctoken_err_t map_qcbor_error(QCBORError uErr)
{
    // TODO: make this better
    if(uErr) {
        return CTOKEN_ERR_GENERAL;
    } else {
        return CTOKEN_ERR_SUCCESS;
    }
}


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
ctoken_decode_get_kid(struct ctoken_decode_ctx *me,
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
ctoken_decode_validate_token(struct ctoken_decode_ctx *me,
                             struct q_useful_buf_c         token)
{
    enum t_cose_err_t t_cose_error;
    enum ctoken_err_t return_value;
    QCBORError        qcbor_error;

    t_cose_error = t_cose_sign1_verify(&(me->verify_context), token, &me->payload, NULL);
    if(t_cose_error != T_COSE_SUCCESS) {
        return_value = map_t_cose_errors(t_cose_error);
        goto Done;
    }


    /*
     * FIXME: check for CWT/EAT CBOR tag if requested
     */

    QCBORDecode_Init(&(me->qcbor_decode_context), me->payload, 0);
    QCBORDecode_EnterMap(&(me->qcbor_decode_context), NULL);
    qcbor_error = QCBORDecode_GetError(&(me->qcbor_decode_context));
    if(qcbor_error != QCBOR_SUCCESS) {
        // TODO: better error conversion
        return_value = CTOKEN_ERR_CBOR_STRUCTURE;
        goto Done;
    }

    return_value = CTOKEN_ERR_SUCCESS;

Done:
    me->last_error = return_value;
    return return_value;
}

#if 0
// TODO: fix this
/*
 * Public function. See ctoken_decode.h
 */
enum ctoken_err_t
ctoken_decode_get_map(struct ctoken_decode_ctx *me,
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
#endif



/*
 * Public function. See ctoken_decode.h
 */
enum ctoken_err_t
ctoken_decode_get_bstr(struct ctoken_decode_ctx *me,
                       int32_t                 label,
                       struct q_useful_buf_c  *claim)
{
    enum ctoken_err_t return_value;
    QCBORError qcbor_error;

    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return_value = me->last_error;
        *claim = NULL_Q_USEFUL_BUF_C;
        goto Done;
    }

    QCBORDecode_GetByteStringInMapN(&(me->qcbor_decode_context), label, claim);
    qcbor_error = QCBORDecode_GetAndResetError(&(me->qcbor_decode_context));

    return_value = map_qcbor_error(qcbor_error);

Done:
    return return_value;
}


/*
 * Public function. See ctoken_decode.h
 */
enum ctoken_err_t
ctoken_decode_get_tstr(struct ctoken_decode_ctx *me,
                       int32_t                   label,
                       struct q_useful_buf_c    *claim)
{
    enum ctoken_err_t return_value;
    QCBORError qcbor_error;

    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return_value = me->last_error;
        *claim = NULL_Q_USEFUL_BUF_C;
        goto Done;
    }

    QCBORDecode_GetTextStringInMapN(&(me->qcbor_decode_context), label, claim);
    qcbor_error = QCBORDecode_GetAndResetError(&(me->qcbor_decode_context));

    return_value = map_qcbor_error(qcbor_error);

Done:
    return return_value;
}


/*
 * Public function. See ctoken_decode.h
 */
enum ctoken_err_t
ctoken_decode_get_int(struct ctoken_decode_ctx *me,
                      int32_t                   label,
                      int64_t                  *integer)
{
    enum ctoken_err_t return_value;
    QCBORError qcbor_error;

    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return_value = me->last_error;
        *integer = 0;
        goto Done;
    }

    QCBORDecode_GetInt64InMapN(&(me->qcbor_decode_context), label, integer);
    qcbor_error = QCBORDecode_GetAndResetError(&(me->qcbor_decode_context));

    return_value = map_qcbor_error(qcbor_error);

Done:
    return return_value;
}


/*
 * Public function. See ctoken_decode.h
 */
enum ctoken_err_t
ctoken_decode_get_uint(struct ctoken_decode_ctx *me,
                       int32_t                   label,
                       uint64_t                 *integer)
{
    enum ctoken_err_t return_value;
    QCBORError qcbor_error;

    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return_value = me->last_error;
        *integer = 0;
        goto Done;
    }

    QCBORDecode_GetUInt64InMapN(&(me->qcbor_decode_context), label, integer);
    qcbor_error = QCBORDecode_GetAndResetError(&(me->qcbor_decode_context));

    return_value = map_qcbor_error(qcbor_error);

Done:
    return return_value;
}


/*
 * Public function. See ctoken_decode.h
 */
enum ctoken_err_t
ctoken_decode_get_payload(struct ctoken_decode_ctx *me,
                          struct q_useful_buf_c    *payload)
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



/*
 * Public function. See ctoken_eat_encode.h
 */
enum ctoken_err_t
ctoken_eat_decode_boot_state(struct ctoken_decode_ctx *me,
                             bool *secure_boot_enabled,
                             enum ctoken_eat_debug_level_t *debug_state)
{
    enum ctoken_err_t       return_value;
    int64_t boot_state;

    /* Note that this claim is still being debated in
     the working group and may change.

     This errors out ff the claim doesn't exist. It could
     default to some values.

     TODO: test this
     */

    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return_value = me->last_error;
        goto Done;
    }

    QCBORDecode_EnterArrayFromMapN(&(me->qcbor_decode_context),
                                   CTOKEN_EAT_LABEL_BOOT_STATE);
    // TODO: error check here maybe

    QCBORDecode_GetBool(&(me->qcbor_decode_context), secure_boot_enabled);
    QCBORDecode_GetInt64(&(me->qcbor_decode_context), &boot_state);

    QCBORDecode_ExitArray(&(me->qcbor_decode_context));

    if(boot_state < EAT_DL_NOT_REPORTED ||
       boot_state > EAT_DL_FULL_PERMANENT_DISABLE) {
        // TODO: better error here
        return_value = CTOKEN_ERR_CBOR_NOT_WELL_FORMED;
        goto Done;
    }

    *debug_state = (enum ctoken_eat_debug_level_t)boot_state;

    return_value = CTOKEN_ERR_SUCCESS;

Done:
    return return_value;
}


/*
 * Public function. See ctoken_eat_encode.h
 */
enum ctoken_err_t
ctoken_decode_location(struct ctoken_decode_ctx     *me,
                           struct ctoken_eat_location_t *location)
{
    enum ctoken_err_t   return_value = 0;
    double              d;
    int64_t             label;

    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return_value = me->last_error;
        goto Done;
    }

    QCBORDecode_EnterMapFromMapN(&(me->qcbor_decode_context),
                                 CTOKEN_EAT_LABEL_LOCATION);
    // TODO: probably need error here to indicate claim is not present

    for(label = CTOKEN_EAT_LABEL_LATITUDE; label < NUM_LOCATION_ITEMS; label++) {
        QCBORDecode_GetDoubleInMapN(&(me->qcbor_decode_context), label, &d);
        QCBORError e = QCBORDecode_GetAndResetError(&(me->qcbor_decode_context));
        if(!e) {
            location->items[label-1] = d;
            location->item_flags |= (0x01U << (label-1));
        }
    }

    QCBORDecode_ExitMap(&(me->qcbor_decode_context));
    if(QCBORDecode_GetError(&(me->qcbor_decode_context)) != QCBOR_SUCCESS) {
        return_value = CTOKEN_ERR_CBOR_STRUCTURE;
    }

Done:
    me->last_error = return_value;
    return return_value;
}






static void
descend_submod(struct ctoken_decode_ctx *me)
{
    // TODO: guard against calling too many times?
    QCBORDecode_EnterMapFromMapN(&(me->qcbor_decode_context), CTOKEN_EAT_LABEL_SUBMODS);
    me->in_submods++;
}


static void
ascend_submod(struct ctoken_decode_ctx *me)
{
    // TODO: guard against calling too many times?
    me->in_submods--;
    QCBORDecode_ExitMap(&(me->qcbor_decode_context));
}


/* exit conditions are: found nth, got to the end, errored out. */

static enum ctoken_err_t
ctoken_decode_eat_nth_submod(struct ctoken_decode_ctx *me,
                             uint32_t                  submod_index,
                             uint32_t                 *num_submods)
{
    /* Traverse submods map until nth one is found and stop */
    QCBORItem         map_item;
    QCBORError        error;
    uint32_t          submod_count;
    enum ctoken_err_t return_value;
    QCBORDecodeContext *decode_context = &(me->qcbor_decode_context);

    // Must be entered into submods before calling this

    // QCBORDecode_Rewind(decode_context);

    submod_count = 0;
    return_value = CTOKEN_ERR_SUCCESS;
    while(submod_index > 0) {
        error = QCBORDecode_GetError(decode_context);
        if(error == QCBOR_SUCCESS) {
            error = QCBORDecode_PeekNext(decode_context, &map_item);
        }
        if(error != QCBOR_SUCCESS) {
            if(error == QCBOR_ERR_NO_MORE_ITEMS) {
                // Got to the end of the submods map
                return_value = CTOKEN_ERR_SUCCESS;
            } else if(QCBORDecode_IsNotWellFormedError(error)) {
                return_value = CTOKEN_ERR_CBOR_NOT_WELL_FORMED;
            } else  {
                return_value = CTOKEN_ERR_TOKEN_FORMAT;
            }
            goto Done;
        }

        if(map_item.uDataType == QCBOR_TYPE_MAP) {
            // Enter and Exit is the way to skip over the whole submod
            QCBORDecode_EnterMap(decode_context, &map_item);
            QCBORDecode_ExitMap(decode_context);
        } else {
            QCBORDecode_VGetNext(decode_context, &map_item);
        }
        // TODO: should this check skipped submods for correctness?
        submod_count++;
        submod_index--;
    }

Done:
    *num_submods = submod_count;
    return return_value;
}


/* Possible errors:
 not well formed
 no submods section at all
 nesting too deep or other limitation error
 label of incorrect type
 general token structure error

 */
enum ctoken_err_t
ctoken_decode_get_num_submods(struct ctoken_decode_ctx *me,
                                  uint32_t                  *num_submods)
{
    enum ctoken_err_t return_value;

    descend_submod(me);

    return_value = ctoken_decode_eat_nth_submod(me, UINT32_MAX, num_submods);

    ascend_submod(me);

    return return_value;
}




enum ctoken_err_t
ctoken_decode_enter_nth_submod(struct ctoken_decode_ctx *me,
                                   uint32_t                   submod_index,
                                   struct q_useful_buf_c    *name)
{
    QCBORItem map_item;
    QCBORError error;
    enum ctoken_err_t return_value;
    uint32_t num_submods;

    descend_submod(me);

    return_value = ctoken_decode_eat_nth_submod(me, submod_index, &num_submods);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    if(num_submods != submod_index) {
        return_value = 99; // TODO: error code
    }

    QCBORDecode_EnterMap(&(me->qcbor_decode_context), &map_item);


    error = QCBORDecode_GetError(&(me->qcbor_decode_context));

    if(map_item.uLabelType != QCBOR_TYPE_TEXT_STRING) {
        error = 99; // TODO: fix error code
    }

    if(name) {
        *name = map_item.label.string;
    }

Done:
    // TODO: error handling
    // TODO: keep track to help error handling when exiting?
    return return_value;
}


enum ctoken_err_t
ctoken_decode_enter_submod_sz(struct ctoken_decode_ctx *me,
                                  const char               *name)
{
    descend_submod(me);

    QCBORDecode_EnterMapFromMapSZ(&(me->qcbor_decode_context), name);

    return 0; // TODO: error handling
}


enum ctoken_err_t
ctoken_eat_decode_enter_submod_n(struct ctoken_decode_ctx *me,
                                 int64_t                   name)
{
    descend_submod(me);

    QCBORDecode_EnterMapFromMapN(&(me->qcbor_decode_context), name);

    return 0; // TODO: error handling
}




enum ctoken_err_t
ctoken_decode_exit_submod(struct ctoken_decode_ctx *me)
{
    QCBORDecode_ExitMap(&(me->qcbor_decode_context));

    ascend_submod(me);

    // TODO: error code

    return 0;
}


static enum ctoken_err_t
ctoken_eat_decode_finish_token(struct ctoken_decode_ctx *me,
                               const QCBORItem           Item,
                               enum ctoken_type         *type,
                               struct q_useful_buf_c    *token)
{
    enum ctoken_err_t return_value = CTOKEN_ERR_SUCCESS;

    QCBORError qcbor_error = QCBORDecode_GetError(&(me->qcbor_decode_context));
    if(QCBORDecode_IsNotWellFormedError(qcbor_error)) {
        return_value = CTOKEN_ERR_CBOR_NOT_WELL_FORMED;
        goto Done;
    }

    // TODO: make Item a pointer
    if(Item.uDataType == QCBOR_TYPE_BYTE_STRING) {
        *token = Item.val.string;
        *type = CTOKEN_TYPE_CWT;
    } else if(Item.uDataType == QCBOR_TYPE_TEXT_STRING) {
        *token = Item.val.string;
        *type = CTOKEN_TYPE_JSON;
    } else {
        return_value = CTOKEN_ERR_TOKEN_FORMAT;
        goto Done;
    }

Done:
    return return_value;
}



enum ctoken_err_t
ctoken_eat_decode_get_submod_sz(struct ctoken_decode_ctx *me,
                                 const char              *name,
                                 enum ctoken_type        *type,
                                 struct q_useful_buf_c   *token)
{
    QCBORItem Item;
    enum ctoken_err_t return_value;

     descend_submod(me);

    QCBORDecode_GetItemInMapSZ(&(me->qcbor_decode_context), name, QCBOR_TYPE_ANY, &Item);
    // All error handling from QCBOR last error in ctoken_eat_decode_finish_token()
    // TODO: is this working well?

    return_value = ctoken_eat_decode_finish_token(me, Item, type, token);

    ascend_submod(me);

    return return_value;
}

enum ctoken_err_t
ctoken_decode_get_submod_n(struct ctoken_decode_ctx *me,
                                 uint32_t               name,
                                 enum ctoken_type        *type,
                                 struct q_useful_buf_c   *token)
{
    QCBORItem Item;
    enum ctoken_err_t return_value;


    descend_submod(me);

    QCBORDecode_GetItemInMapN(&(me->qcbor_decode_context), name, QCBOR_TYPE_ANY, &Item);
    // All error handling from QCBOR last error in ctoken_eat_decode_finish_token()
    // TODO: is this working well?

    return_value = ctoken_eat_decode_finish_token(me, Item, type, token);

    ascend_submod(me);

    return return_value;
}


enum ctoken_err_t
ctoken_eat_decode_get_nth_submod(struct ctoken_decode_ctx *me,
                                  uint32_t                  submod_index,
                                 enum ctoken_type        *type,
                                 struct q_useful_buf_c   *token)
{
    QCBORItem Item;
    enum ctoken_err_t return_value;

    descend_submod(me);

    return_value = ctoken_decode_eat_nth_submod(me, submod_index, NULL);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        return return_value;
    }

    QCBORDecode_GetNext(&(me->qcbor_decode_context), &Item);

    return_value = ctoken_eat_decode_finish_token(me, Item, type, token);

    ascend_submod(me);

    return return_value;
}
