/*
 * ctoken_decode.c (formerly attest_token_decode.c)
 *
 * Copyright (c) 2019-2021, Laurence Lundblade.
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
                        uint32_t                  ctoken_options,
                        enum ctoken_protection_t  protection_type)
{
    memset(me, 0, sizeof(struct ctoken_decode_ctx));
    me->ctoken_options         = ctoken_options;
    me->last_error             = CTOKEN_ERR_NO_VALID_TOKEN;
    me->protection_type        = protection_type;
    me->actual_protection_type = CTOKEN_PROTECTION_UNKNOWN;


    /* Always initialize, even if we turn out not to use COSE */
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
    0, // TODO: fix this list
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


static inline enum ctoken_err_t map_qcbor_error(QCBORError error)
{
    // TODO: make this better
    if(QCBORDecode_IsNotWellFormedError(error)) {
        return CTOKEN_ERR_CBOR_NOT_WELL_FORMED;
    } else if(error == QCBOR_ERR_LABEL_NOT_FOUND) {
        return CTOKEN_ERR_CLAIM_NOT_PRESENT;
    } else if(error == QCBOR_ERR_UNEXPECTED_TYPE) {
        return CTOKEN_ERR_CBOR_TYPE;
    } else if(error) {
        return CTOKEN_ERR_GENERAL;
    } else {
        return CTOKEN_ERR_SUCCESS;
    }
}


/**
 * \brief Map t_cose errors into ctoken errors
 *
 * \param[in] t_cose_error  The t_cose error to map
 *
 * \return The ctoken error.
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


/*
* Public function. See ctoken_decode.h
*/
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


uint64_t get_nth_tag(struct ctoken_decode_ctx *me, int protection_type, QCBORItem *item, uint32_t n)
{
    uint64_t tag_number;

    switch(protection_type) {
        case CTOKEN_PROTECTION_NONE:
            tag_number = QCBORDecode_GetNthTag(&(me->qcbor_decode_context), item, n);
            break;

        case CTOKEN_PROTECTION_COSE_SIGN1:
            tag_number = t_cose_sign1_get_nth_tag(&(me->verify_context), n);
            break;

        default:
            tag_number = CBOR_TAG_INVALID64;
    }

    return tag_number;
}


/*
 * Public function. See ctoken_decode.h
 */
enum ctoken_err_t
ctoken_decode_validate_token(struct ctoken_decode_ctx *me,
                             struct q_useful_buf_c     token)
{
    enum t_cose_err_t        t_cose_error;
    enum ctoken_err_t        return_value;
    QCBORError               qcbor_error;
    enum ctoken_protection_t protection_type;
    int                      returned_tag_index;
    uint64_t                 tag_number;
    uint64_t                 expected_tag;
    QCBORItem                item;
    uint32_t                 item_tag_index;

    memset(me->auTags, 0xff, sizeof(me->auTags));
    tag_number      = CBOR_TAG_INVALID64;
    protection_type = me->protection_type;
    expected_tag    = CBOR_TAG_INVALID32; /* to be different from CBOR_TAG_INVALID64 */

    /* Peek to get the tag number from the first item if there is one.
     * This also
     * initializes the decoder for UCCS decoding (the same decoder is re initialized for COSE decoding. */
    QCBORDecode_Init(&(me->qcbor_decode_context), token, 0);
    QCBORDecode_PeekNext(&(me->qcbor_decode_context), &item);

    tag_number = QCBORDecode_GetNthTag(&(me->qcbor_decode_context), &item, 0);


    if(tag_number == CBOR_TAG_COSE_SIGN1 ||
       tag_number == CBOR_TAG_CWT ||
       (tag_number == CBOR_TAG_INVALID64 && protection_type == CTOKEN_PROTECTION_COSE_SIGN1)) {
        /* It is a case where COSE protection is expected. Call COSE and let it work. */

        t_cose_error = t_cose_sign1_verify(&(me->verify_context), token, &me->payload, NULL);
        if(t_cose_error != T_COSE_SUCCESS) {
            return_value = map_t_cose_errors(t_cose_error);
            goto Done;
        }

        expected_tag = CBOR_TAG_CWT;

        me->actual_protection_type = CTOKEN_PROTECTION_COSE_SIGN1;

        /* Re-initialize with the payload of the COSE_sign1 */
        QCBORDecode_Init(&(me->qcbor_decode_context), me->payload, 0);

    } else if(tag_number == 601 || protection_type == CTOKEN_PROTECTION_NONE) {
        /* Seems to be an unprotected token, a UCCS, either a tag or not. */

        me->payload = token;

        me->actual_protection_type = CTOKEN_PROTECTION_NONE;

        expected_tag = 601;
        
    } else {
        /* Neither the tag nor the argument told us the protection type */
        return_value = CTOKEN_ERR_UNDETERMINED_PROTECTION_TYPE;
        goto Done;
    }

    /* Copy the tags not processed so they are available to caller and do check on innermost tag */
    item_tag_index = 0;
    for(returned_tag_index = 0; returned_tag_index < CTOKEN_MAX_TAGS_TO_RETURN; returned_tag_index++) {
        tag_number = get_nth_tag(me, protection_type, &item, item_tag_index);

        if(item_tag_index == 0) {
            if(tag_number == expected_tag && (me->ctoken_options & CTOKEN_OPT_PROHIBIT_TOP_LEVEL_TAG)) {
                return_value = CTOKEN_ERR_SHOULD_NOT_BE_TAG;
                goto Done;
            }
            if(tag_number != expected_tag && (me->ctoken_options & CTOKEN_OPT_REQUIRE_TOP_LEVEL_TAG)) {
                return_value = CTOKEN_ERR_SHOULD_BE_TAG;
                goto Done;
            }
            continue;
        }

        if(tag_number == CBOR_TAG_INVALID64) {
            break;
        }

        item_tag_index++;

        me->auTags[returned_tag_index] = tag_number;
    }

    /* Now processing for either COSE-secured or UCCS. Enter the map that holds all the claims */
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
    if(return_value != CTOKEN_ERR_SUCCESS) {
        me->actual_protection_type = CTOKEN_PROTECTION_UNKNOWN;
    }
    return return_value;
}


/*
 * Public function. See ctoken_decode.h
 */
enum ctoken_err_t
ctoken_decode_get_bstr(struct ctoken_decode_ctx *me,
                       int32_t                  label,
                       struct q_useful_buf_c   *claim)
{
    enum ctoken_err_t return_value;
    QCBORError        qcbor_error;

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
    QCBORError        qcbor_error;

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
    QCBORError        qcbor_error;

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
    QCBORError        qcbor_error;

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
ctoken_decode_get_bool(struct ctoken_decode_ctx *me,
                       int32_t                   label,
                       bool                     *b)
{
    enum ctoken_err_t return_value;
    QCBORError        qcbor_error;

    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return_value = me->last_error;
        goto Done;
    }

    QCBORDecode_GetBoolInMapN(&(me->qcbor_decode_context), label, b);
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
ctoken_decode_get_int_constrained(struct ctoken_decode_ctx *me,
                                  int32_t                   label,
                                  int64_t                   min,
                                  int64_t                   max,
                                  int64_t                  *claim)
{
    enum ctoken_err_t error;

    error = ctoken_decode_get_int(me, label, claim);
    if(error != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    if(*claim < min || *claim > max) {
        error = CTOKEN_ERR_CLAIM_RANGE;
    }

Done:
    return error;
}


/*
 * Public function. See ctoken_eat_encode.h
 */
enum ctoken_err_t
ctoken_decode_location(struct ctoken_decode_ctx   *me,
                       struct ctoken_location_t   *location)
{
    enum ctoken_err_t  return_value = CTOKEN_ERR_SUCCESS;
    double             d;
    int                label;
    QCBORError         cbor_error;

    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return_value = me->last_error;
        goto Done;
    }

    location->item_flags = 0;

    QCBORDecode_EnterMapFromMapN(&(me->qcbor_decode_context),
                                 CTOKEN_EAT_LABEL_LOCATION);
    cbor_error = QCBORDecode_GetAndResetError(&(me->qcbor_decode_context));
    if(cbor_error != QCBOR_SUCCESS) {
        return_value = map_qcbor_error(cbor_error);
        goto Done;
    }

    for(label = CTOKEN_EAT_LABEL_LATITUDE; label <= NUM_FLOAT_LOCATION_ITEMS; label++) {
        QCBORDecode_GetDoubleInMapN(&(me->qcbor_decode_context), label, &d);
        cbor_error = QCBORDecode_GetAndResetError(&(me->qcbor_decode_context));
        if(cbor_error == QCBOR_SUCCESS) {
            location->items[label-1] = d;
            ctoken_location_mark_item_present(location, label);
        } else if(cbor_error != QCBOR_ERR_LABEL_NOT_FOUND) {
            return_value = map_qcbor_error(cbor_error);
            goto Done;
        }
    }

    if(!ctoken_location_is_item_present(location, CTOKEN_EAT_LABEL_LATITUDE) ||
        !ctoken_location_is_item_present(location, CTOKEN_EAT_LABEL_LONGITUDE)) {
        /* Per EAT and W3C specs, the lattitude and longitude must be present */
        return_value = CTOKEN_ERR_CLAIM_FORMAT;
        goto Done;
    }

    QCBORDecode_GetUInt64InMapN(&(me->qcbor_decode_context), CTOKEN_EAT_LABEL_TIME_STAMP, &(location->time_stamp));
    cbor_error = QCBORDecode_GetAndResetError(&(me->qcbor_decode_context));
    if(cbor_error == QCBOR_SUCCESS) {
        ctoken_location_mark_item_present(location, CTOKEN_EAT_LABEL_TIME_STAMP);
    } else if(cbor_error != QCBOR_ERR_LABEL_NOT_FOUND) {
        return_value = map_qcbor_error(cbor_error);
        goto Done;
    }

    QCBORDecode_GetUInt64InMapN(&(me->qcbor_decode_context), CTOKEN_EAT_LABEL_AGE, &(location->age));
    cbor_error = QCBORDecode_GetAndResetError(&(me->qcbor_decode_context));
    if(cbor_error == QCBOR_SUCCESS) {
        ctoken_location_mark_item_present(location, CTOKEN_EAT_LABEL_AGE);
    } else if(cbor_error != QCBOR_ERR_LABEL_NOT_FOUND) {
        return_value = map_qcbor_error(cbor_error);
        goto Done;
    }

    QCBORDecode_ExitMap(&(me->qcbor_decode_context));
    cbor_error = QCBORDecode_GetAndResetError(&(me->qcbor_decode_context));
    if(cbor_error != QCBOR_SUCCESS) {
        return_value = map_qcbor_error(cbor_error);
    }

    return_value = CTOKEN_ERR_SUCCESS;

Done:
    me->last_error = return_value;
    return return_value;
}


static inline bool
QCBORItem_IsMapOrArray(const QCBORItem *pMe)
{
   const uint8_t uDataType = pMe->uDataType;
   return uDataType == QCBOR_TYPE_MAP ||
          uDataType == QCBOR_TYPE_ARRAY ||
          uDataType == QCBOR_TYPE_MAP_AS_ARRAY;
}


static inline QCBORError
consume_item(QCBORDecodeContext *decode_context, const QCBORItem  *first_item)
{
   QCBORError return_value;
   QCBORItem  Item;

   /* If it is a map or array, this will tell if it is empty. */
   const bool is_empty = (first_item->uNextNestLevel <= first_item->uNestingLevel);

   if(QCBORItem_IsMapOrArray(first_item) && !is_empty) {
      /* There is only real work to do for non-empty maps and arrays */

      /* This works for definite and indefinite length
       * maps and arrays by using the nesting level
       */
      do {
          return_value = QCBORDecode_GetNext(decode_context, &Item);
          if(QCBORDecode_IsUnrecoverableError(return_value) ||
              return_value == QCBOR_ERR_NO_MORE_ITEMS) {
              goto Done;
          }

      } while(Item.uNextNestLevel >= first_item->uNextNestLevel);

      return_value = QCBOR_SUCCESS;

   } else {
      return_value = QCBOR_SUCCESS;
   }

Done:
    return return_value;
}


/*
 * Public function. See ctoken_eat_encode.h
 */
enum ctoken_err_t
ctoken_decode_next_claim(struct ctoken_decode_ctx   *me,
                         QCBORItem                  *claim)
{
    QCBORError        cbor_error;
    enum ctoken_err_t return_value;

    /* Loop is only to skip the submods section and executes only
     * once in most cases. It executes twice if there is a submods section.
     */
    do {
        cbor_error = QCBORDecode_GetNext(&(me->qcbor_decode_context), claim);
        if(cbor_error == QCBOR_ERR_NO_MORE_ITEMS) {
            return_value = CTOKEN_ERR_NO_MORE_CLAIMS;
            goto Done;
        }
        if(cbor_error) {
            // TODO: refine this error.
            return_value = CTOKEN_ERR_CBOR_NOT_WELL_FORMED;
            goto Done;
        }

        cbor_error = consume_item(&(me->qcbor_decode_context), claim);
        if(cbor_error == QCBOR_ERR_NO_MORE_ITEMS) {
             return_value = CTOKEN_ERR_NO_MORE_CLAIMS;
             goto Done;
         }
        if(cbor_error) {
            // TODO: refine this error.
            return_value = CTOKEN_ERR_CBOR_NOT_WELL_FORMED;
            goto Done;
        }

    } while(claim->label.int64 == CTOKEN_EAT_LABEL_SUBMODS &&
            claim->uLabelType == QCBOR_TYPE_INT64);

    return_value = CTOKEN_ERR_SUCCESS;

    claim->uNestingLevel = 0;
    claim->uNextNestLevel = 0;

Done:
    return return_value;
}

// TODO: get rid of this
void QCBORDecode_Rewind(QCBORDecodeContext *x)
{
    x->uDecodeMode =0 ;
}


static enum ctoken_err_t
enter_submod_section(struct ctoken_decode_ctx *me)
{
    if(me->in_submods >= CTOKEN_MAX_SUBMOD_NESTING) {
        return CTOKEN_ERR_SUBMOD_NESTING_TOO_DEEP;
    }
    QCBORDecode_EnterMapFromMapN(&(me->qcbor_decode_context),
                                 CTOKEN_EAT_LABEL_SUBMODS);
    if(QCBORDecode_GetAndResetError(&(me->qcbor_decode_context))) {
        return CTOKEN_ERR_SUBMOD_SECTION;
    }
    me->in_submods++;

    return CTOKEN_ERR_SUCCESS;
}


static enum ctoken_err_t
leave_submod_section(struct ctoken_decode_ctx *me)
{
    if(me->in_submods == 0) {
        return CTOKEN_ERR_NO_SUBMOD_OPEN;
    }
    me->in_submods--;
    QCBORDecode_ExitMap(&(me->qcbor_decode_context));

    return CTOKEN_ERR_SUCCESS;
}


/* exit conditions are: found nth, got to the end, errored out. */

static enum ctoken_err_t
ctoken_decode_nth_submod(struct ctoken_decode_ctx *me,
                             uint32_t                  submod_index,
                             uint32_t                 *num_submods)
{
    /* Traverse submods map until nth one is found and stop */
    QCBORItem         map_item;
    QCBORError        error;
    uint32_t          submod_count;
    enum ctoken_err_t return_value;
    QCBORDecodeContext *decode_context = &(me->qcbor_decode_context);

    /* Must be entered into submods before calling this */

    submod_count = 0;
    return_value = CTOKEN_ERR_SUCCESS;
    while(submod_index > 0) {
        error = QCBORDecode_GetAndResetError(decode_context);
        if(error == QCBOR_SUCCESS) {
            error = QCBORDecode_PeekNext(decode_context, &map_item);
        }
        if(error != QCBOR_SUCCESS) {
            if(error == QCBOR_ERR_NO_MORE_ITEMS) {
                /* Got to the end of the submods map */
                return_value = CTOKEN_ERR_SUCCESS;
            } else if(QCBORDecode_IsNotWellFormedError(error)) {
                return_value = CTOKEN_ERR_CBOR_NOT_WELL_FORMED;
            } else  {
                return_value = CTOKEN_ERR_TOKEN_FORMAT;
            }
            goto Done;
        }

        if(map_item.uDataType == QCBOR_TYPE_MAP) {
            /* Enter and Exit is the way to skip over the whole submod */
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


/*
 * Public function. See ctoken_decode.h
 */
enum ctoken_err_t
ctoken_decode_get_num_submods(struct ctoken_decode_ctx *me,
                              uint32_t                 *num_submods)
{
    enum ctoken_err_t return_value;

    return_value = enter_submod_section(me);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    return_value = ctoken_decode_nth_submod(me, UINT32_MAX, num_submods);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    return_value = leave_submod_section(me);

Done:
    return return_value;
}


/*
 * Public function. See ctoken_decode.h
 */
enum ctoken_err_t
ctoken_decode_enter_nth_submod(struct ctoken_decode_ctx *me,
                               uint32_t                  submod_index,
                               struct q_useful_buf_c    *name)
{
    QCBORItem         map_item;
    QCBORError        qcbor_error;
    enum ctoken_err_t return_value;
    uint32_t          num_submods;

    return_value = enter_submod_section(me);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    return_value = ctoken_decode_nth_submod(me, submod_index, &num_submods);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    if(num_submods != submod_index) {
        return_value = CTOKEN_ERR_SUBMOD_INDEX_TOO_LARGE;
        leave_submod_section(me);
        goto Done;
    }

    QCBORDecode_EnterMap(&(me->qcbor_decode_context), &map_item);
    qcbor_error = QCBORDecode_GetAndResetError(&(me->qcbor_decode_context));
    if(qcbor_error != QCBOR_SUCCESS) {
        return_value = map_qcbor_error(qcbor_error);
        leave_submod_section(me);
        goto Done;
    }

    if(map_item.uLabelType != QCBOR_TYPE_TEXT_STRING) {
        return_value = CTOKEN_ERR_SUBMOD_NAME_NOT_A_TEXT_STRING;
        QCBORDecode_ExitMap(&(me->qcbor_decode_context));
        leave_submod_section(me);
        goto Done;
    }

    if(name != NULL) {
        *name = map_item.label.string;
    }

Done:
    return return_value;
}

/*
* Public function. See ctoken_decode.h
*/
enum ctoken_err_t
ctoken_decode_enter_submod_sz(struct ctoken_decode_ctx *me,
                              const char               *name)
{
    enum ctoken_err_t return_value;
    QCBORError        error;

    return_value = enter_submod_section(me);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    QCBORDecode_EnterMapFromMapSZ(&(me->qcbor_decode_context), name);
    error = QCBORDecode_GetAndResetError(&(me->qcbor_decode_context));
    if(error == QCBOR_ERR_LABEL_NOT_FOUND) {
        return_value = CTOKEN_ERR_NAMED_SUBMOD_NOT_FOUND;
        goto Done;
    } else if(error == QCBOR_ERR_UNEXPECTED_TYPE) {
        return_value = CTOKEN_ERR_SUBMOD_TYPE;
    } else if(error != QCBOR_SUCCESS) {
        return_value = map_qcbor_error(error);
        goto Done;
    }

Done:
    if(return_value != CTOKEN_ERR_SUCCESS) {
        /* try to reset decoding can continue even on error. */
        leave_submod_section(me);
    }
    return return_value;
}


/*
 * Public function. See ctoken_decode.h
 */
enum ctoken_err_t
ctoken_decode_exit_submod(struct ctoken_decode_ctx *me)
{
    enum ctoken_err_t return_value;
    QCBORError        error;

    QCBORDecode_ExitMap(&(me->qcbor_decode_context));
    error = QCBORDecode_GetAndResetError(&(me->qcbor_decode_context));
    if(error != QCBOR_SUCCESS) {
        return_value = map_qcbor_error(error);
        goto Done;
    }

    return_value = leave_submod_section(me);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

Done:
    return return_value;
}


static enum ctoken_err_t
ctoken_decode_submod_token(struct ctoken_decode_ctx  *me,
                           const QCBORItem           *item,
                           enum ctoken_type_t        *type,
                           struct q_useful_buf_c     *token)
{
    enum ctoken_err_t return_value;
    QCBORError        qcbor_error;

    qcbor_error = QCBORDecode_GetAndResetError(&(me->qcbor_decode_context));
    if(qcbor_error == QCBOR_ERR_LABEL_NOT_FOUND) {
        return_value = CTOKEN_ERR_NAMED_SUBMOD_NOT_FOUND;
        goto Done;
    } else if(qcbor_error != QCBOR_SUCCESS) {
        return_value = map_qcbor_error(qcbor_error);
        goto Done;
    }

    return_value = CTOKEN_ERR_SUCCESS;
    if(item->uDataType == QCBOR_TYPE_BYTE_STRING) {
        *token = item->val.string;
        *type = CTOKEN_TYPE_CWT;
    } else if(item->uDataType == QCBOR_TYPE_TEXT_STRING) {
        *token = item->val.string;
        *type = CTOKEN_TYPE_JSON;
    } else {
        return_value = CTOKEN_ERR_SUBMOD_TYPE;
        goto Done;
    }

Done:
    return return_value;
}


/*
 * Public function. See ctoken_decode.h
 */
enum ctoken_err_t
ctoken_decode_get_nested_token_sz(struct ctoken_decode_ctx *me,
                                  const char              *name,
                                  enum ctoken_type_t      *type,
                                  struct q_useful_buf_c   *token)
{
    QCBORItem         item;
    enum ctoken_err_t return_value;
    enum ctoken_err_t return_value2;

    return_value = enter_submod_section(me);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    QCBORDecode_GetItemInMapSZ(&(me->qcbor_decode_context), name, QCBOR_TYPE_ANY, &item);
    /* Errors checked in next call to ctoken_decode_submod_token */

    return_value = ctoken_decode_submod_token(me, &item, type, token);

    return_value2 = leave_submod_section(me);
    if(return_value == CTOKEN_ERR_SUCCESS) {
        return_value = return_value2;
    }

Done:

    return return_value;
}


/*
 * Public function. See ctoken_decode.h
 */
enum ctoken_err_t
ctoken_decode_get_nth_nested_token(struct ctoken_decode_ctx *me,
                             uint32_t                  submod_index,
                             enum ctoken_type_t         *type,
                             struct q_useful_buf_c    *token)
{
    QCBORItem         item;
    enum ctoken_err_t return_value;
    uint32_t          n;

    return_value = enter_submod_section(me);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    return_value = ctoken_decode_nth_submod(me, submod_index, &n);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        leave_submod_section(me);
        goto Done;
    }

    if(n != submod_index) {
        return_value = CTOKEN_ERR_SUBMOD_INDEX_TOO_LARGE;
        leave_submod_section(me);
        goto Done;
    }

    QCBORDecode_VGetNext(&(me->qcbor_decode_context), &item);
    /* Errors are checked in following call to ctoken_decode_submod_token */

    return_value = ctoken_decode_submod_token(me, &item, type, token);
    if(return_value != CTOKEN_ERR_SUCCESS) {
         return return_value;
     }

    return_value = leave_submod_section(me);

Done:
    return return_value;
}

