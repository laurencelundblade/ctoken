/*
 * ctoken_decode.c (formerly attest_token_decode.c)
 *
 * Copyright (c) 2019-2021, Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "ctoken/ctoken_decode.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/q_useful_buf.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "ctoken_common.h"


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


    /* It is simpler to always initialize, even if t_cose is not needed */
    t_cose_sign1_verify_init(&(me->verify_context), t_cose_options);
}


/**
 * \brief Get most recent QCBOR error and map QCBOR into ctoken error
 *
 * \param[in] decode_context  Decode context from which to get recent error.
 *
 * \return The ctoken error.
 */
enum ctoken_err_t ctoken_get_and_reset_cbor_error(QCBORDecodeContext *decode_context)
{
    QCBORError cbor_error;

    cbor_error = QCBORDecode_GetAndResetError(decode_context);

    if(QCBORDecode_IsNotWellFormedError(cbor_error)) {
        return CTOKEN_ERR_CBOR_NOT_WELL_FORMED;
    } else if(cbor_error == QCBOR_ERR_NO_MORE_ITEMS) {
        return CTOKEN_ERR_NO_MORE_CLAIMS;
    } else if(cbor_error == QCBOR_ERR_LABEL_NOT_FOUND) {
        return CTOKEN_ERR_CLAIM_NOT_PRESENT;
    } else if(cbor_error == QCBOR_ERR_UNEXPECTED_TYPE) {
        return CTOKEN_ERR_CBOR_TYPE;
    } else if(cbor_error == QCBOR_ERR_DUPLICATE_LABEL) {
        return CTOKEN_ERR_DUPLICATE_LABEL;
    } else if(cbor_error == QCBOR_ERR_ARRAY_DECODE_NESTING_TOO_DEEP) {
        return CTOKEN_ERR_NESTING_TOO_DEEP;
    } else if(cbor_error) {
        return CTOKEN_ERR_CBOR_DECODE;
    } else {
        return CTOKEN_ERR_SUCCESS;
    }
}



/*
 * Public function. See ctoken_decode.h
 */
enum ctoken_err_t
ctoken_decode_get_kid(struct ctoken_decode_ctx *me,
                      struct q_useful_buf_c    token,
                      struct q_useful_buf_c   *kid)
{
    struct q_useful_buf_c     payload;
    struct t_cose_parameters  parameters;
    enum t_cose_err_t         t_cose_error;

    // TODO: how to handle combined options here?
    t_cose_sign1_verify_init(&(me->verify_context), T_COSE_OPT_DECODE_ONLY);
    t_cose_error = t_cose_sign1_verify(&(me->verify_context), token, &payload, &parameters);

    if(t_cose_error != T_COSE_SUCCESS) {
        return map_t_cose_errors(t_cose_error);
    }

    *kid = parameters.kid;

    return CTOKEN_ERR_SUCCESS;
}


static uint64_t
get_nth_tag(struct ctoken_decode_ctx *me, int protection_type, QCBORItem *item, uint32_t n)
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
void
ctoken_decode_validate_token(struct ctoken_decode_ctx *me,
                             struct q_useful_buf_c     token)
{
    enum t_cose_err_t        t_cose_error;
    enum ctoken_err_t        return_value;
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
     * This also initializes the decoder for UCCS decoding (the same
     * decoder is re initialized for COSE decoding. */
    QCBORDecode_Init(&(me->qcbor_decode_context), token, 0);
    QCBORDecode_PeekNext(&(me->qcbor_decode_context), &item);

    tag_number = QCBORDecode_GetNthTag(&(me->qcbor_decode_context), &item, 0);


    if(tag_number == CBOR_TAG_COSE_SIGN1 ||
       tag_number == CBOR_TAG_CWT ||
       (tag_number == CBOR_TAG_INVALID64 && protection_type == CTOKEN_PROTECTION_COSE_SIGN1)) {
        /* It is a case where COSE protection is expected. Call COSE
          and let it work. */

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

    /* Copy the tags not processed so they are available to caller and do a
     * check on innermost tag */
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

    /* Now processing for either COSE-secured or UCCS. Enter the map
       that holds all the claims */
    QCBORDecode_EnterMap(&(me->qcbor_decode_context), NULL);
    return_value = ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));

    me->submod_nest_level = 0;

Done:
    me->last_error = return_value;
    if(return_value != CTOKEN_ERR_SUCCESS) {
        me->actual_protection_type = CTOKEN_PROTECTION_UNKNOWN;
    }
}


/*
 * Public function. See ctoken_decode.h
 */
void
ctoken_decode_bstr(struct ctoken_decode_ctx *me,
                   int64_t                  label,
                   struct q_useful_buf_c   *claim)
{
    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        *claim = NULL_Q_USEFUL_BUF_C;
        return;
    }

    QCBORDecode_GetByteStringInMapN(&(me->qcbor_decode_context), label, claim);

    me->last_error = ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));
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
 * Public function. See ctoken_decode.h
 */
void
ctoken_decode_tstr(struct ctoken_decode_ctx *me,
                   int64_t                   label,
                   struct q_useful_buf_c    *claim)
{
    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        *claim = NULL_Q_USEFUL_BUF_C;
        return;
    }

    QCBORDecode_GetTextStringInMapN(&(me->qcbor_decode_context), label, claim);

    me->last_error = ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));
}


/*
 * Public function. See ctoken_decode.h
 */
void
ctoken_decode_int(struct ctoken_decode_ctx *me,
                  int64_t                   label,
                  int64_t                  *integer)
{
    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return;
    }

    QCBORDecode_GetInt64InMapN(&(me->qcbor_decode_context), label, integer);

    me->last_error = ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));
}


/*
 * Public function. See ctoken_eat_encode.h
 */
void
ctoken_decode_int_constrained(struct ctoken_decode_ctx *me,
                              int64_t                   label,
                              int64_t                   min,
                              int64_t                   max,
                              int64_t                  *claim)
{
    ctoken_decode_int(me, label, claim);
    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return;
    }

    if(*claim < min || *claim > max) {
        me->last_error = CTOKEN_ERR_CLAIM_RANGE;
    }
}


/*
 * Public function. See ctoken_decode.h
 */
void
ctoken_decode_uint(struct ctoken_decode_ctx *me,
                   int64_t                   label,
                   uint64_t                 *integer)
{
    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return;
    }

    QCBORDecode_GetUInt64InMapN(&(me->qcbor_decode_context), label, integer);

    me->last_error = ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));
}


/*
 * Public function. See ctoken_decode.h
 */
void
ctoken_decode_double(struct ctoken_decode_ctx *me,
                     int64_t                  label,
                     double                  *claim)
{
    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return;
    }

    QCBORDecode_GetDoubleInMapN(&(me->qcbor_decode_context), label, claim);

    me->last_error = ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));
}

/*
 * Public function. See ctoken_decode.h
 */
void
ctoken_decode_bool(struct ctoken_decode_ctx *me,
                   int64_t                   label,
                   bool                     *b)
{
    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return;
    }

    QCBORDecode_GetBoolInMapN(&(me->qcbor_decode_context), label, b);

    me->last_error = ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));
}


/*
 * Public function. See ctoken_decode.h
 */
void
ctoken_decode_enter_map(struct ctoken_decode_ctx *me,
                       int64_t                   label,
                        QCBORDecodeContext     **decoder)
{
    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return;
    }

    QCBORDecode_EnterMapFromMapN(&(me->qcbor_decode_context), label);
    me->last_error = ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));
    if(me->last_error == CTOKEN_ERR_SUCCESS) {
        *decoder = &(me->qcbor_decode_context);
    } else {
        *decoder = NULL;
    }}


/*
 * Public function. See ctoken_decode.h
 */
void
ctoken_decode_exit_map(struct ctoken_decode_ctx *me)
{
    QCBORDecode_ExitMap(&(me->qcbor_decode_context));
    me->last_error = ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));
}


/*
 * Public function. See ctoken_decode.h
 */
void
ctoken_decode_enter_array(struct ctoken_decode_ctx *me,
                          int64_t                   label,
                          QCBORDecodeContext     **decoder)
{
    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return;
    }

    QCBORDecode_EnterArrayFromMapN(&(me->qcbor_decode_context), label);
    me->last_error = ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));
    if(me->last_error == CTOKEN_ERR_SUCCESS) {
        *decoder = &(me->qcbor_decode_context);
    } else {
        *decoder = NULL;
    }
}


/*
 * Public function. See ctoken_decode.h
 */
void
ctoken_decode_exit_array(struct ctoken_decode_ctx *me)
{
    QCBORDecode_ExitArray(&(me->qcbor_decode_context));
    me->last_error = ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));
}


/*
 * Public function. See ctoken_eat_encode.h
 */
void
ctoken_decode_location(struct ctoken_decode_ctx   *me,
                       struct ctoken_location_t   *location)
{
    enum ctoken_err_t  return_value = CTOKEN_ERR_SUCCESS;
    double             d;
    int                label;
    QCBORDecodeContext *decoder;

    location->item_flags = 0;

    ctoken_decode_enter_map(me, CTOKEN_EAT_LABEL_LOCATION, &decoder);
    return_value = ctoken_decode_get_error(me);

#ifndef CTOKEN_DISABLE_TEMP_LABELS
    if(return_value == CTOKEN_ERR_CLAIM_NOT_PRESENT) {
        (void)ctoken_decode_get_and_reset_error(me);
        ctoken_decode_enter_map(me, CTOKEN_TEMP_EAT_LABEL_LOCATION, &decoder);
    }
#endif

    if(ctoken_decode_get_error(me) != CTOKEN_ERR_SUCCESS) {
        return;
    }

    for(label = CTOKEN_EAT_LABEL_LATITUDE; label <= NUM_FLOAT_LOCATION_ITEMS; label++) {
        QCBORDecode_GetDoubleInMapN(decoder, label, &d);
        me->last_error = ctoken_get_and_reset_cbor_error(decoder);
        if(me->last_error == CTOKEN_ERR_CLAIM_NOT_PRESENT) {
            continue;
        }
        if(me->last_error != CTOKEN_ERR_SUCCESS) {
            return;
        }

        location->items[label-1] = d;
        ctoken_location_mark_item_present(location, label);
    }

    if(!ctoken_location_is_item_present(location, CTOKEN_EAT_LABEL_LATITUDE) ||
        !ctoken_location_is_item_present(location, CTOKEN_EAT_LABEL_LONGITUDE)) {
        /* Per EAT and W3C specs, the latitude and longitude must be present */
        me->last_error = CTOKEN_ERR_CLAIM_FORMAT;
        return;
    }

    QCBORDecode_GetUInt64InMapN(decoder, CTOKEN_EAT_LABEL_TIME_STAMP, &(location->time_stamp));
    me->last_error = ctoken_get_and_reset_cbor_error(decoder);
    if(me->last_error == CTOKEN_ERR_SUCCESS) {
        ctoken_location_mark_item_present(location, CTOKEN_EAT_LABEL_TIME_STAMP);
    } else if(me->last_error != CTOKEN_ERR_CLAIM_NOT_PRESENT) {
        return;
    }

    QCBORDecode_GetUInt64InMapN(decoder, CTOKEN_EAT_LABEL_AGE, &(location->age));
    me->last_error = ctoken_get_and_reset_cbor_error(decoder);
    if(me->last_error == CTOKEN_ERR_SUCCESS) {
        ctoken_location_mark_item_present(location, CTOKEN_EAT_LABEL_AGE);
    } else if(me->last_error != CTOKEN_ERR_CLAIM_NOT_PRESENT) {
        return;
    }

    ctoken_decode_exit_map(me);
    me->last_error = ctoken_decode_get_and_reset_error(me);
}


/*
 * Public function. See ctoken_eat_encode.h
 */
void
ctoken_decode_hw_version(struct ctoken_decode_ctx  *me,
                         enum ctoken_hw_type_t      hw_type,
                         int32_t                   *version_scheme,
                         struct q_useful_buf_c     *version)
{
    int64_t             version_scheme_64;
    QCBORDecodeContext *decode_context = &(me->qcbor_decode_context);
    const int64_t       versions_label = CTOKEN_EAT_LABEL_CHIP_VERSION + (int64_t)hw_type;

    if(me->last_error) {
        return;
    }

    QCBORDecode_EnterArrayFromMapN(decode_context, versions_label);
    QCBORDecode_GetInt64(decode_context, &version_scheme_64);
    QCBORDecode_GetTextString(decode_context, version);
    QCBORDecode_ExitArray(decode_context);

    me->last_error = ctoken_get_and_reset_cbor_error(decode_context);

    if(me->last_error) {
        return;
    }

    /* The valid range comes from the CoSWID specification */
    if(version_scheme_64 > 65535  || version_scheme_64 < -256) {
        me->last_error = CTOKEN_ERR_CLAIM_RANGE;
        return;
    }

    /* Check above makes this cast OK */
    *version_scheme = (int32_t)version_scheme_64;
}


static bool is_submod_section(const QCBORItem *claim)
{
    if(claim->uLabelType != QCBOR_TYPE_INT64) {
        return false;
    }
    if(claim->label.int64 == CTOKEN_EAT_LABEL_SUBMODS) {
        return true;
    }
#ifndef CTOKEN_DISABLE_TEMP_LABELS
    if(claim->label.int64 == CTOKEN_TEMP_EAT_LABEL_SUBMODS) {
        return true;
    }
#endif
    return false;
}

/*
 * Public function. See ctoken_eat_encode.h
 */
void
ctoken_decode_next_claim(struct ctoken_decode_ctx   *me,
                         QCBORItem                  *claim)
{
    enum ctoken_err_t return_value;

    if(me->last_error) {
        return;
    }

    /* Loop is only to skip the submods section and executes only
     * once in most cases. It executes twice if there is a submods section.
     * This is necessary because no ordering of the map is expected.
     */
    do {
        QCBORDecode_VGetNextConsume(&(me->qcbor_decode_context), claim);

        return_value = ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));
        if(return_value != CTOKEN_ERR_SUCCESS) {
            goto Done;
        }

    } while(is_submod_section(claim));

    claim->uNestingLevel  = 0;
    claim->uNextNestLevel = 0;

Done:
    me->last_error = return_value;
}


/**
 * @brief Enter the map that is the submod section.
 *
 * @param[in] me            The token decode context
 *
 * @retval CTOKEN_SUCCESS        There is a submods section and it was entered.
 *
 * @retval CTOKEN_ERR_CBOR_TYPE  There is a item with the correct label, but
 *                               it is not of type map.
 *
 * @retval CTOKEN_ERR_SUBMOD_NESTING_TOO_DEEP  Input is nested to deep to
 *                                             handle.
 *
 * @retval CTOKEN_ERR_CLAIM_NOT_PRESENT        There is no submods section.
 *
 * Other CTOKEN errors are also possible and usualy indicate the input
 * is malformed, invalid or such.
 *
 * CToken decoding hides the existance of the submod section from the
 * caller. The caller of the public API doesn't need to manage
 * entering and exiting the submod section map.
 *
 * When the caller enters a submod that is not a nested token, the
 * submod section map is entered and the map holding the submod claims
 * is also entered. The QCBOR bounded decoding stays at that level
 * until either the submod is exited or a deeper level submod is
 * entered.
 *
 * When the caller fetches a nested token, the submod section map is
 * entered, the nested token fetched and then the submod section map
 * is exited.
 *
 * The nest-level tracker counts submod levels not map levels, so it
 * doesn't count the submod section map.
 */
static enum ctoken_err_t
enter_submod_section(struct ctoken_decode_ctx *me)
{
    enum ctoken_err_t return_value;

    QCBORDecode_EnterMapFromMapN(&(me->qcbor_decode_context),
                                 CTOKEN_EAT_LABEL_SUBMODS);

    return_value = ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));

#ifndef CTOKEN_DISABLE_TEMP_LABELS
    if(return_value == CTOKEN_ERR_CLAIM_NOT_PRESENT) {
        QCBORDecode_EnterMapFromMapN(&(me->qcbor_decode_context),
                                     CTOKEN_TEMP_EAT_LABEL_SUBMODS);
        return_value = ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));
    }
#endif

Done:
    return return_value;
}


static inline enum ctoken_err_t
leave_submod_section(struct ctoken_decode_ctx *me)
{
    QCBORDecode_ExitMap(&(me->qcbor_decode_context));

    return ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));
}


/**
 * @brief Consume submodules to nth to get to nth or to count submodules
 *
 * @param[in] me            The token decode context
 * @param[in] submod_index  Number to consume or UINT32_MAX to count
 * @param[in] num_submods   Number of submods consumed
 *
 * @return  CTOKEN_ERR_SUCCESS if got to the nth submod or hit
 *          the end of submods section. Other errors indicate
 *          malformed or invalid submodules.
 *
 * Exit conditions are: found nth, got to the end, errored out.
 *
 * Other errors indicate the CBOR is malformed or invalid.
 *
 * If num_submods is equal to submod_index on return, then the
 * traversal cursor is at the requested index and the call is a
 * success.
 *
 * If num_submods is less than submod_index, then there are less than
 * submod_index in the submod section and the call is not a success
 * unless the objective was to count the number of submods.
 *
 * This does not check for duplicate labels. It should to validate the
 * CBOR thoroughly. Improvement: check for duplicate labels.
 */
static enum ctoken_err_t
ctoken_decode_to_nth_submod(struct ctoken_decode_ctx *me,
                            uint32_t                  submod_index,
                            uint32_t                 *num_submods)
{
    /* Traverse submods map until nth one is found and stop */
    QCBORItem           map_item;
    uint32_t            submod_count;
    enum ctoken_err_t   return_value;
    QCBORDecodeContext *decode_context = &(me->qcbor_decode_context);

    /* Must have entered into submods map before calling this */
    submod_count = 0;
    return_value = CTOKEN_ERR_SUCCESS;

    while(submod_index > 0) {
        QCBORDecode_VGetNextConsume(decode_context, &map_item);
        return_value = ctoken_get_and_reset_cbor_error(decode_context);
        if(return_value != CTOKEN_ERR_SUCCESS) {
            break;
        }

        submod_count++;
        submod_index--;
    }

    if(return_value == CTOKEN_ERR_NO_MORE_CLAIMS) {
        return_value = CTOKEN_ERR_SUCCESS;
    }

Done:
    *num_submods = submod_count;
    return return_value;
}


/*
 * Public function. See ctoken_decode.h
 */
void
ctoken_decode_get_num_submods(struct ctoken_decode_ctx *me,
                              uint32_t                 *num_submods)
{
    enum ctoken_err_t return_value;
    enum ctoken_err_t return_value2;

    if(me->last_error) {
        return;
    }

    return_value = enter_submod_section(me);
    if(return_value == CTOKEN_ERR_CLAIM_NOT_PRESENT) {
        *num_submods = 0;
        return_value = CTOKEN_ERR_SUCCESS;
        goto Done;
    }
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    return_value = ctoken_decode_to_nth_submod(me, UINT32_MAX, num_submods);

    return_value2 = leave_submod_section(me);
    if(return_value == CTOKEN_ERR_SUCCESS) {
        return_value = return_value2;
    }

Done:
    me->last_error = return_value;
}


/*
 * Public function. See ctoken_decode.h
 */
void
ctoken_decode_enter_nth_submod(struct ctoken_decode_ctx *me,
                               uint32_t                  submod_index,
                               struct q_useful_buf_c    *name)
{
    QCBORItem         item;
    enum ctoken_err_t return_value;
    uint32_t          num_submods;
    QCBORError        cbor_error;

    if(me->last_error) {
        return;
    }

    return_value = enter_submod_section(me);
    if(return_value == CTOKEN_ERR_CLAIM_NOT_PRESENT) {
        /* There is no submods section */
        return_value = CTOKEN_ERR_SUBMOD_NOT_FOUND;
        goto Done2;
    }
    if(return_value != CTOKEN_ERR_SUCCESS) {
        /* The submodules section is malformed or invalid */
        goto Done2;
    }

    return_value = ctoken_decode_to_nth_submod(me, submod_index, &num_submods);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    if(num_submods != submod_index) {
        return_value = CTOKEN_ERR_SUBMOD_NOT_FOUND;
        goto Done;
    }

    /* Peek uses a lot of stack space, but is necessary
     * because attempting to get the next item will move the
     * cursor forward. Maybe this could be rewritten using rewind
     * to avoid the stack use.
     */
    cbor_error = QCBORDecode_PeekNext(&(me->qcbor_decode_context), &item);
    if(cbor_error == QCBOR_ERR_NO_MORE_ITEMS) {
        return_value = CTOKEN_ERR_SUBMOD_NOT_FOUND;
        goto Done;
    }
    if(cbor_error != QCBOR_SUCCESS) {
        /* Because QCBORDecode_PeekNext() does not set the last
         * error, get_and_reset_error() can't be used here. For
         * now error mapping is more crude than it should be.
         */
         return_value = CTOKEN_ERR_CBOR_DECODE;
        goto Done;
    }

    if(item.uLabelType != QCBOR_TYPE_TEXT_STRING) {
        return_value = CTOKEN_ERR_SUBMOD_NAME_NOT_A_TEXT_STRING;
        goto Done;
    }

    if(item.uDataType == QCBOR_TYPE_BYTE_STRING ||
       item.uDataType == QCBOR_TYPE_TEXT_STRING) {
        /* The data item is a string so it is presumably a nested
         * token, not a map type of submod that is handled here
         */
        return_value = CTOKEN_ERR_SUBMOD_IS_A_TOKEN;
        goto Done;
    }

    if(item.uDataType != QCBOR_TYPE_MAP) {
        /* It's not a map type (and not a string) so it is an
         * error of the wrong CBOR type
         */
        return_value = CTOKEN_ERR_SUBMOD_TYPE;
        goto Done;
    }

    /* At this point the data item is known to be a map and
     * that the rest will succeed. */

    QCBORDecode_EnterMap(&(me->qcbor_decode_context), &item);
    return_value = ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));
    if(return_value == CTOKEN_ERR_CLAIM_NOT_PRESENT) {
        /* This should never happen because the QCBORDecode_PeekNext()
         * succeeded.
         */
        return_value = CTOKEN_ERR_SUBMOD_NOT_FOUND;
        goto Done;
    }

    me->submod_nest_level++;

    if(name != NULL) {
        /* Label type was checked above */
        *name = item.label.string;
    }

Done:
    if(return_value != CTOKEN_ERR_SUCCESS) {
        /* try to reset so decoding can continue even on error. */
        leave_submod_section(me);
    }

Done2:
    me->last_error = return_value;
}


/*
 * Public function. See ctoken_decode.h
 */
void
ctoken_decode_enter_named_submod(struct ctoken_decode_ctx *me,
                                 const char               *name)
{
    enum ctoken_err_t     return_value;
    QCBORItem             item;

    if(me->last_error) {
        return;
    }

    return_value = enter_submod_section(me);
    if(return_value == CTOKEN_ERR_CLAIM_NOT_PRESENT) {
        /* There is no submods section */
        return_value = CTOKEN_ERR_SUBMOD_NOT_FOUND;
        goto Done2;
    }
    if(return_value != CTOKEN_ERR_SUCCESS) {
        /* The submodules section is malformed or invalid */
        goto Done2;
    }


    /* Try to enter has a map */
    QCBORDecode_EnterMapFromMapSZ(&(me->qcbor_decode_context), name);
    return_value = ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));
    if(return_value == CTOKEN_ERR_CLAIM_NOT_PRESENT) {
        return_value = CTOKEN_ERR_SUBMOD_NOT_FOUND;
        goto Done;
    }
    if(return_value != CTOKEN_ERR_SUCCESS && return_value != CTOKEN_ERR_CBOR_TYPE) {
        /* Clearly an error with malformed or invalid input */
        goto Done;
    }

    if(return_value == CTOKEN_ERR_CBOR_TYPE) {
        /* It wasn't a map. If it is a bstr or tstr, then it's a nested token */
        QCBORDecode_GetItemInMapSZ(&(me->qcbor_decode_context), name, QCBOR_TYPE_ANY, &item);
        return_value = ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));
        if(return_value != CTOKEN_ERR_SUCCESS) {
            /* An error with malformed or invalid input. Error probably
             * always occurs in attempt to enter as a map above rather
             * than here. */
            goto Done;
        }

        if(item.uDataType == QCBOR_TYPE_BYTE_STRING ||
           item.uDataType == QCBOR_TYPE_TEXT_STRING) {
            /* Tell the caller they called the wrong function to get this */
            return_value = CTOKEN_ERR_SUBMOD_IS_A_TOKEN;
        } else {
            return_value = CTOKEN_ERR_SUBMOD_TYPE;
        }
    }

    /* Successfully entered the submod */
    me->submod_nest_level++;

Done:
    if(return_value != CTOKEN_ERR_SUCCESS) {
        /* Reset so decoding can continue even on error. */
        leave_submod_section(me);
    }
Done2:
    me->last_error = return_value;
}


/*
 * Public function. See ctoken_decode.h
 */
void
ctoken_decode_exit_submod(struct ctoken_decode_ctx *me)
{
    enum ctoken_err_t return_value;

    if(me->last_error) {
        return;
    }

    if(me->submod_nest_level == 0) {
        return_value = CTOKEN_ERR_NO_SUBMOD_OPEN;
        goto Done;
    }

    QCBORDecode_ExitMap(&(me->qcbor_decode_context));
    return_value = ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    me->submod_nest_level--;

    return_value = leave_submod_section(me);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

Done:
    me->last_error = return_value;
}


static enum ctoken_err_t
ctoken_decode_nested_token(struct ctoken_decode_ctx  *me,
                           const QCBORItem           *item,
                           enum ctoken_type_t        *type,
                           struct q_useful_buf_c     *token)
{
    enum ctoken_err_t return_value;

    *token = NULL_Q_USEFUL_BUF_C;

    return_value = ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));

    if(return_value == CTOKEN_ERR_CLAIM_NOT_PRESENT ||
       return_value == CTOKEN_ERR_NO_MORE_CLAIMS) {
        return_value = CTOKEN_ERR_SUBMOD_NOT_FOUND;
        goto Done;
    }
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    if(item->uDataType == QCBOR_TYPE_NONE) {
        return_value = CTOKEN_ERR_SUBMOD_NOT_FOUND;
        goto Done;
    }

    if(item->uLabelType != QCBOR_TYPE_TEXT_STRING) {
        return_value = CTOKEN_ERR_SUBMOD_NAME_NOT_A_TEXT_STRING;
        goto Done;
    }

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
void
ctoken_decode_get_named_nested_token(struct ctoken_decode_ctx *me,
                                     struct q_useful_buf_c     submod_name,
                                     enum ctoken_type_t       *type,
                                     struct q_useful_buf_c    *token)
{
    enum ctoken_err_t return_value;
    enum ctoken_err_t return_value2;
    QCBORItem         search[2];

    if(me->last_error) {
        return;
    }

    return_value = enter_submod_section(me);
    if(return_value == CTOKEN_ERR_CLAIM_NOT_PRESENT) {
        return_value = CTOKEN_ERR_SUBMOD_NOT_FOUND;
        goto Done;
    }
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }


    search[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
    search[0].label.string = submod_name;
    search[0].uDataType    = QCBOR_TYPE_ANY;
    search[1].uLabelType   = QCBOR_TYPE_NONE; /* Indicates end of array */

    QCBORDecode_GetItemsInMap(&(me->qcbor_decode_context), search);
    /*  QCBOR error checked in ctoken_decode_submod_token() */

    return_value = ctoken_decode_nested_token(me, &search[0], type, token);

    return_value2 = leave_submod_section(me);
    if(return_value == CTOKEN_ERR_SUCCESS) {
        return_value = return_value2;
    }

Done:
    me->last_error = return_value;
}


/*
 * Public function. See ctoken_decode.h
 */
void
ctoken_decode_get_nth_nested_token(struct ctoken_decode_ctx *me,
                                   uint32_t                  submod_index,
                                   enum ctoken_type_t       *type,
                                   struct q_useful_buf_c    *name,
                                   struct q_useful_buf_c    *token)
{
    QCBORItem         item;
    enum ctoken_err_t return_value;
    enum ctoken_err_t return_value2;
    uint32_t          returned_index;

    if(me->last_error) {
        return;
    }

    return_value = enter_submod_section(me);
    if(return_value == CTOKEN_ERR_CLAIM_NOT_PRESENT) {
        return_value = CTOKEN_ERR_SUBMOD_NOT_FOUND;
        goto Done2;
    }
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done2;
    }


    return_value = ctoken_decode_to_nth_submod(me, submod_index, &returned_index);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    if(returned_index != submod_index) {
        return_value = CTOKEN_ERR_SUBMOD_NOT_FOUND;
        goto Done;
    }

    QCBORDecode_VGetNext(&(me->qcbor_decode_context), &item);
    /* Errors are checked in ctoken_decode_submod_token() */

    return_value = ctoken_decode_nested_token(me, &item, type, token);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    /* label type was checked in ctoken_decode_nested_token(). */
    *name = item.label.string;

Done:
    return_value2 = leave_submod_section(me);
    if(return_value == CTOKEN_ERR_SUCCESS) {
        return_value = return_value2;
    }

Done2:
    me->last_error = return_value;
}

