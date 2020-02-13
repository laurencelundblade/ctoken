/*
 * ctoken_eat_decode.c
 *
 * Copyright (c) 2020 Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 2/1/20.
 */

#include "ctoken_eat_decode.h"
#include "qcbor_util.h"

static QCBORError
GetBool(QCBORDecodeContext *decode, bool *b)
{
    QCBORItem   boolean_item;
    QCBORError  qcbor_error;

    qcbor_error = QCBORDecode_GetNext(decode, & boolean_item);
    if(qcbor_error) {
        return qcbor_error;
    }

    switch( boolean_item.uDataType) {
        case QCBOR_TYPE_TRUE:
            *b = true;
            break;
        case QCBOR_TYPE_FALSE:
            *b = false;
            break;
        default:
            return 99; // TODO: fix this
    }

    return QCBOR_SUCCESS;
}


/**
 * \brief Decode the next map item into a double float
 *
 * \param[in] decode            The CBOR decode context to decode from
 * \param[out] label            The integer label of the item
 * \param[out] n                The value of the number.
 * \param[out] next_nest_level  Nesting level of next item.
 *
 * \retval CTOKEN_ERR_CBOR_NOT_WELL_FORMED  CBOR is not well-formed.
 * \retval CTOKEN_ERR_CBOR_STRUCTURE        Data item is not a number, label
 *                                          is not a number.
 * \retval CTOKEN_ERR_SUCCESS               Correctly returned number.
 *
 * This decodes one item from the decode context. It must be an
 * integer, unsigned integer or half, single or double precision float.
 * It must also have an integer label.
 *
 * The nest level of the next item is returned so the caller using it
 * to process items in a map can know when the end of the map is
 * reaced.
 */
static inline enum ctoken_err_t
GetDouble(QCBORDecodeContext *decode,
          int64_t            *label,
          double             *n,
          uint8_t            *next_nest_level)
{
    QCBORItem   number_item;
    QCBORError  qcbor_error;

    qcbor_error = QCBORDecode_GetNext(decode, &number_item);
    if(qcbor_error) {
        // TODO: might need a little more error handling here.
        return CTOKEN_ERR_CBOR_NOT_WELL_FORMED;
    }

    if(number_item.uLabelType != QCBOR_TYPE_INT64) {
        return CTOKEN_ERR_CBOR_STRUCTURE;
    }

    /* A location field is a "number" in CDDL which means it can be a
     * CBOR half, float, double, signed integer or unsigned integer.
     * This invokes conversion of integer to double to always output
     * a double. */
    switch(number_item.uDataType) {
        case QCBOR_TYPE_DOUBLE:
            *n = number_item.val.dfnum;
            break;
        case QCBOR_TYPE_UINT64:
            *n = (double)number_item.val.uint64;
            break;
        case QCBOR_TYPE_INT64:
            *n = (double)number_item.val.int64;
        default:
            return CTOKEN_ERR_CBOR_STRUCTURE;
    }

    *label = number_item.label.int64;
    *next_nest_level = number_item.uNextNestLevel;

    return CTOKEN_ERR_SUCCESS;
}


/*
 * Public function. See ctoken_eat_encode.h
 */
enum ctoken_err_t
ctoken_eat_decode_boot_state(struct ctoken_decode_cxt *me,
                             bool *secure_boot_enabled,
                             enum ctoken_eat_debug_level_t *debug_state)
{
    enum ctoken_err_t       return_value;
    QCBORItem               boot_state_array_item;
    QCBORDecodeContext      decode_context;
    QCBORItem               boot_state_item;
    QCBORError              qcbor_error;
    uint_fast8_t            exit_array_level;

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

    QCBORDecode_Init(&decode_context, me->payload, 0);

    /* Find the array containing pair of items. */
    return_value = qcbor_util_decode_to_labeled_item(&decode_context,
                                                     CTOKEN_EAT_LABEL_BOOT_STATE,
                                                     &boot_state_array_item);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    if(boot_state_array_item.uDataType != QCBOR_TYPE_ARRAY) {
        return_value = CTOKEN_ERR_CBOR_TYPE;
        goto Done;
    }

    exit_array_level = boot_state_array_item.uNextNestLevel;


    qcbor_error = GetBool(&decode_context, secure_boot_enabled);
    if(qcbor_error) {
        /* no tolerance for any errors here */
        // TODO: better error here
        return_value = CTOKEN_ERR_CBOR_NOT_WELL_FORMED;
        goto Done;
    }

    qcbor_error = QCBORDecode_GetNext(&decode_context, &boot_state_item);
    if(qcbor_error) {
        /* no tolerance for any errors here */
        // TODO: better error here
        return_value = CTOKEN_ERR_CBOR_NOT_WELL_FORMED;
        goto Done;
    }

    if(boot_state_item.uNestingLevel != exit_array_level ||
       boot_state_item.uNextNestLevel == exit_array_level) {
        /* Wrong number of items in the array */
        // TODO: better error here
        return_value = CTOKEN_ERR_CBOR_NOT_WELL_FORMED;
        goto Done;
    }

    if(boot_state_item.uDataType != QCBOR_TYPE_INT64) {
        // TODO: better error here
        // TODO: tolerate a UINT64 here?
        return_value = CTOKEN_ERR_CBOR_NOT_WELL_FORMED;
        goto Done;
    }


    if(boot_state_item.val.int64 < NOT_REPORTED || boot_state_item.val.int64 > FULL_PERMANENT_DISABLE) {
        // TODO: better error here
        return_value = CTOKEN_ERR_CBOR_NOT_WELL_FORMED;
        goto Done;
    }

    *debug_state = (enum ctoken_eat_debug_level_t)boot_state_item.val.int64;

    return_value = CTOKEN_ERR_SUCCESS;

Done:
    return return_value;
}


/*
 * Public function. See ctoken_eat_encode.h
 */
enum ctoken_err_t
ctoken_eat_decode_location(struct ctoken_decode_cxt     *me,
                           struct ctoken_eat_location_t *location)
{
    enum ctoken_err_t   return_value;
    QCBORItem           location_map_item;
    QCBORDecodeContext  decode_context;
    double              d;
    int64_t             label;
    uint8_t             next_nest_level;

    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return_value = me->last_error;
        goto Done;
    }

    QCBORDecode_Init(&decode_context, me->payload, 0);

    /* Find the map containing location claim */
    return_value = qcbor_util_decode_to_labeled_item(&decode_context,
                                                     CTOKEN_EAT_LABEL_LOCATION,
                                                     &location_map_item);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    /* Has to be of type map */
    if(location_map_item.uDataType != QCBOR_TYPE_MAP) {
        return_value = CTOKEN_ERR_CBOR_STRUCTURE;
        goto Done;
    }

    /* Loop fetching all the items in the map */
    do {
        return_value = GetDouble(&decode_context, &label, &d, &next_nest_level);
        if(return_value) {
            goto Done;
        }

        if(label < CTOKEN_EAT_LABEL_LATITUDE || label > NUM_LOCATION_ITEMS) {
            return CTOKEN_ERR_CBOR_STRUCTURE;
        }

        location->items[label-1] = d;
    } while(next_nest_level == location_map_item.uNextNestLevel);

Done:
    me->last_error = return_value;
    return return_value;
}

