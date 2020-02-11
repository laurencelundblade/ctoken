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

QCBORError GetBool(QCBORDecodeContext *decode, bool *b)
{
    QCBORItem Boolean;
    QCBORError              qcbor_error;

    qcbor_error = QCBORDecode_GetNext(decode, &Boolean);
    if(qcbor_error) {
        return qcbor_error;
    }

    switch(Boolean.uDataType) {
        case QCBOR_TYPE_TRUE:
            *b = true;
            break;
        case QCBOR_TYPE_FALSE:
            *b = false;
            break;
        default:
            return 99;
    }

    return QCBOR_SUCCESS;
}


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

     This errors out of the claim doesn't exist. It could
     default to some values.

     TODO: test this
     */

    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return_value = me->last_error;
        goto Done;
    }

    QCBORDecode_Init(&decode_context, me->payload, 0);

    /* Find the map containing all the SW Components */
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
