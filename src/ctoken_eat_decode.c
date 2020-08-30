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
#include "qcbor/qcbor_spiffy_decode.h"


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
ctoken_eat_decode_location(struct ctoken_decode_ctx     *me,
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

