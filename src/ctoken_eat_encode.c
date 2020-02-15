/*
 * ctoken_eat_encode.c
 *
 * Copyright (c) 2020 Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 1/31/20.
 */


#include "ctoken_eat_encode.h"


/*
 * Public function. See ctoken_eat_encode.h
 */
void
ctoken_eat_encode_boot_state(struct ctoken_encode_ctx     *me,
                             bool                          secure_boot_enabled,
                             enum ctoken_eat_debug_level_t debug_state)
{
    QCBOREncodeContext *encode_context = ctoken_encode_borrow_cbor_cntxt(me);

    QCBOREncode_OpenArrayInMapN(encode_context, CTOKEN_EAT_LABEL_BOOT_STATE);
    QCBOREncode_AddBool(encode_context, secure_boot_enabled);
    QCBOREncode_AddUInt64(encode_context, debug_state);
    QCBOREncode_CloseArray(encode_context);
}


/*
 * Public function. See ctoken_eat_encode.h
 */
void
ctoken_eat_encode_location(struct ctoken_encode_ctx *me,
                           const struct ctoken_eat_location_t *location)
{
    int                 item_iterator;
    QCBOREncodeContext *encode_cxt = ctoken_encode_borrow_cbor_cntxt(me);

    QCBOREncode_OpenMapInMapN(encode_cxt, CTOKEN_EAT_LABEL_LOCATION);

    for(item_iterator = CTOKEN_EAT_LABEL_LATITUDE-1; item_iterator < NUM_LOCATION_ITEMS-1; item_iterator++) {
        if(location->item_flags & (0x01u << item_iterator)) {
            QCBOREncode_AddDoubleToMapN(encode_cxt,
                                        item_iterator + 1,
                                        location->items[item_iterator]);
        }
    }

    QCBOREncode_CloseMap(encode_cxt);
}


