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
ctoken_encode_eat_boot_state(struct ctoken_encode_ctx     *me,
                             bool                          secure_boot_enabled,
                             enum ctoken_eat_debug_level_t debug_state)
{
    QCBOREncodeContext *encode_context = ctoken_encode_borrow_cbor_cntxt(me);

    QCBOREncode_OpenArrayInMapN(encode_context, CTOKEN_EAT_LABEL_BOOT_STATE);
    QCBOREncode_AddBool(encode_context, secure_boot_enabled);
    QCBOREncode_AddUInt64(encode_context, debug_state);
    QCBOREncode_CloseArray(encode_context);
}
