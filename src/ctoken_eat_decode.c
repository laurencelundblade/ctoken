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
ctoken_decode_eat_get_num_submods(struct ctoken_decode_ctx *me,
                                  uint32_t                  *num_submods)
{
    enum ctoken_err_t return_value;

    descend_submod(me);

    return_value = ctoken_decode_eat_nth_submod(me, UINT32_MAX, num_submods);

    ascend_submod(me);

    return return_value;
}




enum ctoken_err_t
ctoken_eat_decode_enter_nth_submod(struct ctoken_decode_ctx *me,
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
ctoken_eat_decode_enter_submod_sz(struct ctoken_decode_ctx *me,
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
ctoken_eat_decode_exit_submod(struct ctoken_decode_ctx *me)
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
ctoken_eat_decode_get_submod_n(struct ctoken_decode_ctx *me,
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
