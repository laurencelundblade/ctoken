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




/*
 * Public function. See ctoken_eat_encode.h
 */
void ctoken_eat_encode_start_submod_section(struct ctoken_encode_ctx *me)
{
    const enum ctoken_encode_nest_state * const end = &(me->submod_level_state[CTOKEN_MAX_SUBMOD_NESTING-1]);


    if(me->current_level == NULL) {
        me->current_level = &(me->submod_level_state[0]);
    } else if(me->current_level >= end) {
        me->error = CTOKEN_ERR_SUBMOD_NESTING_TOO_DEEP;
        return;

        // TODO: allow this to be called only once per level
    } else {
        if(*me->current_level != SUBMODS_IN_SECTION_AND_SUBMOD) {
            me->error = CTOKEN_CANT_START_SUBMOD_SECTION;
            return;
        }
        me->current_level++;

        // Clear all levels below to "SUBMODS_NO"
        for(enum ctoken_encode_nest_state *i = me->current_level + 1; i < end; i++) {
            *i = SUBMODS_NO;
        }
    }

    *me->current_level = SUBMODS_IN_SECTION;

    QCBOREncode_OpenMapInMapN(&(me->cbor_encode_context), CTOKEN_EAT_LABEL_SUBMODS);
}


/*
 * Public function. See ctoken_eat_encode.h
 */
void ctoken_eat_encode_end_submod_section(struct ctoken_encode_ctx *me)
{
    if(me->current_level == NULL) {
        me->error = CTOKEN_ERR_NO_SUBMOD_SECTION_STARTED;
        return;
    } else {
        *me->current_level = SUBMODS_SECTION_DONE;

        if (me->current_level ==  &(me->submod_level_state[0])) {
            me->current_level = NULL;
        } else {
            me->current_level--;
        }
    }

    QCBOREncode_CloseMap(&(me->cbor_encode_context));
}


/*
 * Public function. See ctoken_eat_encode.h
 */
void ctoken_eat_encode_open_submod(struct ctoken_encode_ctx *me,
                                   const char               *submod_name)
{
    if(me->error != CTOKEN_ERR_SUCCESS) {
        return; /* In the error state so do nothing */
    }

    if(me->current_level == NULL) {
        me->error = CTOKEN_ERR_NO_SUBMOD_SECTION_STARTED;
        return;
    }

    if(*me->current_level != SUBMODS_IN_SECTION) {
        me->error = CTOKEN_ERR_CANT_MAKE_SUBMOD_IN_SUBMOD;
        return;
    }

    *me->current_level = SUBMODS_IN_SECTION_AND_SUBMOD;

    QCBOREncode_OpenMapInMap(&(me->cbor_encode_context), submod_name);
}


/*
 * Public function. See ctoken_eat_encode.h
 */
void ctoken_eat_encode_close_submod(struct ctoken_encode_ctx *me)
{
    if(me->error != CTOKEN_ERR_SUCCESS) {
        return; /* In the error state so do nothing */
    }

    if(me->current_level == NULL) {
        me->error = CTOKEN_ERR_NO_SUBMOD_OPEN;
        return;
    }

    if(*me->current_level != SUBMODS_IN_SECTION_AND_SUBMOD) {
        me->error = CTOKEN_ERR_NO_SUBMOD_OPEN;
        return;
    }

    QCBOREncode_CloseMap(&(me->cbor_encode_context));

    *me->current_level = SUBMODS_IN_SECTION;
}


/*
 * Public function. See ctoken_eat_encode.h
 */
void ctoken_eat_encode_add_token(struct ctoken_encode_ctx *me,
                                 enum ctoken_type          type,
                                 const  char              *submod_name,
                                 struct q_useful_buf_c     token)
{
    if(me->error != CTOKEN_ERR_SUCCESS) {
        return; /* In the error state so do nothing */
    }

    if(me->current_level == NULL) {
        me->error = CTOKEN_ERR_NO_SUBMOD_OPEN;
        return;
    }

    if(*me->current_level  != SUBMODS_IN_SECTION) {
        me->error = CTOKEN_ERR_CANT_MAKE_SUBMOD_IN_SUBMOD;
        return;
    }

    if(type == CTOKEN_TYPE_CWT) {
        QCBOREncode_AddBytesToMap(&(me->cbor_encode_context), submod_name, token);
    } else {
        QCBOREncode_AddTextToMap(&(me->cbor_encode_context), submod_name, token);
    }
}
