/*
 * ctoken_encode.c (formerly attest_token_encode.c)
 *
 * Copyright (c) 2018-2020, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "ctoken_encode.h"
#include "qcbor/qcbor.h"
#include "t_cose/t_cose_sign1_sign.h"
#include "ctoken_eat_labels.h"


/**
 * \file ctoken_encode.c
 *
 * \brief Attestation token creation implementation

 */

/**
 * \brief Map t_cose error to attestation token error.
 *
 * \param[in] err   The t_cose error to map.
 *
 * \return the attestation token error.
 */
static enum ctoken_err_t t_cose_err_to_attest_err(enum t_cose_err_t err)
{
    switch(err) {

    case T_COSE_SUCCESS:
        return CTOKEN_ERR_SUCCESS;

    case T_COSE_ERR_UNSUPPORTED_HASH:
        return CTOKEN_ERR_HASH_UNAVAILABLE;

    default:
        /* A lot of the errors are not mapped because they are
         * primarily internal errors that should never happen. They
         * end up here.
         */
        return CTOKEN_ERR_GENERAL;
    }
}


/*
 * Public function. See attest_token_decode.h
 */
enum ctoken_err_t
ctoken_encode_start(struct ctoken_encode_ctx        *me,
                          const struct q_useful_buf out_buf)
{
    /* approximate stack usage on 32-bit machine: 4 bytes */
    enum t_cose_err_t cose_return_value;
    enum ctoken_err_t return_value;

    /* Spin up the CBOR encoder */
    QCBOREncode_Init(&(me->cbor_encode_context), out_buf);

    // TODO: add the CBOR tag if requested

    // TODO: other option proessing

    /* Initialize COSE signer. This will cause the cose headers to be
     * encoded and written into out_buf using me->cbor_enc_ctx
     */
    cose_return_value = t_cose_sign1_encode_parameters(&(me->signer_ctx),
                                                       &(me->cbor_encode_context));
    if(cose_return_value) {
        return_value = t_cose_err_to_attest_err(cose_return_value);
        goto Done;
    }

    QCBOREncode_OpenMap(&(me->cbor_encode_context));

    return_value = CTOKEN_ERR_SUCCESS;

Done:
    return return_value;
}


/*
 * Public function. See ctoken_encode.h
 */
enum ctoken_err_t
ctoken_encode_finish(struct ctoken_encode_ctx *me,
                     struct q_useful_buf_c    *completed_token)
{
    /* approximate stack usage on 32-bit machine: 4 + 4 + 8 + 8 = 24 */
    enum ctoken_err_t       return_value = CTOKEN_ERR_SUCCESS;
    /* The payload with all the claims that is signed */
    /* The completed and signed encoded cose_sign1 */
    struct q_useful_buf_c   completed_token_ub;
    QCBORError              qcbor_result;
    enum t_cose_err_t       cose_return_value;

    if(me->error != CTOKEN_ERR_SUCCESS) {
        return_value = me->error;
        goto Done;
    }

    // TODO: check that all submod sections have been exited


    /* Close the map that holds all the claims */
    QCBOREncode_CloseMap(&(me->cbor_encode_context));

    /* Finish off the cose signature. This does all the interesting work of
     hashing and signing */
    cose_return_value = t_cose_sign1_encode_signature(&(me->signer_ctx), &(me->cbor_encode_context));
    if(cose_return_value) {
        /* Main errors are invoking the hash or signature */
        return_value = t_cose_err_to_attest_err(cose_return_value);
        goto Done;
    }

    /* Close off the CBOR encoding and return the completed token */
    qcbor_result = QCBOREncode_Finish(&(me->cbor_encode_context),  &completed_token_ub);
    if(qcbor_result == QCBOR_ERR_BUFFER_TOO_SMALL) {
        return_value = CTOKEN_ERR_TOO_SMALL;
    } else if (qcbor_result != QCBOR_SUCCESS) {
        /* likely from array not closed, too many closes, ... */
        return_value = CTOKEN_ERR_CBOR_FORMATTING;
    } else {
        *completed_token = completed_token_ub;
    }

Done:
    return return_value;
}


/*
 * Public function. See ctoken_eat_encode.h
 */
void
ctoken_encode_boot_state(struct ctoken_encode_ctx     *me,
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
ctoken_encode_location(struct ctoken_encode_ctx *me,
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
void ctoken_encode_start_submod_section(struct ctoken_encode_ctx *me)
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
void ctoken_encode_end_submod_section(struct ctoken_encode_ctx *me)
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
void ctoken_encode_open_submod(struct ctoken_encode_ctx *me,
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
void ctoken_encode_close_submod(struct ctoken_encode_ctx *me)
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
void ctoken_encode_add_token(struct ctoken_encode_ctx *me,
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
