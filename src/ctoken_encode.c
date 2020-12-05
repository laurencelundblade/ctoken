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
#include "qcbor/qcbor_encode.h"
#include "t_cose/t_cose_sign1_sign.h"


/**
 * \file ctoken_encode.c
 *
 * \brief Attestation token creation implementation

 */


/*
 TODO: run this through the spelling checker.
 TODO: make this whole thing disablaable.

 The following collection of functions and the ctoken_submod_state
 structure tracking nesting of submodules to report errors in
 the calling sequence for creating submodules. This whole
 facility is unnecessary in run time code that is known to be
 correct, but getting the calling sequence right is not perfectly
 easy so there is this facility.

 This starts out with the top level in the state SUBMODS_NONE.
 There is no submodules section in the top level claim set.
 The only thing possible in this state is the opening of the
 submodules section, a transition from SUBMODS_NONE to
 SUBMODS_IN_SECTION. This is taken care of submod_state_start_section().

 From the SUBMODS_IN_SECTION state 3 things can happen as described
 in the three following paragraphs.

 First from the SUBMODS_IN_SECTION state, a submodule can be opened and
 claims added to it. This puts the current level in the
 SUBMODS_IN_SECTION_AND_SUBMOD state and opens up a new level
 that is in the SUBMODS_NONE state. This is handled by submod_state_open_submod().

 Second from the SUBMODS_IN_SECTION state, a whole formatted
 and secured token can be added. This happens in one go and doesn't
 change the state. This is handled by submod_state_ok_for_token().

 Third from the SUBMODS_IN_SECTION state, the submods section may
 be closed off. To produce a correct token it must be closed off
 when all submodules are added. When closed off it goes into the
 SUBMODS_SECTION_DONE state. This is handled by submod_state_end_section().

 From the SUBMODS_IN_SECTION_AND_SUBMOD state, the only thing that
 can happen is the closing of the submodule. This is handled by
 submod_state_close_submod().

 Finally, from the SUBMODS_SECTION_DONE state, the only thing that
 can happen is the closing out of the submodule the section is in
 unless it is at the top level in which nothing can happen.
 This hs handled by submod_state_close_submod().

 To confirm all submodules and submodule sections are closed
 out call submod_state_all_finished().
 */
static inline void
submodstate_init(struct ctoken_submod_state *me)
{
    me->current_level    = &me->level_state[0];
    *(me->current_level) = SUBMODS_NONE;
}

static inline enum ctoken_err_t
submod_state_start_section(struct ctoken_submod_state *me)
{
    if(*(me->current_level) != SUBMODS_NONE) {
        return CTOKEN_CANT_START_SUBMOD_SECTION;
    }
    *(me->current_level) = SUBMODS_IN_SECTION;
    return CTOKEN_ERR_SUCCESS;
}

static inline enum ctoken_err_t
submod_state_end_section(struct ctoken_submod_state *me)
{
    if(*(me->current_level) != SUBMODS_IN_SECTION) {
        return CTOKEN_ERR_NO_SUBMOD_SECTION_STARTED;
    }
    *(me->current_level) = SUBMODS_SECTION_DONE;
    return CTOKEN_ERR_SUCCESS;
}

static inline enum ctoken_err_t
submod_state_open_submod(struct ctoken_submod_state *me)
{
    if(*(me->current_level) != SUBMODS_IN_SECTION) {
        return CTOKEN_ERR_NO_SUBMOD_SECTION_STARTED;
    }

    const enum ctoken_encode_nest_state * const array_end = &(me->level_state[CTOKEN_MAX_SUBMOD_NESTING-1]);
    if(me->current_level >= array_end) {
        return CTOKEN_ERR_SUBMOD_NESTING_TOO_DEEP;
    }

    *(me->current_level) = SUBMODS_IN_SECTION_AND_SUBMOD;
    me->current_level++;
    *(me->current_level) = SUBMODS_NONE;

    return CTOKEN_ERR_SUCCESS;
}

static inline enum ctoken_err_t
submod_state_close_submod(struct ctoken_submod_state *me)
{
    if(*(me->current_level) != SUBMODS_NONE &&
       *(me->current_level) != SUBMODS_SECTION_DONE) {
        return CTOKEN_ERR_NO_SUBMOD_OPEN;
    }

    if(me->current_level == &me->level_state[0]) {
        return CTOKEN_ERR_NO_SUBMOD_OPEN;
    }
    me->current_level--;

    if(*(me->current_level) != SUBMODS_IN_SECTION_AND_SUBMOD) {
        return CTOKEN_ERR_NO_SUBMOD_OPEN;
    }
    *(me->current_level) = SUBMODS_IN_SECTION;

    return CTOKEN_ERR_SUCCESS;
}

static inline enum ctoken_err_t
submod_state_ok_for_token(struct ctoken_submod_state *me)
{
    if(*(me->current_level) != SUBMODS_IN_SECTION) {
        return CTOKEN_ERR_CANT_MAKE_SUBMOD_IN_SUBMOD;
    } else {
        return CTOKEN_ERR_SUCCESS;
    }
}

static inline enum ctoken_err_t
submod_state_all_finished(struct ctoken_submod_state *me)
{
    if(me->current_level != &me->level_state[0]) {
        return CTOKEN_ERR_SUBMODS_NOT_CLOSED;
    }

    if(*me->current_level != SUBMODS_NONE &&
       *me->current_level != SUBMODS_SECTION_DONE) {
        return CTOKEN_ERR_SUBMODS_NOT_CLOSED;
    }
    return CTOKEN_ERR_SUCCESS;
}




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


static enum ctoken_err_t
ctoken_encode_start2(struct ctoken_encode_ctx *me, const struct q_useful_buf out_buf)
{
    enum t_cose_err_t cose_return_value;
    enum ctoken_err_t return_value;

    /* Spin up the CBOR encoder */
    QCBOREncode_Init(&(me->cbor_encode_context), out_buf);

    submodstate_init(&(me->submod_state));

    // TODO: add the CBOR tag if requested

    // TODO: other option proessing

    /* Initialize COSE signer. This will cause the cose headers to be
     * encoded and written into out_buf using me->cbor_enc_ctx
     */
    cose_return_value = t_cose_sign1_encode_parameters(&(me->signer_ctx),
                                                       &(me->cbor_encode_context));
    return_value = t_cose_err_to_attest_err(cose_return_value);

    return return_value;
}


/*
 * Public function. See attest_token_decode.h
 */
enum ctoken_err_t
ctoken_encode_start(struct ctoken_encode_ctx  *me,
                    const struct q_useful_buf  out_buf)
{
    enum ctoken_err_t return_value = ctoken_encode_start2(me, out_buf);

    QCBOREncode_OpenMap(&(me->cbor_encode_context));

    return_value = CTOKEN_ERR_SUCCESS;

Done:
    return return_value;
}


static enum ctoken_err_t
ctoken_encode_finish2(struct ctoken_encode_ctx *me, struct q_useful_buf_c *completed_token)
{
    QCBORError            qcbor_result;
    enum t_cose_err_t     cose_return_value;
    enum ctoken_err_t     return_value;
    /* The payload with all the claims that is signed */
    /* The completed and signed encoded cose_sign1 */
    struct q_useful_buf_c  completed_token_ub;

    /* Finish off the cose signature. This does all the interesting work of
     hashing and signing */
    cose_return_value = t_cose_sign1_encode_signature(&(me->signer_ctx), &(me->cbor_encode_context));
    if(cose_return_value) {
        /* Main errors are invoking the hash or signature */
        return_value = t_cose_err_to_attest_err(cose_return_value);
        goto Done;
    }

    return_value = CTOKEN_ERR_SUCCESS;

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
 * Public function. See ctoken_encode.h
 */
enum ctoken_err_t
ctoken_encode_finish(struct ctoken_encode_ctx *me,
                     struct q_useful_buf_c    *completed_token)
{
    enum ctoken_err_t       return_value = CTOKEN_ERR_SUCCESS;

    if(me->error != CTOKEN_ERR_SUCCESS) {
        return_value = me->error;
        goto Done;
    }

    return_value = submod_state_all_finished(&me->submod_state);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    /* Close the map that holds all the claims */
    QCBOREncode_CloseMap(&(me->cbor_encode_context));

    return_value = ctoken_encode_finish2(me, completed_token);

Done:
    return return_value;
}


/*
 * Public function. See ctoken_eat_encode.h
 */
enum ctoken_err_t
ctoken_encode_one_shot(struct ctoken_encode_ctx    *me,
                       const struct q_useful_buf    out_buf,
                       const struct q_useful_buf_c  encoded_payload,
                       struct q_useful_buf_c       *completed_token)
{
    enum ctoken_err_t       return_value;

    return_value = ctoken_encode_start2(me, out_buf);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    QCBOREncode_AddEncoded(&(me->cbor_encode_context), encoded_payload);

    return_value = ctoken_encode_finish2(me, completed_token);

Done:
    return return_value;
}


/*
 * Public function. See ctoken_eat_encode.h
 */
void
ctoken_encode_boot_state(struct ctoken_encode_ctx     *me,
                             bool                          secure_boot_enabled,
                             enum ctoken_debug_level_t debug_state)
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
                           const struct ctoken_location_t *location)
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
 * Public function. See ctoken_encode.h
 */
void ctoken_encode_start_submod_section(struct ctoken_encode_ctx *me)
{
    if(me->error != CTOKEN_ERR_SUCCESS) {
        return; /* In the error state so do nothing */
    }

    me->error = submod_state_start_section(&(me->submod_state));
    if(me->error == CTOKEN_ERR_SUCCESS) {
        QCBOREncode_OpenMapInMapN(&(me->cbor_encode_context), CTOKEN_EAT_LABEL_SUBMODS);
    }
}


/*
 * Public function. See ctoken_encode.h
 */
void ctoken_encode_end_submod_section(struct ctoken_encode_ctx *me)
{
    if(me->error != CTOKEN_ERR_SUCCESS) {
        return; /* In the error state so do nothing */
    }

    me->error = submod_state_end_section(&(me->submod_state));
    if(me->error == CTOKEN_ERR_SUCCESS) {
        QCBOREncode_CloseMap(&(me->cbor_encode_context));
    }
}


/*
 * Public function. See ctoken_encode.h
 */
void ctoken_encode_open_submod(struct ctoken_encode_ctx *me,
                               const char               *submod_name)
{
    if(me->error != CTOKEN_ERR_SUCCESS) {
        return; /* In the error state so do nothing */
    }

    me->error = submod_state_open_submod(&(me->submod_state));
    if(me->error == CTOKEN_ERR_SUCCESS) {
        QCBOREncode_OpenMapInMap(&(me->cbor_encode_context), submod_name);
    }
}


/*
 * Public function. See ctoken_encode.h
 */
void ctoken_encode_close_submod(struct ctoken_encode_ctx *me)
{
    if(me->error != CTOKEN_ERR_SUCCESS) {
        return; /* In the error state so do nothing */
    }

    me->error = submod_state_close_submod(&(me->submod_state));
    if(me->error == CTOKEN_ERR_SUCCESS) {
        QCBOREncode_CloseMap(&(me->cbor_encode_context));
    }
}


/*
 * Public function. See ctoken_encode.h
 */
void ctoken_encode_add_token(struct ctoken_encode_ctx *me,
                             enum ctoken_type          type,
                             const  char              *submod_name,
                             struct q_useful_buf_c     token)
{
    if(me->error != CTOKEN_ERR_SUCCESS) {
        return; /* In the error state so do nothing */
    }

    me->error = submod_state_ok_for_token(&(me->submod_state));
    if(me->error == CTOKEN_ERR_SUCCESS) {
        if(type == CTOKEN_TYPE_CWT) {
            QCBOREncode_AddBytesToMap(&(me->cbor_encode_context), submod_name, token);
        } else {
            QCBOREncode_AddTextToMap(&(me->cbor_encode_context), submod_name, token);
        }
    }
}
