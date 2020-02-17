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
#include "qcbor.h"
#include "t_cose_sign1_sign.h"


/**
 * \file attest_token_encode.c
 *
 * \brief Attestation token creation implementation
 *
 * Outline of token creation. Much of this occurs inside
 * t_cose_sign1_init() and t_cose_sign1_finish().
 *
 * - Create encoder context
 * - Open the CBOR array that hold the \c COSE_Sign1
 * - Write COSE Headers
 *   - Protected Header
 *      - Algorithm ID
 *   - Unprotected Headers
 *     - Key ID
 * - Open payload bstr
 *   - Write payload data, maybe lots of it
 *   - Get bstr that is the encoded payload
 * - Compute signature
 *   - Create a separate encoder context for \c Sig_structure
 *     - Encode CBOR context identifier
 *     - Encode protected headers
 *     - Encode two empty bstr
 *     - Add one more empty bstr that is a "fake payload"
 *     - Close off \c Sig_structure
 *   - Hash all but "fake payload" of \c Sig_structure
 *   - Get payload bstr ptr and length
 *   - Continue hash of the real encoded payload
 *   - Run ECDSA
 * - Write signature into the CBOR output
 * - Close CBOR array holding the \c COSE_Sign1
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

    if(me->opt_flags & CTOKEN_OPT_ARRAY_MODE) {
        QCBOREncode_OpenArray(&(me->cbor_encode_context));
    } else  {
        QCBOREncode_OpenMap(&(me->cbor_encode_context));
    }

    return_value = CTOKEN_ERR_SUCCESS;

Done:
    return return_value;
}

#ifdef THIS_CODE_IS_COMPLETED
void attest_token_encode_open_submod(struct ctoken_encode_ctx *me,
                                            char              *submod_name,
                                            int                nConnectionType)
{
    if(me->submod_nest_level == 255) {
        return; // TODO: error out properly (or set error)
    } else if(me->submod_nest_level == 0) {
        /* entering submods for the first time. */
        QCBOREncode_OpenMapInMapN(&(me->cbor_enc_ctx), 888);
    }
    QCBOREncode_OpenMapInMap(&(me->cbor_enc_ctx), submod_name);
    QCBOREncode_AddInt64ToMapN(&(me->cbor_enc_ctx), 77, nConnectionType);
    me->submod_nest_level++; // TODO; check for overflow
}

static void attest_token_encode_close_submod(struct ctoken_encode_ctx *me)
{
    if(me->submod_nest_level == 0 || me->submod_nest_level == 255) {
        // error
    }
    QCBOREncode_CloseMap(&(me->cbor_enc_ctx));
    me->submod_nest_level--;
    if(me->submod_nest_level == 0) {
        /* Closed the last submod. Set to 255 to indicate no more submods
         * can be added */
        me->submod_nest_level = 255;
    }
}


static void attest_token_encode_add_token(struct ctoken_encode_ctx *me,
                                          char *submod_name,
                                          int nConnectionType,
                                          struct q_useful_buf_c token)
{

}
#endif /*THIS_CODE_IS_COMPLETED */

/*
 * Public function. See attest_token_decode.h
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

    if(me->opt_flags & CTOKEN_OPT_ARRAY_MODE) {
        QCBOREncode_CloseArray(&(me->cbor_encode_context));
    } else {
        QCBOREncode_CloseMap(&(me->cbor_encode_context));
    }

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

