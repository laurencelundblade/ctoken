/*
 * ctoken_cwt_encode.h
 *
 * Copyright (c) 2020 Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 1/31/20.
 */

#ifndef cwt_encode_h
#define cwt_encode_h

#include "ctoken_encode.h"
#include "ctoken_cwt_labels.h"


#ifdef __cplusplus
extern "C" {
#if 0
} /* Keep editor indention formatting happy */
#endif
#endif


/**
 * \brief Encode the issuer in to the token.
 *
 * \param[in] context   The token encoder context.
 * \param[in] issuer    Pointer and length of issuer.
 *
 * The principle that created the token. It is a text string or a URI.

 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static inline void ctoken_encode_cwt_issuer(struct ctoken_encode_ctx *context,
                                            struct q_useful_buf_c issuer);


/**
 * \brief Encode the subject in to the token.
 *
 * \param[in] context  The token encoder context.
 * \param[in] subject  Pointer and length of subject.
 *
 * Identifies the subject of the token. It is a text string or URI.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static inline void ctoken_encode_cwt_subject(struct ctoken_encode_ctx *context,
                                             struct q_useful_buf_c subject);


/**
 * \brief Encode the audience in to the token.
 *
 * \param[in] context   The token encoder context.
 * \param[in] audience  Pointer and length of audience.
 *
 * This identifies the recipient for which the token is intended. It is
 * a text string or URI.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static inline void ctoken_encode_cwt_audience(struct ctoken_encode_ctx *context,
                                              struct q_useful_buf_c audience);


/**
 * \brief Encode the expiration time in to the token.
 *
 * \param[in] context     The token encoder context.
 * \param[in] expiration  The expiration time to encode.
 *
 * The time format is that described as Epoch Time in CBOR, RFC 7049, the
 * number of seconds since Jan 1, 1970.
 *
 * This implementation only supports int64_t time, not floating point,
 * even though the specification allows floating point.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static inline void ctoken_encode_cwt_expiration(struct ctoken_encode_ctx *context,
                                                int64_t expiration);


/**
 * \brief Encode the not-before claim in to the token.
 *
 * \param[in] context      The token encoder context.
 * \param[in] not_before   The not-before time to encode.
 *
 * The time format is that described as Epoch Time in CBOR, RFC 7049, the
 * number of seconds since Jan 1, 1970.
 *
 * This implementation only supports int64_t time, not floating point,
 * even though the specification allows floating point.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static inline void ctoken_encode_cwt_not_before(struct ctoken_encode_ctx *context,
                                                int64_t not_before);


/**
 * \brief Encode the "issued-at" in to the token.
 *
 * \param[in] context  The token encoder context.
 * \param[in] iat      The issued-at time.
 *
 * The time at which the token was issued at.
 *
 * The time format is that described as Epoch Time in CBOR, RFC 7049, the
 * number of seconds since Jan 1, 1970.
 *
 * This implementation only supports int64_t time, not floating point,
 * even though the specification allows floating point.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static inline void ctoken_encode_cwt_iat(struct ctoken_encode_ctx *context,
                                         int64_t iat);


/**
 * \brief Encode the CWT claim ID in to the token.
 *
 * \param[in] context   The token encoder context.
 * \param[in] cti       Pointer and length of CWT claim ID.
 *
 * This is a byte string that uniquely identifies the token.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static inline void ctoken_encode_cwt_cti(struct ctoken_encode_ctx *context,
                                         struct q_useful_buf_c cti);



/* --------------------------------------------------------------------------
 *       Inline implementations
 * --------------------------------------------------------------------------*/


static inline void ctoken_encode_cwt_issuer(struct ctoken_encode_ctx *me,
                                            struct q_useful_buf_c issuer)
{
    ctoken_encode_add_tstr(me, CTOKEN_CWT_LABEL_ISSUER, issuer);
}

static inline void ctoken_encode_cwt_subject(struct ctoken_encode_ctx *me,
                                             struct q_useful_buf_c subject)
{
    ctoken_encode_add_tstr(me, CTOKEN_CWT_LABEL_SUBJECT, subject);
}

static inline void ctoken_encode_cwt_audience(struct ctoken_encode_ctx *me,
                                              struct q_useful_buf_c audience)
{
    ctoken_encode_add_tstr(me, CTOKEN_CWT_LABEL_AUDIENCE, audience);
}


static inline void ctoken_encode_cwt_expiration(struct ctoken_encode_ctx *me,
                                                int64_t expiration)
{
    ctoken_encode_add_integer(me, CTOKEN_CWT_LABEL_EXPIRATION, expiration);
}


static inline void ctoken_encode_cwt_not_before(struct ctoken_encode_ctx *me,
                                               int64_t not_before)
{
    ctoken_encode_add_integer(me, CTOKEN_CWT_LABEL_NOT_BEFORE, not_before);
}


static inline void ctoken_encode_cwt_iat(struct ctoken_encode_ctx *me,
                                         int64_t iat)
{
    ctoken_encode_add_integer(me, CTOKEN_CWT_LABEL_IAT, iat);
}


static inline void ctoken_encode_cwt_cti(struct ctoken_encode_ctx *me,
                                         struct q_useful_buf_c cti)
{
    ctoken_encode_add_bstr(me, CTOKEN_CWT_LABEL_CTI, cti);
}

#ifdef __cplusplus
}
#endif

#endif /* cwt_encode_h */
