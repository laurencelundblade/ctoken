/*
 * ctoken_cwt_decode.h
 *
 * Copyright (c) 2020 Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 2/1/20.
 */

#ifndef cwt_decode_h
#define cwt_decode_h

#include "ctoken_cwt_labels.h"
#include "ctoken_decode.h"


#ifdef __cplusplus
extern "C" {
#if 0
} /* Keep editor indention formatting happy */
#endif
#endif



/**
 * \brief Decode the issuer.
 *
 * \param[in] context  The decoding context to decode from.
 * \param[out] issuer  Place to put pointer and length of the issuer claim.
 *
 * \retval CTOKEN_ERR_CBOR_STRUCTURE
 *         General structure of the token is incorrect, for example
 *         the top level is not a map or some map wasn't closed.
 *
 * \retval CTOKEN_ERR_CBOR_NOT_WELL_FORMED
 *         CBOR syntax is wrong and it is not decodable.
 *
 * \retval CTOKEN_ERR_CBOR_TYPE
 *         Returned if the claim is not a text string.
 *
 * \retval CTOKEN_ERR_NOT_FOUND
 *         Data item for \c label was not found in token.
 *
 *  The principle that created the token. It is a text string or a URI.
 */
static inline enum ctoken_err_t
ctoken_decode_cwt_issuer(struct ctoken_decode_ctx *context,
                         struct q_useful_buf_c *issuer);


/**
 * \brief Decode the subject claim.
 *
 * \param[in] context   The decoding context to decode from.
 * \param[out] subject  Place to put pointer and length of the subject claim.
 *
 * \retval CTOKEN_ERR_CBOR_STRUCTURE
 *         General structure of the token is incorrect, for example
 *         the top level is not a map or some map wasn't closed.
 *
 * \retval CTOKEN_ERR_CBOR_NOT_WELL_FORMED
 *         CBOR syntax is wrong and it is not decodable.
 *
 * \retval CTOKEN_ERR_CBOR_TYPE
 *         Returned if the claim is not a text string.
 *
 * \retval CTOKEN_ERR_NOT_FOUND
 *         Data item for \c label was not found in token.
 *
 * Identifies the subject of the token. It is a text string or URI.
 */
static inline enum ctoken_err_t
ctoken_decode_cwt_subject(struct ctoken_decode_ctx *context,
                          struct q_useful_buf_c *subject);


/**
 * \brief Decode the audience claim.
 *
 * \param[in] context    The decoding context to decode from.
 * \param[out] audience  Place to put pointer and length of the audience claim.
 *
 * \retval CTOKEN_ERR_CBOR_STRUCTURE
 *         General structure of the token is incorrect, for example
 *         the top level is not a map or some map wasn't closed.
 *
 * \retval CTOKEN_ERR_CBOR_NOT_WELL_FORMED
 *         CBOR syntax is wrong and it is not decodable.
 *
 * \retval CTOKEN_ERR_CBOR_TYPE
 *         Returned if the claim is not a text string.
 *
 * \retval CTOKEN_ERR_NOT_FOUND
 *         Data item for \c label was not found in token.
 *
 * This identifies the recipient for which the token is intended. It is
 * a text string or URI.
 */
static inline enum ctoken_err_t
ctoken_decode_cwt_audience(struct ctoken_decode_ctx *context,
                           struct q_useful_buf_c *audience);


/**
 * \brief Decode the expiration claim.
 *
 * \param[in] context      The decoding context to decode from.
 * \param[out] expiration  Place to return expiration claim.
 *
 * \retval CTOKEN_ERR_CBOR_STRUCTURE
 *         General structure of the token is incorrect, for example
 *         the top level is not a map or some map wasn't closed.
 *
 * \retval CTOKEN_ERR_CBOR_NOT_WELL_FORMED
 *         CBOR syntax is wrong and it is not decodable.
 *
 * \retval CTOKEN_ERR_CBOR_TYPE
 *         Returned if the claim is not an integer.
 *
 * \retval CTOKEN_ERR_NOT_FOUND
 *         Data item for \c label was not found in token.
 *
 * The time format is that described as Epoch Time in CBOR, RFC 7049, the
 * number of seconds since Jan 1, 1970.
 *
 * This implementation only supports int64_t time, not floating point,
 * even though the specification allows floating point.
 */
static inline enum ctoken_err_t
ctoken_decode_cwt_expiration(struct ctoken_decode_ctx *context,
                             int64_t *expiration);


/**
 * \brief Decode the not-before claim.
 *
 * \param[in] context      The decoding context to decode from.
 * \param[out] not_before  Place to return the not-before claim.
 *
 * \retval CTOKEN_ERR_CBOR_STRUCTURE
 *         General structure of the token is incorrect, for example
 *         the top level is not a map or some map wasn't closed.
 *
 * \retval CTOKEN_ERR_CBOR_NOT_WELL_FORMED
 *         CBOR syntax is wrong and it is not decodable.
 *
 * \retval CTOKEN_ERR_CBOR_TYPE
 *         Returned if the claim is not an integer.
 *
 * \retval CTOKEN_ERR_NOT_FOUND
 *         Data item for \c label was not found in token.
 *
 * The time format is that described as Epoch Time in CBOR, RFC 7049, the
 * number of seconds since Jan 1, 1970.
 *
 * This implementation only supports int64_t time, not floating point,
 * even though the specification allows floating point.
 */
static inline enum ctoken_err_t
ctoken_decode_cwt_not_before(struct ctoken_decode_ctx *context,
                             int64_t *not_before);


/**
 * \brief Decode the issued-at claim.
 *
 * \param[in] context  The decoding context to decode from.
 * \param[out] iat     Place to put pointer and length of the issued-at claim.
 *
 * \retval CTOKEN_ERR_CBOR_STRUCTURE
 *         General structure of the token is incorrect, for example
 *         the top level is not a map or some map wasn't closed.
 *
 * \retval CTOKEN_ERR_CBOR_NOT_WELL_FORMED
 *         CBOR syntax is wrong and it is not decodable.
 *
 * \retval CTOKEN_ERR_CBOR_TYPE
 *         Returned if the claim is not a byte string.
 *
 * \retval CTOKEN_ERR_NOT_FOUND
 *         Data item for \c label was not an integer.
 *
 * The time at which the token was issued at.
 *
 * The time format is that described as Epoch Time in CBOR, RFC 7049, the
 * number of seconds since Jan 1, 1970.
 *
 * This implementation only supports int64_t time, not floating point,
 * even though the specification allows floating point.
 */
static inline enum ctoken_err_t
ctoken_decode_cwt_iat(struct ctoken_decode_ctx *context,
                      int64_t *iat);


/**
 * \brief Decode the CWT ID claim.
 *
 * \param[in] context  The decoding context to decode from.
 * \param[out] cti     Place to put pointer and length of the CWT ID claim.
 *
 * \retval CTOKEN_ERR_CBOR_STRUCTURE
 *         General structure of the token is incorrect, for example
 *         the top level is not a map or some map wasn't closed.
 *
 * \retval CTOKEN_ERR_CBOR_NOT_WELL_FORMED
 *         CBOR syntax is wrong and it is not decodable.
 *
 * \retval CTOKEN_ERR_CBOR_TYPE
 *         Returned if the claim is not a byte string.
 *
 * \retval CTOKEN_ERR_NOT_FOUND
 *         Data item for \c label was not found in token.
 *
 * This is a byte string that uniquely identifies the token.
 */
static inline enum ctoken_err_t
ctoken_decode_cwt_cti(struct ctoken_decode_ctx *context,
                      struct q_useful_buf_c *cti);




/* --------------------------------------------------------------------------
 *       Inline implementations
 * --------------------------------------------------------------------------*/


static inline enum ctoken_err_t
ctoken_decode_cwt_issuer(struct ctoken_decode_ctx *me,
                         struct q_useful_buf_c *issuer)
{
    return ctoken_decode_get_tstr(me, CTOKEN_CWT_LABEL_ISSUER, issuer);
}


static inline enum ctoken_err_t
ctoken_decode_cwt_subject(struct ctoken_decode_ctx *me,
                          struct q_useful_buf_c *subject)
{
    return ctoken_decode_get_tstr(me, CTOKEN_CWT_LABEL_SUBJECT, subject);
}


static inline enum ctoken_err_t
ctoken_decode_cwt_audience(struct ctoken_decode_ctx *me,
                           struct q_useful_buf_c *audience)
{
    return ctoken_decode_get_tstr(me, CTOKEN_CWT_LABEL_AUDIENCE, audience);
}


static inline enum ctoken_err_t
ctoken_decode_cwt_expiration(struct ctoken_decode_ctx *me,
                             int64_t *expiration)
{
    return ctoken_decode_get_int(me, CTOKEN_CWT_LABEL_EXPIRATION, expiration);
}

static inline enum ctoken_err_t
ctoken_decode_cwt_not_before(struct ctoken_decode_ctx *me,
                             int64_t *not_before)
{
    return ctoken_decode_get_int(me, CTOKEN_CWT_LABEL_NOT_BEFORE, not_before);
}


static inline enum ctoken_err_t
ctoken_decode_cwt_iat(struct ctoken_decode_ctx *me,
                      int64_t *iat)
{
    return ctoken_decode_get_int(me, CTOKEN_CWT_LABEL_NOT_BEFORE, iat);
}


static inline enum ctoken_err_t
ctoken_decode_cwt_cti(struct ctoken_decode_ctx *me,
                      struct q_useful_buf_c *cti)
{
    return ctoken_decode_get_bstr(me, CTOKEN_CWT_LABEL_CTI,  cti);
}

#ifdef __cplusplus
}
#endif

#endif /* cwt_decode_h */
