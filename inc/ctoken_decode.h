/*
 * ctoken_decode.h (formerly attest_token_decode.h)
 *
 * Copyright (c) 2019-2020, Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */
#ifndef __CTOKEN_DECODE_H__
#define __CTOKEN_DECODE_H__

#include "t_cose/q_useful_buf.h"
#include <stdbool.h>
#include "ctoken.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "qcbor/qcbor_decode.h"

#include "ctoken_cwt_labels.h"
#include "ctoken_eat_labels.h"


#ifdef __cplusplus
extern "C" {
#if 0
} /* Keep editor indention formatting happy */
#endif
#endif


/**
 * \file ctoken_decode.h
 *
 * \brief CBOR Token Decoding Interface
 *
 * The context and functions here are used to decode a
 * token as follows:
 *
 * -# Create a \ref ctoken_decode_context, most likely as a
 *    stack variable.
 *
 * -# Initialize it by calling ctoken_decode_init().
 *
 * -# Tell it which public key to use for verification using
 *    ctoken_decode_set_verification_key().
 *
 * -# Pass the token in and validate it by calling
 *    ctoken_decode_validate_token().
 *
 * -# Call the various \c ctoken_get_xxx() methods in any
 * order. Also call the ctoken_decode_xxx(), ctoken_cwt_decode_xxx() and
 * other methods in any order. The strings returned by the these functions
 * will point into
 * the token passed to ctoken_decode_validate_token(). A copy is
 * NOT made.
 *
 * The entire token is validated and decoded in place.  No copies are
 * made internally. The data returned by the \c ctoken_get_xxx()
 * methods is not a copy so the lifetime of the \c struct \c
 * q_useful_buf_c containing the token must be maintained.
 *
 * Aside from the cryptographic functions, this allocates no
 * memory. It works entirely off the stack. It makes use of t_cose to
 * validate the signature and QCBOR for CBOR decoding.
 *
 * This decoder only works with labels (keys) that are integers even
 * though labels can be any data type in CBOR. The presumption is that
 * this is for small embedded use cases where space is a premium and
 * only integer labels will be used.
 *
 * All claims are optional in tokens. This decoder will ignore all
 * CBOR encoded data that it doesn't understand without error.
 *
 * The claims are not described in detail here. That is left to the
 * definition documents and eventually an IETF standard.
 *
 * If a method to get the claim you are interested in doesn't exist,
 * there are several methods where you can give the label (the key)
 * for the claim and have it returned. This only works for simple
 * claims (strings and integers).
 *
 * The entire payload can be retrieved unparsed. Then you can use a
 * separate CBOR parser to decode the claims out of it.  Future work may
 * include more general facilities for handling claims with complex
 * structures made up of maps and arrays.
 */


#define CTOKEN_MAX_TAGS_TO_RETURN 3


/**
 * The context for decoding a CBOR token. The caller of ctoken must
 * create one of these and pass it to the functions here. It is small
 * enough that it can go on the stack. It is most of the memory needed
 * to create a token except the output buffer and any memory
 * requirements for the cryptographic operations.
 *
 * The structure is opaque for the caller.
 *
 * Aproximate size on 64-bit CPU: 48 bytes.
 */
struct ctoken_decode_ctx {
    /* PRIVATE DATA STRUCTURE */
    struct t_cose_sign1_verify_ctx verify_context;
    struct q_useful_buf_c          payload;
    uint32_t                       token_options;
    enum ctoken_err_t              last_error;
    QCBORDecodeContext             qcbor_decode_context;
    uint8_t                        in_submods;
    uint64_t                       auTags[CTOKEN_MAX_TAGS_TO_RETURN];
    enum ctoken_protection_t       protection_type;
};


/**
 * \brief Initialize token decoder.
 *
 * \param[in] context        The token decoder context to be initialized.
 * \param[in] t_cose_options Options passed to t_cose verification.
 * \param[in] token_options  Decoding options.
 *
 * Must be called on a \ref attest_token_decode_context before
 * use. An instance of \ref attest_token_decode_context can
 * be used again by calling this on it again.
 **/
void ctoken_decode_init(struct ctoken_decode_ctx *context,
                        uint32_t                  t_cose_options,
                        uint32_t                  token_options,
                        enum ctoken_protection_t  protection_type);


/**
 * \brief Set specific public key to use for verification.
 *
 * \param[in] me           The token decoder context to configure.
 * \param[in] verification_key  TODO: reference to t_cose.
 *
 *
 * (This has not been implemented yet)
 *
 * The key type must work with the signing algorithm in the token
 * being verified.
 *
 * The \c kid in the \c COSE_Key must match the one in the token.
 *
 * If there is no kid in the \c COSE_Key it will be used no matter
 * what kid is indicated in the token.
 *
 * Once set, a key can be used for multiple verifications.
 *
 * Calling this again will replace the previous key that was
 * configured. It will also replace the key set by
 * attest_token_decode_set_pub_key_select().
 */
static inline void
ctoken_decode_set_verification_key(struct ctoken_decode_ctx *me,
                                   struct t_cose_key         verification_key);


/**
 * \brief Get the kid (key ID) from the token
 *
 * \param[in] me     The token decoder context.
 * \param[in] token  The token from which to get the kid.
 * \param[out] kid   The kid from the token.
 *
 * This decodes the token, particularly the COSE headers
 * in it to get the kid (key ID).
 *
 * Typically use is to call this first to get the kid,
 * then use the kid to look up the public key, and then
 * call ctoken_decode_set_verification_key() to
 * set the public key for verification.
 *
 * Different use cases for tokens (CWTs, EATs, etc will
 * have different ways of managing the signing keys. Some
 * will use key ID and some will not.
 */
enum ctoken_err_t
ctoken_decode_get_kid(struct ctoken_decode_ctx *me,
                      struct q_useful_buf_c     token,
                      struct q_useful_buf_c    *kid);


/**
 * \brief Set the token to work on and validate its signature.
 *
 * \param[in] me     The token decoder context to validate with.
 * \param[in] token  The CBOR-encoded token to validate and decode.
 *
 * \return An error from \ref CTOKEN_ERR_t.
 *
 * The signature on the token is validated. If it is successful the
 * token and its payload is remembered in the \ref
 * attest_token_decode_context \c me so the \c
 * attest_token_decode_get_xxx() functions can be called to get the
 * various claims out of it.
 *
 * Generally, a public key has to be configured for this to work. It
 * can however validate short-circuit signatures even if one is not
 * set.
 *
 * The code for any error that occurs during validation is remembered
 * in decode context. The \c attest_token_decode_get_xxx() functions
 * can be called and they will just return this error. The \c
 * attest_token_decode_get_xxx() functions will generally return 0 or
 * \c NULL if the token is in error.
 *
 * It is thus possible to call attest_token_decode_validate_token()
 * and all the \c attest_token_decode_get_xxx() functions to parse the
 * token and ignore the error codes as long as
 * attest_token_decode_get_error() is called before any of the claim
 * data returned is used.
 *
 * TODO: this may need an option to be able to decode fields in the
 * token without signature verification because the info to look
 * up the verification key is the token, not the COSE key id.
 */
enum ctoken_err_t
ctoken_decode_validate_token(struct ctoken_decode_ctx *me,
                             struct q_useful_buf_c     token);


/**
 * \brief Get the last decode error.
 *
 * \param[in] me The token decoder context.
 *
 * \return An error from \ref CTOKEN_ERR_t.
 */
static enum ctoken_err_t
ctoken_decode_get_error(struct ctoken_decode_ctx *me);


/**
 * \brief Return unprocessed tags from most recent token validation
 *
 * \param[in] context   The t_cose signature verification context.
 * \param[in] n         Index of the tag to return.
 *
 * \return  The tag value or \ref CBOR_TAG_INVALID64 if there is no tag
 *          at the index or the index is too large.
 *
 * The 0th tag is the one for which the CWT or UCCS message is the content. Loop
 * from 0 up until \ref CBOR_TAG_INVALID64 is returned. The maximum
 * is \ref T_COSE_MAX_TAGS_TO_RETURN.
 */
uint64_t
ctoken_decode_get_nth_tag(const struct ctoken_decode_ctx *context,
                          size_t                          n);


/**
 * \brief Get undecoded CBOR payload from the token.
 *
 * \param[in]  me      The token decoder context.
 * \param[out] payload The returned, verified token payload.
 *
 * \return An error from \ref CTOKEN_ERR_t.
 *
 * This will return an error if the signature over the payload did not
 * validate.
 *
 * The ctoken_decode_get_xxx() methods are limited to unstructured
 * claims. This is useful to decode more complicated claims by
 * creating and instance QCBOREncodeContext to operating on the \c payload.
 * This also allows use of any CBOR decoder, or even handling payloads
 * that are not CBOR.
 */
enum ctoken_err_t
ctoken_decode_get_payload(struct ctoken_decode_ctx *me,
                          struct q_useful_buf_c    *payload);


/**
 *
 * \brief Get a claim of type byte string.
 *
 * \param[in]  me    The token decoder context.
 * \param[in]  label The integer label identifying the claim.
 * \param[out] claim The byte string or \c NULL_Q_USEFUL_BUF_C.
 *
 * \return An error from \ref CTOKEN_ERR_t.
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
 * If an error occurs, the claim will be set to \c NULL_Q_USEFUL_BUF_C
 * and the error state inside \c attest_token_decode_context will
 * be set.
 */
enum ctoken_err_t
ctoken_decode_get_bstr(struct ctoken_decode_ctx  *me,
                       int32_t                    label,
                       struct q_useful_buf_c     *claim);


/**
 * \brief Get a claim of type text string.
 * string.
 *
 * \param[in] me     The token decoder context.
 * \param[in] label  The integer label identifying the claim.
 * \param[out] claim The byte string or \c NULL_Q_USEFUL_BUF_C.
 *
 * \return An error from \ref CTOKEN_ERR_t.
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
 * Even though this is a text string, it is not NULL-terminated.
 *
 * If an error occurs, the claim will be set to \c NULL_Q_USEFUL_BUF_C
 * and the error state inside \c attest_token_decode_context will
 * be set.
 */
enum ctoken_err_t
ctoken_decode_get_tstr(struct ctoken_decode_ctx *me,
                       int32_t                   label,
                       struct q_useful_buf_c    *claim);


/**
 * \brief Get a claim of type signed integer.
 *
 * \param[in]  me    The token decoder context.
 * \param[in]  label The integer label identifying the claim.
 * \param[out] claim The signed integer or 0.
 *
 * \return An error from \ref CTOKEN_ERR_t.
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
 * \retval CTOKEN_ERR_INTEGER_VALUE
 *         Returned if the integer value is larger
 *         than \c INT64_MAX.
 *
 * This will succeed if the CBOR type of the claim is either a
 * positive or negative integer as long as the value is between \c
 * INT64_MIN and \c INT64_MAX.
 *
 * See also attest_token_decode_get_uint().
 *
 * If an error occurs the value 0 will be returned and the error
 * inside the \c attest_token_decode_context will be set.
 */
enum ctoken_err_t
ctoken_decode_get_int(struct ctoken_decode_ctx *me,
                      int32_t                   label,
                      int64_t                  *claim);


/**
 * \brief Get a claim of type unsigned integer.
 *
 * \param[in]  me    The token decoder context.
 * \param[in]  label The integer label identifying the claim.
 * \param[out] claim The unsigned integer or 0.
 *
 * \return An error from \ref CTOKEN_ERR_t.
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
 * \retval CTOKEN_ERR_INTEGER_VALUE
 *         Returned if the integer value is negative.
 *
 * This will succeed if the CBOR type of the claim is either a
 * positive or negative integer as long as the value is between 0 and
 * \c MAX_UINT64.
 *
 * See also attest_token_decode_get_int().
 *
 *  If an error occurs the value 0 will be returned and the error
 *  inside the \c attest_token_decode_context will be set.
 */
enum ctoken_err_t
ctoken_decode_get_uint(struct ctoken_decode_ctx *me,
                       int32_t                  label,
                       uint64_t                *claim);




/**
 * \brief Decode the CWT issuer.
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
 *  The principle that created the token. It is a text string or a URI as described in
 *  [RFC 8392](https://tools.ietf.org/html/rfc8392#section-3.1.1)
 * and [RFC 7519] (https://tools.ietf.org/html/rfc7519#section-4.1.1).
 */
static inline enum ctoken_err_t
ctoken_decode_issuer(struct ctoken_decode_ctx *context,
                     struct q_useful_buf_c    *issuer);


/**
 * \brief Decode the CWT subject claim.
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
 * Identifies the subject of the token. It is a text string or URI as described in
 * [RFC 8392](https://tools.ietf.org/html/rfc8392#section-3.1.2)
 * and [RFC 7519] (https://tools.ietf.org/html/rfc7519#section-4.1.2).
 */
static inline enum ctoken_err_t
ctoken_decode_subject(struct ctoken_decode_ctx *context,
                      struct q_useful_buf_c    *subject);


/**
 * \brief Decode the CWT audience claim.
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
 * a text string or URI as
 * described in [RFC 8392](https://tools.ietf.org/html/rfc8392#section-3.1.3)
 * and [RFC 7519] (https://tools.ietf.org/html/rfc7519#section-4.1.3).
 */
static inline enum ctoken_err_t
ctoken_decode_audience(struct ctoken_decode_ctx *context,
                       struct q_useful_buf_c    *audience);


/**
 * \brief Decode the CWT expiration claim.
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
 *
 * Details are described in
 * [RFC 8392](https://tools.ietf.org/html/rfc8392#section-3.1.4)
 * and [RFC 7519] (https://tools.ietf.org/html/rfc7519#section-4.1.4).
 */
static inline enum ctoken_err_t
ctoken_decode_expiration(struct ctoken_decode_ctx *context,
                         int64_t                  *expiration);


/**
 * \brief Decode the CWT not-before claim.
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
 *
 * Details are described in
 * [RFC 8392](https://tools.ietf.org/html/rfc8392#section-3.1.5)
 * and [RFC 7519] (https://tools.ietf.org/html/rfc7519#section-4.1.5).
 */
static inline enum ctoken_err_t
ctoken_decode_not_before(struct ctoken_decode_ctx *context,
                         int64_t                  *not_before);


/**
 * \brief Decode the CWT and EAT issued-at claim.
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
 *
 * Details are described in
 * [RFC 8392](https://tools.ietf.org/html/rfc8392#section-3.1.6)
 * and [RFC 7519] (https://tools.ietf.org/html/rfc7519#section-4.1.6).
 * This claim is also used by (EAT)[https://tools.ietf.org/html/draft-ietf-rats-eat-04].
 */
static inline enum ctoken_err_t
ctoken_decode_iat(struct ctoken_decode_ctx *context,
                  int64_t                  *iat);


/**
 * \brief Decode the CWT and EAT ID claim.
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
 *
 * [RFC 8392](https://tools.ietf.org/html/rfc8392#section-3.1.7)
 * and [RFC 7519] (https://tools.ietf.org/html/rfc7519#section-4.1.7).
 * This claim is also used by (EAT)[https://tools.ietf.org/html/draft-ietf-rats-eat-04].
 */
static inline enum ctoken_err_t
ctoken_decode_cti(struct ctoken_decode_ctx *context,
                  struct q_useful_buf_c    *cti);


/**
 * \brief Decode the nonce.
 *
 * \param[in] context   The decoding context to decode from.
 * \param[out] nonce    Place to put pointer and length of nonce.
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
 * This gets the nonce claim out of the token.
 */
static inline enum ctoken_err_t
ctoken_decode_nonce(struct ctoken_decode_ctx *context,
                    struct q_useful_buf_c    *nonce);


/**
 * \brief Decode the UEID.
 *
 * \param[in] context  The decoding context to decode from.
 * \param[out] ueid    Place to put pointer and length of the UEID.
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
 * This gets the UEID claim out of the token.
 *
 * The UEID is the Universal Entity ID, an opaque binary blob that uniquely
 * identifies the device.
 */
static inline enum ctoken_err_t
ctoken_decode_ueid(struct ctoken_decode_ctx *context,
                   struct q_useful_buf_c    *ueid);


/**
 * \brief Decode the OEMID, identifier of the manufacturer of the device.
 *
 * \param[in] context  The decoding context to decode from.
 * \param[out] oemid   Place to put pointer and length of the OEMID.
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
 * This gets the OEMID claim out of the token.
 *
 * The OEMID is an opaque binary blob that identifies the manufacturer.
 */
static inline enum ctoken_err_t
ctoken_decode_oemid(struct ctoken_decode_ctx *context,
                    struct q_useful_buf_c    *oemid);


/**
 * \brief Decode the origination string.
 *
 * \param[in] context       The decoding context to decode from.
 * \param[out] origination  Place to put pointer and length of the origination.
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
 * This gets the origination claim out of the token.
 *
 * This describes the part of the device that created the token. It
 * is a text string or a URI.
 */
static inline enum ctoken_err_t
ctoken_decode_origination(struct ctoken_decode_ctx *context,
                          struct q_useful_buf_c    *origination);


/**
 * \brief Decode the security level
 *
 * \param[in] context          The decoding context to decode from.
 * \param[out] security_level  Place to put security level.

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
 * This gets the security level claim out of the token.
 *
 * The security level gives a rough indication of how security
 * the HW and SW are.  See \ref ctoken_security_level_t.
 */
static inline enum ctoken_err_t
ctoken_decode_security_level(struct ctoken_decode_ctx         *context,
                             enum ctoken_security_level_t *security_level);


/**
 * \brief Decode the boot and debug state claim.
 *
 * \param[in] context               The decoding context to decode from.
 * \param[out] secure_boot_enabled  This is \c true if secure boot
 *                                  is enabled or \c false it no.
 * \param[out] debug_state          See \ref ctoken_debug_level_t for
 *                                  the different debug states.
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
 * This gets the boot and debug state out of the token.
 *
 * The security level gives a rough indication of how security
 * the HW and SW are.  See \ref ctoken_security_level_t.
 */
enum ctoken_err_t
ctoken_decode_boot_state(struct ctoken_decode_ctx *context,
                         bool                     *secure_boot_enabled,
                         enum ctoken_debug_level_t *debug_state);


/**
 * \brief Decode position location (e.g. GPS location)
 *
 * \param[in] context   The decoding context to decode from.
 * \param[out] location The returned location
 *
 * \retval CTOKEN_ERR_NOT_FOUND             No location claims exists.
 * \retval CTOKEN_ERR_CBOR_NOT_WELL_FORMED  CBOR is not well formed.
 * \retval CTOKEN_ERR_CLAIM_FORMAT          The location claim format is bad.
 *
 * This finds the location claim in the token and returns its
 * contents.
 *
 * Only some of the values in the location claim may be present. See
 * \ref ctoken_location_t for how the data is returned.
 */
enum ctoken_err_t
ctoken_decode_location(struct ctoken_decode_ctx     *context,
                       struct ctoken_location_t *location);


/**
 * \brief  Decode the uptime claim.
 *
 * \param[in] context         The decoding context.
 * \param[in] uptime          The uptime in seconds since boot or restart.
 *
 * This decodes the uptime claim.
 *
 * This is the time in seconds since the device booted or started.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when
 * ctoken_encode_finish() is called.
 */
static inline enum ctoken_err_t
ctoken_decode_uptime(struct ctoken_decode_ctx *context,
                     uint64_t                 *uptime);



/**
 * \brief Get the number of submodules.
 *
 * \param[in] context         The decoding context.
 * \param[out] num_submods     The returned number of submodules.
 *
 * \returns A ctoken error code
 *
 * This returns the number of submodules at the current submodule
 * nesting level.
 */
enum ctoken_err_t
ctoken_decode_get_num_submods(struct ctoken_decode_ctx *context,
                              uint32_t                 *num_submods);

/**
 * \brief Enter the nth submodule.
 *
 * \param[in] context       The decoding context.
 * \param[in] submod_index  Index of the submodule to enter.
 * \param[out] name         The returned string name of the submodule.
 *
 * \returns A ctoken error code
 *
 * After this call, all claims fetched will be from the submodule that
 * was entered.  This, and the other functions to enter submodules,
 * may be called multiple times to enter nested submodules.
 *
 * The \c name parameter may be NULL if the submodule name is not of
 * interest.
 */
enum ctoken_err_t
ctoken_decode_enter_nth_submod(struct ctoken_decode_ctx *context,
                               uint32_t                  submod_index,
                               struct q_useful_buf_c    *name);


/**
 * \brief Enter a submodule by name.
 *
 * \param[in] context         The decoding context.
 * \param[in] name     The name of the submodule to enter.
 *
 * \returns A ctoken error code
 *
 * After this call, all claims fetched will be from the submodule that
 * was entered.  This, and the other functions to enter submodules,
 * may be called multiple times to enter nested submodules.
 */
enum ctoken_err_t
ctoken_decode_enter_submod_sz(struct ctoken_decode_ctx *context,
                              const char               *name);


/**
 * \brief Exit one submodule level.
 *
 * \param[in] context         The decoding context.
 *
 * \returns A ctoken error code
 *
 * Pop up one level of submodule nesting.
 */
enum ctoken_err_t
ctoken_decode_exit_submod(struct ctoken_decode_ctx *context);


/**
 * \brief Get the nth nested token.
 *
 * \param[in] context       The decoding context.
 * \param[in] submod_index  Index of the submodule to fetch.
 * \param[out] type         The type of the nested token returned.
 * \param[out] token        Pointer and length of the token returned.
 *
 * \returns A ctoken error code.
 *
 * A submodule may be a signed and secured token. Such submodules are
 * returned as a byte or text string. To process these that are in CWT
 * format, create a new instance of the ctoken decoder, set up the
 * verification keys and process it like the superior token it came
 * from. JWT format tokens must be processed by a JWT token decoder.
 */
enum ctoken_err_t
ctoken_decode_get_nth_nested_token(struct ctoken_decode_ctx *context,
                                   uint32_t                  submod_index,
                                   enum ctoken_type         *type,
                                   struct q_useful_buf_c    *token);


/**
 * \brief Get a nested token by name.
 *
 * \param[in] context  The decoding context.
 * \param[in] name     Index of the submodule to fetch.
 * \param[out] type    The type of the nested token returned.
 * \param[out] token   Pointer and length of the token returned.
 *
 * \returns A ctoken error code
 *
 * See ctoken_decode_get_nth_nested_token() for discussion on the
 * token returned.
 */
enum ctoken_err_t
ctoken_decode_get_nested_token_sz(struct ctoken_decode_ctx *context,
                                  const char               *name,
                                  enum ctoken_type         *type,
                                  struct q_useful_buf_c    *token);




/* ====================================================================
 *   Inline Implementations
 * ==================================================================== */


static inline void
ctoken_decode_set_verification_key(struct ctoken_decode_ctx *me,
                                   struct t_cose_key         verification_key)
{
    t_cose_sign1_set_verification_key(&(me->verify_context), verification_key);
}


static inline enum ctoken_err_t
ctoken_decode_get_error(struct ctoken_decode_ctx *me)
{
    return me->last_error;
}


static inline enum ctoken_err_t
ctoken_decode_issuer(struct ctoken_decode_ctx *me,
                     struct q_useful_buf_c    *issuer)
{
    return ctoken_decode_get_tstr(me, CTOKEN_CWT_LABEL_ISSUER, issuer);
}


static inline enum ctoken_err_t
ctoken_decode_subject(struct ctoken_decode_ctx *me,
                      struct q_useful_buf_c    *subject)
{
    return ctoken_decode_get_tstr(me, CTOKEN_CWT_LABEL_SUBJECT, subject);
}


static inline enum ctoken_err_t
ctoken_decode_audience(struct ctoken_decode_ctx *me,
                       struct q_useful_buf_c    *audience)
{
    return ctoken_decode_get_tstr(me, CTOKEN_CWT_LABEL_AUDIENCE, audience);
}


static inline enum ctoken_err_t
ctoken_decode_expiration(struct ctoken_decode_ctx *me,
                         int64_t                  *expiration)
{
    return ctoken_decode_get_int(me, CTOKEN_CWT_LABEL_EXPIRATION, expiration);
}

static inline enum ctoken_err_t
ctoken_decode_not_before(struct ctoken_decode_ctx *me,
                         int64_t                  *not_before)
{
    return ctoken_decode_get_int(me, CTOKEN_CWT_LABEL_NOT_BEFORE, not_before);
}


static inline enum ctoken_err_t
ctoken_decode_iat(struct ctoken_decode_ctx *me,
                  int64_t                  *iat)
{
    return ctoken_decode_get_int(me, CTOKEN_CWT_LABEL_NOT_BEFORE, iat);
}


static inline enum ctoken_err_t
ctoken_decode_cti(struct ctoken_decode_ctx *me,
                  struct q_useful_buf_c    *cti)
{
    return ctoken_decode_get_bstr(me, CTOKEN_CWT_LABEL_CTI,  cti);
}


static inline enum ctoken_err_t
ctoken_decode_nonce(struct ctoken_decode_ctx *me,
                    struct q_useful_buf_c    *nonce)
{
    return ctoken_decode_get_bstr(me, CTOKEN_EAT_LABEL_NONCE, nonce);
}


static inline enum ctoken_err_t
ctoken_decode_ueid(struct ctoken_decode_ctx *me,
                   struct q_useful_buf_c    *ueid)
{
    return ctoken_decode_get_bstr(me, CTOKEN_EAT_LABEL_UEID, ueid);
}


static inline enum ctoken_err_t
ctoken_decode_oemid(struct ctoken_decode_ctx *me,
                    struct q_useful_buf_c    *oemid)
{
    return ctoken_decode_get_bstr(me, CTOKEN_EAT_LABEL_OEMID, oemid);
}


static inline enum ctoken_err_t
ctoken_decode_origination(struct ctoken_decode_ctx *me,
                          struct q_useful_buf_c    *origination)
{
    return ctoken_decode_get_tstr(me, CTOKEN_EAT_LABEL_ORIGINATION, origination);
}


static inline enum ctoken_err_t
ctoken_decode_security_level(struct ctoken_decode_ctx         *me,
                             enum ctoken_security_level_t *security_level)
{
    return ctoken_decode_get_int(me, CTOKEN_EAT_LABEL_SECURITY_LEVEL, (int64_t *)security_level);
}


static inline enum ctoken_err_t
ctoken_decode_uptime(struct ctoken_decode_ctx *me,
                     uint64_t                 *uptime)
{
    return ctoken_decode_get_uint(me, CTOKEN_EAT_LABEL_UPTIME, uptime);
}


#ifdef __cplusplus
}
#endif

#endif /* __CTOKEN_DECODE_H__ */
