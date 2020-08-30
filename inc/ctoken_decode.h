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

#ifdef __cplusplus
extern "C" {
#ifdef 0
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
 * order. Also call the ctoken_eat_decode_xxx(), ctoken_cwt_decode_xxx() and
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
    /* PRIVATE DATA STRUCTURE. USE ACCESSOR FUNCTIONS. */
    struct t_cose_sign1_verify_ctx verify_context;
    struct q_useful_buf_c          payload;
    uint32_t                       options;
    enum ctoken_err_t              last_error;
    QCBORDecodeContext             qcbor_decode_context;
};


/**
 * \brief Initialize token decoder.
 *
 * \param[in] me             gtThe token decoder context to be initialized.
 * \param[in] t_cose_options Options passed to t_cose verification.
 * \param[in] token_options  Decoding options.
 *
 * Must be called on a \ref attest_token_decode_context before
 * use. An instance of \ref attest_token_decode_context can
 * be used again by calling this on it again.
 **/
void ctoken_decode_init(struct ctoken_decode_ctx *me,
                        uint32_t t_cose_options,
                        uint32_t token_options);


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
                                   struct t_cose_key verification_key);



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
                      struct q_useful_buf_c token,
                      struct q_useful_buf_c *kid);


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
                             struct q_useful_buf_c token);


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
ctoken_decode_get_bstr(struct ctoken_decode_ctx    *me,
                       int32_t                label,
                       struct q_useful_buf_c *claim);


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
                       int32_t label,
                       struct q_useful_buf_c *claim);


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
                      int32_t label,
                      int64_t *claim);


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
                       int32_t label,
                       uint64_t *claim);




/* ====================================================================
 *   Inline Implementations
 *   Typically, these are small and called only once.
 * ==================================================================== */


static inline void
ctoken_decode_set_verification_key(struct ctoken_decode_ctx *me,
                                   struct t_cose_key verification_key) {

    t_cose_sign1_set_verification_key(&(me->verify_context), verification_key);
}


static inline enum ctoken_err_t
ctoken_decode_get_error(struct ctoken_decode_ctx *me)
{
    return me->last_error;
}


#ifdef __cplusplus
}
#endif

#endif /* __CTOKEN_DECODE_H__ */
