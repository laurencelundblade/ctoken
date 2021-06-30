/*
 * ctoken_decode.h (formerly attest_token_decode.h)
 *
 * Copyright (c) 2019-2021, Laurence Lundblade.
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
#include "qcbor/qcbor_spiffy_decode.h"

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
 * order. Also call the ctoken_decode_xxx() and
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
 *
 *  \anchor Token-Decode-Errors-Overview
 * # Token Decode Errors Overview
 *
 * The main validation and decoding of claims is designed so that
 * there can be only an error check at the end of fetching all the
 * claims. The error state is tracked inside the decode context, so
 * the caller doesn't need to check a return value on the decode of
 * every claim. Once ctoken encounters an error it enters an error
 * state and further decode calls don't do anything, so it is safe to
 * continue decoding as if there was no error. In many uses the only error check is calling
 * ctoken_decode_get_error() once after all claims have been decoded
 * making the decode implementation very neat.
 *
 * Sometimes claim values need to be referenced before all claims have
 * been decoded. In those cases the error state must be checked before
 * the all claim values have been decoded. Fetching the error status
 * is very inexpensive.
 *
 * CBOR is not a redundant data format. To traverse a token to find a
 * requested claim all the claims the token must be well-formed CBOR.
 * Thus, even if a claim requested is well-formed and valid, it will
 * not be possible to retrieve it or any other claim if any single
 * claim in the token is not well-formed.
 *
 * CBOR and this implementation distinguish not well-formed CBOR from
 * invalid CBOR.  It is possible to traverse invalid CBOR and continue
 * on to decode claims. That is, if a claim is invalid, it will not
 * prevent the decoding of other claims, but will cause an error when
 * a call is made to decode it.
 *
 * The decoding of any particular claim is partially independent of
 * decoding other claims. As long as all the claims are well-formed
 * the error state resulting from one invalid claim can be reset so
 * that other claims can be decoded. This is by calling
 * ctoken_decode_get_and_reset_error().
 *
 * For example, if the latitude in the location claim is a boolean
 * value, the retrieval of the location claim will fail, but that
 * error can be reset and decoding for other claims is possible.
 *
 * On the other hand, if the CBOR of the location claim is not-well
 * formed, then the whole CBOR decode of the token will fail and no
 * other claims can be fetched.
 *
 * There is no finish method like QCBOR has because it is
 * unnecessary. It is unnecessary to retrieve all the claims in a
 * token when decoding. Retrieval of any claim in a token will cause
 * the general validation of the CBOR of the whole token to
 * happen. All that is necessary is to check the error before
 * referencing any decoded claim values.
 */

/** The maximum number of tag numbers on the token that were not processed.
 * Any tag number that is not supported by ctoken will be returned so
 * the caller can try to processed them.
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
 * Aproximate size on 64-bit CPU: 432 bytes.
 */
struct ctoken_decode_ctx {
    /* PRIVATE DATA STRUCTURE */
    struct t_cose_sign1_verify_ctx verify_context;
    struct q_useful_buf_c          payload;
    uint32_t                       ctoken_options;
    enum ctoken_err_t              last_error;
    QCBORDecodeContext             qcbor_decode_context;
    uint8_t                        submod_nest_level;
    uint64_t                       auTags[CTOKEN_MAX_TAGS_TO_RETURN];
    enum ctoken_protection_t       protection_type;
    enum ctoken_protection_t       actual_protection_type;
};



/** Passed to ctoken_decode_init(). Decoding requires a UCCS or CWT tag. It cannot be a bare CWT or UCCS.
 */
#define CTOKEN_OPT_REQUIRE_TOP_LEVEL_TAG 0x01

/**
 Passed to ctoken_decode_init(). Decoding requires a bare CWT or UCCS. The input can't be
 a UCCS or CWT tag. When the input is a bare CWT, it can still be a COSE tag.
 */
#define CTOKEN_OPT_PROHIBIT_TOP_LEVEL_TAG 0x02


/**
 * \brief Initialize token decoder.
 *
 * \param[in] context          The token decoder context to be initialized.
 * \param[in] t_cose_options   Options passed to t_cose verification.
 * \param[in] ctoken_options   Decoding options.
 * \param[in] protection_type  The protection type if indicated by tag.
 *
 * Must be called on a \ref ctoken_decode_ctx before
 * use. An instance of \ref ctoken_decode_ctx can
 * be used again by calling this on it again.
 *
 * The protection type may or may not be indicated by the CBOR tag(s)
 * on the token passed to ctoken_decode_validate_token(). If it is indicated
 * \c protection_type given here is ignored. If the CBOR tag(s) don't
 * indicate the protection type, then it must be given here for the decoder
 * to know what to do. The value for this parameter usually comes from
 * the file type, content type, MIME type or such associated with the
 * transmission of the token.
 *
 * If the token itself indicates the protection
 * type, that indication overrides the \c protection_type parameter
 * given here. Use ctoken_decode_get_protection_type() to know
 * the actual protection type that was decoded.
 *
 * By default, the input token can be a tag or not as long as the protection
 * type can be determined. To require it to always be a tag pass
 * \ref CTOKEN_OPT_REQUIRE_TOP_LEVEL_TAG for
 * \c ctoken_options. To prohibit it from being a tag, pass
 * \ref CTOKEN_OPT_PROHIBIT_TOP_LEVEL_TAG. These
 * options work on the CWT tag and the UCCS tag.
 *
 * Whether the COSE part of a CWT is a tag or not is governed by the
 * t_cose tag options given in \ref t_cose_options. See T_COSE_OPT_TAG_REQUIRED
 * and T_COSE_OPT_TAG_PROHIBITED in the t_cose documentation.
 *
 * See also \ref TagsAndProtection
 */
void ctoken_decode_init(struct ctoken_decode_ctx *context,
                        uint32_t                  t_cose_options,
                        uint32_t                  ctoken_options,
                        enum ctoken_protection_t  protection_type);


/**
 * \brief Set specific public key to use for verification.
 *
 * \param[in] context           The token decoder context to configure.
 * \param[in] verification_key  The key used for verification.
 *
 * The \c verification_key is a structure defined in t_cose to
 * generically hold a key for different algorithms and different
 * cryptographic libraries. See its definition in
 * t_cose_common.h. This is left abstract like this so ctoken (and
 * t_cose) can work with multiple cryptographic libraries and still
 * have small code size.
 *
 * The key given here must be for the one your particular instance of
 * ctoken is integrated with. Openssl is the most likely.
 *
 * Once set, a key can be used for multiple verifications.
 *
 * Calling this again will replace the previous key that was
 * configured.
 *
 * How to find the verification key? That depends on the particular
 * profile of EAT. In many cases the verifier must get the key
 * out-of-band. The key may or may not be identified by the kid.
 * Another possible scenario is the key is in a certificate in the EAT
 * in a COSE header parameter. An API to extract it is not yet
 * provided here.
 */
static inline void
ctoken_decode_set_verification_key(struct ctoken_decode_ctx *context,
                                   struct t_cose_key         verification_key);


/**
 * \brief Get the kid (key ID) from the token
 *
 * \param[in] context     The token decoder context.
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
ctoken_decode_get_kid(struct ctoken_decode_ctx *context,
                      struct q_useful_buf_c     token,
                      struct q_useful_buf_c    *kid);


/**
 * \brief Set the token to work on and validate its signature.
 *
 * \param[in] context           The token decoder context to validate with.
 * \param[in] token             The CBOR-encoded token to validate and decode.
 *
 * The signature on the token is validated. If it is successful the
 * token and its payload are remembered in the \ref
 * ctoken_decode_ctx \c context so the \c
 * ctoken_decode_get_xxx() functions can be called to get the
 * various claims out of it.
 *
 * Generally, a public key has to be configured for this to work. It
 * can however validate short-circuit signatures even if one is not
 * set.
 *
 * This may result in many different errors, including signature
 * verification errors.  The error result is saved in the @ref
 * ctoken_decode_ctx and can be obtained by calling
 * ctoken_decode_get_error(). It is OK to follow this call with calls
 * to decode many claims as long as none of the values of the claims
 * are used until the error result is checked. The calls to fetch
 * claims will do nothing if the token validation failed.  See [Token
 * Decode Error Overview](#Token-Decode-Errors-Overview).
 *
 *
 * TODO: this may need an option to be able to decode fields in the
 * token without signature verification because the info to look
 * up the verification key is the token, not the COSE key id.
 */
void
ctoken_decode_validate_token(struct ctoken_decode_ctx *context,
                             struct q_useful_buf_c     token);


/**
 * \brief Get the actual protection type that was used on the token.
 *
 * \param[in] context The token decoder context.
 *
 * \return The protection type from \ref ctoken_protection_t.
 *
 * This must be called after ctoken_decode_validate_token() and it must have
 * succeeded.
 */
static enum ctoken_protection_t
ctoken_decode_get_protection_type(const struct ctoken_decode_ctx *context);


/**
 * \brief Get the decode error.
 *
 * \param[in] context The token decoder context.
 *
 * \return An error from \ref CTOKEN_ERR_t.
 */
static enum ctoken_err_t
ctoken_decode_get_error(struct ctoken_decode_ctx *context);


/**
 * \brief Get and reset the decode error.
 *
 * \param[in] context The token decoder context.
 *
 * \return An error from \ref CTOKEN_ERR_t.
 *
 * In addition to returning the decode error, this resets it to \ref
 * CTOKEN_ERR_SUCCESS so the last error can be ignored and decoding
 * can proceed. This is useful to decode further claims if one is
 * invalid. Note however, it is usually not possible to decode other
 * claims if one claim is not well-formed.
 */
static inline enum ctoken_err_t
ctoken_decode_get_and_reset_error(struct ctoken_decode_ctx *context);

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
 * \param[in]  context      The token decoder context.
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
ctoken_decode_get_payload(struct ctoken_decode_ctx *context,
                          struct q_useful_buf_c    *payload);


/**
 * \brief Get the QCBOR decoder context.
 *
 * \param[in]  context    The token decoder context.
 * \returns The QCBOR decoder context
 *
 * Use this to decode claims that are not supported
 * by ctoken. This allows use of all the QCBORDecode
 * functions.
 *
 * Some care is needed when using this to avoid confusing
 * ctoken's internal state, particularly when decoding
 * submodules. Use of spiffy decode functions to find
 * data items in the map works well. The CBOR nesting
 * level must be left the same as it was before the
 * claim(s) were decoded.
 *
 * See also ctoken_decode_enter_array() and
 * ctoken_decode_enter_map()
 *
 * If the decoder is in the error state, this will return NULL.
 */
static QCBORDecodeContext *
ctoken_decode_borrow_context(struct ctoken_decode_ctx *context);


/**
 * \brief Get a claim of type signed integer.
 *
 * \param[in]  context    The token decoder context.
 * \param[in]  label The integer label identifying the claim.
 * \param[out] claim The signed integer.
 *
 * This will succeed if the CBOR type of the claim is either a
 * positive or negative integer as long as the value is between \c
 * INT64_MIN and \c INT64_MAX.
 *
 * See also ctoken_decode_get_uint() and ctoken_decode_int_constrained().
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
void
ctoken_decode_int(struct ctoken_decode_ctx *context,
                  int64_t                   label,
                  int64_t                  *claim);


/**
 * \brief Get a claim of type signed integer with constraints.
 *
 * \param[in]  context  The token decoder context.
 * \param[in]  label    The integer label identifying the claim.
 * \param[in]  min      The decoded claim must be smaller than this.
 * \param[in]  max      The decoded claim must be larger than this.
 * \param[out] claim    Place to return the claim value.
 *
 * This is the same as ctoken_decode_get_int() except the error \ref
 * CTOKEN_ERR_CLAIM_RANGE is returned if the decoded value is less
 * than \c min or more than \c max.
 *
 * This is useful for claims that are a range of integer values that
 * usually fit into an enumerated type.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
void
ctoken_decode_int_constrained(struct ctoken_decode_ctx *context,
                              int64_t                   label,
                              int64_t                   min,
                              int64_t                   max,
                              int64_t                  *claim);


/**
 * \brief Get a claim of type unsigned integer.
 *
 * \param[in]  context    The token decoder context.
 * \param[in]  label The integer label identifying the claim.
 * \param[out] claim The unsigned integer.
 *
 * This will succeed if the CBOR type of the claim is either a
 * positive or negative integer as long as the value is between 0 and
 * \c MAX_UINT64.
 *
 * See also ctoken_decode_get_int().
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
void
ctoken_decode_uint(struct ctoken_decode_ctx *context,
                   int64_t                  label,
                   uint64_t                *claim);


/**
 *
 * \brief Get a claim of type byte string.
 *
 * \param[in]  context    The token decoder context.
 * \param[in]  label The integer label identifying the claim.
 * \param[out] claim The byte string or \c NULL_Q_USEFUL_BUF_C.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). Also, on error
 * \c NULL_Q_USEFUL_BUF_C will be returned for the claim value.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
void
ctoken_decode_bstr(struct ctoken_decode_ctx  *context,
                   int64_t                    label,
                   struct q_useful_buf_c     *claim);


/**
 * \brief Get a claim of type text string.
 * string.
 *
 * \param[in] context     The token decoder context.
 * \param[in] label  The integer label identifying the claim.
 * \param[out] claim The text string or \c NULL_Q_USEFUL_BUF_C.
 *
 * Even though this is a text string, it is not NULL-terminated.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). Also, on error
 * \c NULL_Q_USEFUL_BUF_C will be returned for the claim value.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
void
ctoken_decode_tstr(struct ctoken_decode_ctx *context,
                   int64_t                   label,
                   struct q_useful_buf_c    *claim);


/**
 * \brief Get a claim of type boolean
 *
 * \param[in]  context    The token decoder context.
 * \param[in]  label The integer label identifying the claim.
 * \param[out] claim The boolean value tha t is returned.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
void
ctoken_decode_bool(struct ctoken_decode_ctx *context,
                   int64_t                   label,
                   bool                     *claim);


/**
 * \brief Get a claim of type double.
 *
 * \param[in]  context    The token decoder context.
 * \param[in]  label The integer label identifying the claim.
 * \param[out] claim The double value tha t is returned.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
void
ctoken_decode_double(struct ctoken_decode_ctx *context,
                     int64_t                  label,
                     double                  *claim);


/**
 * \brief Start decoding a claim that is an array.
 *
 * \param[in]  context  The token decoder context.
 * \param[in]  label    The integer label identifying the claim.
 * \param[out] decoder  Instance of the CBOR decoder from which to
 *                      get array items or \c NULL on error.
 *
 * After some or all the items in the array have been retrieved, call
 * ctoken_decode_exit_array().
 *
 * This is  mostly a wrapper around QCBORDecode_EnterArrayFromMapN() from
 * QCBOR spiffy decode.  It enters the array in bounded mode.  Methods
 * like QCBORDecode_GetNext(), QCBORDecode_GetInt64() and
 * QCBORDecode_GetTextString() can then be called until one returns \ref
 * QCBOR_ERR_NO_MORE_ITEMS.  The array may contain other arrays and
 * maps.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). Also, on error
 * \c NULL will be returned for decoder context.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
void
ctoken_decode_enter_array(struct ctoken_decode_ctx *context,
                          int64_t                   label,
                          QCBORDecodeContext      **decoder);


/**
 * \brief End decoding a claim that is an array.
 *
 * \param[in]  context  The token decoder context.
 *
 * This ends decoding of a claim that is an array started by
 * ctoken_decode_enter_array().
 *
 * This is mostly a wrapper around QCBORDecode_ExitArray() from CBOR
 * spiffy decode.  Any maps or arrays subordinate to the main array of
 * the claim must be exitied if they were entered before this is
 * called.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error result
 * should be checked to know the array was well-formed and valid.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
void
ctoken_decode_exit_array(struct ctoken_decode_ctx *context);


/**
 * \brief Start decoding a claim that is a map.
 *
 * \param[in]  context  The token decoder context.
 * \param[in]  label    The integer label identifying the claim.
 * \param[out] decoder  Instance of the CBOR decoder from which to
 *                      get map items or \c NULL.
 *
 * After some or all the items in the map have been retrieved, call
 * ctoken_decode_exit_map().
 *
 * This is mostly a wrapper around QCBORDecode_EnterMapFromMapN() from
 * QCBOR spiffy decode.  It enters the map in bounded mode.  Methods
 * like QCBORDecode_GetInt64InMapN(),
 * QCBORDecode_GetTextStringInMapN() and
 * QCBORDecode_EnterArrayFromMapN() can then be called.  The map may
 * contain other arrays and maps.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). Also, on error
 * \c NULL will be returned for decoder context.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
void
ctoken_decode_enter_map(struct ctoken_decode_ctx *context,
                        int64_t                   label,
                        QCBORDecodeContext      **decoder);


/**
 * \brief End decoding a claim that is an map.
 *
 * \param[in]  context  The token decoder context.
 *
 * This ends decoding of a claim that is an array started by
 * ctoken_decode_enter_map().
 *
 * This is mostly a wrapper around QCBORDecode_ExitMap() from CBOR
 * spiffy decode.  Any maps or arrays subordinate to the main array of
 * the claim must be exitied if they were entered before this is
 * called.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error result
 * should be checked to know the map was well-formed and valid.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
void
ctoken_decode_exit_map(struct ctoken_decode_ctx *context);


/**
 * \brief Decode the CWT issuer.
 *
 * \param[in] context  The decoding context to decode from.
 * \param[out] issuer  Place to put pointer and length of the issuer claim.
 *
 *  The principle that created the token. It is a text string or a URI as described in
 *  [RFC 8392](https://tools.ietf.org/html/rfc8392#section-3.1.1)
 * and [RFC 7519] (https://tools.ietf.org/html/rfc7519#section-4.1.1).
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static inline void
ctoken_decode_issuer(struct ctoken_decode_ctx *context,
                     struct q_useful_buf_c    *issuer);


/**
 * \brief Decode the CWT subject claim.
 *
 * \param[in] context   The decoding context to decode from.
 * \param[out] subject  Place to put pointer and length of the subject claim.
 *
 * Identifies the subject of the token. It is a text string or URI as described in
 * [RFC 8392](https://tools.ietf.org/html/rfc8392#section-3.1.2)
 * and [RFC 7519] (https://tools.ietf.org/html/rfc7519#section-4.1.2).
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static inline void
ctoken_decode_subject(struct ctoken_decode_ctx *context,
                      struct q_useful_buf_c    *subject);


/**
 * \brief Decode the CWT audience claim.
 *
 * \param[in] context    The decoding context to decode from.
 * \param[out] audience  Place to put pointer and length of the audience claim.
 *
 * This identifies the recipient for which the token is intended. It is
 * a text string or URI as
 * described in [RFC 8392](https://tools.ietf.org/html/rfc8392#section-3.1.3)
 * and [RFC 7519] (https://tools.ietf.org/html/rfc7519#section-4.1.3).
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static inline void
ctoken_decode_audience(struct ctoken_decode_ctx *context,
                       struct q_useful_buf_c    *audience);


/**
 * \brief Decode the CWT expiration claim.
 *
 * \param[in] context      The decoding context to decode from.
 * \param[out] expiration  Place to return expiration claim.
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
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static inline void
ctoken_decode_expiration(struct ctoken_decode_ctx *context,
                         int64_t                  *expiration);


/**
 * \brief Decode the CWT not-before claim.
 *
 * \param[in] context      The decoding context to decode from.
 * \param[out] not_before  Place to return the not-before claim.
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
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static inline void
ctoken_decode_not_before(struct ctoken_decode_ctx *context,
                         int64_t                  *not_before);


/**
 * \brief Decode the CWT and EAT issued-at claim.
 *
 * \param[in] context  The decoding context to decode from.
 * \param[out] iat     Place to put pointer and length of the issued-at claim.
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
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static inline void
ctoken_decode_iat(struct ctoken_decode_ctx *context,
                  int64_t                  *iat);


/**
 * \brief Decode the CWT and EAT ID claim.
 *
 * \param[in] context  The decoding context to decode from.
 * \param[out] cti     Place to put pointer and length of the CWT ID claim.
 *
 * This is a byte string that uniquely identifies the token.
 *
 * [RFC 8392](https://tools.ietf.org/html/rfc8392#section-3.1.7)
 * and [RFC 7519] (https://tools.ietf.org/html/rfc7519#section-4.1.7).
 * This claim is also used by (EAT)[https://tools.ietf.org/html/draft-ietf-rats-eat-04].
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static inline void
ctoken_decode_cti(struct ctoken_decode_ctx *context,
                  struct q_useful_buf_c    *cti);


/**
 * \brief Decode the nonce.
 *
 * \param[in] context   The decoding context to decode from.
 * \param[out] nonce    Place to put pointer and length of nonce.
 *
 * This gets the nonce claim out of the token.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static inline void
ctoken_decode_nonce(struct ctoken_decode_ctx *context,
                    struct q_useful_buf_c    *nonce);


/**
 * \brief Decode the UEID.
 *
 * \param[in] context  The decoding context to decode from.
 * \param[out] ueid    Place to put pointer and length of the UEID.
 *
 * This gets the UEID claim out of the token.
 *
 * The UEID is the Universal Entity ID, an opaque binary blob that uniquely
 * identifies the device.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static inline void
ctoken_decode_ueid(struct ctoken_decode_ctx *context,
                   struct q_useful_buf_c    *ueid);


/**
 * \brief Decode the OEMID, identifier of the manufacturer of the device.
 *
 * \param[in] context  The decoding context to decode from.
 * \param[out] oemid   Place to put pointer and length of the OEMID.
 *
 * This gets the OEMID claim out of the token.
 *
 * The OEMID is an opaque binary blob that identifies the manufacturer.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static inline void
ctoken_decode_oemid(struct ctoken_decode_ctx *context,
                    struct q_useful_buf_c    *oemid);


/**
 * \brief Decode the origination string.
 *
 * \param[in] context       The decoding context to decode from.
 * \param[out] origination  Place to put pointer and length of the origination.
 *
 * This gets the origination claim out of the token.
 *
 * This describes the part of the device that created the token. It
 * is a text string or a URI.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static inline void
ctoken_decode_origination(struct ctoken_decode_ctx *context,
                          struct q_useful_buf_c    *origination);


/**
 * \brief Decode the security level
 *
 * \param[in] context          The decoding context to decode from.
 * \param[out] security_level  Place to put security level.
 *
 * This gets the security level claim out of the token.
 *
 * The security level gives a rough indication of how security
 * the HW and SW are.  See \ref ctoken_security_level_t.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static void
ctoken_decode_security_level(struct ctoken_decode_ctx         *context,
                             enum ctoken_security_level_t *security_level);


/**
 * \brief Decode the boot and debug state claim.
 *
 * \param[in] context               The decoding context to decode from.
 * \param[out] secure_boot_enabled  This is \c true if secure boot
 *                                  is enabled or \c false it no.
 *
 * This gets the boot and debug state out of the token.
 *
 * The security level gives a rough indication of how security
 * the HW and SW are.  See \ref ctoken_security_level_t.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static void
ctoken_decode_secure_boot(struct ctoken_decode_ctx *context,
                          bool                     *secure_boot_enabled);


/**
 * \brief Decode the boot and debug state claim.
 *
 * \param[in] context               The decoding context to decode from.
 * \param[out] debug_state          See \ref ctoken_debug_level_t for
 *                                  the different debug states.
 *
 * This gets the boot and debug state out of the token.
 *
 * The security level gives a rough indication of how security
 * the HW and SW are.  See \ref ctoken_security_level_t.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static void
ctoken_decode_debug_state(struct ctoken_decode_ctx  *context,
                          enum ctoken_debug_level_t *debug_state);


/**
 * \brief Decode position location (e.g. GPS location)
 *
 * \param[in] context   The decoding context to decode from.
 * \param[out] location The returned location
 *
 * This finds the location claim in the token and returns its
 * contents.
 *
 * Only some of the values in the location claim may be present. See
 * \ref ctoken_location_t for how the data is returned.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
void
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
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static void
ctoken_decode_uptime(struct ctoken_decode_ctx *context,
                     uint64_t                 *uptime);


/**
 * \brief  Decode the intended use claim.
 *
 * \param[in] context  The decoding context.
 * \param[in] use      See \ref ctoken_intended_use_t for meaning of values.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static void
ctoken_decode_intended_use(struct ctoken_decode_ctx   *context,
                           enum ctoken_intended_use_t *use);


/**
 * \brief  Decode an OID-format profile claim.
 *
 * \param[in] context  The decoding context.
 * \param[out] uri     The decoded URI.
 *
 * See also ctoken_decode_profile_uri() and ctoken_decode_profile().
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static inline void
ctoken_decode_profile_oid(struct ctoken_decode_ctx *context,
                          struct q_useful_buf_c    *uri);


/**
 * \brief  Decode a URI-format profile claim.
 *
 * \param[in] context  The decoding context.
 * \param[out] uri     The decoded URI.
 *
 * See also ctoken_decode_profile_oid() and ctoken_decode_profile().
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static inline void
ctoken_decode_profile_uri(struct ctoken_decode_ctx *context,
                          struct q_useful_buf_c    *uri);


/**
 * \brief  Decode profile claim in either URI or OID format
 *
 * \param[in] context  The decoding context.
 * \param[out] is_oid_format  True if the profile is oid format
 *                            false is uri format.
 * \param[out] profile   The decoded profile.
 *
 * This decodes either the oid or uri format profile claim,
 * returning \c is_oid_format to indicate which format.

 * See also ctoken_decode_profile_oid() and
 * ctoken_decode_profile_uri().
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static inline void
ctoken_decode_profile(struct ctoken_decode_ctx *context,
                      bool                     *is_oid_format,
                      struct q_useful_buf_c    *profile);


/**
 * \brief Decode next claim in token or submodule
 *
 * \param[in] context  The decoding context.
 * \param[out] claim      The decoded claim.
 *
 * All the claims in a token or submodule can be iterated over by
 * calling this until the end is indicated.  This will not descend in
 * to submodules. The various submodule-related tunctions must be
 * called to enter the submodule. Once a submodule is entered this can
 * be used to iterate over all the claims in it.
 *
 * This always returns the label for a claim, but can only return the
 * value for a claim that is a common non-aggregate type. For example,
 * the value for the UEID claim is returned because it is a byte
 * string, but the value for the location claim is not returned
 * because it is a map made up of several values.
 *
 * To decode values that aren't decoded by this function call the
 * specific function to decode that type of claim. Alternately, use
 * QCBOR decode functions to decode it. See
 * ctoken_decode_borrow_context().
 *
 * This uses \ref QCBORItem to return the claims. The nest level
 * fields are never filled in and should be ignored. The other fields
 * work as documented. In particular pay attention to uDataType to
 * know the type of value of the claim.
 *
 * When the claim is an aggregate type, and array or map, the data
 * type will indicate an array or map however iteration will not
 * descend into the array or map. Instead the whole content of the
 * array or map will be skipped over with the iteration going on to
 * the next claim. This is the main difference between this function
 * and QCBORDecode_GetNext().
 *
 * Note that this maintains its own iteration cursor indepdent of the
 * other functions for getting claims so calls to this can be
 * intermixed with the other calls.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error result
 * must be checked to know the claim returned is valid and that all
 * the claims have not been consumed.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
*/
void
ctoken_decode_next_claim(struct ctoken_decode_ctx   *context,
                         QCBORItem                  *claim);



/*
 *
 */
static void
ctoken_decode_rewind(struct ctoken_decode_ctx   *context);


/**
 * \brief Get the number of submodules.
 *
 * \param[in] context        The decoding context.
 * \param[out] num_submods   The returned number of submodules.
 *
 * This returns the number of submodules at the current submodule
 * nesting level. If there is no submodules section or it is
 * empty the error code returned is CTOKEN_ERR_SUCCESS and the
 * num_submods returned is 0.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must be
 * checked before use is made of the number of submodules returned.
 * See [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
void
ctoken_decode_get_num_submods(struct ctoken_decode_ctx *context,
                              uint32_t                 *num_submods);


/**
 * \brief Enter the nth submodule.
 *
 * \param[in] context        The decoding context.
 * \param[in] submod_index   Index of the submodule to enter.
 * \param[out] submod_name   The returned string name of the submodule.
 *
 * After this call, all claims fetched will be from the submodule that
 * was entered.  This, and the other functions to enter submodules,
 * may be called multiple times to enter nested submodules.
 *
 * If the submodule at the index is a nested token, then it is not
 * entered and \ref CTOKEN_ERR_SUBMOD_IS_A_TOKEN is returned.
 *
 * This does NOT check for duplicate labels. See
 * ctoken_decode_enter_named_submod()
 *
 * The \c name parameter may be NULL if the submodule name is not of
 * interest.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must be
 * checked before use is made of the submodule's name or of decoded
 * claims from the submodule.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
void
ctoken_decode_enter_nth_submod(struct ctoken_decode_ctx *context,
                               uint32_t                  submod_index,
                               struct q_useful_buf_c    *submod_name);


/**
 * \brief Enter a submodule by name.
 *
 * \param[in] context      The decoding context.
 * \param[in] submod_name  The name of the submodule to enter.
 *
 * After this call, all claims fetched will be from the submodule that
 * was entered.  This, and the other functions to enter submodules,
 * may be called multiple times to enter nested submodules.
 *
 * If the submodule with the given name is a nested token, then it is
 * not entered and \ref CTOKEN_ERR_SUBMOD_IS_A_TOKEN is returned.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must be
 * checked before use is made of decoded claims from the submodule.
 * See [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
void
ctoken_decode_enter_named_submod(struct ctoken_decode_ctx *context,
                                 const char               *submod_name);


/**
 * \brief Exit one submodule level.
 *
 * \param[in] context   The decoding context.
 *
 * Pop up one level of submodule nesting.
 *
 * This may result in an error as the end of the submodule must
 * be found, but usually any such error will show up earlier when
 * decoding claims in the submodule.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error can be
 * checked to be sure the submodule was fully valid .  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
void
ctoken_decode_exit_submod(struct ctoken_decode_ctx *context);


/**
 * \brief Get the nth nested token.
 *
 * \param[in] context        The decoding context.
 * \param[in] submod_index   Index of the submodule to fetch.
 * \param[out] type          The type of the nested token returned.
 * \param[out] submod_name   The name of the submodule.
 * \param[out] token         Pointer and length of the token returned.
 *
 * A submodule may be a signed and secured token. Such submodules are
 * returned as a byte or text string. To process these that are in CWT
 * format, create a new instance of the ctoken decoder, set up the
 * verification keys and process it like the superior token it came
 * from. JWT format tokens must be processed by a JWT token decoder.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). Also, on error \c
 * NULL_Q_USEFUL_BUF_C will be returned for @c token.  See 
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
void
ctoken_decode_get_nth_nested_token(struct ctoken_decode_ctx *context,
                                   uint32_t                  submod_index,
                                   enum ctoken_type_t       *type,
                                   struct q_useful_buf_c    *submod_name,
                                   struct q_useful_buf_c    *token);


/**
 * \brief Get a nested token by name.
 *
 * \param[in] context      The decoding context.
 * \param[in] submod_name  The name of the submodule to fetch.
 * \param[out] type        The type of the nested token returned.
 * \param[out] token       Pointer and length of the token returned.
 *
 * See ctoken_decode_get_nth_nested_token() for discussion on the
 * token returned.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). Also, on error \c
 * NULL_Q_USEFUL_BUF_C will be returned for @c token.  See 
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
void
ctoken_decode_get_named_nested_token(struct ctoken_decode_ctx *context,
                                     struct q_useful_buf_c     submod_name,
                                     enum ctoken_type_t       *type,
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
ctoken_decode_get_and_reset_error(struct ctoken_decode_ctx *me)
{
    enum ctoken_err_t error =  me->last_error;
    me->last_error = CTOKEN_ERR_SUCCESS;
    return error;
}


static inline enum ctoken_protection_t
ctoken_decode_get_protection_type(const struct ctoken_decode_ctx *me)
{
    return me->actual_protection_type;
}


static inline QCBORDecodeContext *
ctoken_decode_borrow_context(struct ctoken_decode_ctx *me)
{
    if(me->last_error) {
        return NULL;
    } else {
        return &me->qcbor_decode_context;
    }
}


static inline void
ctoken_decode_issuer(struct ctoken_decode_ctx *me,
                     struct q_useful_buf_c    *issuer)
{
    ctoken_decode_tstr(me, CTOKEN_CWT_LABEL_ISSUER, issuer);
}


static inline void
ctoken_decode_subject(struct ctoken_decode_ctx *me,
                      struct q_useful_buf_c    *subject)
{
    ctoken_decode_tstr(me, CTOKEN_CWT_LABEL_SUBJECT, subject);
}


static inline void
ctoken_decode_audience(struct ctoken_decode_ctx *me,
                       struct q_useful_buf_c    *audience)
{
    ctoken_decode_tstr(me, CTOKEN_CWT_LABEL_AUDIENCE, audience);
}


void
ctoken_decode_expiration(struct ctoken_decode_ctx *me,
                         int64_t                  *expiration)
{
    ctoken_decode_int(me, CTOKEN_CWT_LABEL_EXPIRATION, expiration);
}

static inline void
ctoken_decode_not_before(struct ctoken_decode_ctx *me,
                         int64_t                  *not_before)
{
    ctoken_decode_int(me, CTOKEN_CWT_LABEL_NOT_BEFORE, not_before);
}


static inline void
ctoken_decode_iat(struct ctoken_decode_ctx *me,
                  int64_t                  *iat)
{
    ctoken_decode_int(me, CTOKEN_CWT_LABEL_NOT_BEFORE, iat);
}


static inline void
ctoken_decode_cti(struct ctoken_decode_ctx *me,
                  struct q_useful_buf_c    *cti)
{
    ctoken_decode_bstr(me, CTOKEN_CWT_LABEL_CTI,  cti);
}


static inline void
ctoken_decode_nonce(struct ctoken_decode_ctx *me,
                    struct q_useful_buf_c    *nonce)
{
    ctoken_decode_bstr(me, CTOKEN_EAT_LABEL_NONCE, nonce);

#ifndef CTOKEN_DISABLE_TEMP_LABELS
    if(me->last_error == CTOKEN_ERR_CLAIM_NOT_PRESENT) {
        me->last_error = CTOKEN_ERR_SUCCESS;
        ctoken_decode_bstr(me, CTOKEN_TEMP_EAT_LABEL_NONCE, nonce);
    }
#endif
}


static inline void
ctoken_decode_ueid(struct ctoken_decode_ctx *me,
                   struct q_useful_buf_c    *ueid)
{
    ctoken_decode_bstr(me, CTOKEN_EAT_LABEL_UEID, ueid);

#ifndef CTOKEN_DISABLE_TEMP_LABELS
    if(me->last_error == CTOKEN_ERR_CLAIM_NOT_PRESENT) {
        me->last_error = CTOKEN_ERR_SUCCESS;
        ctoken_decode_bstr(me, CTOKEN_TEMP_EAT_LABEL_UEID, ueid);
    }
#endif
}


static inline void
ctoken_decode_oemid(struct ctoken_decode_ctx *me,
                    struct q_useful_buf_c    *oemid)
{
    ctoken_decode_bstr(me, CTOKEN_EAT_LABEL_OEMID, oemid);

#ifndef CTOKEN_DISABLE_TEMP_LABELS
    if(me->last_error == CTOKEN_ERR_CLAIM_NOT_PRESENT) {
        me->last_error = CTOKEN_ERR_SUCCESS;
        ctoken_decode_bstr(me, CTOKEN_TEMP_EAT_LABEL_OEMID, oemid);
    }
#endif
}


static inline void
ctoken_decode_origination(struct ctoken_decode_ctx *me,
                          struct q_useful_buf_c    *origination)
{
    ctoken_decode_tstr(me, CTOKEN_EAT_LABEL_ORIGINATION, origination);
}


static inline void
ctoken_decode_security_level(struct ctoken_decode_ctx         *me,
                             enum ctoken_security_level_t *security_level)
{
    ctoken_decode_int_constrained(me,
                                  CTOKEN_EAT_LABEL_SECURITY_LEVEL,
                                  EAT_SL_UNRESTRICTED,
                                  EAT_SL_HARDWARE,
                                  (int64_t *)security_level);

#ifndef CTOKEN_DISABLE_TEMP_LABELS
    if(ctoken_decode_get_error(me) == CTOKEN_ERR_CLAIM_NOT_PRESENT) {
        ctoken_decode_get_and_reset_error(me);
        ctoken_decode_int_constrained(me,
                                      CTOKEN_TEMP_EAT_LABEL_SECURITY_LEVEL,
                                      EAT_SL_UNRESTRICTED,
                                      EAT_SL_HARDWARE,
                                      (int64_t *)security_level);
    }
#endif
}


static inline void
ctoken_decode_uptime(struct ctoken_decode_ctx *me,
                     uint64_t                 *uptime)
{
    ctoken_decode_uint(me, CTOKEN_EAT_LABEL_UPTIME, uptime);
}


static inline void
ctoken_decode_secure_boot(struct ctoken_decode_ctx *me,
                          bool                     *secure_boot_enabled)
{
    ctoken_decode_bool(me, CTOKEN_EAT_LABEL_SECURE_BOOT, secure_boot_enabled);

#ifndef CTOKEN_DISABLE_TEMP_LABELS
    if(ctoken_decode_get_error(me) == CTOKEN_ERR_CLAIM_NOT_PRESENT) {
        (void)ctoken_decode_get_and_reset_error(me);
        ctoken_decode_bool(me,
                           CTOKEN_TEMP_EAT_LABEL_SECURE_BOOT,
                           secure_boot_enabled);
    }
#endif
}


static inline void
ctoken_decode_debug_state(struct ctoken_decode_ctx  *me,
                          enum ctoken_debug_level_t *debug_level)
{
    ctoken_decode_int_constrained(me,
                                  CTOKEN_EAT_LABEL_DEBUG_STATE,
                                  CTOKEN_DEBUG_ENABLED,
                                  CTOKEN_DEBUG_DISABLED_FULL_PERMANENT,
                                  (int64_t *)debug_level);
#ifndef CTOKEN_DISABLE_TEMP_LABELS
    if(ctoken_decode_get_error(me) == CTOKEN_ERR_CLAIM_NOT_PRESENT) {
        ctoken_decode_get_and_reset_error(me);
        ctoken_decode_int_constrained(me,
                                      CTOKEN_TEMP_EAT_LABEL_DEBUG_STATE,
                                      CTOKEN_DEBUG_ENABLED,
                                      CTOKEN_DEBUG_DISABLED_FULL_PERMANENT,
                                      (int64_t *)debug_level);
    }
#endif
}


static inline void
ctoken_decode_intended_use(struct ctoken_decode_ctx    *me,
                           enum ctoken_intended_use_t  *use)
{
    ctoken_decode_int_constrained(me,
                                  CTOKEN_EAT_LABEL_INTENDED_USE,
                                  CTOKEN_USE_GENERAL,
                                  CTOKEN_USE_PROOF_OF_POSSSION,
                                  (int64_t *)use);
}


static inline void
ctoken_decode_profile_uri(struct ctoken_decode_ctx *me,
                          struct q_useful_buf_c    *profile)
{
    ctoken_decode_tstr(me, CTOKEN_EAT_LABEL_PROFILE, profile);
}


static inline void
ctoken_decode_profile_oid(struct ctoken_decode_ctx *me,
                          struct q_useful_buf_c    *profile)
{
    ctoken_decode_bstr(me, CTOKEN_EAT_LABEL_PROFILE, profile);
}

static inline void
ctoken_decode_profile(struct ctoken_decode_ctx *me,
                      bool                     *is_oid_format,
                      struct q_useful_buf_c    *profile)
{
    *is_oid_format = false;
    ctoken_decode_profile_uri(me, profile);
    if(ctoken_decode_get_error(me) == CTOKEN_ERR_CBOR_TYPE) {
        ctoken_decode_get_and_reset_error(me);
        *is_oid_format = true;
        ctoken_decode_profile_oid(me, profile);
    }
}


static inline void
ctoken_decode_rewind(struct ctoken_decode_ctx   *me)
{
    QCBORDecode_Rewind(&(me->qcbor_decode_context));
}


/* Function not for public use, but shared between implementation files.
 * This is the only one so it is stuck in here rather than making a new
 * header
 */
enum ctoken_err_t ctoken_get_and_reset_cbor_error(QCBORDecodeContext *decode_context);


static inline enum ctoken_err_t
ctoken_decode_hw_version(struct ctoken_decode_ctx  *me,
                         enum ctoken_hw_type_t      hw_type,
                         int32_t                    *version_scheme,
                         struct q_useful_buf_c      *version)
{
    enum ctoken_err_t return_value;
    int64_t           version_scheme_64;

    return_value =  ctoken_decode_tstr(me, CTOKEN_EAT_LABEL_CHIP_VERSION + hw_type, version);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    /* -256 and 65535 are constraints from the PSA token document. */
    return_value = ctoken_decode_int_constrained(me,
                                                 -256,
                                                 65535,
                                                 CTOKEN_EAT_LABEL_CHIP_VERSION_SCHEME + hw_type,
                                                &version_scheme_64);
    if(return_value == CTOKEN_ERR_CLAIM_NOT_PRESENT) {
        // TODO: what is the version scheme when it is not given?
        *version_scheme = 99;
        return_value = CTOKEN_ERR_SUCCESS;
    }
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }
    /* cast is ok because of use of ctoken_decode_int_constrained() */
    *version_scheme = (int32_t)version_scheme_64;

    Done:
    return return_value;
}


static inline enum ctoken_err_t
ctoken_decode_hw_ean_version(struct ctoken_decode_ctx  *me,
                             enum ctoken_hw_type_t      hw_type,
                             struct q_useful_buf_c      *version)
{
    return ctoken_decode_tstr(me, CTOKEN_EAT_LABEL_EAN_CHIP_VERSION + hw_type, version);
}


#ifdef __cplusplus
}
#endif

#endif /* __CTOKEN_DECODE_H__ */
