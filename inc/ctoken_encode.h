/*
 * ctoken_encode.h (formerly attest_token_encode.h)
 *
 * Copyright (c) 2018-2020, Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef __CTOKEN_ENCODE_H__
#define __CTOKEN_ENCODE_H__

#include "ctoken.h"
#include "qcbor/qcbor_encode.h"
#include "t_cose/t_cose_sign1_sign.h"

#include "ctoken_cwt_labels.h"
#include "ctoken_eat_labels.h"


#ifdef __cplusplus
extern "C" {
#if 0
} /* Keep editor indention formatting happy */
#endif
#endif


/**
 * \file ctoken_encode.h
 *
 * \brief CBOR Token Creation Interface
 *
 * The context and functions here are the way to create an attestation
 * token. The steps are roughly:
 *
 *   -# Create and initialize a ctoken_encode_ctx indicating the
 *   options, key and such using ctoken_encode_init(), ctoken_encode_set_key(),
 *   and ctoken_encode_start().
 *
 *   -# Use various add methods to fill in the payload with claims. The
 *   encoding context can also be borrowed for more rich payloads.
 *
 *   -# Call ctoken_encode_finish() to create the signature and finish
 *   formatting the COSE signed output.
 */



enum ctoken_encode_nest_state {
    /* Private enumerated type */
     SUBMODS_NONE = 0,
     SUBMODS_IN_SECTION,
     SUBMODS_IN_SECTION_AND_SUBMOD,
     SUBMODS_SECTION_DONE
};

struct ctoken_submod_state {
    /* Private data structure */
    enum ctoken_encode_nest_state   level_state[CTOKEN_MAX_SUBMOD_NESTING];
    /* NULL means at the top level. */
    enum ctoken_encode_nest_state  *current_level;
};


/**
 * The context for creating a CBOR token.  The caller of
 * ctoken_encode must create one of these and pass it to the functions
 * here. It is small enough that it can go on the stack. It is most of
 * the memory needed to create a token except the output buffer and
 * any memory requirements for the cryptographic operations.
 *
 * The structure is opaque for the caller.
 *
 * This is 304 bytes on a 64-bit x86 CPU with the System V ABI (MacOS)
 */
struct ctoken_encode_ctx {
    /* Private data structure */
    uint32_t                        opt_flags;
    enum ctoken_err_t               error;
    QCBOREncodeContext              cbor_encode_context;
    struct ctoken_submod_state      submod_state;
    struct t_cose_sign1_sign_ctx    signer_ctx;
};




/**
 * \brief Initialize a token creation context.
 *
 * \param[in] context                The token creation context to be initialized.
 * \param[in] token_opt_flags   Flags to select different custom options,
 *                              for example \ref TOKEN_OPT_OMIT_CLAIMS.
 * \param[in] t_cose_opt_flags  Option flags passed on to t_cose.
 * \param[in] cose_alg_id       The algorithm to sign with. The IDs are
 *                              defined in [COSE (RFC 8152)]
 *                              (https://tools.ietf.org/html/rfc8152) or
 *                              in the [IANA COSE Registry]
 *                              (https://www.iana.org/assignments/cose/cose.xhtml).
 *                              See T_COSE_ALGORITHM_XXX in t_cose_common.h.
 *
 */
static void
ctoken_encode_init(struct ctoken_encode_ctx *context,
                   uint32_t                  t_cose_opt_flags,
                   uint32_t                  token_opt_flags,
                   int32_t                   cose_alg_id);


/**
 * \brief Set the signing key.
 *
 *
 * \param[in] context           The token creation context.
 * \param[in] signing_key  The signing key to use or \ref T_COSE_NULL_KEY.
 * \param[in] kid          COSE kid (key ID) parameter or \c NULL_Q_USEFUL_BUF_C.
 *
 * This needs to be called to set the signing key to use. The \c kid
 * may be omitted by giving \c NULL_Q_USEFUL_BUF_C.
 *
 * If short-circuit signing is used,
 * \ref T_COSE_OPT_SHORT_CIRCUIT_SIG, then this does not need to be
 * called. If it is called the \c kid given will be used, but the \c
 * signing_key is never used. When the \c kid is given with a
 * short-circuit signature, the internally fixed kid for short circuit
 * will not be used and this \c COSE_Sign1 message can not be verified
 * by t_cose_sign1_verify().
 */
static void
ctoken_encode_set_key(struct ctoken_encode_ctx *context,
                      struct t_cose_key         signing_key,
                      struct q_useful_buf_c     kid);


/**
 * \brief Give output buffer and start token creation
 *
 * \param[in] context          The token creation context.
 * \param[in] out_buffer  The pointer and length of buffer to write token to.
 *
 * \returns               0 on success or error.

 * The size of the buffer in \c out_buffer->len
 * determines the size of the token that can be created. It must be
 * able to hold the final encoded and signed token. The data encoding
 * overhead is just that of CBOR. The signing overhead depends on the
 * signing key size. It is about 150 bytes for 256-bit ECDSA.
 *
 * If \c out_buffer->ptr is \c NULL and \c out_buffer_ptr->len is
 * large like \c UINT32_MAX no token will be created but the length of
 * the token that would be created will be in \c completed_token as
 * returned by ctoken_encode_finish(). None of the cryptographic
 * functions run during this, but the sizes of what they would output
 * is taken into account.
 */
enum ctoken_err_t
ctoken_encode_start(struct ctoken_encode_ctx  *context,
                    const struct q_useful_buf  out_buffer);



/**
 * \brief Add a 64-bit signed integer claim
 *
 * \param[in] context     Token creation context.
 * \param[in] label  Integer label for claim.
 * \param[in] value  The signed integer claim data.
 */
static void ctoken_encode_add_integer(struct ctoken_encode_ctx *context,
                                      int32_t                   label,
                                      int64_t                   value);


/**
 * \brief Add a binary string claim
 *
 * \param[in] context     Token creation context.
 * \param[in] label  Integer label for claim.
 * \param[in] value  The binary claim data.
 */
static void ctoken_encode_add_bstr(struct ctoken_encode_ctx *context,
                                   int32_t                   label,
                                   struct q_useful_buf_c     value);


/**
 * \brief Add a text string claim
 *
 * \param[in] context     Token creation context.
 * \param[in] label  Integer label for claim.
 * \param[in] value  The text claim data.
 */
static void ctoken_encode_add_tstr(struct ctoken_encode_ctx *context,
                                   int32_t                   label,
                                   struct q_useful_buf_c     value);


/**
 * \brief Add some already-encoded CBOR to payload
 *
 * \param[in] context       Token creation context.
 * \param[in] label    Integer label for claim.
 * \param[in] encoded  The already-encoded CBOR.
 *
 * Encoded CBOR must be a full map or full array or a non-aggregate
 * type. It cannot be a partial map or array. It can be nested maps
 * and arrays, but they must all be complete.
 */
static void ctoken_encode_add_cbor(struct ctoken_encode_ctx *context,
                                   int32_t                   label,
                                   struct q_useful_buf_c     encoded);


/**
 * \brief Open an array.
 *
 * \param[in] context       Token creation context.
 * \param[in] label    Integer label for new array.
 *
 * This must be matched by a ctoken_encode_close_array().
 */
static inline void
ctoken_encode_open_array(struct ctoken_encode_ctx *context, int32_t label);


/**
 * \brief Close an array.
 *
 * \param[in] context       Token creation context.
 *
 * Close array opened by ctoken_encode_open_array().
 */
static inline void
ctoken_encode_close_array(struct ctoken_encode_ctx *context);


/**
 * \brief Open an map.
 *
 * \param[in] context       Token creation context.
 * \param[in] label    Integer label for new map.
 *
 * This must be matched by a ctoken_encode_close_map().
 */
static inline void
ctoken_encode_open_map(struct ctoken_encode_ctx *context, int32_t label);


/**
 * \brief Close a map.
 *
 * \param[in] context       Token creation context.
 *
 * Close a map opened by ctoken_encode_open_map().
 */
static inline void
ctoken_encode_close_map(struct ctoken_encode_ctx *context);


/**
 * \brief Get a copy of the CBOR encoding context
 *
 * \param[in] context     The token creation context.
 *
 * \return The CBOR encoding context
 *
 * Allows the caller to encode CBOR right into the output buffer using
 * any of the \c QCBOREncode_AddXXXX() methods. Anything added here
 * will be part of the claims that gets hashed. This can be used to
 * make complex CBOR structures. All open arrays and maps must be
 * close before calling any other \c ctoken methods.  \c
 * QCBOREncode_Finish() should not be closed on this context.
 */
static QCBOREncodeContext *
ctoken_encode_borrow_cbor_cntxt(struct ctoken_encode_ctx *context);


/**
 * \brief Encode the CWT issuer in to the token.
 *
 * \param[in] context   The token encoder context.
 * \param[in] issuer    Pointer and length of issuer.
 *
 * The principle that created the token. It is a text string or a URI as
 * described in [RFC 8392](https://tools.ietf.org/html/rfc8392#section-3.1.1)
 * and [RFC 7519] (https://tools.ietf.org/html/rfc7519#section-4.1.1).

 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static void ctoken_encode_issuer(struct ctoken_encode_ctx *context,
                                 struct q_useful_buf_c     issuer);


/**
 * \brief Encode the CWT subject in to the token.
 *
 * \param[in] context  The token encoder context.
 * \param[in] subject  Pointer and length of subject.
 *
 * Identifies the subject of the token. It is a text string or URI as
 * described in [RFC 8392](https://tools.ietf.org/html/rfc8392#section-3.1.2)
 * and [RFC 7519] (https://tools.ietf.org/html/rfc7519#section-4.1.2).
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static void ctoken_encode_subject(struct ctoken_encode_ctx *context,
                                  struct q_useful_buf_c     subject);


/**
 * \brief Encode the CWT audience in to the token.
 *
 * \param[in] context   The token encoder context.
 * \param[in] audience  Pointer and length of audience.
 *
 * This identifies the recipient for which the token is intended. It is
 * a text string or URI as
 * described in [RFC 8392](https://tools.ietf.org/html/rfc8392#section-3.1.3)
 * and [RFC 7519] (https://tools.ietf.org/html/rfc7519#section-4.1.3).
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static void ctoken_encode_audience(struct ctoken_encode_ctx *context,
                                   struct q_useful_buf_c     audience);


/**
 * \brief Encode the CWT expiration time in to the token.
 *
 * \param[in] context     The token encoder context.
 * \param[in] expiration  The expiration time to encode.
 *
 * The time format is that described as Epoch Time in CBOR, RFC 7049, the
 * number of seconds since Jan 1, 1970.
 *
 * Details are described in
 * [RFC 8392](https://tools.ietf.org/html/rfc8392#section-3.1.4)
 * and [RFC 7519] (https://tools.ietf.org/html/rfc7519#section-4.1.4).
 *
 * This implementation only supports int64_t time, not floating point,
 * even though the specification allows floating point.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static void ctoken_encode_expiration(struct ctoken_encode_ctx *context,
                                     int64_t                   expiration);


/**
 * \brief Encode the CWT not-before claim in to the token.
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
 * Details are described in
 * [RFC 8392](https://tools.ietf.org/html/rfc8392#section-3.1.5)
 * and [RFC 7519] (https://tools.ietf.org/html/rfc7519#section-4.1.5).
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static void ctoken_encode_not_before(struct ctoken_encode_ctx *context,
                                     int64_t                   not_before);


/**
 * \brief Encode the CWT and EAT "issued-at" in to the token.
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
 * Details are described in
 * [RFC 8392](https://tools.ietf.org/html/rfc8392#section-3.1.6)
 * and [RFC 7519] (https://tools.ietf.org/html/rfc7519#section-4.1.6).
 * This claim is also used by (EAT)[https://tools.ietf.org/html/draft-ietf-rats-eat-04].
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static void ctoken_encode_iat(struct ctoken_encode_ctx *context,
                              int64_t                   iat);


/**
 * \brief Encode the CWT and EAT claim ID in to the token.
 *
 * \param[in] context   The token encoder context.
 * \param[in] cti       Pointer and length of CWT claim ID.
 *
 * This is a byte string that uniquely identifies the token.
 *
 * [RFC 8392](https://tools.ietf.org/html/rfc8392#section-3.1.7)
 * and [RFC 7519] (https://tools.ietf.org/html/rfc7519#section-4.1.7).
 * This claim is also used by (EAT)[https://tools.ietf.org/html/draft-ietf-rats-eat-04].
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static void ctoken_encode_cti(struct ctoken_encode_ctx *context,
                              struct q_useful_buf_c     cti);



/**
 * \brief  Encode the EAT nonce claim.
 *
 * \param[in] context  The encoding context to output to.
 * \paran[in] nonce    Pointer and length of nonce to output.
 *
 * This outputs the nonce claim.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static void
ctoken_encode_nonce(struct ctoken_encode_ctx *context,
                    struct q_useful_buf_c     nonce);


/**
 * \brief  Encode the EAT UEID claim.
 *
 * \param[in] context  The encoding context to output to.
 * \paran[in] ueid     Pointer and length of UEID to output.
 *
 * This outputs the UEID claim.
 *
 * The UEID is the Universal Entity ID, an opaque binary blob that uniquely
 * identifies the device.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static void
ctoken_encode_ueid(struct ctoken_encode_ctx *context,
                   struct q_useful_buf_c     ueid);


/**
 * \brief  Encode the EAT OEM ID (oemid) claim.
 *
 * \param[in] context  The encoding context to output to.
 * \paran[in] oemid     Pointer and length of OEM ID to output.
 *
 * This outputs the OEM ID claim.
 *
 * The OEMID is an opaque binary blob that identifies the manufacturer.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static void
ctoken_encode_oemid(struct ctoken_encode_ctx *context,
                        struct q_useful_buf_c     oemid);


/**
 * \brief  Encode the EAT origination claim.
 *
 * \param[in] context       The encoding context to output to.
 * \paran[in] origination   Pointer and length of origination claim to output.
 *
 * This outputs the origination claim.
 *
 * This describes the part of the device that created the token. It
 * is a text string or a URI.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static void
ctoken_encode_origination(struct ctoken_encode_ctx *context,
                              struct q_useful_buf_c     origination);


/**
 * \brief  Encode the security level claim.
 *
 * \param[in] context         The encoding context to output to.
 * \paran[in] security_level  The security level enum to output.
 *
 * This outputs the security level claim.
 *
 * The security level gives a rough indication of how security
 * the HW and SW are.  See \ref ctoken_security_level_t.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static void
ctoken_encode_security_level(struct ctoken_encode_ctx        *context,
                                 enum ctoken_security_level_t security_level);



/**
 * \brief  Encode the EAT debug and boot state claim.
 *
 * \param[in] context              The encoding context to output to.
 * \paran[in] secure_boot_enabled  This is \c true if secure boot
 *                                 is enabled or \c false it no.
 * \param[out] debug_state         See \ref ctoken_debug_level_t for
 *                                 the different debug states.
 *
 * This outputs the debug and boot state claim.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
void
ctoken_encode_boot_state(struct ctoken_encode_ctx     *context,
                         bool                          secure_boot_enabled,
                         enum ctoken_debug_level_t debug_state);


/**
 * \brief Encode an EAT location claim.
 *
 * \param[in] context   ctoken encode context to output to.
 * \param[in] location  The location to output.
 *
 * See \ref ctoken_location_t for the details of the location claim.
 * Only the location fields indicated as present in \c item_flags
 * will be output. The latitude and longitude fields must always
 * be present.
 */
void
ctoken_encode_location(struct ctoken_encode_ctx       *context,
                       const struct ctoken_location_t *location);



/**
 * \brief  Encode the EAT uptime claim.
 *
 * \param[in] context         The encoding context to output to.
 * \paran[in] uptime          The time in seconds since the system started.
 *
 * This outputs the uptime claim.
 *
 * This is the time in seconds since the device booted or started.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static void
ctoken_encode_uptime(struct ctoken_encode_ctx  *context,
                         uint64_t                    uptime);


/**
 * \brief  Start encoding EAT submodules.
 *
 * \param[in] context  Encoding context.
 *
 * This must be called to start the submodules section before calling
 * ctoken_encode_open_submod() or ctoken_encode_add_token().  There is
 * only one submodules section, so this can only be called once.  All
 * submodules must be added together.
 *
 * When all submodules have been added, then
 * ctoken_encode_end_submod_section() must be called to close out the
 * submodules section.
 */
void ctoken_encode_start_submod_section(struct ctoken_encode_ctx *context);


/**
 * \brief  End encoding EAT submodules.
 *
 * \param[in] context  Encoding context.
 *
 * Close out the submodules section after calling
 * ctoken_encode_start_submod_section() and adding all submodules that
 * are to be added.
 */
void ctoken_encode_end_submod_section(struct ctoken_encode_ctx *context);


/**
 * \brief  Start encoding claims in an EAT submodule.
 *
 * \param[in] context  Encoding context
 * \param [in] submod_name  Text string naming sub module.
 *
 * Initiates the creation of a sub module. All claims added after this
 * call until the a call to ctoken_encode_close_submod() will go into
 * the named submodule.
 *
 * ctoken_encode_start_submod_section() must be called before this is
 * called to open the submodules
 * section. ctoken_encode_end_submod_section() must be called at some
 * point after this is called.
 *
 * Submodules can nest to a depth of \ref CTOKEN_MAX_SUBMOD_NESTING.
 * To nest one submodule inside another, simply call this again before
 * calling ctoken_encode_close_submod().
 *
 * If an error occurs, such as nesting too deep, it will be reported
 * when ctoken_encode_finish() is called.
 */
void ctoken_encode_open_submod(struct ctoken_encode_ctx *context,
                               const char               *submod_name);


/**
 * \brief  End encoding claims in an EAT submodule.
 *
 * \param[in] context  Encoding context
 *
 * Close out the current submodule.
 *
 * All submodules opened, must be closed for a token to be valid.
 *
 * If an error occurs, such as no submod open, it will be reported when
 * ctoken_encode_finish() is called.
 */
void ctoken_encode_close_submod(struct ctoken_encode_ctx *context);


/**
 * \brief Add a complete EAT as a nested token submodule.
 *
 * \param[in] context      Token creation context.
 * \param[in] type         Whether added token is CBOR format or JSON format.
 * \param[in] submod_name  String naming the submodule.
 * \param[in] token        The full encoded token to add.
 *
 * A submodule can be a fully encoded and signed EAT token such as the
 * completed_token returned from ctoken_encode_finish(). Use this call
 * to add such a token.
 *
 * The added token may be CBOR/COSE/CWT format or JSON/JOSE/JWT
 * format.  Indicate which with the \c type parameter.
 *
 * The contents of token are not checked by this call. The bytes
 * are just added.
 *
 * ctoken_encode_start_submod_section() must be called before this is
 * called to open the submodules
 * section. ctoken_encode_end_submod_section() must be called at some
 * point after this is called.
 *
 * If an error occurs it will be reported when ctoken_encode_finish()
 * is called.
 */
void ctoken_encode_nested_token(struct ctoken_encode_ctx *context,
                                enum ctoken_type          type,
                                const char               *submod_name,
                                struct q_useful_buf_c     token);


/**
 * \brief Finish the token, complete the signing and get the result
 *
 * \param[in] context                Token creation context.
 * \param[out] completed_token  Pointer and length to completed token.
 *
 * \return                      One of the \ref ctoken_err_t errors.
 *
 * This completes the token after the payload has been added. When
 * this is called the signing algorithm is run and the final
 * formatting of the token is completed.
 */
enum ctoken_err_t
ctoken_encode_finish(struct ctoken_encode_ctx *context,
                     struct q_useful_buf_c    *completed_token);


/**
 * \brief Sign and tag already encoded claims
 *
 * \param[in] context                Token creation context.
 * \param[in] out_buf            The buffer the completed token will be written to.
 * \param[in] encoded_payload   The already-encoded claims.
 * \param[out] completed_token  Pointer and length to completed token.
 *
 * \return                      One of the \ref ctoken_err_t errors.
 *
 * This is used in lieu of ctoken_encode_start(),
 * ctoken_encode_finish() and all the calls in between. Instead of
 * encoding the claims one at a time this assumes they have already be
 * fully encoded. The encoding context must still have been set up
 * with ctoken_encode_init(), ctoken_encode_set_key() and such.
 *
 * This is a good way to turn a UCCS (Unprotected CWT Claim Set) into
 * a real signed CWT. The encoded_payload is simply the encoded UCCS
 * and the complted_token will be a CWT.
 */
enum ctoken_err_t
ctoken_encode_one_shot(struct ctoken_encode_ctx   *context,
                       const struct q_useful_buf   out_buf,
                       const struct q_useful_buf_c encoded_payload,
                       struct q_useful_buf_c      *completed_token);




/* ----- inline implementations ------ */

static inline void
ctoken_encode_set_key(struct ctoken_encode_ctx *me,
                      struct t_cose_key        signing_key,
                      struct q_useful_buf_c    key_id)
{
    t_cose_sign1_set_signing_key(&(me->signer_ctx), signing_key, key_id);
}


static inline void
ctoken_encode_init(struct ctoken_encode_ctx *me,
                   uint32_t                 t_cose_opt_flags,
                   uint32_t                 token_opt_flags,
                   int32_t                  cose_alg_id)
{
    /*
       me->in_submod_mode = 0
       me->submod_nest_level = 0
       me->error = CTOKEN_ERR_SUCCESS
     */
    memset(me, 0, sizeof(struct ctoken_encode_ctx));
    me->opt_flags = token_opt_flags;
    t_cose_sign1_sign_init(&(me->signer_ctx), t_cose_opt_flags, cose_alg_id);
}


static inline QCBOREncodeContext *
ctoken_encode_borrow_cbor_cntxt(struct ctoken_encode_ctx *me)
{
    return &(me->cbor_encode_context);
}


static inline void
ctoken_encode_add_integer(struct ctoken_encode_ctx *me,
                          int32_t label,
                          int64_t Value)
{
    QCBOREncode_AddInt64ToMapN(&(me->cbor_encode_context), label, Value);
}


static inline void
ctoken_encode_add_unsigned(struct ctoken_encode_ctx *me,
                          int32_t label,
                          uint64_t Value)
{
    QCBOREncode_AddUInt64ToMapN(&(me->cbor_encode_context), label, Value);
}


static inline void
ctoken_encode_add_bstr(struct ctoken_encode_ctx *me,
                       int32_t label,
                       struct q_useful_buf_c bstr)
{
    QCBOREncode_AddBytesToMapN(&(me->cbor_encode_context), label, bstr);
}


static inline void
ctoken_encode_add_tstr(struct ctoken_encode_ctx *me,
                       int32_t label,
                       struct q_useful_buf_c tstr)
{
    QCBOREncode_AddTextToMapN(&(me->cbor_encode_context), label, tstr);
}


static inline void
ctoken_encode_add_cbor(struct ctoken_encode_ctx *me,
                       int32_t label,
                       struct q_useful_buf_c encoded)
{
    QCBOREncode_AddEncodedToMapN(&(me->cbor_encode_context), label, encoded);
}


static inline void
ctoken_encode_open_array(struct ctoken_encode_ctx *me, int32_t label)
{
    QCBOREncode_OpenArrayInMapN(&(me->cbor_encode_context), label);
}


static inline void
ctoken_encode_close_array(struct ctoken_encode_ctx *me)
{
    QCBOREncode_CloseArray(&(me->cbor_encode_context));
}


static inline void
ctoken_encode_open_map(struct ctoken_encode_ctx *me, int32_t label)
{
    QCBOREncode_OpenMapInMapN(&(me->cbor_encode_context), label);
}


static inline void
ctoken_encode_close_map(struct ctoken_encode_ctx *me)
{
    QCBOREncode_CloseMap(&(me->cbor_encode_context));
}


static inline void ctoken_encode_issuer(struct ctoken_encode_ctx *me,
                                            struct q_useful_buf_c issuer)
{
    ctoken_encode_add_tstr(me, CTOKEN_CWT_LABEL_ISSUER, issuer);
}

static inline void ctoken_encode_subject(struct ctoken_encode_ctx *me,
                                             struct q_useful_buf_c subject)
{
    ctoken_encode_add_tstr(me, CTOKEN_CWT_LABEL_SUBJECT, subject);
}

static inline void ctoken_encode_audience(struct ctoken_encode_ctx *me,
                                              struct q_useful_buf_c audience)
{
    ctoken_encode_add_tstr(me, CTOKEN_CWT_LABEL_AUDIENCE, audience);
}


static inline void ctoken_encode_expiration(struct ctoken_encode_ctx *me,
                                                int64_t expiration)
{
    ctoken_encode_add_integer(me, CTOKEN_CWT_LABEL_EXPIRATION, expiration);
}


static inline void ctoken_encode_not_before(struct ctoken_encode_ctx *me,
                                               int64_t not_before)
{
    ctoken_encode_add_integer(me, CTOKEN_CWT_LABEL_NOT_BEFORE, not_before);
}


static inline void ctoken_encode_iat(struct ctoken_encode_ctx *me,
                                         int64_t iat)
{
    ctoken_encode_add_integer(me, CTOKEN_CWT_LABEL_IAT, iat);
}


static inline void ctoken_encode_cti(struct ctoken_encode_ctx *me,
                                         struct q_useful_buf_c cti)
{
    ctoken_encode_add_bstr(me, CTOKEN_CWT_LABEL_CTI, cti);
}


static inline void
ctoken_encode_nonce(struct ctoken_encode_ctx *me,
                        struct q_useful_buf_c     nonce)
{
    ctoken_encode_add_bstr(me, CTOKEN_EAT_LABEL_NONCE, nonce);
}


static inline void
ctoken_encode_ueid(struct ctoken_encode_ctx *me,
                       struct q_useful_buf_c     ueid)
{
    ctoken_encode_add_bstr(me, CTOKEN_EAT_LABEL_UEID, ueid);
}


static inline void
ctoken_encode_oemid(struct ctoken_encode_ctx *me,
                        struct q_useful_buf_c     oemid)
{
    ctoken_encode_add_bstr(me, CTOKEN_EAT_LABEL_OEMID, oemid);
}



static inline void
ctoken_encode_origination(struct ctoken_encode_ctx *me,
                              struct q_useful_buf_c origination)
{
    ctoken_encode_add_tstr(me, CTOKEN_EAT_LABEL_ORIGINATION, origination);
}

static inline void
ctoken_encode_security_level(struct ctoken_encode_ctx *me,
                                 enum ctoken_security_level_t security_level)
{
    ctoken_encode_add_integer(me,
                              CTOKEN_EAT_LABEL_SECURITY_LEVEL,
                              (int64_t)security_level);
}


static inline void
ctoken_encode_uptime(struct ctoken_encode_ctx  *me,
                         uint64_t                   uptime)
{
    ctoken_encode_add_integer(me, CTOKEN_EAT_LABEL_UPTIME, uptime);
}


#ifdef __cplusplus
}
#endif

#endif /* __CTOKEN_ENCODE_H__ */
