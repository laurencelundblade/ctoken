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
#include "qcbor.h"
#include "t_cose_sign1_sign.h"


/**
 * \file attest_token_encode.h
 *
 * \brief CBOR Token Creation Interface
 *
 * The context and functions here are the way to create an attestation
 * token. The steps are roughly:
 *
 *   -# Create and initialize an attest_token_ctx indicating the
 *   options, key and such using attest_token_start().
 *
 *   -# Use various add methods to fill in the payload with claims. The
 *   encoding context can also be borrowed for more rich payloads.
 *
 *   -# Call attest_token_encode_finish() to create the signature and finish
 *   formatting the COSE signed output.
 */


/**
 * The context for creating a CBOR token.  The caller of
 * ctoken_encode must create one of these and pass it to the functions
 * here. It is small enough that it can go on the stack. It is most of
 * the memory needed to create a token except the output buffer and
 * any memory requirements for the cryptographic operations.
 *
 * The structure is opaque for the caller.
 *
 * This is roughly 148 + 8 + 32 = 188 bytes
 */
struct ctoken_encode_ctx {
    /* Private data structure */
    QCBOREncodeContext           cbor_enc_ctx;
    uint32_t                     opt_flags;
    uint8_t                      submod_nest_level;
    struct t_cose_sign1_sign_ctx signer_ctx;
};


/**
 * \brief Initialize a token creation context.
 *
 * \param[in] me          The token creation context to be initialized.
 * \param[in] token_opt_flags   Flags to select different custom options,
 *                        for example \ref TOKEN_OPT_OMIT_CLAIMS.
 * \param[in] t_cose_opt_flags  Option flags passed on to t_cose.
 * \param[in] cose_alg_id The algorithm to sign with. The IDs are
 *                        defined in [COSE (RFC 8152)]
 *                        (https://tools.ietf.org/html/rfc8152) or
 *                        in the [IANA COSE Registry]
 *                        (https://www.iana.org/assignments/cose/cose.xhtml).
 * *
 * The size of the buffer in \c out_buffer->len
 * determines the size of the token that can be created. It must be
 * able to hold the final encoded and signed token. The data encoding
 * overhead is just that of CBOR. The signing overhead depends on the
 * signing key size. It is about 150 bytes for 256-bit ECDSA.
 *
 * If \c out_buffer->ptr is \c NULL and \c out_buffer_ptr->len is
 * large like \c UINT32_MAX no token will be created but the length of
 * the token that would be created will be in \c completed_token as
 * returned by attest_token_finish(). None of the cryptographic
 * functions run during this, but the sizes of what they would output
 * is taken into account.
 */

static void
ctoken_encode_init(struct ctoken_encode_ctx *me,
                   uint32_t                  t_cose_opt_flags,
                   uint32_t                  token_opt_flags,
                   int32_t                   cose_alg_id);


static void
ctoken_encode_set_key(struct ctoken_encode_ctx *me,
                      struct t_cose_key         key,
                      struct q_useful_buf_c     key_id);


enum ctoken_err_t
ctoken_encode_start(struct ctoken_encode_ctx *me,
                    const struct q_useful_buf *out_buffer);



/**
 * \brief Get a copy of the CBOR encoding context
 *
 * \param[in] me     Token creation context.
 *
 * \return The CBOR encoding context
 *
 * Allows the caller to encode CBOR right into the output buffer using
 * any of the \c QCBOREncode_AddXXXX() methods. Anything added here
 * will be part of the payload that gets hashed. This can be used to
 * make complex CBOR structures. All open arrays and maps must be
 * close before calling any other \c attest_token methods.  \c
 * QCBOREncode_Finish() should not be closed on this context.
 */
static QCBOREncodeContext *
ctoken_encode_borrow_cbor_cntxt(struct ctoken_encode_ctx *me);

/**
 * \brief Add a 64-bit signed integer claim
 *
 * \param[in] me     Token creation context.
 * \param[in] label  Integer label for claim.
 * \param[in] value  The integer claim data.
 */
static void ctoken_encode_add_integer(struct ctoken_encode_ctx *me,
                                      int32_t label,
                                      int64_t value);

/**
 * \brief Add a binary string claim
 *
 * \param[in] me     Token creation context.
 * \param[in] label  Integer label for claim.
 * \param[in] value  The binary claim data.
 */
static void ctoken_encode_add_bstr(struct ctoken_encode_ctx *me,
                                   int32_t label,
                                   struct q_useful_buf_c value);

/**
 * \brief Add a text string claim
 *
 * \param[in] me     Token creation context.
 * \param[in] label  Integer label for claim.
 * \param[in] value  The text claim data.
 */
static void ctoken_encode_add_tstr(struct ctoken_encode_ctx *me,
                                   int32_t label,
                                   struct q_useful_buf_c value);

/**
 * \brief Add some already-encoded CBOR to payload
 *
 * \param[in] me       Token creation context.
 * \param[in] label    Integer label for claim.
 * \param[in] encoded  The already-encoded CBOR.
 *
 * Encoded CBOR must be a full map or full array or a non-aggregate
 * type. It cannot be a partial map or array. It can be nested maps
 * and arrays, but they must all be complete.
 */
static void ctoken_encode_add_cbor(struct ctoken_encode_ctx *me,
                                   int32_t label,
                                   struct q_useful_buf_c encoded);




/**
 * \brief Finish the token, complete the signing and get the result
 *
 * \param[in] me                Token Creation Context.
 * \param[out] completed_token  Pointer and length to completed token.
 *
 * \return one of the \ref CTOKEN_ERR_t errors.
 *
 * This completes the token after the payload has been added. When
 * this is called the signing algorithm is run and the final
 * formatting of the token is completed.
 */
enum ctoken_err_t
ctoken_encode_finish(struct ctoken_encode_ctx *me,
                     struct q_useful_buf_c *completed_token);






/* ----- inline implementations ------ */

static inline void
ctoken_encode_set_key(struct ctoken_encode_ctx *me,
                      struct t_cose_key key,
                      struct q_useful_buf_c key_id)
{
    t_cose_sign1_set_signing_key(&(me->signer_ctx), key, key_id);
}


static inline void
ctoken_encode_init(struct ctoken_encode_ctx *me,
                   uint32_t t_cose_opt_flags,
                   uint32_t token_opt_flags,
                   int32_t cose_alg_id)
{
    me->opt_flags = token_opt_flags;
    t_cose_sign1_sign_init(&(me->signer_ctx), t_cose_opt_flags, cose_alg_id);
}


static inline QCBOREncodeContext *
ctoken_encode_borrow_cbor_cntxt(struct ctoken_encode_ctx *me)
{
    return &(me->cbor_enc_ctx);
}


static inline void
ctoken_encode_add_integer(struct ctoken_encode_ctx *me,
                          int32_t label,
                          int64_t Value)
{
    QCBOREncode_AddInt64ToMapN(&(me->cbor_enc_ctx), label, Value);
}


static inline void
ctoken_encode_add_unsigned(struct ctoken_encode_ctx *me,
                          int32_t label,
                          uint64_t Value)
{
    QCBOREncode_AddUInt64ToMapN(&(me->cbor_enc_ctx), label, Value);
}


static inline void
ctoken_encode_add_bstr(struct ctoken_encode_ctx *me,
                       int32_t label,
                       struct q_useful_buf_c bstr)
{
    QCBOREncode_AddBytesToMapN(&(me->cbor_enc_ctx), label, bstr);
}


static inline void
ctoken_encode_add_tstr(struct ctoken_encode_ctx *me,
                       int32_t label,
                       struct q_useful_buf_c tstr)
{
    QCBOREncode_AddTextToMapN(&(me->cbor_enc_ctx), label, tstr);
}


static inline void
ctoken_encode_add_cbor(struct ctoken_encode_ctx *me,
                       int32_t label,
                       struct q_useful_buf_c encoded)
{
    QCBOREncode_AddEncodedToMapN(&(me->cbor_enc_ctx), label, encoded);
}


static inline void
attest_token_encode_open_array(struct ctoken_encode_ctx *me, int32_t label)
{
    QCBOREncode_OpenArrayInMapN(&(me->cbor_enc_ctx), label);
}


static inline void
attest_token_encode_close_array(struct ctoken_encode_ctx *me)
{
    QCBOREncode_CloseArray(&(me->cbor_enc_ctx));
}


#ifdef __cplusplus
}
#endif

#endif /* __CTOKEN_ENCODE_H__ */
