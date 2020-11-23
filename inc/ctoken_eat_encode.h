/*
 * ctoken_eat_encode.h
 *
 * Copyright (c) 2020 Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 1/31/20.
 */


#ifndef eat_encode_h
#define eat_encode_h

#include "ctoken_cwt_encode.h" /* EAT is a type of CWT */
#include "ctoken_eat_labels.h"


#ifdef __cplusplus
extern "C" {
#ifdef 0
} /* Keep editor indention formatting happy */
#endif
#endif

/**
 * \file ctoken_eat_encode.h
 *
 * These are methods to be used with the ctoken encoder
 * to output the EAT-defined claims for a token. EAT is currently
 * an IETF standards track draft, a product of the IETF RATS
 * working group. This implementation will evolve with the
 * IETF standard.
 *
 * Most of these are simple inline functions that use the
 * main ctoken functions for encoding claims of basic CBOR types.
 */



static void
ctoken_eat_encode_init(struct ctoken_encode_ctx *me,
                       uint32_t                  t_cose_opt_flags,
                       uint32_t                  token_opt_flags,
                       int32_t                   cose_alg_id);



/**
 * \brief Set the signing key.
 *
 *
 * \param[in] me           The token creation context.
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
ctoken_eat_encode_set_key(struct ctoken_encode_ctx *me,
                          struct t_cose_key         signing_key,
                          struct q_useful_buf_c     kid);



static enum ctoken_err_t
ctoken_eat_encode_start(struct ctoken_encode_ctx  *me,
                        const struct q_useful_buf out_buffer);

/**
 * \brief  Encode the nonce claim.
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
ctoken_eat_encode_nonce(struct ctoken_encode_ctx *context,
                        struct q_useful_buf_c     nonce);


/**
 * \brief  Encode the UEID claim.
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
ctoken_eat_encode_ueid(struct ctoken_encode_ctx *context,
                       struct q_useful_buf_c     ueid);


/**
 * \brief  Encode the OEM ID (oemid) claim.
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
ctoken_eat_encode_oemid(struct ctoken_encode_ctx *context,
                        struct q_useful_buf_c     oemid);


/**
 * \brief  Encode the origination claim.
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
ctoken_eat_encode_origination(struct ctoken_encode_ctx *context,
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
 * the HW and SW are.  See \ref ctoken_eat_security_level_t.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static void
ctoken_eat_encode_security_level(struct ctoken_encode_ctx        *context,
                                 enum ctoken_eat_security_level_t security_level);



/**
 * \brief  Encode the debug and boot state claim.
 *
 * \param[in] context              The encoding context to output to.
 * \paran[in] secure_boot_enabled  This is \c true if secure boot
 *                                 is enabled or \c false it no.
 * \param[out] debug_state         See \ref ctoken_eat_debug_level_t for
 *                                 the different debug states.
 *
 * This outputs the debug and boot state claim.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
void
ctoken_eat_encode_boot_state(struct ctoken_encode_ctx     *context,
                             bool                          secure_boot_enabled,
                             enum ctoken_eat_debug_level_t debug_state);


/**
 * \brief Encode an EAT location claims
 *
 * \param[in] context   ctoken encode context to output to.
 * \param[in] location  The location to output.
 *
 * Only the location fields indicated as present in \c item_flags
 * will be output.
 */
void
ctoken_eat_encode_location(struct ctoken_encode_ctx           *context,
                           const struct ctoken_eat_location_t *location);


/**
 * \brief  Encode the age claim.
 *
 * \param[in] context         The encoding context to output to.
 * \paran[in] age             The age in seconds of the token.
 *
 * This outputs the age claim.
 *
 * If the other claims in token were obtained previously and held
 * until token creation, this gives their age in seconds in the epoch
 * (January 1, 1970).
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static void
ctoken_eat_encode_age(struct ctoken_encode_ctx  *context,
                      uint64_t                   age);


/**
 * \brief  Encode the uptime claim.
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
ctoken_eat_encode_uptime(struct ctoken_encode_ctx  *context,
                         uint64_t                    uptime);


/*

 start_submods
 enter_submod
 enter_submod -- error
 exit_submod
 enter_submod
 end_submods

 enter_submod -- error

 enter_submod
 exit_submod
 enter_submod
 enter_submod -- nests
 exit_submod
 exit_submod
 add_encoded_submod



 */

void ctoken_eat_encode_start_submod_section(struct ctoken_encode_ctx *context);


void ctoken_eat_encode_end_submod_section(struct ctoken_encode_ctx *context);



/**
 * \brief  Start encoding claims in a sub module.
 *
 * \param[in] context  Encoding context
 * \param [in] submod_name  Text string naming sub module.
 *
 * Initiates the creation of a sub module. All claims added after this
 * call until the a call to ctoken_eat_encode_close_submod() will
 * go into the named submodule.
 *
 * Submodules can nest to a depth of \ref CTOKEN_MAX_SUBMOD_NESTING. To
 * nest one submodule inside another, simply call this again
 * before calling ctoken_eat_encode_close_submod().
 *
 * All submodule go into a special map at the top level
 * designated to hold them by the label TODO: xxxx.
 * When the first submodule is opened, this map is
 * created. When the last submodule is closed, this
 * map is closed. Thus, encoding of all the submodules
 * must be done together and can't be intermixed with
 * other top-level claims.
 *
 * If an error occurs, such as nesting too deep, it will be reported when
 * ctoken_encode_finish() is called.
 */
void ctoken_eat_encode_open_submod(struct ctoken_encode_ctx *context,
                                   const char               *submod_name);


/**
 * \brief  End encoding claims in a sub module.
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
void ctoken_eat_encode_close_submod(struct ctoken_encode_ctx *context);


/**
 * \brief Add a complete EAT token as a submodule.
 *
 * \param[in] context           Token creation context.
 * \param[in] type                  Whether added token is CBOR format or JSON format.
 * \param[in] submod_name  String naming the submodule.
 * \param[in] token               The full encoded token.
 *
 * A submodule can be a fully encoded and signed EAT token such as
 * the completed_token returned from ctoken_encode_finish(). Use this
 * call to add such a token.
 *
 * The added token may be CBOR/COSE/CWT format or JSON/JOSE/JWT format.
 * Indicate which with the \c type parameter.
 *
 * The contents of token are not checked by this call. The bytes
 * are just added.
 *
 * Submods may only be added at the end of token creation. All
 * non-submod claims must be added before any call to attest_token_encode_open_submod()
 * or attest_token_encode_add_token().
 *
 * If an error occurs it will be reported when
 * ctoken_encode_finish() is called.
 */
void ctoken_eat_encode_add_token(struct ctoken_encode_ctx *context,
                                 enum ctoken_type          type,
                                 const char               *submod_name,
                                 struct q_useful_buf_c     token);



/**
 * \brief Finish the token, complete the signing and get the result
 *
 * \param[in] me                Token creation context.
 * \param[out] completed_token  Pointer and length to completed token.
 *
 * \return                      One of the \ref ctoken_err_t errors.
 *
 * This completes the token after the payload has been added. When
 * this is called the signing algorithm is run and the final
 * formatting of the token is completed.
 */
static enum ctoken_err_t
ctoken_eat_encode_finish(struct ctoken_encode_ctx *me,
                         struct q_useful_buf_c    *completed_token);




/* --------------------------------------------------------------------------
 *       Inline implementations
 * --------------------------------------------------------------------------*/

static inline void
ctoken_eat_encode_init(struct ctoken_encode_ctx *me,
                       uint32_t                  t_cose_opt_flags,
                       uint32_t                  token_opt_flags,
                       int32_t                   cose_alg_id)
{
    ctoken_encode_init(me, t_cose_opt_flags, token_opt_flags, cose_alg_id);
}


static inline void
ctoken_eat_encode_set_key(struct ctoken_encode_ctx *me,
                          struct t_cose_key         signing_key,
                          struct q_useful_buf_c     kid)
{
    ctoken_encode_set_key(me, signing_key, kid);
}


static inline enum ctoken_err_t
ctoken_eat_encode_start(struct ctoken_encode_ctx  *me,
                        const struct q_useful_buf  out_buffer)
{
    return ctoken_encode_start(me, out_buffer);
}


static inline void
ctoken_eat_encode_nonce(struct ctoken_encode_ctx *me,
                        struct q_useful_buf_c     nonce)
{
    ctoken_encode_add_bstr(me, CTOKEN_EAT_LABEL_NONCE, nonce);
}


static inline void
ctoken_eat_encode_ueid(struct ctoken_encode_ctx *me,
                       struct q_useful_buf_c     ueid)
{
    ctoken_encode_add_bstr(me, CTOKEN_EAT_LABEL_UEID, ueid);
}


static inline void
ctoken_eat_encode_oemid(struct ctoken_encode_ctx *me,
                        struct q_useful_buf_c     oemid)
{
    ctoken_encode_add_bstr(me, CTOKEN_EAT_LABEL_OEMID, oemid);
}



static inline void
ctoken_eat_encode_origination(struct ctoken_encode_ctx *me,
                              struct q_useful_buf_c origination)
{
    ctoken_encode_add_tstr(me, CTOKEN_EAT_LABEL_ORIGINATION, origination);
}

static inline void
ctoken_eat_encode_security_level(struct ctoken_encode_ctx *me,
                                 enum ctoken_eat_security_level_t security_level)
{
    ctoken_encode_add_integer(me,
                              CTOKEN_EAT_LABEL_SECURITY_LEVEL,
                              (int64_t)security_level);
}

static inline void
ctoken_eat_encode_age(struct ctoken_encode_ctx  *me,
                      uint64_t                   age)
{
    ctoken_encode_add_integer(me, CTOKEN_EAT_LABEL_AGE, age);
}


static inline void
ctoken_eat_encode_uptime(struct ctoken_encode_ctx  *me,
                         uint64_t                   uptime)
{
    ctoken_encode_add_integer(me, CTOKEN_EAT_LABEL_UPTIME, uptime);
}




static inline enum ctoken_err_t
ctoken_eat_encode_finish(struct ctoken_encode_ctx *me,
                         struct q_useful_buf_c    *completed_token)
{
    return ctoken_encode_finish(me, completed_token);
}

#ifdef __cplusplus
}
#endif

#endif /* eat_encode_h */
