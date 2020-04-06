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

#include "ctoken_cwt_encode.h"
#include "ctoken_eat_labels.h"


#ifdef __cplusplus
extern "C" {
#if 0
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
static inline void
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
static inline void
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
static inline void
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
static inline void
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
static inline void
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
static inline void
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
static inline void
ctoken_eat_encode_uptime(struct ctoken_encode_ctx  *context,
                         uint64_t                    uptime);


#ifdef SUBMODS_ARE_IMPLEMENTED

// Prototypes for the planned submods impementation
static void ctoken_eat_encode_open_submod(struct attest_token_encode_ctx *me,
                                            char *submod_name,
                                            int nConnectionType);

static void ctoken_eat_encode_close_submod(struct attest_token_encode_ctx *me);


static void ctoken_eat_encode_add_token(struct attest_token_encode_ctx *me,
                                          char *submod_name,
                                          int nConnectionType,
                                          struct q_useful_buf_c token);
#endif

/* --------------------------------------------------------------------------
 *       Inline implementations
 * --------------------------------------------------------------------------*/
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

#ifdef __cplusplus
}
#endif

#endif /* eat_encode_h */
