/*
 * ctoken_eat_decode.h
 *
 * Copyright (c) 2020 Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 2/1/20.
 */

#ifndef eat_decode_h
#define eat_decode_h

#include "ctoken_cwt_decode.h"
#include "ctoken_eat_labels.h"
#include "ctoken_decode.h"


/**
 * \file ctoken_eat_decode.h
 *
 * These are methods to be used with the ctoken decoder
 * to get the EAT-defined claims out of the token. EAT is currently
 * an IETF standards track draft, a product of the IETF RATS
 * working group. This implementation will evolve with the
 * IETF standard.
 *
 * Most of these are simple inline functions that use the
 * main ctoken functions for getting claims of basic CBOR types.
 *
 * The storage for all strings and binary blobs returned is
 * that of the token passed in. They are not malloced and do
 * not have to be freed.
 */


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
ctoken_eat_decode_nonce(struct ctoken_decode_ctx *context,
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
ctoken_eat_decode_ueid(struct ctoken_decode_ctx *context,
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
ctoken_eat_decode_oemid(struct ctoken_decode_ctx *context,
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
ctoken_eat_decode_origination(struct ctoken_decode_ctx *context,
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
 * the HW and SW are.  See \ref ctoken_eat_security_level_t.
 */
static inline enum ctoken_err_t
ctoken_eat_decode_security_level(struct ctoken_decode_ctx         *context,
                                 enum ctoken_eat_security_level_t *security_level);


/**
 * \brief Decode the boot and debug state claim.
 *
 * \param[in] context               The decoding context to decode from.
 * \param[out] secure_boot_enabled  This is \c true if secure boot
 *                                  is enabled or \c false it no.
 * \param[out] debug_state          See \ref ctoken_eat_debug_level_t for
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
 * the HW and SW are.  See \ref ctoken_eat_security_level_t.
 */
enum ctoken_err_t
ctoken_eat_decode_boot_state(struct ctoken_decode_ctx *context,
                             bool                     *secure_boot_enabled,
                             enum ctoken_eat_debug_level_t *debug_state);


/**
 * \brief Decode position location (e.g. GPS location)
 *
 * \param[in] context   The decoding context to decode from.
 * \param[out] location The returned location
 *
 * \retval CTOKEN_ERR_NOT_FOUND             No location claims exists.
 * \retval CTOKEN_ERR_CBOR_NOT_WELL_FORMED  CBOR is not well formed.
 * \retval CTOKEN_ERR_CBOR_STRUCTURE        The location claim format is bad.
 *
 * This finds the location claim in the token and returns its
 * contents.
 *
 * Only some of the values in the location claim may be present. See
 * \ref ctoken_eat_location_t for how the data is returned.
 */
enum ctoken_err_t
ctoken_eat_decode_location(struct ctoken_decode_ctx     *context,
                           struct ctoken_eat_location_t *location);


/**
 * \brief  Decode the age claim.
 *
 * \param[in] context         The decoding context to output to.
 * \paran[in] age             The age in seconds of the token.
 *
 * This decodes the age claim.
 *
 * If the other claims in token were obtained previously and held
 * until token creation, this gives their age in seconds in the epoch
 * (January 1, 1970).
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static inline enum ctoken_err_t
ctoken_eat_decode_age(struct ctoken_decode_ctx  *context,
                      uint64_t                   *age);




static inline enum ctoken_err_t
ctoken_eat_decode_uptime(struct ctoken_decode_ctx  *context,
                         uint64_t                   *uptime);


// TODO: the age and uptime claims

#ifdef SUBMODS_ARE_IMPLEMENTED

// Prototypes for the planned submods impementation
enum ctoken_err_t
ctoken_decode_eat_get_num_submods(struct ctoken_decode_context *me,
                                  uint8_t *num_submods);

enum ctoken_err_t
ctoken_decode_eat_enter_submod(struct ctoken_decode_context *me,
                                     uint8_t submod_index,
                                     struct q_useful_buf_c *name,
                                     int *connection_type);

enum ctoken_err_t
ctoken_decode_eat_leave_submod(struct ctoken_decode_context *me);

#endif




/* --------------------------------------------------------------------------
 *       Inline implementations
 * --------------------------------------------------------------------------*/

static inline enum ctoken_err_t
ctoken_eat_decode_nonce(struct ctoken_decode_ctx *me,
                        struct q_useful_buf_c    *nonce)
{
    return ctoken_decode_get_bstr(me, CTOKEN_EAT_LABEL_NONCE, nonce);
}


static inline enum ctoken_err_t
ctoken_eat_decode_ueid(struct ctoken_decode_ctx *me,
                       struct q_useful_buf_c    *ueid)
{
    return ctoken_decode_get_bstr(me, CTOKEN_EAT_LABEL_UEID, ueid);
}


static inline enum ctoken_err_t
ctoken_eat_decode_oemid(struct ctoken_decode_ctx *me,
                        struct q_useful_buf_c        *oemid)
{
    return ctoken_decode_get_bstr(me, CTOKEN_EAT_LABEL_OEMID, oemid);
}


static inline enum ctoken_err_t
ctoken_eat_decode_origination(struct ctoken_decode_ctx *me,
                              struct q_useful_buf_c    *origination)
{
    return ctoken_decode_get_tstr(me, CTOKEN_EAT_LABEL_ORIGINATION, origination);
}


static inline enum ctoken_err_t
ctoken_eat_decode_security_level(struct ctoken_decode_ctx         *me,
                                 enum ctoken_eat_security_level_t *security_level)
{
    return ctoken_decode_get_int(me, CTOKEN_EAT_LABEL_SECURITY_LEVEL, (int64_t *)security_level);
}

static inline enum ctoken_err_t
ctoken_eat_decode_age(struct ctoken_decode_ctx  *me,
                      uint64_t                   *age)
{
    return ctoken_decode_get_uint(me, CTOKEN_EAT_LABEL_AGE, age);
}


static inline enum ctoken_err_t
ctoken_eat_decode_uptime(struct ctoken_decode_ctx  *me,
                         uint64_t                   *uptime)
{
    return ctoken_decode_get_uint(me, CTOKEN_EAT_LABEL_UPTIME, uptime);
}

#endif /* eat_decode_h */
