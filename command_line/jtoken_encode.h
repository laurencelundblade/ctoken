//
//  jtoken_encode.h -- the beginning of a JWT encoder
//  CToken
//
//  Created by Laurence Lundblade on 2/2/21.
//  Copyright © 2021 Laurence Lundblade. All rights reserved.
//

#ifndef jtoken_encode_h
#define jtoken_encode_h

#include <stdio.h>
#include "t_cose/q_useful_buf.h"
#include "ctoken.h"


enum jtoken_simple_t {JSON_TRUE, JSON_FALSE, JSON_NULL};

enum jtoken_security_level_t {
    /* Never appears in a protocol message. */
    JTOKEN_EAT_SL_INVALID           = 0,
    /** Signing key is protected by a general purpose OS running on generic
      * hardware
      */
    JTOKEN_EAT_SL_UNRESTRICTED      = 1,
    /** Signing key is running on an isolated subsystem, perhaps special
     * hardware, but it is not a security-oriented subystem.
     */
    JTOKEN_EAT_SL_RESTRICTED        = 2,
    /** Signing key is protected by a security-oriented subsystem like a TEE
      */
    JTOKEN_EAT_SL_SECURE_RESTRICTED = 3,
    /** Signing key is protected by a security-oriented subsystem with
     * defenses against hardware invasive attacks
     */
    JTOKEN_EAT_SL_HARDWARE          = 4};


/**
 * This characterizes the hardware and system debug state of the
 * attestor.
 */
enum jtoken_debug_level_t {
    /* Never appears in a protocol message. */
    JTOKEN_DEBUG_INVALID = -1,
    /** The debug system is enabled */
    JTOKEN_DEBUG_ENABLED = 0,
    /** The debug system is disabled, but might have been enabled recently,
     * been enabled since the system booted or started */
    JTOKEN_DEBUG_DISABLED = 1,
    /** The debug system is disabled and has not been enabled recently, not
     * since before the device most recently booted or restarted
     */
    JTOKEN_DEBUG_DISABLED_SINCE_BOOT = 2,
    /** The debug system is disabled and cannot be enabled by any put the
     * chip / hardware manufacturer
     */
    JTOKEN_DEBUG_DISABLED_PERMANENT = 3,
    /** The debug system cannot be enabled by anyone */
    JTOKEN_DEBUG_DISABLED_FULL_PERMANENT = 4};


struct jtoken_encode_ctx {
    FILE *out_file; // TODO: write to memory instead like ctoken.
    int   indent_level;
};

int jwt_encode_init(struct jtoken_encode_ctx *me, FILE *out_file);


int jtoken_encode_location(struct jtoken_encode_ctx *me, const struct ctoken_location_t *location);

void jtoken_encode_int64(struct jtoken_encode_ctx *me, const char *claim_name, int64_t claim_value);

void jtoken_encode_uint64(struct jtoken_encode_ctx *me, const char *claim_name, uint64_t claim_value);

void jtoken_encode_double(struct jtoken_encode_ctx *me, const char *claim_name, double claim_value);

void jtoken_encode_text_string(struct jtoken_encode_ctx *me,
                               const char               *claim_name,
                               struct q_useful_buf_c     claim_value);

static void jtoken_encode_text_string_z(struct jtoken_encode_ctx *me,
                                 const char               *claim_name,
                                 const char               *claim_value);

void jtoken_encode_byte_string(struct jtoken_encode_ctx *me,
                               const char               *claim_name,
                               struct q_useful_buf_c     claim_value);

void jtoken_encode_simple(struct jtoken_encode_ctx *me,
                               const char               *claim_name,
                               enum jtoken_simple_t      simple);

void jtoken_encode_bool(struct jtoken_encode_ctx *me,
                        const char               *claim_name,
                        bool claim_value);

void jtoken_encode_null(struct jtoken_encode_ctx *me,
                        const char               *claim_name);


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
static void jtoken_encode_issuer(struct jtoken_encode_ctx *context,
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
static void jtoken_encode_subject(struct jtoken_encode_ctx *context,
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
static void jtoken_encode_audience(struct jtoken_encode_ctx *context,
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
static void jtoken_encode_expiration(struct jtoken_encode_ctx *context,
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
static void jtoken_encode_not_before(struct jtoken_encode_ctx *context,
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
static void jtoken_encode_iat(struct jtoken_encode_ctx *context,
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
static void jtoken_encode_jti(struct jtoken_encode_ctx *context,
                              struct q_useful_buf_c     cti);


static inline void jtoken_encode_ueid(struct jtoken_encode_ctx *me,
                                      struct q_useful_buf_c     claim_value);


static inline void jtoken_encode_nonce(struct jtoken_encode_ctx *me,
                                       struct                    q_useful_buf_c claim_value);


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
jtoken_encode_oemid(struct jtoken_encode_ctx *context,
                    struct q_useful_buf_c     oemid);


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
jtoken_encode_security_level(struct jtoken_encode_ctx        *context,
                             enum jtoken_security_level_t security_level);



/**
 * \brief  Encode the EAT debug state claim.
 *
 * \param[in] context              The encoding context to output to.
 * \param[out] debug_state         See \ref ctoken_debug_level_t for
 *                                 the different debug states.
 *
 * This outputs the debug state claim.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static void
jtoken_encode_debug_state(struct jtoken_encode_ctx  *context,
                          enum ctoken_debug_level_t  debug_state);





void jtoken_encode_start_submod_section(struct jtoken_encode_ctx  *context);

void jtoken_encode_end_submod_section(struct jtoken_encode_ctx  *context);

void jtoken_encode_open_submod(struct jtoken_encode_ctx *context,
                               const char               *submod_name);

void jtoken_encode_close_submod_section(struct jtoken_encode_ctx  *context);





static inline void
jtoken_encode_text_string_z(struct jtoken_encode_ctx *me,
                                 const char               *claim_name,
                                 const char               *claim_value)
{
    jtoken_encode_text_string(me,
                              claim_name,
                              q_useful_buf_from_sz(claim_value));
}


static inline void jtoken_encode_issuer(struct jtoken_encode_ctx *me,
                                        struct q_useful_buf_c     issuer)
{
    jtoken_encode_text_string(me, "iss", issuer);
}

static inline void jtoken_encode_subject(struct jtoken_encode_ctx *me,
                                  struct q_useful_buf_c     subject)
{
    jtoken_encode_text_string(me, "sub", subject);
}

static inline void jtoken_encode_audience(struct jtoken_encode_ctx *me,
                                   struct q_useful_buf_c     audience)
{
    jtoken_encode_text_string(me, "aud", audience);
}

static inline void jtoken_encode_expiration(struct jtoken_encode_ctx *me,
                                     int64_t                   expiration)
{
    jtoken_encode_int64(me, "exp", expiration);
}

static inline void jtoken_encode_not_before(struct jtoken_encode_ctx *me,
                                     int64_t                   not_before)
{
    jtoken_encode_int64(me, "nbf", not_before);
}

static inline void jtoken_encode_iat(struct jtoken_encode_ctx *me,
                                     int64_t                   iat)
{
    jtoken_encode_int64(me, "iat", iat);
}

static inline void jtoken_encode_jti(struct jtoken_encode_ctx *me,
                              struct q_useful_buf_c     jti)
{
    jtoken_encode_text_string(me, "jti", jti);
}




static inline void jtoken_encode_ueid(struct jtoken_encode_ctx *me,
                                      struct q_useful_buf_c     claim_value)
{
    jtoken_encode_byte_string(me, "ueid", claim_value);
}


static inline void jtoken_encode_nonce(struct jtoken_encode_ctx *me,
                                       struct                    q_useful_buf_c nonce)
{
    jtoken_encode_byte_string(me, "nonce", nonce);
}


static inline void
jtoken_encode_oemid(struct jtoken_encode_ctx *me,
                    struct q_useful_buf_c     oemid)
{
    jtoken_encode_byte_string(me, "oemid", oemid);

}

static inline void
jtoken_encode_security_level(struct jtoken_encode_ctx    *me,
                             enum jtoken_security_level_t security_level)
{
    // TODO: check for invalid
    jtoken_encode_int64(me, "seclevel", security_level);
}

static inline void
jtoken_encode_debug_state(struct jtoken_encode_ctx  *me,
                          enum ctoken_debug_level_t  debug_state)
{
    // TODO: check for invalid
    jtoken_encode_int64(me, "dbgstate", debug_state);
}


#endif /* jtoken_encode_h */
