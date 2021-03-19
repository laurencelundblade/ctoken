/*
 * ctoken.h (formerly attest_token.h)
 *
 * Copyright (c) 2018-2021, Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __CTOKEN_H__
#define __CTOKEN_H__

#include <stdint.h>
#include "ctoken_eat_labels.h"
#include <stdbool.h>


#ifdef __cplusplus
extern "C" {
#if 0
} /* Keep editor indention formatting happy */
#endif
#endif


/**
 * \file ctoken.h
 *
 * \brief Common definitions for ctoken encoding and decoding.
 *
 */


#ifndef C_ARRAY_COUNT
#define C_ARRAY_COUNT(array, type) (sizeof(array)/sizeof(type))
#endif


/**
 * Error codes returned from CBOR token creation.
 */
enum ctoken_err_t {
    /** Success */
    CTOKEN_ERR_SUCCESS = 0,

    /** The buffer passed in to receive the output is too small. */
    CTOKEN_ERR_TOO_SMALL = 1,

    /** Something went wrong formatting the CBOR, most likely the
     payload has maps or arrays that are not closed. */
    CTOKEN_ERR_CBOR_FORMATTING = 2,

    /** A general, unspecific error when creating or decoding the
        token. */
    CTOKEN_ERR_GENERAL = 3,

    /** A hash function that is needed to make the token is not
        available. */
    CTOKEN_ERR_HASH_UNAVAILABLE = 4,

    /** CBOR Syntax not well-formed -- a CBOR syntax error. */
    CTOKEN_ERR_CBOR_NOT_WELL_FORMED = 5,

    /** Bad CBOR structure, for example not a map when was is
        required. */
    CTOKEN_ERR_CBOR_STRUCTURE = 6,

    /** Bad CBOR type, for example an not a text string, when a text
        string is required. */
    CTOKEN_ERR_CBOR_TYPE = 7,

    /** Integer too large, for example an \c int32_t is required, but
        value only fits in \c int64_t */
    CTOKEN_ERR_INTEGER_VALUE = 8,

    /** Something is wrong with the COSE signing structure, missing
        headers or such. */
    CTOKEN_ERR_COSE_SIGN1_FORMAT = 9,

    /** COSE signature is invalid, data is corrupted. */
    CTOKEN_ERR_COSE_SIGN1_VALIDATION = 10,

    /** The signing algorithm is not supported. */
    CTOKEN_ERR_UNSUPPORTED_SIG_ALG = 11,

    /** Out of memory. */
    CTOKEN_ERR_INSUFFICIENT_MEMORY = 12,

    /** Tampering detected in cryptographic function. */
    CTOKEN_ERR_TAMPERING_DETECTED = 13,

    /** Verification key is not found or of wrong type. */
    CTOKEN_ERR_VERIFICATION_KEY = 14,

    /** No token was given or validated. */
    CTOKEN_ERR_NO_VALID_TOKEN = 15,

    /** Data item with label wasn't found. */
    CTOKEN_ERR_NOT_FOUND = 16,

    /** SW Compoments absence not correctly indicated. */
    CTOKEN_ERR_SW_COMPONENTS_MISSING = 17,

    /** Trying to nest more than \ref CTOKEN_MAX_SUBMOD_NESTING or the
     * nesting of some claim is deeper than \c QCBOR_MAX_ARRAY_NESTING.
     */
    CTOKEN_ERR_NESTING_TOO_DEEP = 18,

    /** Trying to close a submod with no submods open. */
    CTOKEN_ERR_NO_SUBMOD_OPEN = 19,

    /** When decoding, something wrong with the token format other
     * than CBOR not well formed. */
    CTOKEN_ERR_TOKEN_FORMAT = 20,

    /** Can't start submodule section because one is already started,
      * or one was started and completed for this submodule. */
    CTOKEN_CANT_START_SUBMOD_SECTION = 21,

    /** Trying to end a submod section with no submod section
     * started. */
    CTOKEN_ERR_NO_SUBMOD_SECTION_STARTED = 22,

    /** Attempting to make a submod or add a token without starting a
      * submod section */
    CTOKEN_ERR_CANT_MAKE_SUBMOD_IN_SUBMOD = 23,

    /** All submodules and submodule sections were not closed out. */
    CTOKEN_ERR_SUBMODS_NOT_CLOSED = 24,

    /** The name of a submodule is not a text string. */
    CTOKEN_ERR_SUBMOD_NAME_NOT_A_TEXT_STRING = 25,

    /** The submodule is a nested token and can't be entered. */
    CTOKEN_ERR_SUBMOD_IS_A_TOKEN = 26,

    /** No submodule of the given name as found. */
    //CTOKEN_NAMED_SUBMOD_NOT_FOUND = 27, // TODO: renumber around

    /** Claim is not present in the token */
    CTOKEN_ERR_CLAIM_NOT_PRESENT = 28,

    /** The requested submodule was not found. */
    CTOKEN_ERR_SUBMOD_NOT_FOUND = 29,

    /** Submodule is the wrong CBOR type */
    CTOKEN_ERR_SUBMOD_TYPE = 30,

    /** Submods section in input is wrong data type, malformed or invalid. */
    CTOKEN_ERR_SUBMOD_SECTION = 31,

    /** Something is wrong with the content of a claim such as mandatory
     * parts are missing, the CBOR structure is wrong or other. */
    CTOKEN_ERR_CLAIM_FORMAT = 32,

    /** The latitude and longitude fields are required in the location claim */
    CTOKEN_ERR_LAT_LONG_REQUIRED = 33,

    /** */
    CTOKEN_ERR_TOO_MANY_TAGS = 34,

    /** The @ref ctoken_protection_t type passed to encode or decode
     * is not supported. */
    CTOKEN_ERR_UNSUPPORTED_PROTECTION_TYPE = 35,

    /** When decoding the token is not a tag that specifies a
     protection type (e.g. CWT/COSE) nor was a protection type given
     as an argument. */
    CTOKEN_ERR_UNDETERMINED_PROTECTION_TYPE = 36,

    /** The content of a tag is not of the right type. */
    CTOKEN_ERR_TAG_CONTENT = 37,

    /** The value of the claim is outside allowed range. */
    CTOKEN_ERR_CLAIM_RANGE = 38,

    /** CWT requires a COSE tag be the content of a CWT tag. */
    CTOKEN_ERR_TAG_COMBO_NOT_ALLOWED = 39,

    /** The input token was a tag when a decode options was set to
     * prohibit a tag and accept only bare/unwrapped tag content. */
    CTOKEN_ERR_SHOULD_NOT_BE_TAG = 40,

    /** The input token was bare/unwrapped tag content when a decode
     * options was set to require a tag. */
    CTOKEN_ERR_SHOULD_BE_TAG = 41,

    /** When calling ctoken_decode_next_claim(), no more
     * claims in the token or submodule. */
    CTOKEN_ERR_NO_MORE_CLAIMS = 42,

    /** A duplicate label was found in the token (two instances of the same claim).
     * It may not be the claim that was being decoded. */
    CTOKEN_ERR_DUPLICATE_LABEL = 43,

    /** An unexpected error was returned by the CBOR decoder, one
     * that is not specifically mapped to another error here.*/
    CTOKEN_ERR_CBOR_DECODE = 44,

    /** A t_cose error that is not mapped to any particular ctoken error. */
    CTOKEN_ERROR_GENERAL_T_COSE = 45,

    /** Something went wrong with the crypto library called by t_cose. */
    CTOKEN_ERROR_T_COSE_CRYPTO = 46,

    /** Something is wrong with the COSE header parameters. */
    CTOKEN_ERROR_COSE_PARAMETERS = 47,

    /** Error with short-circuit signature (see t_cose).  */
    CTOKEN_ERROR_SHORT_CIRCUIT_SIG = 48,

    /** An issue with a signing or verification key. */
    CTOKEN_ERROR_KEY = 49,

    /** An issue with the CBOR tags on the COSE structures. */
    CTOKEN_ERROR_COSE_TAG = 50
};


/** The maximum nesting depth for submodules. */
#define CTOKEN_MAX_SUBMOD_NESTING  (QCBOR_MAX_ARRAY_NESTING/2)



/*
 @anchor TagsAndProtection

 EAT tokens can be one of these three: CWT (RFC8392), JWT (RFC7519) or
 UCCS (draft-birkholz-rats-uccs). While JWT provided for an
 unprotected form, CWT does not. To compensate for this UCCS was
 created. It is purely a CWT with no protection. The discussion below
 is just for CWT and UCCS as this implementation doesn’t support JWT.

 TODO: explain the confusing use of "tag" in CBOR.

 This describes the configuration parameters for encoding and decoding
 that control what sort of CBOR tag and protection type
 handling. Here, protection type refers to whether a token has no
 protection (it is a UCCS) or has COSE protection (it is a CWT) and
 when it has protection, the type of protection (COSE signing, COSE
 Mac, COSE encryption…).

 When encoding, some indication of the protection type is typically
 put in the encoded token, so the decoder can determine the protection
 type and process it correctly. However, sometimes no indication of
 the protection type is put in the encoded token. Instead, it is in
 the protocol that carries the token. For example, it might indicated
 by a content type, file type or MIME type.

 Whether protection type is indicated or not indicated is up to the
 design of the protocol that is carrying the EAT. This author
 recommends explicitly indicating the protection type by CBOR tag even
 if it is redundant unless the carrying protocol really can indicate
 all the variants of protection. These variants include UCCS for no
 protection, COSE_Sign1 and COSE_Mac0 for authenticity and/or variants
 of COSE encryption enveloping the signing. The message size cost is
 an insignificant 2-3 bytes.

 Three parameters control what is encoded. They are passed to
 ctoken_encode_init(). First is the actual protection type. It must
 always be given. Second is whether to indicate by tag if it is an
 EAT/CWT/UCCS or not. Third, is whether to indicate the type of COSE
 protection used. There are five combinations of these three that are
 useful.

 1. Unprotected UCCS tag

 There is no signing or encryption. The output is a UCCS tag which
 tells the recipient it is an EAT/CWT with no protection. A UCCS is by
 definition a CWT with no COSE protection.

     Token: 601(map containing claims)
     Call:  ctoken_encode_init(context, 0, 0, CTOKEN_PROTECTION_NONE, 0);

 2. Bare unprotected token

 There is no signing or encryption. The output is not a tag at
 all. This is sometimes referred to as an “unwrapped UCCS tag”. The
 recipient has to know by other context that they are receiving an
 EAT/CWT with no protection.

     Token: map containing claims
     Call:  ctoken_encode_init(context, 0, CTOKEN_OPT_TOP_LEVEL_NOT_TAG, CTOKEN_PROTECTION_NONE, 0);

 3. COSE protected and indication by tags.

COSE signing and/or encryption is used. The output is a CWT tag plus a
COSE tag to tell the recipient that the token is an CWT/EAT and what
sort of COSE protection is in use.

    Token: 61(18(Cose_Sign1 array, claims map in the payload))
    Call: ctoken_encode_init(context, 0, 0, CTOKEN_PROTECTION_COSE_SIGN1, ECDSA256);

 4. COSE protected with only type of protection indicated by tag.

 This is the same as 3, but only the tag indicating the type of COSE
 protection is used. The recipient must know that what they got is a
 CWT and that some type of COSE protection is in use.

    Token: 18(Cose_Sign1 array, claims map in the payload)
    Call:  ctoken_encode_init(context, 0, CTOKEN_OPT_TOP_LEVEL_NOT_TAG, CTOKEN_PROTECTION_COSE_SIGN1, ECDSA256);

 5. COSE protection with no indication at all by tag.

 COSE signing and/or encryption is used, but there is no indication of
 what type by tag. The recipient must know a) that it is a CWT, b)
 that COSE protection is used and c) the type of COSE protection used.

    Token: Cose_Sign1 array, claims map in the payload
    Call:  ctoken_encode_init(context, T_COSE_OPT_OMIT_CBOR_TAG,
                              CTOKEN_OPT_TOP_LEVEL_NOT_TAG, CTOKEN_PROTECTION_COSE_SIGN1, ECDSA256);

 The default configuration for ctoken_decode_init() is to require that
 protection type be indicated by CBOR tags in the token to be
 decoded. This aligns with the recommendation above that the input be
 explicit about protection with the use of tags.

     Call: ctoken_decode_init(context, 0, 0, CTOKEN_PROTECTION_BY_TAG)
     Tokens: 601(map)
             61(18(array))
             18(array)

 The mechanism delivering the token may have a means of indicating the
 protection type. This might be a file type, MIME type, content type
 or such. That should be translated into one of the types in the enum
 \ref ctoken_protection_type_t and passed to ctoken_decode_init(). If
 there is no explicit indication of protection in the token itself,
 then the value passed in will be used. However, the indicated
 protection type in the token takes precedence. The protection type
 passed in to ctoken_decode_init() will be ignored if the type is
 indicated in the token.

 To confirm a token is sufficiently protected
 ctoken_decode_get_protection_type() can be called to retrieve the
 protection it actually has.

 By default, ctoken is liberal in what it accepts in regards to
 tags. If the token can be correctly decoded with or without the tag,
 it will be. However, in some cases it may be desired that the decoder
 error out if the input is a tag when it should not be or vice versa.

 \ref CTOKEN_OPT_REQUIRE_TOP_LEVEL_TAG and \ref
 CTOKEN_OPT_PROHIBIT_TOP_LEVEL_TAG passed in the \c ctoken_options
 parameter control the requirement for or prohibition against the CWT
 and UCCS tag.  The t_cose options T_COSE_OPT_TAG_REQUIRED and
 T_COSE_OPT_TAG_PROHIBITED passed in the \c t_cose_options do similar
 for the COSE tags.
 */



/** Indicates whether COSE was used or not and if used, the type of
 COSE protection.  CTOKEN_PROTECTION_NONE corresponds to a UCCS-format
 token. The other specific protections are COSE protection in a CWT
 format token. */
enum ctoken_protection_t {
    /** When decoding, the CBOR protection processed is based on CBOR
     tag input.  Or put another way, the caller has no way to know the
     protection, so the EAT better have been explicitly tagged with
     the type or protection. */
    CTOKEN_PROTECTION_BY_TAG,

    /** There is no COSE signing or encryption. The UCCS format is
     * used. */
    CTOKEN_PROTECTION_NONE,

    /** The token is a CWT with authenticity protected using a
     * COSE_Sign1 */
    CTOKEN_PROTECTION_COSE_SIGN1,

    /** The token is a CWT with authenticity protected using a
     * COSE_Mac0. Not yet supported. */
    CTOKEN_PROTECTION_COSE_MAC0,

    /** The token is a CWT with authenticity protected using a
     * COSE_Sign1 and privacy protected by COSE_Encrypt0. Not yet
     * supported. */
    CTOKEN_PROTECTION_SIGN1_ENCRYPT0,

    /** Returned from decoder if the protection type is not yet know
     * or can't be known .*/
    CTOKEN_PROTECTION_UNKNOWN,
};



/**
 * Holds a geographic location (e.g. a GPS position). The exact
 * specification for this is in the EAT document.
 */
struct ctoken_location_t {
    /** Array of doubles to hold latitude, longitude... indexed
     * CTOKEN_EAT_LABEL_XXX - 1. Use accessor macros below for
     * convenience. Array entry is only valid if flag for it is set
     * in item_flags. */
    double items[NUM_FLOAT_LOCATION_ITEMS];

    /** Epoch-based time for when the location was obtained, particularly
     * if it is different than when the token is generated. */
    uint64_t time_stamp;
    /** The time difference in seconds between when the location was obtained
     * and when the token was created. It is preferable to use time_stamp
     * rather than this, but some system may not know what time it is.
     * Note that this does require a "ticker" to count seconds to implement,
     * but does not require knowing the time.
     */
    uint64_t age;
    /** Bit flags indicating valid data in array. Corresponding bit is
     * 0x01u << (CTOKEN_EAT_LABEL_XXX - 1)
     */
    uint32_t item_flags;
};

/* Accessor macros for ctoken_eat_location_t. */
#define  eat_loc_latitude   items[CTOKEN_EAT_LABEL_LATITUDE-1]
#define  eat_loc_longitude  items[CTOKEN_EAT_LABEL_LONGITUDE-1]
#define  eat_loc_altitude   items[CTOKEN_EAT_LABEL_ALTITUDE-1]
#define  eat_loc_accuracy   items[CTOKEN_EAT_LABEL_ACCURACY-1]
#define  eat_loc_altitude_accuracy items[CTOKEN_EAT_LABEL_ALTITUDE_ACCURACY-1]
#define  eat_loc_heading    items[CTOKEN_EAT_LABEL_HEADING-1]
#define  eat_loc_speed      items[CTOKEN_EAT_LABEL_SPEED-1]


static inline bool ctoken_location_is_item_present(const struct ctoken_location_t *l, int label)
{
    /* This will misbehave if label is greater than 32, but the
     * effect is not of any consequence.
     */
    return l->item_flags & (0x01 << (label-1));
}

static inline void ctoken_location_mark_item_present(struct ctoken_location_t *l, int label)
{
    /* This will misbehave if label is greater than 32, but the
     * effect is not of any consequence.
     */
    l->item_flags |= (0x01 << (label-1));
}




/** The type of a submodule that is a token. */
enum ctoken_type_t {
    /** The submodule token is a CWT as defined by RFC 8392. It may be
     * a CWT tag or CWT protocol message. It may be signed and/or encrypted.
     * It may not be a UCCS per the EAT draft.
     */
    CTOKEN_TYPE_CWT,

    /** The submodule token is a JWT as defined by RFC 7519. It must not be
     * an unsecured JWT per the EAT draft.
     */
    CTOKEN_TYPE_JSON
};



#ifdef __cplusplus
}
#endif

#endif /* __CTOKEN_H__ */
