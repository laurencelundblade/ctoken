/*
 * ctoken.h (formerly attest_token.h)
 *
 * Copyright (c) 2018-2020, Laurence Lundblade.
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


/**
 * Error codes returned from CBOR token creation.
 */
enum ctoken_err_t {
    /** Success */
    CTOKEN_ERR_SUCCESS = 0,
    /** The buffer passed in to receive the output is too small. */
    CTOKEN_ERR_TOO_SMALL,
    /** Something went wrong formatting the CBOR, most likely the
     payload has maps or arrays that are not closed. */
    CTOKEN_ERR_CBOR_FORMATTING,
    /** A general, unspecific error when creating or decoding the
        token. */
    CTOKEN_ERR_GENERAL,
    /** A hash function that is needed to make the token is not
        available. */
    CTOKEN_ERR_HASH_UNAVAILABLE,
    /** CBOR Syntax not well-formed -- a CBOR syntax error. */
    CTOKEN_ERR_CBOR_NOT_WELL_FORMED,
    /** Bad CBOR structure, for example not a map when was is
        required. */
    CTOKEN_ERR_CBOR_STRUCTURE,
    /** Bad CBOR type, for example an not a text string, when a text
        string is required. */
    CTOKEN_ERR_CBOR_TYPE,
    /** Integer too large, for example an \c int32_t is required, but
        value only fits in \c int64_t */
    CTOKEN_ERR_INTEGER_VALUE,
    /** Something is wrong with the COSE signing structure, missing
        headers or such. */
    CTOKEN_ERR_COSE_SIGN1_FORMAT,
    /** COSE signature is invalid, data is corrupted. */
    CTOKEN_ERR_COSE_SIGN1_VALIDATION,
    /** The signing algorithm is not supported. */
    CTOKEN_ERR_UNSUPPORTED_SIG_ALG,
    /** Out of memory. */
    CTOKEN_ERR_INSUFFICIENT_MEMORY,
    /** Tampering detected in cryptographic function. */
    CTOKEN_ERR_TAMPERING_DETECTED,
    /** Verification key is not found or of wrong type. */
    CTOKEN_ERR_VERIFICATION_KEY,
    /** No token was given or validated. */
    CTOKEN_ERR_NO_VALID_TOKEN,
    /** Data item with label wasn't found. */
    CTOKEN_ERR_NOT_FOUND,
    /** SW Compoments absence not correctly indicated. */
    CTOKEN_ERR_SW_COMPONENTS_MISSING,
    /** Trying to nest more than \ref CTOKEN_MAX_SUBMOD_NESTING. */
    CTOKEN_ERR_SUBMOD_NESTING_TOO_DEEP,
    /** Trying to close a submod with no submods open. */
    CTOKEN_ERR_NO_SUBMOD_OPEN,
    /** When decoding, something wrong with the token format other
     * than CBOR not well formed. */
    CTOKEN_ERR_TOKEN_FORMAT,
    /** Can't start submodule section because one is already started,
      * or one was started and completed for this submodule. */
    CTOKEN_CANT_START_SUBMOD_SECTION,
    /** Trying to end a submod section with no submod section
     * started. */
    CTOKEN_ERR_NO_SUBMOD_SECTION_STARTED,
    /** Attempting to make a submod or add a token without starting a
      * submod section */
    CTOKEN_ERR_CANT_MAKE_SUBMOD_IN_SUBMOD,
    /** All submodules and submodule sections were not closed out. */
    CTOKEN_ERR_SUBMODS_NOT_CLOSED,
    /** The name of a submodule is not a text string. */
    CTOKEN_ERR_SUBMOD_NAME_NOT_A_TEXT_STRING,
    /** Index beyond the number of submodules. */
    CTOKEN_ERR_SUBMOD_INDEX_TOO_LARGE,
    /** No submodule of the given name as found. */
    CTOKEN_NAMED_SUBMOD_NOT_FOUND,

    /** Claim is not present in the token */
    CTOKEN_ERR_CLAIM_NOT_PRESENT,

    CTOKEN_ERR_NAMED_SUBMOD_NOT_FOUND,
    /** Submodule is the wrong CBOR type */
    CTOKEN_ERR_SUBMOD_TYPE,
    /** Submods section is missing or wrong type */
    CTOKEN_ERR_SUBMOD_SECTION,
    /** Something is wrong with the content of a claim such as mandatory
     * parts are missing, the CBOR structure is wrong or other
     */
    CTOKEN_ERR_CLAIM_FORMAT,
    /** The latitude and longitude fields are required in the location claim */
    CTOKEN_ERR_LAT_LONG_REQUIRED,

    CTOKEN_ERR_TOO_MANY_TAGS,
    /** The @ref ctoken_protection_t type passed to encode or decode is not supported. */
    CTOKEN_ERR_UNSUPPORTED_PROTECTION_TYPE,
    /** When decoding the token is not a tag that specifies a protection type (e.g. CWT/COSE)
     nor was a protection type given as an argument. */
    CTOKEN_ERR_UNDETERMINED_PROTECTION_TYPE,
    /** The content of a tag is not of the right type. In particular, this
     occurs when the content of a CWT tag is not a COSE tag.
     */
    CTOKEN_ERR_TAG_CONTENT,


    /** The value of the claim is outside allowed range. */
    CTOKEN_ERR_CLAIM_RANGE,

    /** CWT requires a COSE tag be the content of a CWT tag */
    CTOKEN_ERR_TAG_COMBO_NOT_ALLOWED,

    CTOKEN_ERR_SHOULD_NOT_BE_TAG,

    CTOKEN_ERR_SHOULD_BE_TAG
};


/** The maximum nesting depth for submodules. */
#define CTOKEN_MAX_SUBMOD_NESTING  (QCBOR_MAX_ARRAY_NESTING/2)



/*

 When encoding, the protection type must always be given.

 The encoded

 The encoded output can identified as an EAT/CWT by making it either a CWT tag or a UCCS tag. A CWT


 An EAT can be protected (signed and/or encrypted) by COSE in several ways or not at all.
 The manner of protection can be recorded in the EAT or not.
 If it is not recorded in the EAT it must be recorded in or implied by the protocol carrying the EAT.
 For example, the EAT might be in a labeled map item in a CBOR protocol whose content is always COSE_Sign1 protected CWT, in which case there no need to record the protection type in the EAT.
 This implementation accommodates all scenarios, but is a little complicated for it.

 When encoding an EAT, the type of protection must always be given.
 This is by protection_type parameter to ctoken_encode_init().
 Whether or not the type of protection is recorded in the EAT is by token_opt_flags parameter, also given to ctoken_encode_init().
 By default the type of protection is recorded in the EAT and must be explicitly excluded using flags in token_opt_flags.

 When decoding an EAT, the type of protection to decode can be given as a parameter or come from what is recorded in the EAT.
 If it is known from the protocol carrying the EAT then it should be given as the protection_type parameter to ctoken_decode_init().
 If it is not known from the carrying protocol, then the protection_type given should be CTOKEN_PROTECTION_BY_TAG.

 It is also possible to expliclitly record in the EAT that it is an EAT/CWT or an EAT/UCCS or not record this and this interelates to the recording of the protection.

 This "recording" is by the CBOR tag mechanism which sounds and seems like a tacked-on "tag", but is officially is not.
 In CBOR a "tag" made up of both the tag number and the tag content.
 It's not just the tag number, but here one doesn't go too far wrong thinking of it a just the tag number.

 Here's the table of possibilities for encoding.

   TAGS
 TOP COSE    PROTECTION                      OUTPUT
  0    X   CTOKEN_PROTECTION_NONE        601(claim-set)
  1    X   CTOKEN_PROTECTION_NONE        claim-set
  0    0   CTOKEN_PROTECTION_COSE_SIGN1  61(18(sign1-protected-claim-set))
  0    1   CTOKEN_PROTECTION_COSE_SIGN1  prohibited by RFC 8392
  1    0   CTOKEN_PROTECTION_COSE_SIGN1  18(sign1-protected-claim-set)
  1    1   CTOKEN_PROTECTION_COSE_SIGN1  sign1-protected-claim-set


 COSE_Sign1 array
 UCCS map
 601(map)
 18(COSE_Sign1 array)
 61(18(COSE_Sign1 array))
 61(COSE_Sign1 array)
 X(COSE_Sign1 array)
 X(UCCS map)


 Make an unprotected EAT
     Make an unprotected EAT that is a UCCS tag
         601(map containing claims)
         ctoken_encode_init(context, 0, 0, CTOKEN_PROTECTION_NONE, 0);

    Make an uprotected EAT that is not a tag (AKA an unwrapped UCCS tag)
         map containing claims
         ctoken_encode_init(context, 0, CTOKEN_OPT_TOP_LEVEL_NOT_TAG, CTOKEN_PROTECTION_NONE, 0);

Make a protected EAT
    Make a protected EAT that is a COSE tag nested in an CWT tag
         61(18(Cose_Sign1 array, claims map in the payload))
         ctoken_encode_init(context, 0, 0, CTOKEN_PROTECTION_COSE_SIGN1, ECDSA256);

    Make a protected EAT that is just a COSE tag, not an CEWT tag
         18(Cose_Sign1 array, claims map in the payload)
         ctoken_encode_init(context, 0, CTOKEN_OPT_TOP_LEVEL_NOT_TAG, CTOKEN_PROTECTION_COSE_SIGN1, ECDSA256);

    Make a protected EAT that is not a tag at all, just a bare COSE_Sign1
         Cose_Sign1 array, claims map in the payload
         ctoken_encode_init(context, T_COSE_OPT_OMIT_CBOR_TAG, CTOKEN_OPT_TOP_LEVEL_NOT_TAG, CTOKEN_PROTECTION_COSE_SIGN1, ECDSA256);


 Decode an EAT of any protection type by what tag it is
    ctoken_decode_init(context, 0, 0, CTOKEN_PROTECTION_BY_TAG)
    This will error out if the input token isn't tag well enough
        601(map) -- OK, unprotected
        61(18(array)) -- OK, protected
        18(array) -- OK protected
        map containing claims -- fail
        Cose_Sign1 array, claims map in the payload -- fail

 Decode EAT that is known to be a CWT and expected to have COSE protection of varying type


 Decode an EAT that is must be a bare UCCS
     ctoken_decode_init(context, 0, CTOKEN_OPT_PROHIBIT_TOP_LEVEL_TAG, CTOKEN_PROTECTION_NONE)
        map containing claims -- OK
        601(map) -- fail because it is a tag
        Cose_Sign1 array, claims map in the payload -- fail because it is protected
        18(array) -- fail because it is protected and it is a tag


 Does the protocol your putting EAT into provide the signing and encryption
 needed. Note that signing should be by an attestation key, so an ordinary
 TLS cert won't do.

 If yes, then you can use UCCS.

 Will the protocol identify the EAT as an EAT? For example will it go in to a field
 in a protocol message that only can contain an EAT?

 Do you want to be liberal in what you accept?

 If yes, then you can accept unwrapped UCCS or tag UCCS.

 If no, then accept only unwrapped UCCS.

 If your protocol doesn't identify EATs






 */



/** Indicates whether COSE was used or not and if used, the type of COSE protection.
 CTOKEN_PROTECTION_NONE corresponds to a UCCS-format token. The other
 specific protections are COSE protection in a CWT format token. */
enum ctoken_protection_t {
    /** When decoding, the CBOR protection processed is based on CBOR tag input.
     Or put another way, the caller has no way to know the protection, so
     the EAT better have been explicitly tagged with the type or protection. */
    CTOKEN_PROTECTION_BY_TAG,

    /** There is no COSE signing or encryption. The UCCS format is used. */
    CTOKEN_PROTECTION_NONE,

    /** The token is a CWT with authenticity protected using a COSE_Sign1 */
    CTOKEN_PROTECTION_COSE_SIGN1,

    /** The token is a CWT with authenticity protected using a COSE_Mac0. Not yet supported. */
    CTOKEN_PROTECTION_COSE_MAC0,

    /** The token is a CWT with authenticity protected using a COSE_Sign1 and privacy protected by COSE_Encrypt0. Not yet supported. */
    CTOKEN_PROTECTION_SIGN1_ENCRYPT0,

    /** Returned from decoder if the protection type is not yet know or can't be known .*/
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
enum ctoken_type {
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
