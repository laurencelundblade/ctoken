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
    /** The value of the claim is outside allowed range. */
    CTOKEN_ERR_CLAIM_RANGE,
};


/** The maximum nesting depth for submodules. */
#define CTOKEN_MAX_SUBMOD_NESTING  (QCBOR_MAX_ARRAY_NESTING/2)




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
