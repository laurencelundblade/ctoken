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

#ifdef __cplusplus
extern "C" {
#ifdef 0
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
    /** When decoding, something wrong with the token format other than CBOR not well formed. */
    CTOKEN_ERR_TOKEN_FORMAT,
    /** Can't start submodule section because one is already started, or one was started and completed for this submodule.*/
    CTOKEN_CANT_START_SUBMOD_SECTION,
    /** Trying to end a submod section with no submod section started. */
    CTOKEN_ERR_NO_SUBMOD_SECTION_STARTED,
    /** Attempting to make a submod or add a token without starting a submod section */
    CTOKEN_ERR_CANT_MAKE_SUBMOD_IN_SUBMOD

};


// TODO: Test that -3 is right; might need to divide by two
/** The maximum nesting depth for submodules. */
#define CTOKEN_MAX_SUBMOD_NESTING  QCBOR_MAX_ARRAY_NESTING - 3

#ifdef __cplusplus
}
#endif

#endif /* __CTOKEN_H__ */
