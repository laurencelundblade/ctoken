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
#endif


/**
 * \file ctoken.h
 *
 * \brief Common definitions for ctoken encoding and decoding
 *
 */


/**
 Error codes returned from CBOR token creation.
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
    /** No token was given or validated */
    CTOKEN_ERR_NO_VALID_TOKEN,
    /** Data item with label wasn't found. */
    CTOKEN_ERR_NOT_FOUND,
    /** SW Compoments absence not correctly indicated. */
    CTOKEN_ERR_SW_COMPONENTS_MISSING
};



/**
 * Request that the claims internally generated not be added to the
 * token.  This is a test mode that results in a static token that
 * never changes. Only the nonce is included. The nonce is under
 * the callers control unlike the other claims.
 */
#define TOKEN_OPT_OMIT_CLAIMS        0x40000000


/**
 * A special test mode where a proper signature is not produced. In
 * its place there is a concatenation of hashes of the payload to be
 * the same size as the signature. This works and can be used to
 * verify all of the SW stack except the public signature part. The
 * token has no security value in this mode because anyone can
 * replicate it. */
#define TOKEN_OPT_SHORT_CIRCUIT_SIGN 0x80000000


    
#ifdef __cplusplus
}
#endif

#endif /* __CTOKEN_H__ */
