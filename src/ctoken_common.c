/*
 * ctoken_common.c
 *
 * Copyright (c) 2021 Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 4/5/21.
 */


#include "ctoken_common.h"
#include <stdint.h>
#include <stddef.h>


/* Use uint8_t instead of enum so map will be 4x smaller. Compilers usually
 * make enums 4 bytes. */
static const uint8_t t_cose_verify_error_map[] = {
    /* T_COSE_SUCCESS = 0 */
    CTOKEN_ERR_SUCCESS,

    /* T_COSE_ERR_UNSUPPORTED_SIGNING_ALG = 1 */
    CTOKEN_ERR_UNSUPPORTED_SIG_ALG,

    /* T_COSE_ERR_MAKING_PROTECTED = 2 */
    CTOKEN_ERROR_GENERAL_T_COSE,

    /* T_COSE_ERR_UNSUPPORTED_HASH = 3 */
    CTOKEN_ERR_HASH_UNAVAILABLE,

    /* T_COSE_ERR_HASH_GENERAL_FAIL = 4 */
    CTOKEN_ERROR_T_COSE_CRYPTO,

    /* T_COSE_ERR_HASH_BUFFER_SIZE = 5 */
    CTOKEN_ERROR_GENERAL_T_COSE,

    /* T_COSE_ERR_SIG_BUFFER_SIZE = 6 */
    CTOKEN_ERROR_GENERAL_T_COSE,

    /* Unassigned by t_cose */
    CTOKEN_ERROR_GENERAL_T_COSE,

    /* T_COSE_ERR_SIGN1_FORMAT = 8 */
    CTOKEN_ERR_COSE_SIGN1_FORMAT,

    /* T_COSE_ERR_CBOR_NOT_WELL_FORMED = 9 */
    CTOKEN_ERR_CBOR_NOT_WELL_FORMED,

    /* T_COSE_ERR_PARAMETER_CBOR = 10 */
    CTOKEN_ERR_COSE_SIGN1_FORMAT,

    /* T_COSE_ERR_NO_ALG_ID = 11 */
    CTOKEN_ERR_COSE_SIGN1_FORMAT,

    /* T_COSE_ERR_NO_KID = 12 */
    CTOKEN_ERR_COSE_SIGN1_FORMAT,

    /* T_COSE_ERR_SIG_VERIFY = 13 */
    CTOKEN_ERR_COSE_SIGN1_VALIDATION,

    /* T_COSE_ERR_BAD_SHORT_CIRCUIT_KID = 14 */
    CTOKEN_ERROR_SHORT_CIRCUIT_SIG,

    /* T_COSE_ERR_INVALID_ARGUMENT = 15 */
    CTOKEN_ERROR_GENERAL_T_COSE,

    /* T_COSE_ERR_INSUFFICIENT_MEMORY = 16 */
    CTOKEN_ERR_INSUFFICIENT_MEMORY,

    /* T_COSE_ERR_FAIL = 17 */
    CTOKEN_ERROR_GENERAL_T_COSE,

    /* T_COSE_ERR_TAMPERING_DETECTED = 18 */
    CTOKEN_ERR_TAMPERING_DETECTED,

    /* T_COSE_ERR_UNKNOWN_KEY = 19 */
    CTOKEN_ERR_VERIFICATION_KEY,

    /* T_COSE_ERR_WRONG_TYPE_OF_KEY = 20 */
    CTOKEN_ERR_VERIFICATION_KEY,

    /* T_COSE_ERR_SIG_STRUCT = 21 */
    CTOKEN_ERR_COSE_SIGN1_FORMAT,

    /* T_COSE_ERR_SHORT_CIRCUIT_SIG = 22 */
    CTOKEN_ERROR_SHORT_CIRCUIT_SIG,

    /* T_COSE_ERR_SIG_FAIL = 23 */
    CTOKEN_ERROR_T_COSE_CRYPTO,

    /* T_COSE_ERR_CBOR_FORMATTING = 24 */
    CTOKEN_ERR_COSE_SIGN1_FORMAT,

    /* T_COSE_ERR_TOO_SMALL = 25 */
    CTOKEN_ERR_TOO_SMALL,

    /* T_COSE_ERR_TOO_MANY_PARAMETERS = 26 */
    CTOKEN_ERROR_COSE_PARAMETERS,

    /* T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER = 27 */
    CTOKEN_ERROR_COSE_PARAMETERS,

    /* T_COSE_ERR_SHORT_CIRCUIT_SIG_DISABLED = 28 */
    CTOKEN_ERROR_SHORT_CIRCUIT_SIG,

    /* T_COSE_ERR_INCORRECT_KEY_FOR_LIB = 29 */
    CTOKEN_ERROR_T_COSE_CRYPTO,

    /* T_COSE_ERR_NON_INTEGER_ALG_ID = 30 */
    CTOKEN_ERROR_COSE_PARAMETERS,

    /* T_COSE_ERR_BAD_CONTENT_TYPE = 31 */
    CTOKEN_ERROR_COSE_PARAMETERS,

    /* T_COSE_ERR_INCORRECTLY_TAGGED = 32 */
    CTOKEN_ERROR_COSE_TAG,

    /* T_COSE_ERR_EMPTY_KEY = 33 */
    CTOKEN_ERROR_KEY,

    /* T_COSE_ERR_DUPLICATE_PARAMETER = 34 */
    CTOKEN_ERROR_COSE_PARAMETERS,

    /* T_COSE_ERR_PARAMETER_NOT_PROTECTED = 35 */
    CTOKEN_ERROR_COSE_PARAMETERS,

    /* T_COSE_ERR_CRIT_PARAMETER = 36 */
    CTOKEN_ERROR_COSE_PARAMETERS,

    /* T_COSE_ERR_TOO_MANY_TAGS = 37 */
    CTOKEN_ERR_TOO_MANY_TAGS
};


/**
 * \brief Map t_cose errors into ctoken errors
 *
 * \param[in] t_cose_error  The t_cose error to map
 *
 * \return The ctoken error.
 */
enum ctoken_err_t
map_t_cose_errors(enum t_cose_err_t t_cose_error)
{
    /* Object code is smaller by using the mapping array */
    enum ctoken_err_t return_value;
    const size_t map_size = sizeof(t_cose_verify_error_map) /  sizeof(uint8_t);

    if(t_cose_error >= map_size) {
        return_value = CTOKEN_ERROR_GENERAL_T_COSE;
    } else {
        return_value = t_cose_verify_error_map[t_cose_error];
    }

    return return_value;
}
