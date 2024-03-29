/*
 * ctoken_decode_psa.h (formerly part of attest_token_decode.h)
 *
 * Copyright (c) 2019-2021 Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 1/31/20.
 */


#ifndef decode_psa_h
#define decode_psa_h

#include "ctoken_decode.h"
#include "ctoken_psa_labels.h"


#ifdef __cplusplus
extern "C" {
#if 0
} /* Keep editor indention formatting happy */
#endif
#endif


/**
 * Compute the bit indicating a claim is present
 */
#define CLAIM_PRESENT_BIT(item_index) (0x01U << (item_index))


/**
 * \brief Batch fetch of all simple data items in a token.
 *
 * \param[in]  context     The token decoder context.
 * \param[out] items  Structure into which all found items are placed.
 *
 * \return An error from \ref CTOKEN_ERR_t.
 *
 * \retval CTOKEN_ERR_SUCCESS
 *         Indicates that the token was successfully searched. It
 *         could mean that all the data item were found, only
 *         some were found, or even none were found.
 *
 * This searches the token for the simple unstructured data items all
 * at once. It can be a little more efficient than getting them one by
 * one.
 *
 * Use \ref IS_ITEM_FLAG_SET on \c item_flags in \c
 * ctoken_psa_simple_claims_t to determine if the data item was found or
 * not and whether the corresponding member in the structure is valid.
 */
enum ctoken_err_t
ctoken_decode_psa_simple_claims(struct ctoken_decode_ctx          *context,
                                struct ctoken_psa_simple_claims_t *items);


/**
 * \brief Get the boot seed out of the token.
 *
 * \param[in]  context         The token decoder context.
 * \param[out] boot_seed  Returned pointer and length of boot_seed.
 *
 * The boot seed is a byte string.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static void
ctoken_decode_psa_boot_seed(struct ctoken_decode_ctx *context,
                            struct q_useful_buf_c    *boot_seed);


/**
 * \brief Get the HW Version out of the token
 *
 * \param[in]  context          The token decoder context.
 * \param[out] hw_version  Returned pointer and length of
 *                         \c hw_version.
 *
 * This is also known as the HW ID.
 *
 * The HW Version is a UTF-8 text string. It is returned as a pointer
 * and length. It is NOT \c NULL terminated.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static void
ctoken_decode_psa_hw_version(struct ctoken_decode_ctx *context,
                             struct q_useful_buf_c    *hw_version);


/**
 * \brief Get the implementation ID out of the token.
 *
 * \param[in]  context                 The token decoder context.
 * \param[out] implementation_id  Returned pointer and length of
 *                                implementation_id.
 *
 * The implementation ID is a byte string.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static void
ctoken_decode_psa_implementation_id(struct ctoken_decode_ctx *context,
                                    struct q_useful_buf_c    *implementation_id);


/**
 * \brief Get the origination out of the token.
 *
 * \param[in]  context           The token decoder context.
 * \param[out] origination  Returned pointer and length of origination.
 *
 * This is also known as the Verification Service Indicator.
 *
 * The \c origination is a UTF-8 text string. It is returned as a
 * pointer and length. It is NOT \c NULL terminated.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static void
ctoken_decode_psa_origination(struct ctoken_decode_ctx *context,
                              struct q_useful_buf_c    *origination);


/**
 * \brief Get the profile definition out of the token.
 *
 * \param[in]  context             The token decoder context.
 * \param[out] profile_definition  Returned pointer and length of
 *                                 profile_definition.
 *
 * The profile definition is a UTF-8 text string. It is returned as a
 * pointer and length. It is NOT \c NULL terminated.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static void
ctoken_decode_psa_profile_definition(struct ctoken_decode_ctx *context,
                                     struct q_useful_buf_c    *profile_definition);


/**
 * \brief Get the client ID out of the token.
 *
 * \param[in]  context         The token decoder context.
 * \param[out] client_id  Returned pointer and length of client_id.
 *
 * \retval CTOKEN_ERR_INTEGER_VALUE
 *         If integer is larger or smaller than will fit
 *         in an \c int32_t.
 *
 * Also called the caller ID.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static void
ctoken_decode_psa_client_id(struct ctoken_decode_ctx *context,
                            int32_t                  *client_id);


/**
 * \brief Get the security lifecycle out of the token.
 *
 * \param[in]  context         The token decoder context.
 * \param[out] lifecycle  Returned pointer and length of lifecycle.
 *
 * \retval CTOKEN_ERR_INTEGER_VALUE
 *         If integer is larger
 *         or smaller than will fit in a \c uint32_t.
 *
 * The error result is saved in the @ref ctoken_decode_ctx and can be
 * obtained by calling ctoken_decode_get_error(). The error must
 * be checked before the claim's value is used, but that check can be
 * after decoding other claims.  See
 * [Token Decode Error Overview](#Token-Decode-Errors-Overview).
 */
static void
ctoken_decode_psa_security_lifecycle(struct ctoken_decode_ctx *context,
                                     uint32_t                 *lifecycle);


/**
 * Use \ref IS_ITEM_FLAG_SET macro with these values and \c
 * ctoken_psa_simple_claims_t.item_flags to find out if the
 * data item is filled in in the ctoken_psa_sw_component_t structure.
 *
 * Items that are of type \c struct \c q_useful_buf_c will also be \c
 * NULL_Q_USEFUL_BUF_C when they are absent.
 */
enum ctoken_psa_sw_index_t {
    CTOKEN_PSA_SW_MEASUREMENT_TYPE_FLAG = 0,
    CTOKEN_PSA_SW_MEASURMENT_VAL_FLAG   = 1,
    CTOKEN_PSA_SW_EPOCH_FLAG            = 2,
    CTOKEN_PSA_SW_VERSION_FLAG          = 3,
    CTOKEN_PSA_SW_SIGNER_ID_FLAG        = 4,
    CTOKEN_PSA_SW_MEASUREMENT_DESC_FLAG = 5,
    CTOKEN_PSA_SW_NUMBER_OF_ITEMS       = 6
};

/**
 * Structure to hold one SW component
 *
 * This is about 50 bytes on a 32-bit machine and 100 on a 64-bit
 * machine.
 *
 * There will probably be an expanded version of this when more is
 * added to describe a SW component.
 */
struct ctoken_psa_sw_component_t {
    struct q_useful_buf_c measurement_type; /* text string */
    struct q_useful_buf_c measurement_val; /* binary string */
    uint32_t              epoch;
    struct q_useful_buf_c version; /* text string */
    struct q_useful_buf_c signer_id; /* binary string */
    struct q_useful_buf_c measurement_desc; /* text string */
    uint32_t              item_flags;
};


/**
 * \brief Get the number of SW components in the token
 *
 * \param[in]  context           The token decoder context.
 * \param[out] num_sw_components The number of SW components in the
 *                               token.
 *
 * \return An error from \ref CTOKEN_ERR_t.
 *
 * If there are explicitly no SW components, this will return successfully
 * and the \c num_sw_components will be zero.
 *
 * Per Arm's IAT specification the only two ways this will succeed
 * are.
 * - The SW components array is present and has one or more (not zero)
 * SW components and the "no SW Components" claim is absent.
 * - The "no SW Components" integer claim is present, its value
 * is 1, and the SW Components array is absent.
 */
enum ctoken_err_t
ctoken_decode_psa_num_sw_components(struct ctoken_decode_ctx *context,
                                    uint32_t                 *num_sw_components);


/**
 * \brief Get the nth SW component.
 *
 * \param[in] context         The token decoder context.
 * \param[in] requested_index Index, from 0 to num_sw_components,
 *                            of request component.
 * \param[out] sw_components  Place to return the details of the
 *                            SW component
 *
 * \retval CTOKEN_ERR_NO_MORE_CLAIMS
 *         There were not \c requested_index in the token.
 *
 * \retval CTOKEN_ERR_CBOR_TYPE
 *         The claim labeled to contain SW components is not an array.
 */
enum ctoken_err_t
ctoken_decode_psa_sw_component(struct ctoken_decode_ctx         *context,
                               uint32_t                          requested_index,
                               struct ctoken_psa_sw_component_t *sw_components);




/* --------------------------------------------------------------------------
 *       Inline implementations
 * --------------------------------------------------------------------------*/


static inline void
ctoken_decode_psa_boot_seed(struct ctoken_decode_ctx *me,
                            struct q_useful_buf_c    *boot_seed)
{
    ctoken_decode_bstr(me, CTOKEN_PSA_LABEL_BOOT_SEED, boot_seed);
}


static inline void
ctoken_decode_psa_hw_version(struct ctoken_decode_ctx *me,
                             struct q_useful_buf_c    *hw_version)
{
    ctoken_decode_tstr(me, CTOKEN_PSA_LABEL_HW_VERSION, hw_version);
}


static inline void
ctoken_decode_psa_implementation_id(struct ctoken_decode_ctx *me,
                                    struct q_useful_buf_c    *implementation_id)
{
    ctoken_decode_bstr(me, CTOKEN_PSA_LABEL_IMPLEMENTATION_ID, implementation_id);
}


static inline void
ctoken_decode_psa_client_id(struct ctoken_decode_ctx *me,
                            int32_t                  *caller_id)
{
    int64_t caller_id_64;

    ctoken_decode_int(me, CTOKEN_PSA_LABEL_CLIENT_ID, &caller_id_64);
    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return;
    }
    if(caller_id_64 > INT32_MAX || caller_id_64 < INT32_MIN) {
        me->last_error = CTOKEN_ERR_INTEGER_VALUE;
        return;
    }
    *caller_id = (int32_t)caller_id_64;
}


static inline void
ctoken_decode_psa_security_lifecycle(struct ctoken_decode_ctx *me,
                                     uint32_t                 *security_lifecycle)
{
    uint64_t security_lifecycle_64;

    ctoken_decode_uint(me,
                                      CTOKEN_PSA_LABEL_SECURITY_LIFECYCLE,
                                      &security_lifecycle_64);
    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return;
    }
    if(security_lifecycle_64 > UINT32_MAX) {
        me->last_error = CTOKEN_ERR_INTEGER_VALUE;
        return;
    }

    *security_lifecycle = (uint32_t)security_lifecycle_64;
}


static inline void
ctoken_decode_psa_profile_definition(struct ctoken_decode_ctx *me,
                                     struct q_useful_buf_c    *profile_definition)
{
    ctoken_decode_tstr(me, CTOKEN_PSA_LABEL_PROFILE_DEFINITION, profile_definition);
}


static inline void
ctoken_decode_psa_origination(struct ctoken_decode_ctx *me,
                              struct q_useful_buf_c    *origination)
{
    ctoken_decode_origination(me, origination);
}

#ifdef __cplusplus
}
#endif

#endif /* psa_ia_decode_h */
