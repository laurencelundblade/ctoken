/*
 * psa_ia_decode.h
 *
 * Copyright (c) 2020 Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 1/31/20.
 */


#ifndef psa_ia_decode_h
#define psa_ia_decode_h

#include "ctoken_decode.h"
#include "ctoken_eat_decode.h"
#include "psa_ia_labels.h"


/** Label for bits in \c item_flags in \ref
 attest_token_iat_simple_t */
enum attest_token_item_index_t {
    NONCE_FLAG =              0,
    UEID_FLAG  =              1,
    BOOT_SEED_FLAG =          2,
    HW_VERSION_FLAG =         3,
    IMPLEMENTATION_ID_FLAG =  4,
    CLIENT_ID_FLAG =          5,
    SECURITY_LIFECYCLE_FLAG = 6,
    PROFILE_DEFINITION_FLAG = 7,
    ORIGINATION_FLAG =        8,
    NUMBER_OF_ITEMS =         9
};


/**
 * This structure holds the simple-to-get fields from the
 * token that can be bundled into one structure.
 *
 * This is 7 * 8 + 12 = 72 bytes on a 32-bit machine.
 */
struct attest_token_iat_simple_t {
    struct q_useful_buf_c nonce; /* byte string */
    struct q_useful_buf_c ueid; /* byte string */
    struct q_useful_buf_c boot_seed; /* byte string */
    struct q_useful_buf_c hw_version; /* text string */
    struct q_useful_buf_c implementation_id; /* byte string */
    uint32_t              security_lifecycle;
    int32_t               client_id;
    struct q_useful_buf_c profile_definition; /* text string */
    struct q_useful_buf_c origination; /* text string */
    uint32_t              item_flags;
};


/**
 * Macro to determine if data item is present in \ref
 * attest_token_iat_simple_t
 */
#define IS_ITEM_FLAG_SET(item_index, item_flags) \
    (((0x01U << (item_index))) & (item_flags))


/**
 * Compute the bit indicating a claim is present
 */
#define CLAIM_PRESENT_BIT(item_index) (0x01U << (item_index))


/**
 * \brief Batch fetch of all simple data items in a token.
 *
 * \param[in]  me     The token decoder context.
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
 * attest_token_iat_simple_t to determine if the data item was found or
 * not and whether the corresponding member in the structure is valid.
 */
enum ctoken_err_t
attest_token_decode_get_iat_simple(struct ctoken_decode_context *me,
                                   struct attest_token_iat_simple_t *items);


/**
 \brief Get the nonce out of the token.
 *
 * \param[in]  me     The token decoder context.
 * \param[out] nonce  Returned pointer and length of nonce.
 *
 * \return An error from \ref CTOKEN_ERR_t.
 *
 * The nonce is a byte string. The nonce is also known as the
 * challenge.
 */
static inline enum ctoken_err_t
attest_token_decode_get_nonce(struct ctoken_decode_context *me,
                              struct q_useful_buf_c *nonce);


/**
 * \brief Get the boot seed out of the token.
 *
 * \param[in]  me         The token decoder context.
 * \param[out] boot_seed  Returned pointer and length of boot_seed.
 *
 * \return An error from \ref CTOKEN_ERR_t.
 *
 * The boot seed is a byte string.
 */
static enum ctoken_err_t
attest_token_decode_get_boot_seed(struct ctoken_decode_context *me,
                                  struct q_useful_buf_c *boot_seed);


/**
 * \brief Get the UEID out of the token.
 *
 * \param[in]  me    The token decoder context.
 * \param[out] ueid  Returned pointer and length of ueid.
 *
 * \return An error from \ref CTOKEN_ERR_t.
 *
 * The UEID is a byte string.
 */
static inline enum ctoken_err_t
attest_token_decode_get_ueid(struct ctoken_decode_context *me,
                             struct q_useful_buf_c *ueid);



/**
 * \brief Get the HW Version out of the token
 *
 * \param[in]  me          The token decoder context.
 * \param[out] hw_version  Returned pointer and length of
 *                         \c hw_version.
 *
 * \return An error from \ref CTOKEN_ERR_t.
 *
 * This is also known as the HW ID.
 *
 * The HW Version is a UTF-8 text string. It is returned as a pointer
 * and length. It is NOT \c NULL terminated.
 */
static enum ctoken_err_t
attest_token_decode_get_hw_version(struct ctoken_decode_context *me,
                                   struct q_useful_buf_c *hw_version);


/**
 * \brief Get the implementation ID out of the token.
 *
 * \param[in]  me                 The token decoder context.
 * \param[out] implementation_id  Returned pointer and length of
 *                                implementation_id.
 *
 * \return An error from \ref CTOKEN_ERR_t.
 *
 * The implementation ID is a byte string.
 */
static enum ctoken_err_t
attest_token_decode_get_implementation_id(struct ctoken_decode_context*me,
                                          struct q_useful_buf_c *implementation_id);


/**
 * \brief Get the origination out of the token.
 *
 * \param[in]  me           The token decoder context.
 * \param[out] origination  Returned pointer and length of origination.
 *
 * \return An error from \ref CTOKEN_ERR_t.
 *
 * This is also known as the Verification Service Indicator.
 *
 * The \c origination is a UTF-8 text string. It is returned as a
 * pointer* and length. It is NOT \c NULL terminated.
 */
static enum ctoken_err_t
attest_token_decode_get_origination(struct ctoken_decode_context *me,
                                    struct q_useful_buf_c *origination);


/**
 * \brief Get the profile definition out of the token.
 *
 * \param[in]  me                  The token decoder context.
 * \param[out] profile_definition  Returned pointer and length of
 *                                 profile_definition.
 *
 * \return An error from \ref CTOKEN_ERR_t.
 *
 * The profile definition is a UTF-8 text string. It is returned as a
 * pointer and length. It is NOT \c NULL terminated.
 */
static enum ctoken_err_t
attest_token_decode_get_profile_definition(
                                           struct ctoken_decode_context *me,
                                           struct q_useful_buf_c *profile_definition);


/**
 * \brief Get the client ID out of the token.
 *
 * \param[in]  me         The token decoder context.
 * \param[out] client_id  Returned pointer and length of client_id.
 *
 * \return An error from \ref CTOKEN_ERR_t.
 *
 * \retval CTOKEN_ERR_INTEGER_VALUE
 *         If integer is larger or smaller than will fit
 *         in an \c int32_t.
 *
 * Also called the caller ID.
 */
static enum ctoken_err_t
attest_token_decode_get_client_id(struct ctoken_decode_context *me,
                                  int32_t *client_id);


/**
 * \brief Get the security lifecycle out of the token.
 *
 * \param[in]  me         The token decoder context.
 * \param[out] lifecycle  Returned pointer and length of lifecycle.
 *
 * \return An error from \ref CTOKEN_ERR_t.
 *
 * \retval CTOKEN_ERR_INTEGER_VALUE
 *         If integer is larger
 *         or smaller than will fit in a \c uint32_t.
 */
static enum ctoken_err_t
attest_token_decode_get_security_lifecycle(
                                           struct ctoken_decode_context *me,
                                           uint32_t *lifecycle);


/**
 * Use \ref IS_ITEM_FLAG_SET macro with these values and \c
 * attest_token_sw_component_t.item_flags to find out if the
 * data item is filled in in the attest_token_sw_component_t structure.
 *
 * Items that are of type \c struct \c q_useful_buf_c will also be \c
 * NULL_Q_USEFUL_BUF_C when they are absent.
 */
enum attest_token_sw_index_t {
    SW_MEASUREMENT_TYPE_FLAG = 0,
    SW_MEASURMENT_VAL_FLAG = 1,
    SW_EPOCH_FLAG = 2,
    SW_VERSION_FLAG = 3,
    SW_SIGNER_ID_FLAG = 5,
    SW_MEASUREMENT_DESC_FLAG = 6,
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
struct attest_token_sw_component_t {
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
 * \param[in]  me                The token decoder context.
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
attest_token_get_num_sw_components(struct ctoken_decode_context *me,
                                   uint32_t *num_sw_components);


/**
 * \brief Get the nth SW component.
 *
 * \param[in] me              The token decoder context.
 * \param[in] requested_index Index, from 0 to num_sw_components,
 *                            of request component.
 * \param[out] sw_components  Place to return the details of the
 *                            SW component
 *
 * \retval CTOKEN_ERR_NOT_FOUND
 *         There were not \c requested_index in the token.
 *
 * \retval ATTETST_TOKEN_ERR_CBOR_TYPE
 *         The claim labeled to contain SW components is not an array.
 */
enum ctoken_err_t
attest_token_get_sw_component(struct ctoken_decode_context *me,
                              uint32_t requested_index,
                              struct attest_token_sw_component_t *sw_components);



static inline enum ctoken_err_t
attest_token_decode_psa_ia_nonce(struct ctoken_decode_context *me,
                              struct q_useful_buf_c *nonce)
{
    return ctoken_decode_eat_nonce(me, nonce);
}






static inline enum ctoken_err_t
attest_token_decode_get_boot_seed(struct ctoken_decode_context *me,
                                  struct q_useful_buf_c *boot_seed)
{
    return ctoken_decode_get_bstr(me,
                                        EAT_CBOR_ARM_LABEL_BOOT_SEED,
                                        boot_seed);
}


static inline enum ctoken_err_t
attest_token_decode_get_hw_version(struct ctoken_decode_context *me,
                                   struct q_useful_buf_c *hw_version)
{
    return ctoken_decode_get_tstr(me,
                                        EAT_CBOR_ARM_LABEL_HW_VERSION,
                                        hw_version);
}


static inline enum ctoken_err_t
attest_token_decode_get_implementation_id(
                                          struct ctoken_decode_context *me,
                                          struct q_useful_buf_c*implementation_id)
{
    return ctoken_decode_get_bstr(me,
                                        EAT_CBOR_ARM_LABEL_IMPLEMENTATION_ID,
                                        implementation_id);
}


static inline enum ctoken_err_t
attest_token_decode_get_client_id(struct ctoken_decode_context *me,
                                  int32_t *caller_id)
{
    enum ctoken_err_t return_value;
    int64_t caller_id_64;

    return_value = ctoken_decode_get_int(me,
                                               EAT_CBOR_ARM_LABEL_CLIENT_ID,
                                               &caller_id_64);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }
    if(caller_id_64 > INT32_MAX || caller_id_64 < INT32_MIN) {
        return_value = CTOKEN_ERR_INTEGER_VALUE;
        goto Done;
    }
    *caller_id = (int32_t)caller_id_64;

Done:
    return return_value;
}


static inline enum ctoken_err_t
attest_token_decode_get_security_lifecycle(
                                           struct ctoken_decode_context *me,
                                           uint32_t *security_lifecycle)
{
    enum ctoken_err_t return_value;
    uint64_t security_lifecycle_64;

    return_value = ctoken_decode_get_uint(me,
                                                EAT_CBOR_ARM_LABEL_SECURITY_LIFECYCLE,
                                                &security_lifecycle_64);
    if(security_lifecycle_64 > UINT32_MAX) {
        return_value = CTOKEN_ERR_INTEGER_VALUE;
        goto Done;
    }

    *security_lifecycle = (uint32_t)security_lifecycle_64;

Done:
    return return_value;
}

static inline enum ctoken_err_t
attest_token_decode_get_profile_definition(
                                           struct ctoken_decode_context *me,
                                           struct q_useful_buf_c *profile_definition)
{
    return ctoken_decode_get_tstr(me,
                                        EAT_CBOR_ARM_LABEL_PROFILE_DEFINITION,
                                        profile_definition);
}

static inline enum ctoken_err_t
attest_token_decode_get_origination(struct ctoken_decode_context*me,
                                    struct q_useful_buf_c *origination)
{
    return ctoken_decode_get_tstr(me,
                                        EAT_CBOR_ARM_LABEL_ORIGINATION,
                                        origination);
}

#endif /* psa_ia_decode_h */
