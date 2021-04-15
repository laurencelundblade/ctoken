/*
 * ctoken_psa_labels.h (partly derived from attest_eat_defines.h)
 *
 * Copyright (c) 2020-2021, Laurence Lundblade.
 * Copyright (c) 2019, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 */

#ifndef psa_labels_h
#define psa_labels_h

#include "ctoken_eat_labels.h"
#include "t_cose/q_useful_buf.h"


#ifdef __cplusplus
extern "C" {
#if 0
} /* Keep editor indention formatting happy */
#endif
#endif

/**
 * ARM has mostly decided to use labels out of the proprietary space.
 *
 * PSA Token does use three standard EAT claims, for which there were
 * temporary labels in the proprietary space that appear here.
 * Processing of the proprietry-space labels for them can be disabled
 * by defining CTOKEN_DISABLE_TEMP_LABELS
 *
 * See https://tools.ietf.org/html/draft-tschofenig-rats-psa-token-08.
 *
 * Since the claims in the PSA Token are not standards-track because
 * the PSA Token draft is informational, not standards track, these
 * claim keys (labels) could have been allocated from the specification-required
 * or expert-review space rather than the proprietary space. It would
 * probably would have been better to do that.
 */

#define CTOKEN_PSA_LABEL_BASE                 (-75000)
#define CTOKEN_PSA_LABEL_PROFILE_DEFINITION   (CTOKEN_PSA_LABEL_BASE - 0)
#define CTOKEN_PSA_LABEL_CLIENT_ID            (CTOKEN_PSA_LABEL_BASE - 1)
#define CTOKEN_PSA_LABEL_SECURITY_LIFECYCLE   (CTOKEN_PSA_LABEL_BASE - 2)
#define CTOKEN_PSA_LABEL_IMPLEMENTATION_ID    (CTOKEN_PSA_LABEL_BASE - 3)
#define CTOKEN_PSA_LABEL_BOOT_SEED            (CTOKEN_PSA_LABEL_BASE - 4)
#define CTOKEN_PSA_LABEL_HW_VERSION           (CTOKEN_PSA_LABEL_BASE - 5)
#define CTOKEN_PSA_LABEL_SW_COMPONENTS        (CTOKEN_PSA_LABEL_BASE - 6)
#define CTOKEN_PSA_LABEL_NO_SW_COMPONENTS     (CTOKEN_PSA_LABEL_BASE - 7)
// Same as CTOKEN_TEMP_EAT_LABEL_NONCE, should standardize as CTOKEN_EAT_LABEL_NONCE
#define CTOKEN_PSA_LABEL_CHALLENGE            (CTOKEN_PSA_LABEL_BASE - 8)
// Same as CTOKEN_TEMP_EAT_LABEL_UEID, should standardize as CTOKEN_EAT_LABEL_UEID
#define CTOKEN_PSA_LABEL_UEID                 (CTOKEN_PSA_LABEL_BASE - 9)
#define CTOKEN_PSA_LABEL_ORIGINATION          (CTOKEN_PSA_LABEL_BASE - 10)


/* Labels for the data items in the SW components map */
#define CTOKEN_PSA_SW_COMPONENT_MEASUREMENT_TYPE  (1)
#define CTOKEN_PSA_SW_COMPONENT_MEASUREMENT_VALUE (2)
#define CTOKEN_PSA_SW_COMPONENT_SECURITY_EPOCH    (3)
#define CTOKEN_PSA_SW_COMPONENT_VERSION           (4)
#define CTOKEN_PSA_SW_COMPONENT_SIGNER_ID         (5)
#define CTOKEN_PSA_SW_COMPONENT_MEASUREMENT_DESC  (6)


/**
 * This structure holds the simple-to-get fields from the
 * token that can be bundled into one structure.
 *
 * This is 7 * 8 + 12 = 72 bytes on a 32-bit machine.
 */
struct ctoken_psa_simple_claims_t {
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


/** Label for bits in \c item_flags in \ref
 ctoken_psa_simple_claims_t */
enum ctoken_psa_item_index_t {
    CTOKEN_PSA_NONCE_FLAG =              0,
    CTOKEN_PSA_UEID_FLAG  =              1,
    CTOKEN_PSA_BOOT_SEED_FLAG =          2,
    CTOKEN_PSA_HW_VERSION_FLAG =         3,
    CTOKEN_PSA_IMPLEMENTATION_ID_FLAG =  4,
    CTOKEN_PSA_CLIENT_ID_FLAG =          5,
    CTOKEN_PSA_SECURITY_LIFECYCLE_FLAG = 6,
    CTOKEN_PSA_PROFILE_DEFINITION_FLAG = 7,
    CTOKEN_PSA_ORIGINATION_FLAG =        8,
#ifndef CTOKEN_DISABLE_TEMP_LABELS
    CTOKEN_PSA_TEMP_NONCE_FLAG =         9,
    CTOKEN_PSA_TEMP_UEID_FLAG  =        10,
    CTOKEN_PSA_NUMBER_OF_ITEMS =        11
#else
    CTOKEN_PSA_NUMBER_OF_ITEMS =         9
#endif


};


/**
 * Macro to determine if data item is present in \ref
 * ctoken_psa_simple_claims_t
 */
#define ITEM_FLAG(index)  (0x01U << (index))

#define IS_ITEM_FLAG_SET(item_index, item_flags)   (ITEM_FLAG(item_index) & (item_flags))

// TODO: add the security lifecycle values.

#ifdef __cplusplus
}
#endif

#endif /* psa_ia_labels_h */
