/*
 * ctoken_psaia_labels.h (partly derived from attest_eat_defines.h)
 *
 * Copyright (c) 2020 Laurence Lundblade.
 * Copyright (c) 2019, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 */

#ifndef psa_ia_labels_h
#define psa_ia_labels_h

#include "ctoken_eat_labels.h"
#include "q_useful_buf.h"


#ifdef __cplusplus
extern "C" {
#ifdef 0
} /* Keep editor indention formatting happy */
#endif
#endif

/**
 * These labels are temporary and in the proprietary space for
 * CWT claims. These will be changed with they get officially
 * assigned by IANA. See https://tools.ietf.org/html/draft-tschofenig-rats-psa-token-04
 * and eventually https://www.iana.org/assignments/cwt/cwt.xhtml.
 */

#define EAT_CBOR_ARM_RANGE_BASE                 (-75000)
#define EAT_CBOR_ARM_LABEL_PROFILE_DEFINITION   (EAT_CBOR_ARM_RANGE_BASE - 0)
#define EAT_CBOR_ARM_LABEL_CLIENT_ID            (EAT_CBOR_ARM_RANGE_BASE - 1)
#define EAT_CBOR_ARM_LABEL_SECURITY_LIFECYCLE   (EAT_CBOR_ARM_RANGE_BASE - 2)
#define EAT_CBOR_ARM_LABEL_IMPLEMENTATION_ID    (EAT_CBOR_ARM_RANGE_BASE - 3)
#define EAT_CBOR_ARM_LABEL_BOOT_SEED            (EAT_CBOR_ARM_RANGE_BASE - 4)
#define EAT_CBOR_ARM_LABEL_HW_VERSION           (EAT_CBOR_ARM_RANGE_BASE - 5)
#define EAT_CBOR_ARM_LABEL_SW_COMPONENTS        (EAT_CBOR_ARM_RANGE_BASE - 6)
#define EAT_CBOR_ARM_LABEL_NO_SW_COMPONENTS     (EAT_CBOR_ARM_RANGE_BASE - 7)
#define EAT_CBOR_ARM_LABEL_CHALLENGE            (EAT_CBOR_ARM_RANGE_BASE - 8)
#define EAT_CBOR_ARM_LABEL_UEID                 (EAT_CBOR_ARM_RANGE_BASE - 9)
#define EAT_CBOR_ARM_LABEL_ORIGINATION          (EAT_CBOR_ARM_RANGE_BASE - 10)

// TODO: unify with enum in .._decode.h
#define EAT_CBOR_SW_COMPONENT_MEASUREMENT_TYPE  (1)
#define EAT_CBOR_SW_COMPONENT_MEASUREMENT_VALUE (2)
#define EAT_CBOR_SW_COMPONENT_SECURITY_EPOCH    (3)
#define EAT_CBOR_SW_COMPONENT_VERSION           (4)
#define EAT_CBOR_SW_COMPONENT_SIGNER_ID         (5)
#define EAT_CBOR_SW_COMPONENT_MEASUREMENT_DESC  (6)


/**
 * This structure holds the simple-to-get fields from the
 * token that can be bundled into one structure.
 *
 * This is 7 * 8 + 12 = 72 bytes on a 32-bit machine.
 */
struct ctoken_psaia_simple_claims_t {
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
 attest_token_iat_simple_t */
enum ctoken_psaia_item_index_t {
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
 * Macro to determine if data item is present in \ref
 * attest_token_iat_simple_t
 */
#define ITEM_FLAG(index)  (0x01U << (index))

#define IS_ITEM_FLAG_SET(item_index, item_flags)   (ITEM_FLAG(item_index) & (item_flags))

// TODO: add the security lifecycle values.

#ifdef __cplusplus
}
#endif

#endif /* psa_ia_labels_h */
