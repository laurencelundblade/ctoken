/*
 * ctoken_eat_labels.h
 *
 * Copyright (c) 2020-2021, Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 2/1/20.
 */


#ifndef eat_labels_h
#define eat_labels_h

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#if 0
} /* Keep editor indention formatting happy */
#endif
#endif


/**
 * File: ctoken_eat_labels.h
 *
 * The EAT standard (Entity Attestation Token) is still in development
 * in the IETF. This code is roughly based on
 * https://tools.ietf.org/html/draft-ietf-rats-eat-08
 *
 * EAT is expected to become a standard some time in 2021 or 2022. At
 * that point the standard labels for all claims will be permanently assigned
 * in the IANA CWT registry (https://www.iana.org/assignments/cwt/cwt.xhtml).
 * These values will be in the standard range (-256 to 256). Until
 * that happens, EAT implementations have to use temporary labels from
 * the private use range (less than -65536).
 *
 * Ctoken is therefore using temporary labels for the claims both for
 * encoding and decoding.
 *
 * Ctoken also implements the standard CWT claims from RFC 8392. Those
 * labels are standardized, so there are no temporary labels for them.
 *
 * The plan for ctoken label handling when the standard labels get
 * assigned is as follows. Ctoken will recognize claims by either the
 * temporary label or by the standard label. Ctoken will generate
 * claims using the standard label. This will allow interoperability
 * through the transition from temporary labels to standard
 * labels. Ctoken will have a #define to disable recognition of the
 * temporary labels to reduce code size. Eventually, recognition of
 * the temporary labels will be disabled.
*
 * IANA has a process for “early allocation” whereby assignments can
 * be made before something becomes a standard. This has been pursued
 * for nine well-established EAT claims and we therefore have the
 * standard label values for them. This implementation uses the
 * above-described strategy with them. It encodes using the labels
 * that have been allocated early. Decoding recognizes both the value
 * that were allocated early and temporary values used before the
 * early allocation. (As of March 2021, this early allocation is still
 * in-process. It is expected to succeed, but in theory could be
 * rejected.)
 *
 * Some of the temporary label values were picked by the Arm’s PSA token
 * draft (https://tools.ietf.org/id/draft-tschofenig-rats-psa-token-05.html).
 * These are in the range of -75000 to -75010. Some of these are the
 * same as EAT claims and some are not. When they are the same as EAT
 * claims, Arm’s values are used here.
 *
 * The temporary label values used here not from Arm’s PSA are in the
 * range of -76000 to -76100.
 *
 * All early EAT implementors are invited to use the temporary label
 * values used here. That way all the early EAT implementations will
 * interoperate.
 */

#define CTOKEN_EAT_LABEL_NONCE                10
#define CTOKEN_TEMP_EAT_LABEL_NONCE          -75008 // Same as CTOKEN_PSA_LABEL_CHALLENGE

#define CTOKEN_EAT_LABEL_UEID                 11
#define CTOKEN_TEMP_EAT_LABEL_UEID           -75009 // CTOKEN_PSA_LABEL_UEID

#define CTOKEN_EAT_LABEL_OEMID                13
#define CTOKEN_TEMP_EAT_LABEL_OEMID          -76001

#define CTOKEN_EAT_LABEL_SECURITY_LEVEL       14
#define CTOKEN_TEMP_EAT_LABEL_SECURITY_LEVEL -76002

#define CTOKEN_EAT_LABEL_SECURE_BOOT          15
#define CTOKEN_TEMP_EAT_LABEL_SECURE_BOOT    -76003

#define CTOKEN_EAT_LABEL_DEBUG_STATE          16
#define CTOKEN_TEMP_EAT_LABEL_DEBUG_STATE    -76008

#define CTOKEN_EAT_LABEL_LOCATION             17
#define CTOKEN_TEMP_EAT_LABEL_LOCATION       -76004

// TODO: ARM profile label?
#define CTOKEN_EAT_LABEL_PROFILE              18
#define CTOKEN_TEMP_EAT_LABEL_PROFILE        -76004

/* Not really a claim, but must have a label */
#define CTOKEN_EAT_LABEL_SUBMODS              20
#define CTOKEN_TEMP_EAT_LABEL_SUBMODS        -76000

// Expect this to be removed
#define CTOKEN_EAT_LABEL_ORIGINATION                 -75010

#define CTOKEN_EAT_LABEL_UPTIME                      -76006
#define CTOKEN_EAT_LABEL_CHIP_VERSION                -76032
#define CTOKEN_EAT_LABEL_BOARD_VERSION               -76033
#define CTOKEN_EAT_LABEL_DEVICE_VERSION              -76034
#define CTOKEN_EAT_LABEL_CHIP_VERSION_SCHEME         -76035
#define CTOKEN_EAT_LABEL_BOARD_VERSION_SCHEME        -76036
#define CTOKEN_EAT_LABEL_DEVICE_VERSION_SCHEME       -76037
#define CTOKEN_EAT_LABEL_EAN_CHIP_VERSION            -76038
#define CTOKEN_EAT_LABEL_EAN_BOARD_VERSION           -76039
#define CTOKEN_EAT_LABEL_EAN_DEVICE_VERSION          -76040
#define CTOKEN_EAT_LABEL_INTENDED_USE                -76041




/**
 * This gives a rough notion of the security level of the attester.
 */
enum ctoken_security_level_t {
    /* Never appears in a protocol message. */
    EAT_SL_INVALID           = 0,
    /** Signing key is protected by a general purpose OS running on generic
      * hardware
      */
    EAT_SL_UNRESTRICTED      = 1,
    /** Signing key is running on an isolated subsystem, perhaps special
     * hardware, but it is not a security-oriented subystem.
     */
    EAT_SL_RESTRICTED        = 2,
    /** Signing key is protected by a security-oriented subsystem like a TEE
      */
    EAT_SL_SECURE_RESTRICTED = 3,
    /** Signing key is protected by a security-oriented subsystem with
     * defenses against hardware invasive attacks
     */
    EAT_SL_HARDWARE          = 4};


/**
 * This characterizes the hardware and system debug state of the
 * attestor.
 */
enum ctoken_debug_level_t {
    /* Never appears in a protocol message. */
    CTOKEN_DEBUG_INVALID = -1,
    /** The debug system is enabled */
    CTOKEN_DEBUG_ENABLED = 0,
    /** The debug system is disabled, but might have been enabled recently,
     * been enabled since the system booted or started */
    CTOKEN_DEBUG_DISABLED = 1,
    /** The debug system is disabled and has not been enabled recently, not
     * since before the device most recently booted or restarted
     */
    CTOKEN_DEBUG_DISABLED_SINCE_BOOT = 2,
    /** The debug system is disabled and cannot be enabled by any put the
     * chip / hardware manufacturer
     */
    CTOKEN_DEBUG_DISABLED_PERMANENT = 3,
    /** The debug system cannot be enabled by anyone */
    CTOKEN_DEBUG_DISABLED_FULL_PERMANENT = 4
};


/* These are labels for inside the map that is the location claims.
 * The are assigned in the EAT specification.
 *
 * They also index items[] in ctoken_eat_location_t.
 *
 * They also index the bits indicating valid data in item_flags in
 * ctoken_eat_location_t
 */
#define CTOKEN_EAT_LABEL_LATITUDE          1
#define CTOKEN_EAT_LABEL_LONGITUDE         2
#define CTOKEN_EAT_LABEL_ALTITUDE          3
#define CTOKEN_EAT_LABEL_ACCURACY          4
#define CTOKEN_EAT_LABEL_ALTITUDE_ACCURACY 5
#define CTOKEN_EAT_LABEL_HEADING           6
#define CTOKEN_EAT_LABEL_SPEED             7
#define CTOKEN_EAT_LABEL_TIME_STAMP        8
#define CTOKEN_EAT_LABEL_AGE               9

#define NUM_FLOAT_LOCATION_ITEMS CTOKEN_EAT_LABEL_SPEED


/** Value for the Intended Use claim. */
enum ctoken_intended_use_t {
    /* Never appears in a protocol message. */
    CTOKEN_USE_INVALID = 0,
    /** The token is for general use. No specific use is given. */
    CTOKEN_USE_GENERAL = 1,
    /** The token is intended to be used for a registration step. */
    CTOKEN_USE_REGISTRATION = 2,
    /** Token is intended as part of a provisioning step, most likely
      * provisioning cryptographic keys beyond those used for
      * attestation.  */
    CTOKEN_USE_PROVISIONING = 3,
    /** This may be required by a CA before signing a CSR. */
    CTOKEN_USE_CERTIFICATE_ISSUANCE = 4,
    /** Used to prove the device has possesion of a key. */
    CTOKEN_USE_PROOF_OF_POSSSION = 5
};


#ifdef __cplusplus
}
#endif

#endif /* eat_labels_h */
