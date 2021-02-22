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

/* These are temporary labels until the real ones are assigned by
 * IANA.  This is probably sometime in 2021 or 2022 when the EAT draft
 * becomes an RFC. Some are the same as defined in
 * https://tools.ietf.org/id/draft-tschofenig-rats-psa-token-05.html,
 * which has also defined some temporary labels.
 */
#define CTOKEN_EAT_LABEL_UEID -75009 // Same as PSA
#define CTOKEN_EAT_LABEL_NONCE -75008 // Same as PSA
#define CTOKEN_EAT_LABEL_OEMID  -76001
#define CTOKEN_EAT_LABEL_ORIGINATION  -75010 // Same as PSA
#define CTOKEN_EAT_LABEL_SECURITY_LEVEL -76002
#define CTOKEN_EAT_LABEL_BOOT_STATE -76003
#define CTOKEN_EAT_LABEL_SECURE_BOOT -76007
#define CTOKEN_EAT_LABEL_DEBUG_STATE -76008
#define CTOKEN_EAT_LABEL_LOCATION -76004
#define CTOKEN_EAT_LABEL_UPTIME -76006
#define CTOKEN_EAT_LABEL_INTENDED_USE -76009


#define CTOKEN_EAT_LABEL_SUBMODS -76000 // Not really a claim, but most have a label

/**
 * File: ctoken_eat_labels.h
 *
 * The EAT standard (Entity Attestation Token) is still in development
 * in the IETF. This code is roughly based on
 * https://tools.ietf.org/html/draft-ietf-rats-eat-02
 *
 * While the core basis on CWT is unlikely to change, the
 * individual claims are likely to change.
 */

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
    CTOKEN_DEBUG_DISABLED_FULL_PERMANENT = 4};


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
