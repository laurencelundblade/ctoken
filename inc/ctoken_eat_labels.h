/*
 * ctoken_eat_labels.h
 *
 * Copyright (c) 2020 Laurence Lundblade.
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
#ifdef 0
} /* Keep editor indention formatting happy */
#endif
#endif

/* These are temporary labels until the real ones are assigned by IANA.
 * This is probably sometime in 2021 or 2022 when the EAT draft
 * becomes an RFC. Some are the same as defined in https://tools.ietf.org/id/draft-tschofenig-rats-psa-token-05.html,
 * which has also defined some temporary labels.
 */
#define CTOKEN_EAT_LABEL_UEID -75009 // Same as PSA
#define CTOKEN_EAT_LABEL_NONCE -75008 // Same as PSA
#define CTOKEN_EAT_LABEL_OEMID  -76001
#define CTOKEN_EAT_LABEL_ORIGINATION  -75010 // Same as PSA
#define CTOKEN_EAT_LABEL_SECURITY_LEVEL -76002
#define CTOKEN_EAT_LABEL_BOOT_STATE -76003
#define CTOKEN_EAT_LABEL_LOCATION -76004
#define CTOKEN_EAT_LABEL_AGE -76005
#define CTOKEN_EAT_LABEL_UPTIME -76006


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
enum ctoken_eat_security_level_t {
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
enum ctoken_eat_debug_level_t {
    /** The debug state is not reported. It is not know what it is */
    EAT_DL_NOT_REPORTED = 0,
    /** The debug system is enabled */
    EAT_DL_NOT_DISABLED = 1,
    /** The debug system is disabled, but might have been enabled recently,
     * been enabled since the system booted or started */
    EAT_DL_DISABLED = 2,
    /** The debug system is disabled and has not been enabled recently, not
     * since before the device most recently booted or restarted
     */
    EAT_DL_DISABLED_SINCE_BOOT = 3,
    /** The debug system is disabled and cannot be enabled by any put the
     * chip / hardware manufacturer
     */
    EAT_DL_PERMANENT_DISABLE = 4,
    /** The debug system cannot be enabled by anyone */
    EAT_DL_FULL_PERMANENT_DISABLE = 5};


/* These are labels for inside the map that is the location claims.
 The are assigned in the EAT specification.

 They also index items[] in ctoken_eat_location_t.

 They also index the bits indicating valid data in item_flags in ctoken_eat_location_t
 */
#define CTOKEN_EAT_LABEL_LATITUDE          1
#define CTOKEN_EAT_LABEL_LONGITUDE         2
#define CTOKEN_EAT_LABEL_ALTITUDE          3
#define CTOKEN_EAT_LABEL_ACCURACY          4
#define CTOKEN_EAT_LABEL_ALTITUDE_ACCURACY 5
#define CTOKEN_EAT_LABEL_HEADING           6
#define CTOKEN_EAT_LABEL_SPEED             7

#define NUM_LOCATION_ITEMS CTOKEN_EAT_LABEL_SPEED


/**
 * Holds a geographic location (e.g. a GPS position).
 */
struct ctoken_eat_location_t {
    /** Array of doubles to old latitude, longitude... indexed
     * CTOKEN_EAT_LABEL_XXX - 1. Use accessor macros below for
     * convenience. Array entry is only valid id flag for it is set
     * in item_flags. */
    double items[NUM_LOCATION_ITEMS];
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

#endif /* eat_labels_h */
