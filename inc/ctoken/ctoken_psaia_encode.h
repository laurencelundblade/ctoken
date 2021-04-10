/*
 * ctoken_psaia_encode.h
 *
 * Copyright (c) 2020 Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 1/31/20.
 */


#ifndef psa_ia_encode_h
#define psa_ia_encode_h

#include "ctoken_psaia_labels.h"
#include "ctoken_encode.h"


#ifdef __cplusplus
extern "C" {
#if 0
} /* Keep editor indention formatting happy */
#endif
#endif

/**
 * \brief Encode most of the PSA claims at once.
 *
 * \param[in] context  The token encoder context.
 * \param[in] claims   Structure holding the claims.
 *
 * This outputs the claims other than the software component and
 * measurement claims all at once. It is a little more efficient than
 * calling the individual methods to output one at a time.
 *
 * See \ref ctoken_psaia_simple_claims_t for the structure holding the
 * claims to be output. Note that only claims that are indicated as
 * present in \c item_flags will be output.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
void ctoken_psaia_encode_simple_claims(struct ctoken_encode_ctx *context,
                                       const struct ctoken_psaia_simple_claims_t *claims);



/**
 * \brief Encode the boot seed in to the token.
 *
 * \param[in] context    The token encoder context.
 * \param[in] boot_seed  Returned pointer and length of boot seed.
 *
 * This outputs the boot seed.
 *
 * This is binary value, 32 bytes or larger, that is generated
 * at the start of each boot cycle and this indicates the boot
 * session.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static void
ctoken_psaia_encode_boot_seed(struct ctoken_encode_ctx *context,
                              struct q_useful_buf_c boot_seed);


/**
 * \brief Encode the hardware version in to the token.
 *
 * \param[in] context     The token encoder context.
 * \param[in] hw_version  Pointer and length of HW version text string.
 *
 * This outputs the HW version claim.
 *
 * This is an EAN-13 text string that gives the version of the
 * hardware. This may be of the chip, circuit board or device.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static inline void
ctoken_psaia_encode_hw_version(struct ctoken_encode_ctx *context,
                               struct q_useful_buf_c hw_version);


/**
 * \brief Encode the implementation ID in to the token.
 *
 * \param[in] context            The token encoder context.
 * \param[in] implementation_id  Pointer and length of implementation ID.
 *
 * This outputs the implementation ID.
 *
 * This ID is used by the verifier to identify the attestor that created
 * the token so it can know it certification level and such.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static inline void
ctoken_psaia_encode_implementation_id(struct ctoken_encode_ctx *context,
                                      struct q_useful_buf_c implementation_id);

/**
 * \brief Encode the origination in to the token.
 *
 * \param[in] context      The token encoder context.
 * \param[in] origination  Pointer and length of origination claim to output.
 *
 * This outputs the origination claim.
 *
 * This describes the part of the device that created the token. It
 * is a text string or a URI.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static inline void
ctoken_psaia_encode_origination(struct ctoken_encode_ctx *context,
                                struct q_useful_buf_c origination);


/**
 * \brief Encode the profile_definition in to the token.
 *
 * \param[in] context             The token encoder context.
 * \param[in] profile_definition  Pointer and length of profile name.
 *
 * This outputs the text string naming the profile in use.
 *
 * EAT is a very general specification for use in the most broad
 * way. A profile document narrows the EAT specification by
 * requirnig or disallowing some claims. It may also define
 * specific claims.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static inline void
ctoken_psaia_encode_profile_definition(struct ctoken_encode_ctx *context,
                                       struct q_useful_buf_c profile_definition);


/**
 * \brief Encode the security lifecycle in to the token.
 *
 * \param[in] context             The token encoder context.
 * \param[in] security_lifecycle  Integer state of the attester.
 *
 * This outputs the security lifecycle claim.
 *
 * The security lifecycle can have the following values:
 * -  PSA_LIFECYCLE_UNKNOWN (0x0000u)
 * -  PSA_LIFECYCLE_ASSEMBLY_AND_TEST (0x1000u)
 * -  PSA_LIFECYCLE_PSA_ROT_PROVISIONING (0x2000u)
 * -  PSA_LIFECYCLE_SECURED (0x3000u)
 * -  PSA_LIFECYCLE_NON_PSA_ROT_DEBUG (0x4000u)
 * -  PSA_LIFECYCLE_RECOVERABLE_PSA_ROT_DEBUG (0x5000u)
 * -  PSA_LIFECYCLE_DECOMMISSIONED (0x6000u)
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static inline void
ctoken_psaia_encode_security_lifecycle(struct ctoken_encode_ctx *context,
                                       uint32_t security_lifecycle);


/**
 * \brief Encode the client ID in to the token.
 *
 * \param[in] context     The token encoder context.
 * \param[in] client_id   Signed integer that is the client ID.
 *
 * This outputs the client ID.
 *
 * A PSA system identifier representing the partion ID of the caller.
 * Positive values indicate the secure side (e.g. the TEE) and negative
 * the non-secure side (e.g. the rich OS). Partitions identify IPC
 * end points.
 *
 * If there is an error like insufficient space in the output buffer,
 * the error state is entered. It is returned later when ctoken_encode_finish()
 * is called.
 */
static inline void
ctoken_psaia_encode_client_id(struct ctoken_encode_ctx *context,
                              int32_t client_id);


// TODO: output the SW components claims.

/* --------------------------------------------------------------------------
 *       Inline implementations
 * --------------------------------------------------------------------------*/



static inline void
ctoken_psaia_encode_boot_seed(struct ctoken_encode_ctx *me,
                              struct q_useful_buf_c boot_seed)
{
    ctoken_encode_bstr(me, EAT_CBOR_ARM_LABEL_BOOT_SEED, boot_seed);
}

static inline void
ctoken_psaia_encode_hw_version(struct ctoken_encode_ctx *me,
                               struct q_useful_buf_c hw_version)
{
    ctoken_encode_bstr(me, EAT_CBOR_ARM_LABEL_HW_VERSION, hw_version);
}

static inline void
ctoken_psaia_encode_implementation_id(struct ctoken_encode_ctx *me,
                                      struct q_useful_buf_c implementation_id)
{
    ctoken_encode_bstr(me, EAT_CBOR_ARM_LABEL_IMPLEMENTATION_ID, implementation_id);
}

static inline void
ctoken_psaia_encode_origination(struct ctoken_encode_ctx *me,
                                struct q_useful_buf_c origination)
{
    ctoken_encode_origination(me, origination);
}

static inline void
ctoken_psaia_encode_profile_definition(struct ctoken_encode_ctx *me,
                                       struct q_useful_buf_c profile_definition)
{
    ctoken_encode_bstr(me, EAT_CBOR_ARM_LABEL_PROFILE_DEFINITION, profile_definition);
}


static inline void
ctoken_psaia_encode_security_lifecycle(struct ctoken_encode_ctx *me,
                                       uint32_t security_lifecycle)
{
    ctoken_encode_add_unsigned(me, EAT_CBOR_ARM_LABEL_SECURITY_LIFECYCLE, security_lifecycle);
}


static inline void
ctoken_psaia_encode_client_id(struct ctoken_encode_ctx *me,
                              int32_t client_id)
{
    ctoken_encode_int(me, EAT_CBOR_ARM_LABEL_CLIENT_ID, client_id);
}

#ifdef __cplusplus
}
#endif

#endif /* psa_ia_encode_h */
