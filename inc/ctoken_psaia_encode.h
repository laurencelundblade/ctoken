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
#include "ctoken_eat_encode.h"

void ctoken_psaia_encode_simple_claims(struct ctoken_encode_ctx *me,
                                       const struct ctoken_psaia_simple_claims_t *claims);



static inline void
ctoken_psaia_encode_nonce(struct ctoken_encode_ctx *me,
                          struct q_useful_buf_c nonce)
{
    ctoken_eat_encode_nonce(me, nonce);
}


static inline void
ctoken_psaia_encode_boot_seed(struct ctoken_encode_ctx *me,
                              struct q_useful_buf_c boot_seed)
{
    ctoken_encode_add_bstr(me, EAT_CBOR_ARM_LABEL_BOOT_SEED, boot_seed);
}


static inline void
ctoken_psaia_encode_ueid(struct ctoken_encode_ctx *me,
                         struct q_useful_buf_c ueid)
{
    ctoken_eat_encode_ueid(me, ueid);
}


static inline void
ctoken_psaia_encode_hw_version(struct ctoken_encode_ctx *me,
                               struct q_useful_buf_c hw_version)
{
    ctoken_encode_add_bstr(me, EAT_CBOR_ARM_LABEL_HW_VERSION, hw_version);
}

static inline void
ctoken_psaia_encode_implementation_id(struct ctoken_encode_ctx *me,
                                      struct q_useful_buf_c implementation_id)
{
    ctoken_encode_add_bstr(me, EAT_CBOR_ARM_LABEL_IMPLEMENTATION_ID, implementation_id);
}

static inline void
ctoken_psaia_encode_origination(struct ctoken_encode_ctx *me,
                                struct q_useful_buf_c origination)
{
    ctoken_encode_eat_origination(me, origination);
}

static inline void
ctoken_psaia_encode_profile_definition(struct ctoken_encode_ctx *me,
                                       struct q_useful_buf_c profile_definition)
{
    ctoken_encode_add_bstr(me, EAT_CBOR_ARM_LABEL_PROFILE_DEFINITION, profile_definition);
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
    ctoken_encode_add_integer(me, EAT_CBOR_ARM_LABEL_CLIENT_ID, client_id);
}

#endif /* psa_ia_encode_h */
