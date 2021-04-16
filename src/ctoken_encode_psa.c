/*
 * ctoken_encode_psa.c
 *
 * Copyright (c) 2020-2021, Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 1/31/20.
 */


#include "ctoken/ctoken_encode_psa.h"


void ctoken_encode_psa_simple_claims(struct ctoken_encode_ctx *me,
                                       const struct ctoken_psa_simple_claims_t *claims)
{
    if(IS_ITEM_FLAG_SET(CTOKEN_PSA_NONCE_FLAG, claims->item_flags)) {
        ctoken_encode_nonce(me, claims->nonce);
    }

    if(IS_ITEM_FLAG_SET(CTOKEN_PSA_UEID_FLAG, claims->item_flags)) {
        ctoken_encode_ueid(me, claims->ueid);
    }

    if(IS_ITEM_FLAG_SET(CTOKEN_PSA_BOOT_SEED_FLAG, claims->item_flags)) {
        ctoken_encode_psa_boot_seed(me, claims->boot_seed);
    }

    if(IS_ITEM_FLAG_SET(CTOKEN_PSA_HW_VERSION_FLAG, claims->item_flags)) {
       ctoken_encode_psa_hw_version(me, claims->hw_version);
    }

    if(IS_ITEM_FLAG_SET(CTOKEN_PSA_IMPLEMENTATION_ID_FLAG, claims->item_flags)) {
        ctoken_encode_psa_implementation_id(me, claims->implementation_id);
    }

    if(IS_ITEM_FLAG_SET(CTOKEN_PSA_ORIGINATION_FLAG, claims->item_flags)) {
        ctoken_encode_psa_origination(me, claims->origination);
    }

    if(IS_ITEM_FLAG_SET(CTOKEN_PSA_PROFILE_DEFINITION_FLAG, claims->item_flags)) {
        ctoken_encode_psa_profile_definition(me, claims->profile_definition);
    }

    if(IS_ITEM_FLAG_SET(CTOKEN_PSA_CLIENT_ID_FLAG, claims->item_flags)) {
        ctoken_encode_psa_client_id(me, claims->client_id);
    }

    if(IS_ITEM_FLAG_SET(CTOKEN_PSA_SECURITY_LIFECYCLE_FLAG, claims->item_flags)) {
        ctoken_encode_psa_security_lifecycle(me, claims->security_lifecycle);
    }
}

// TODO: implementation of SW components; review the TF-M code to do this.
