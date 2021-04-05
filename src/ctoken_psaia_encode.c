/*
 * ctoken_psaia_encode.c
 *
 * Copyright (c) 2020, Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 1/31/20.
 */


#include "ctoken/ctoken_psaia_encode.h"


void ctoken_psaia_encode_simple_claims(struct ctoken_encode_ctx *me,
                                       const struct ctoken_psaia_simple_claims_t *claims)
{
    if(IS_ITEM_FLAG_SET(CTOKEN_PSAIA_NONCE_FLAG, claims->item_flags)) {
        ctoken_encode_nonce(me, claims->nonce);
    }

    if(IS_ITEM_FLAG_SET(UEID_FLAG, claims->item_flags)) {
        ctoken_encode_ueid(me, claims->ueid);
    }

    if(IS_ITEM_FLAG_SET(BOOT_SEED_FLAG, claims->item_flags)) {
        ctoken_psaia_encode_boot_seed(me, claims->boot_seed);
    }

    if(IS_ITEM_FLAG_SET(HW_VERSION_FLAG, claims->item_flags)) {
       ctoken_psaia_encode_hw_version(me, claims->hw_version);
    }

    if(IS_ITEM_FLAG_SET(IMPLEMENTATION_ID_FLAG, claims->item_flags)) {
        ctoken_psaia_encode_implementation_id(me, claims->implementation_id);
    }

    if(IS_ITEM_FLAG_SET(ORIGINATION_FLAG, claims->item_flags)) {
        ctoken_psaia_encode_origination(me, claims->origination);
    }

    if(IS_ITEM_FLAG_SET(PROFILE_DEFINITION_FLAG, claims->item_flags)) {
        ctoken_psaia_encode_profile_definition(me, claims->profile_definition);
    }

    if(IS_ITEM_FLAG_SET(CLIENT_ID_FLAG, claims->item_flags)) {
        ctoken_psaia_encode_client_id(me, claims->client_id);
    }

    if(IS_ITEM_FLAG_SET(SECURITY_LIFECYCLE_FLAG, claims->item_flags)) {
        ctoken_psaia_encode_security_lifecycle(me, claims->security_lifecycle);
    }
}

// TODO: implementation of SW components; review the TF-M code to do this.
