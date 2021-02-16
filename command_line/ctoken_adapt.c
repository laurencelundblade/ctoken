//
//  ctoken_adapt.c
//  CToken
//
//  Created by Laurence Lundblade on 2/14/21.
//  Copyright © 2021 Laurence Lundblade. All rights reserved.
//

#include "ctoken_adapt.h"

#include "ctoken_encode.h"
#include "ctoken_decode.h"



int xclaim_encode_generic(struct ctoken_encode_ctx *ectx, const QCBORItem *claim_item)
{
    bool bool_value;

    switch(claim_item->uDataType) {
        case QCBOR_TYPE_INT64:
            ctoken_encode_add_integer(ectx, claim_item->label.int64, claim_item->val.int64);
            break;

        // TODO: uint64


        case QCBOR_TYPE_DOUBLE:
            token_encode_add_double(ectx, claim_item->label.int64, claim_item->val.dfnum);
            break;

        case QCBOR_TYPE_TEXT_STRING:
            ctoken_encode_add_tstr(ectx, claim_item->label.int64, claim_item->val.string);
            break;

        case QCBOR_TYPE_BYTE_STRING:
            ctoken_encode_add_bstr(ectx, claim_item->label.int64, claim_item->val.string);
            break;

        case QCBOR_TYPE_TRUE:
        case QCBOR_TYPE_FALSE:
            bool_value = claim_item->uDataType == QCBOR_TYPE_TRUE;
            token_encode_add_bool(ectx, claim_item->label.int64, bool_value);
            break;

        case QCBOR_TYPE_NULL:
            token_encode_add_null(ectx, claim_item->label.int64);
            break;

        default:
            // TODO: some type that is not understood. Fix error code
            return 1;
            break;
    }

    return 0; // TODO: error handling
}


static
int encode_xclaim(void *ctx, const struct xclaim *claim)
{
    struct ctoken_encode_ctx *e_ctx = (struct ctoken_encode_ctx *)ctx;
    switch(claim->qcbor_item.label.int64) {

        case CTOKEN_CWT_LABEL_ISSUER:
            ctoken_encode_issuer(e_ctx, claim->qcbor_item.val.string);
            break;

        case CTOKEN_EAT_LABEL_LOCATION:
            ctoken_encode_location(e_ctx, &(claim->u.location_claim));
            break;

        case CTOKEN_CWT_LABEL_SUBJECT:
            ctoken_encode_subject(e_ctx, claim->qcbor_item.val.string);
            break;

        case CTOKEN_CWT_LABEL_AUDIENCE:
            ctoken_encode_audience(e_ctx, claim->qcbor_item.val.string);
            break;

        case CTOKEN_CWT_LABEL_EXPIRATION:
            ctoken_encode_expiration(e_ctx, claim->qcbor_item.val.int64);
            break;

        case CTOKEN_CWT_LABEL_NOT_BEFORE:
            ctoken_encode_not_before(e_ctx, claim->qcbor_item.val.int64);
            break;

        case CTOKEN_CWT_LABEL_IAT:
            ctoken_encode_iat(e_ctx, claim->qcbor_item.val.int64);
            break;

        case CTOKEN_CWT_LABEL_CTI:
            ctoken_encode_cti(e_ctx, claim->qcbor_item.val.string);
            break;

        case CTOKEN_EAT_LABEL_UEID:
            ctoken_encode_ueid(e_ctx, claim->qcbor_item.val.string);
            break;

        case CTOKEN_EAT_LABEL_NONCE:
            ctoken_encode_nonce(e_ctx, claim->qcbor_item.val.string);
            break;

        case CTOKEN_EAT_LABEL_SECURITY_LEVEL:
            // TODO: check enum
            ctoken_encode_security_level(e_ctx, (enum ctoken_security_level_t)claim->qcbor_item.val.int64);
            break;

        default:
            xclaim_encode_generic(e_ctx, &(claim->qcbor_item));
            break;
    }

    return 0;
}


int xclaim_ctoken_encode_init(xclaim_encode *out, struct ctoken_encode_ctx *ctx)
{
    out->ctx = ctx;

    out->output_claim          = encode_xclaim;

    /* Can use ctoken methods directly. Casts are only for the first arg */
    out->open_submod           = (int (*)(void *, const char *))ctoken_encode_open_submod;
    out->close_submod          = (int (*)(void *))ctoken_encode_close_submod;
    out->start_submods_section = (int (*)(void *))ctoken_encode_start_submod_section;
    out->end_submods_section   = (int (*)(void *))ctoken_encode_start_submod_section;

    return 0;
}




static int
decode_next_xclaim(void *decode_ctx, struct xclaim *xclaim)
{
    enum ctoken_err_t         err;
    struct ctoken_decode_ctx *dctx = (struct ctoken_decode_ctx *)decode_ctx;

    err = ctoken_decode_next_claim(dctx, &(xclaim->qcbor_item));
    if(err != 0) {
        /* End of claims or error getting them. */
        goto Done;
    }

    if(xclaim->qcbor_item.label.int64 == CTOKEN_EAT_LABEL_LOCATION) {
       ctoken_decode_location(dctx, &(xclaim->u.location_claim));
    } else {
        /* Nothing to do. The qcbor_item has everything that is needed. */
    }

Done:
    return err;
}


int
xclaim_ctoken_decode_init(xclaim_decoder *ic, struct ctoken_decode_ctx *ctx)
{
    ic->ctx = ctx;

    ic->next_claim   = decode_next_xclaim;

    /* Can use ctoken methods directly. Casts are only for the first arg */
    ic->enter_submod = (int (*)(void *, uint32_t, struct q_useful_buf_c *))ctoken_decode_enter_nth_submod;
    ic->exit_submod  = (int (*)(void *))ctoken_decode_exit_submod;
    ic->get_nested   = (int (*)(void *, uint32_t, enum ctoken_type_t *, struct q_useful_buf_c *))ctoken_decode_get_nth_nested_token;

    return 0;// TODO: error code
}
