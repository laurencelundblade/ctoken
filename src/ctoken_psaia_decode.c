/*
 * ctoken_psaia_decode.c (formerly part of attest_token_decode.c)
 *
 * Copyright (c) 2019-2020, Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "ctoken_psaia_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"


/*
 * Public function. See ctoken_psaia_decode.h
 */
enum ctoken_err_t
ctoken_psaia_decode_simple_claims(struct ctoken_decode_ctx            *me,
                                  struct ctoken_psaia_simple_claims_t *items)
{
    int64_t            client_id_64;
    enum ctoken_err_t  return_value;
    QCBORItem          list[NUMBER_OF_ITEMS+1]; // This uses a lot of stack
    QCBORError         qcbor_error;

    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return_value = me->last_error;
        goto Done;
    }

    /* Set all q_useful_bufs to NULL and flags to 0 */
    memset(items, 0, sizeof(struct ctoken_psaia_simple_claims_t));

    /* Make the list of labels and types to get. Re use flags as array indexes
     * because it works nicely.
     */
    list[NONCE_FLAG].label.int64 = EAT_CBOR_ARM_LABEL_CHALLENGE;
    list[NONCE_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[NONCE_FLAG].uDataType   = QCBOR_TYPE_BYTE_STRING;

    list[UEID_FLAG].label.int64 = EAT_CBOR_ARM_LABEL_UEID;
    list[UEID_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[UEID_FLAG].uDataType   = QCBOR_TYPE_BYTE_STRING;

    list[BOOT_SEED_FLAG].label.int64 = EAT_CBOR_ARM_LABEL_BOOT_SEED;
    list[BOOT_SEED_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[BOOT_SEED_FLAG].uDataType   = QCBOR_TYPE_BYTE_STRING;

    list[HW_VERSION_FLAG].label.int64 = EAT_CBOR_ARM_LABEL_HW_VERSION;
    list[HW_VERSION_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[HW_VERSION_FLAG].uDataType   = QCBOR_TYPE_TEXT_STRING;

    list[IMPLEMENTATION_ID_FLAG].label.int64 = EAT_CBOR_ARM_LABEL_IMPLEMENTATION_ID;
    list[IMPLEMENTATION_ID_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[IMPLEMENTATION_ID_FLAG].uDataType   = QCBOR_TYPE_BYTE_STRING;

    list[CLIENT_ID_FLAG].label.int64 = EAT_CBOR_ARM_LABEL_CLIENT_ID;
    list[CLIENT_ID_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[CLIENT_ID_FLAG].uDataType   = QCBOR_TYPE_INT64;

    list[SECURITY_LIFECYCLE_FLAG].label.int64 = EAT_CBOR_ARM_LABEL_SECURITY_LIFECYCLE;
    list[SECURITY_LIFECYCLE_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[SECURITY_LIFECYCLE_FLAG].uDataType   = QCBOR_TYPE_INT64;

    list[PROFILE_DEFINITION_FLAG].label.int64 = EAT_CBOR_ARM_LABEL_PROFILE_DEFINITION;
    list[PROFILE_DEFINITION_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[PROFILE_DEFINITION_FLAG].uDataType   = QCBOR_TYPE_TEXT_STRING;

    list[ORIGINATION_FLAG].label.int64 = EAT_CBOR_ARM_LABEL_ORIGINATION;
    list[ORIGINATION_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[ORIGINATION_FLAG].uDataType   = QCBOR_TYPE_TEXT_STRING;

    list[NUMBER_OF_ITEMS].uLabelType  = QCBOR_TYPE_NONE;


    /* Get all the items in one CPU-efficient pass. */
    QCBORDecode_GetItemsInMap(&(me->qcbor_decode_context), list);
    qcbor_error = QCBORDecode_GetError(&(me->qcbor_decode_context));
    if(qcbor_error != QCBOR_SUCCESS) {
        return_value = CTOKEN_ERR_GENERAL; // TODO: error mapping
        goto Done;
    }

    /* ---- NONCE ---- */
    if(list[NONCE_FLAG].uDataType != QCBOR_TYPE_NONE) {
        items->nonce = list[NONCE_FLAG].val.string;
        items->item_flags |= CLAIM_PRESENT_BIT(NONCE_FLAG);
    }

    /* ---- UEID ---- */
    if(list[UEID_FLAG].uDataType != QCBOR_TYPE_NONE) {
        items->ueid = list[UEID_FLAG].val.string;
        items->item_flags |= CLAIM_PRESENT_BIT(UEID_FLAG);
    }

    /* ---- BOOT SEED ---- */
    if(list[BOOT_SEED_FLAG].uDataType != QCBOR_TYPE_NONE) {
        items->boot_seed = list[BOOT_SEED_FLAG].val.string;
        items->item_flags |= CLAIM_PRESENT_BIT(BOOT_SEED_FLAG);
    }

    /* ---- HW VERSION ---- */
    if(list[HW_VERSION_FLAG].uDataType != QCBOR_TYPE_NONE) {
        items->hw_version = list[HW_VERSION_FLAG].val.string;
        items->item_flags |= CLAIM_PRESENT_BIT(HW_VERSION_FLAG);

    }

    /* ----IMPLEMENTATION ID ---- */
    if(list[IMPLEMENTATION_ID_FLAG].uDataType != QCBOR_TYPE_NONE) {
        items->implementation_id = list[IMPLEMENTATION_ID_FLAG].val.string;
        items->item_flags |= CLAIM_PRESENT_BIT(IMPLEMENTATION_ID_FLAG);
    }

    /* ----CLIENT ID ---- */
    if(list[CLIENT_ID_FLAG].uDataType != QCBOR_TYPE_NONE) {
        client_id_64 = list[CLIENT_ID_FLAG].val.int64;
        if(client_id_64 < INT32_MAX || client_id_64 > INT32_MIN) {
            items->client_id = (int32_t)client_id_64;
            items->item_flags |= CLAIM_PRESENT_BIT(CLIENT_ID_FLAG);
        }
        // TODO: error on larger client ID?
    }

    /* ----SECURITY LIFECYCLE ---- */
    if(list[SECURITY_LIFECYCLE_FLAG].uDataType != QCBOR_TYPE_NONE) {
        if(list[SECURITY_LIFECYCLE_FLAG].val.int64 < UINT32_MAX) {
            items->security_lifecycle = (uint32_t)list[SECURITY_LIFECYCLE_FLAG].val.int64;
            items->item_flags |=CLAIM_PRESENT_BIT(SECURITY_LIFECYCLE_FLAG);
        }
    }

    /* ---- PROFILE_DEFINITION ---- */
    if(list[PROFILE_DEFINITION_FLAG].uDataType != QCBOR_TYPE_NONE) {
        items->profile_definition = list[PROFILE_DEFINITION_FLAG].val.string;
        items->item_flags |= CLAIM_PRESENT_BIT(PROFILE_DEFINITION_FLAG);
    }

    /* ---- ORIGINATION ---- */
    if(list[ORIGINATION_FLAG].uDataType != QCBOR_TYPE_NONE) {
        items->origination = list[ORIGINATION_FLAG].val.string;
        items->item_flags |= CLAIM_PRESENT_BIT(ORIGINATION_FLAG);
    }

    return_value = CTOKEN_ERR_SUCCESS;

Done:
    return return_value;
}


/** Value for EAT_CBOR_ARM_LABEL_NO_SW_COMPONENTS when present.
 * It must be this value if present.
 * Indicates that the boot status does not contain any SW components'
 * measurement
 */
#define NO_SW_COMPONENT_FIXED_VALUE 1

/*
 * Public function.  See ctoken_psaia_decode.h
 */
enum ctoken_err_t
ctoken_psaia_decode_num_sw_components(struct ctoken_decode_ctx *me,
                                      uint32_t                 *num_sw_components)
{
    enum ctoken_err_t return_value;
    QCBORItem         item;
    QCBORError        qcbor_error;

    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return_value = me->last_error;
        goto Done;
    }

    // TODO: test all the error conditions and qcbor error returns below

    QCBORDecode_GetItemInMapN(&(me->qcbor_decode_context),
                              EAT_CBOR_ARM_LABEL_SW_COMPONENTS,
                              QCBOR_TYPE_ARRAY,
                              &item);
    qcbor_error = QCBORDecode_GetError(&(me->qcbor_decode_context));

    if(qcbor_error != QCBOR_SUCCESS) {
        if(qcbor_error != QCBOR_ERR_LABEL_NOT_FOUND) {
            /* Something very wrong. Bail out passing on the return_value */
            return_value = CTOKEN_ERR_CBOR_STRUCTURE; // TODO: right error code?
            goto Done;
        } else {
            /* Now decide if it was intentionally left out. */
            QCBORDecode_GetItemInMapN(&(me->qcbor_decode_context),
                                      EAT_CBOR_ARM_LABEL_NO_SW_COMPONENTS,
                                      QCBOR_TYPE_INT64,
                                      &item);
            qcbor_error = QCBORDecode_GetError(&(me->qcbor_decode_context));

            if(qcbor_error == QCBOR_SUCCESS) {
                if(item.val.int64 == NO_SW_COMPONENT_FIXED_VALUE) {
                    /* Successful omission of SW components. Pass on the
                     * success return_value */
                    *num_sw_components = 0;
                    return_value = CTOKEN_ERR_SUCCESS;
                } else {
                    /* Indicator for no SW components malformed */
                    return_value = CTOKEN_ERR_SW_COMPONENTS_MISSING;
                }
            } else if(qcbor_error == QCBOR_ERR_LABEL_NOT_FOUND) {
                /* Should have been an indicator for no SW components */
                return_value = CTOKEN_ERR_SW_COMPONENTS_MISSING;
            } else {
                return_value = CTOKEN_ERR_CBOR_STRUCTURE; // TODO: right error?
            }
        }
    } else {
        /* The SW components claim exists */
        if(item.val.uCount == 0) {
            /* Empty SW component not allowed */
            return_value = CTOKEN_ERR_SW_COMPONENTS_MISSING;
        } else {
            /* SUCESSS! Pass on the success return_value */
            /* Note that this assumes the array is definite length */
            *num_sw_components = item.val.uCount;
            return_value = CTOKEN_ERR_SUCCESS;
        }
    }

Done:
    return return_value;
}


/**
 * \brief Decode a single SW component
 *
 * \param[in] decode_context    The CBOR decoder context to decode from
 * \param[in] sw_component_item The top-level map item for this SW
 *                              component.
 * \param[out] sw_component     The structure to fill in with decoded data.
 *
 * \return An error from \ref CTOKEN_ERR_t.
 *
 */
static inline enum ctoken_err_t
decode_sw_component(QCBORDecodeContext                *decode_context,
                    const QCBORItem                   *sw_component_item,
                    struct ctoken_psaia_sw_component_t *sw_component)
{
    enum ctoken_err_t  return_value;
    QCBORItem          list[SW_NUMBER_OF_ITEMS+1];

    (void)sw_component_item; // TODO: figure out what to do with this.

    QCBORDecode_EnterMap(decode_context, NULL);

    list[SW_MEASUREMENT_TYPE_FLAG].label.int64 = EAT_CBOR_SW_COMPONENT_MEASUREMENT_TYPE;
    list[SW_MEASUREMENT_TYPE_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[SW_MEASUREMENT_TYPE_FLAG].uDataType   = QCBOR_TYPE_TEXT_STRING;

    list[SW_MEASURMENT_VAL_FLAG].label.int64 = EAT_CBOR_SW_COMPONENT_MEASUREMENT_VALUE;
    list[SW_MEASURMENT_VAL_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[SW_MEASURMENT_VAL_FLAG].uDataType   = QCBOR_TYPE_BYTE_STRING;

    list[SW_EPOCH_FLAG].label.int64 = EAT_CBOR_SW_COMPONENT_SECURITY_EPOCH;
    list[SW_EPOCH_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[SW_EPOCH_FLAG].uDataType   = QCBOR_TYPE_INT64;

    list[SW_VERSION_FLAG].label.int64 = EAT_CBOR_SW_COMPONENT_VERSION;
    list[SW_VERSION_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[SW_VERSION_FLAG].uDataType   = QCBOR_TYPE_TEXT_STRING;

    list[SW_SIGNER_ID_FLAG].label.int64 = EAT_CBOR_SW_COMPONENT_SIGNER_ID;
    list[SW_SIGNER_ID_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[SW_SIGNER_ID_FLAG].uDataType   = QCBOR_TYPE_BYTE_STRING;

    list[SW_MEASUREMENT_DESC_FLAG].label.int64 = EAT_CBOR_SW_COMPONENT_MEASUREMENT_DESC;
    list[SW_MEASUREMENT_DESC_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[SW_MEASUREMENT_DESC_FLAG].uDataType   = QCBOR_TYPE_TEXT_STRING;

    list[SW_MEASUREMENT_DESC_FLAG+1].uLabelType  = QCBOR_TYPE_NONE;

    QCBORDecode_GetItemsInMap(decode_context, list);
    if(QCBORDecode_GetError(decode_context) != QCBOR_SUCCESS) {
        return_value = CTOKEN_ERR_CBOR_STRUCTURE; // TODO: right error?
        goto Done;
    }

    memset(sw_component, 0, sizeof(struct ctoken_psaia_sw_component_t));

    if(list[SW_MEASUREMENT_TYPE_FLAG].uDataType != QCBOR_TYPE_NONE) {
        sw_component->measurement_type = list[SW_MEASUREMENT_TYPE_FLAG].val.string;
        sw_component->item_flags |= CLAIM_PRESENT_BIT(SW_MEASUREMENT_TYPE_FLAG);
    }

    if(list[SW_MEASURMENT_VAL_FLAG].uDataType != QCBOR_TYPE_NONE) {
        sw_component->measurement_val = list[SW_MEASURMENT_VAL_FLAG].val.string;
        sw_component->item_flags |= CLAIM_PRESENT_BIT(SW_MEASURMENT_VAL_FLAG);
    }

    if(list[SW_EPOCH_FLAG].uDataType != QCBOR_TYPE_NONE) {
        if(list[SW_EPOCH_FLAG].val.int64 < UINT32_MAX && list[SW_EPOCH_FLAG].val.int64 > 0) {
            sw_component->epoch = (uint32_t)list[SW_EPOCH_FLAG].val.int64;
            sw_component->item_flags |= CLAIM_PRESENT_BIT(SW_EPOCH_FLAG);
        }
        // TODO: error here?
    }

    if(list[SW_VERSION_FLAG].uDataType != QCBOR_TYPE_NONE) {
        sw_component->version = list[SW_VERSION_FLAG].val.string;
        sw_component->item_flags |= CLAIM_PRESENT_BIT(SW_VERSION_FLAG);
    }

    if(list[SW_SIGNER_ID_FLAG].uDataType != QCBOR_TYPE_NONE) {
        sw_component->signer_id = list[SW_VERSION_FLAG].val.string;
        sw_component->item_flags |= CLAIM_PRESENT_BIT(SW_SIGNER_ID_FLAG);
    }

    if(list[SW_MEASUREMENT_DESC_FLAG].uDataType != QCBOR_TYPE_NONE) {
        sw_component->measurement_desc = list[SW_MEASUREMENT_DESC_FLAG].val.string;
        sw_component->item_flags |= CLAIM_PRESENT_BIT(SW_MEASUREMENT_DESC_FLAG);
    }

    return_value = CTOKEN_ERR_SUCCESS;

Done:
    return return_value;
}


/*
 * Public function.  See ctoken_psaia_decode.h
 */
enum ctoken_err_t
ctoken_psaia_decode_sw_component(struct ctoken_decode_ctx           *me,
                                 uint32_t                            requested_index,
                                 struct ctoken_psaia_sw_component_t *sw_components)
{
    enum ctoken_err_t    return_value;
    QCBORDecodeContext   decode_context;
    QCBORItem            sw_component_item;

    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return_value = me->last_error;
        goto Done;
    }

    QCBORDecode_EnterArrayFromMapN(&(me->qcbor_decode_context),
                                   EAT_CBOR_ARM_LABEL_SW_COMPONENTS);

    /* Skip to the SW component index requested */
    for(int i = 0; i < requested_index; i++) {
        QCBORDecode_EnterMap(&(me->qcbor_decode_context), NULL);
        QCBORDecode_ExitMap(&(me->qcbor_decode_context));
    }

    /* Let error check for the above happen in decode_sw_component */

    return_value = decode_sw_component(&decode_context,
                                       &sw_component_item,
                                       sw_components);

Done:
    return return_value;
}
