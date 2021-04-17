/*
 * ctoken_decode_psa.c (formerly part of attest_token_decode.c)
 *
 * Copyright (c) 2019-2021, Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "ctoken/ctoken_decode_psa.h"
#include "qcbor/qcbor_spiffy_decode.h"


/*
 * Public function. See ctoken_decode_psa.h
 */
enum ctoken_err_t
ctoken_decode_psa_simple_claims(struct ctoken_decode_ctx          *me,
                                struct ctoken_psa_simple_claims_t *items)
{
    int64_t            client_id_64;
    enum ctoken_err_t  return_value;
    QCBORItem          list[CTOKEN_PSA_NUMBER_OF_ITEMS+1]; // This uses a lot of stack
    QCBORError         qcbor_error;

    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return_value = me->last_error;
        goto Done;
    }

    /* Set all q_useful_bufs to NULL and flags to 0 */
    memset(items, 0, sizeof(struct ctoken_psa_simple_claims_t));

    /* Make the list of labels and types to get. Re use flags as array indexes
     * because it works nicely.
     */
    list[CTOKEN_PSA_NONCE_FLAG].label.int64 = CTOKEN_EAT_LABEL_NONCE;
    list[CTOKEN_PSA_NONCE_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[CTOKEN_PSA_NONCE_FLAG].uDataType   = QCBOR_TYPE_BYTE_STRING;

    list[CTOKEN_PSA_UEID_FLAG].label.int64 = CTOKEN_EAT_LABEL_UEID;
    list[CTOKEN_PSA_UEID_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[CTOKEN_PSA_UEID_FLAG].uDataType   = QCBOR_TYPE_BYTE_STRING;

    list[CTOKEN_PSA_BOOT_SEED_FLAG].label.int64 = CTOKEN_PSA_LABEL_BOOT_SEED;
    list[CTOKEN_PSA_BOOT_SEED_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[CTOKEN_PSA_BOOT_SEED_FLAG].uDataType   = QCBOR_TYPE_BYTE_STRING;

    list[CTOKEN_PSA_HW_VERSION_FLAG].label.int64 = CTOKEN_PSA_LABEL_HW_VERSION;
    list[CTOKEN_PSA_HW_VERSION_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[CTOKEN_PSA_HW_VERSION_FLAG].uDataType   = QCBOR_TYPE_TEXT_STRING;

    list[CTOKEN_PSA_IMPLEMENTATION_ID_FLAG].label.int64 = CTOKEN_PSA_LABEL_IMPLEMENTATION_ID;
    list[CTOKEN_PSA_IMPLEMENTATION_ID_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[CTOKEN_PSA_IMPLEMENTATION_ID_FLAG].uDataType   = QCBOR_TYPE_BYTE_STRING;

    list[CTOKEN_PSA_CLIENT_ID_FLAG].label.int64 = CTOKEN_PSA_LABEL_CLIENT_ID;
    list[CTOKEN_PSA_CLIENT_ID_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[CTOKEN_PSA_CLIENT_ID_FLAG].uDataType   = QCBOR_TYPE_INT64;

    list[CTOKEN_PSA_SECURITY_LIFECYCLE_FLAG].label.int64 = CTOKEN_PSA_LABEL_SECURITY_LIFECYCLE;
    list[CTOKEN_PSA_SECURITY_LIFECYCLE_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[CTOKEN_PSA_SECURITY_LIFECYCLE_FLAG].uDataType   = QCBOR_TYPE_INT64;

    list[CTOKEN_PSA_PROFILE_DEFINITION_FLAG].label.int64 = CTOKEN_PSA_LABEL_PROFILE_DEFINITION;
    list[CTOKEN_PSA_PROFILE_DEFINITION_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[CTOKEN_PSA_PROFILE_DEFINITION_FLAG].uDataType   = QCBOR_TYPE_TEXT_STRING;

    list[CTOKEN_PSA_ORIGINATION_FLAG].label.int64 = CTOKEN_PSA_LABEL_ORIGINATION;
    list[CTOKEN_PSA_ORIGINATION_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[CTOKEN_PSA_ORIGINATION_FLAG].uDataType   = QCBOR_TYPE_TEXT_STRING;

#ifndef CTOKEN_DISABLE_TEMP_LABELS
    list[CTOKEN_PSA_TEMP_NONCE_FLAG].label.int64 = CTOKEN_PSA_LABEL_CHALLENGE;
    list[CTOKEN_PSA_NONCE_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[CTOKEN_PSA_NONCE_FLAG].uDataType   = QCBOR_TYPE_BYTE_STRING;

    list[CTOKEN_PSA_TEMP_UEID_FLAG].label.int64 = CTOKEN_PSA_LABEL_UEID;
    list[CTOKEN_PSA_UEID_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[CTOKEN_PSA_UEID_FLAG].uDataType   = QCBOR_TYPE_BYTE_STRING;
#endif

    list[CTOKEN_PSA_NUMBER_OF_ITEMS].uLabelType  = QCBOR_TYPE_NONE;


    /* Get all the items in one CPU-efficient pass. */
    QCBORDecode_GetItemsInMap(&(me->qcbor_decode_context), list);
    qcbor_error = QCBORDecode_GetError(&(me->qcbor_decode_context));
    if(qcbor_error != QCBOR_SUCCESS) {
        return_value = CTOKEN_ERR_GENERAL; // TODO: error mapping
        goto Done;
    }

    /* ---- NONCE ---- */
    if(list[CTOKEN_PSA_NONCE_FLAG].uDataType != QCBOR_TYPE_NONE) {
        items->nonce = list[CTOKEN_PSA_NONCE_FLAG].val.string;
        items->item_flags |= CLAIM_PRESENT_BIT(CTOKEN_PSA_NONCE_FLAG);
#ifndef CTOKEN_DISABLE_TEMP_LABELS
    } else if(list[CTOKEN_PSA_TEMP_NONCE_FLAG].uDataType != QCBOR_TYPE_NONE) {
        items->nonce = list[CTOKEN_PSA_NONCE_FLAG].val.string;
        items->item_flags |= CLAIM_PRESENT_BIT(CTOKEN_PSA_NONCE_FLAG);
#endif
    }

    /* ---- UEID ---- */
    if(list[CTOKEN_PSA_UEID_FLAG].uDataType != QCBOR_TYPE_NONE) {
        items->ueid = list[CTOKEN_PSA_UEID_FLAG].val.string;
        items->item_flags |= CLAIM_PRESENT_BIT(CTOKEN_PSA_UEID_FLAG);
#ifndef CTOKEN_DISABLE_TEMP_LABELS
    } else if(list[CTOKEN_PSA_TEMP_UEID_FLAG].uDataType != QCBOR_TYPE_NONE) {
        items->ueid = list[CTOKEN_PSA_UEID_FLAG].val.string;
        items->item_flags |= CLAIM_PRESENT_BIT(CTOKEN_PSA_UEID_FLAG);
#endif
    }

    /* ---- BOOT SEED ---- */
    if(list[CTOKEN_PSA_BOOT_SEED_FLAG].uDataType != QCBOR_TYPE_NONE) {
        items->boot_seed = list[CTOKEN_PSA_BOOT_SEED_FLAG].val.string;
        items->item_flags |= CLAIM_PRESENT_BIT(CTOKEN_PSA_BOOT_SEED_FLAG);
    }

    /* ---- HW VERSION ---- */ // TODO: temp label ???
    if(list[CTOKEN_PSA_HW_VERSION_FLAG].uDataType != QCBOR_TYPE_NONE) {
        items->hw_version = list[CTOKEN_PSA_HW_VERSION_FLAG].val.string;
        items->item_flags |= CLAIM_PRESENT_BIT(CTOKEN_PSA_HW_VERSION_FLAG);
    }

    /* ----IMPLEMENTATION ID ---- */
    if(list[CTOKEN_PSA_IMPLEMENTATION_ID_FLAG].uDataType != QCBOR_TYPE_NONE) {
        items->implementation_id = list[CTOKEN_PSA_IMPLEMENTATION_ID_FLAG].val.string;
        items->item_flags |= CLAIM_PRESENT_BIT(CTOKEN_PSA_IMPLEMENTATION_ID_FLAG);
    }

    /* ----CLIENT ID ---- */
    if(list[CTOKEN_PSA_CLIENT_ID_FLAG].uDataType != QCBOR_TYPE_NONE) {
        client_id_64 = list[CTOKEN_PSA_CLIENT_ID_FLAG].val.int64;
        if(client_id_64 < INT32_MAX || client_id_64 > INT32_MIN) {
            items->client_id = (int32_t)client_id_64;
            items->item_flags |= CLAIM_PRESENT_BIT(CTOKEN_PSA_CLIENT_ID_FLAG);
        }
        // TODO: error on larger client ID?
    }

    /* ----SECURITY LIFECYCLE ---- */
    if(list[CTOKEN_PSA_SECURITY_LIFECYCLE_FLAG].uDataType != QCBOR_TYPE_NONE) {
        if(list[CTOKEN_PSA_SECURITY_LIFECYCLE_FLAG].val.int64 < UINT32_MAX) {
            items->security_lifecycle = (uint32_t)list[CTOKEN_PSA_SECURITY_LIFECYCLE_FLAG].val.int64;
            items->item_flags |= CLAIM_PRESENT_BIT(CTOKEN_PSA_SECURITY_LIFECYCLE_FLAG);
        }
    }

    /* ---- PROFILE_DEFINITION ---- */ // TODO: temp label, but type of claim is different
    if(list[CTOKEN_PSA_PROFILE_DEFINITION_FLAG].uDataType != QCBOR_TYPE_NONE) {
        items->profile_definition = list[CTOKEN_PSA_PROFILE_DEFINITION_FLAG].val.string;
        items->item_flags |= CLAIM_PRESENT_BIT(CTOKEN_PSA_PROFILE_DEFINITION_FLAG);
    }

    /* ---- ORIGINATION ---- */
    if(list[CTOKEN_PSA_ORIGINATION_FLAG].uDataType != QCBOR_TYPE_NONE) {
        items->origination = list[CTOKEN_PSA_ORIGINATION_FLAG].val.string;
        items->item_flags |= CLAIM_PRESENT_BIT(CTOKEN_PSA_ORIGINATION_FLAG);
    }

    return_value = CTOKEN_ERR_SUCCESS;

Done:
    return return_value;
}


/** Value for CTOKEN_PSA_LABEL_NO_SW_COMPONENTS when present.
 * It must be this value if present.
 * Indicates that the boot status does not contain any SW components'
 * measurement
 */
#define NO_SW_COMPONENT_FIXED_VALUE 1

/*
 * Public function.  See ctoken_decode_psa.h
 */
enum ctoken_err_t
ctoken_decode_psa_num_sw_components(struct ctoken_decode_ctx *me,
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
                              CTOKEN_PSA_LABEL_SW_COMPONENTS,
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
                                      CTOKEN_PSA_LABEL_NO_SW_COMPONENTS,
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
            /* SUCCESSS! Pass on the success return_value */
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
decode_psa_sw_component(QCBORDecodeContext                *decode_context,
                        const QCBORItem                   *sw_component_item,
                        struct ctoken_psa_sw_component_t *sw_component)
{
    enum ctoken_err_t  return_value;
    QCBORItem          list[CTOKEN_PSA_SW_NUMBER_OF_ITEMS+1];

    (void)sw_component_item; // TODO: figure out what to do with this.

    QCBORDecode_EnterMap(decode_context, NULL);

    list[CTOKEN_PSA_SW_MEASUREMENT_TYPE_FLAG].label.int64 = CTOKEN_PSA_SW_COMPONENT_MEASUREMENT_TYPE;
    list[CTOKEN_PSA_SW_MEASUREMENT_TYPE_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[CTOKEN_PSA_SW_MEASUREMENT_TYPE_FLAG].uDataType   = QCBOR_TYPE_TEXT_STRING;

    list[CTOKEN_PSA_SW_MEASURMENT_VAL_FLAG].label.int64 = CTOKEN_PSA_SW_COMPONENT_MEASUREMENT_VALUE;
    list[CTOKEN_PSA_SW_MEASURMENT_VAL_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[CTOKEN_PSA_SW_MEASURMENT_VAL_FLAG].uDataType   = QCBOR_TYPE_BYTE_STRING;

    list[CTOKEN_PSA_SW_EPOCH_FLAG].label.int64 = CTOKEN_PSA_SW_COMPONENT_SECURITY_EPOCH;
    list[CTOKEN_PSA_SW_EPOCH_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[CTOKEN_PSA_SW_EPOCH_FLAG].uDataType   = QCBOR_TYPE_INT64;

    list[CTOKEN_PSA_SW_VERSION_FLAG].label.int64 = CTOKEN_PSA_SW_COMPONENT_VERSION;
    list[CTOKEN_PSA_SW_VERSION_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[CTOKEN_PSA_SW_VERSION_FLAG].uDataType   = QCBOR_TYPE_TEXT_STRING;

    list[CTOKEN_PSA_SW_SIGNER_ID_FLAG].label.int64 = CTOKEN_PSA_SW_COMPONENT_SIGNER_ID;
    list[CTOKEN_PSA_SW_SIGNER_ID_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[CTOKEN_PSA_SW_SIGNER_ID_FLAG].uDataType   = QCBOR_TYPE_BYTE_STRING;

    list[CTOKEN_PSA_SW_MEASUREMENT_DESC_FLAG].label.int64 = CTOKEN_PSA_SW_COMPONENT_MEASUREMENT_DESC;
    list[CTOKEN_PSA_SW_MEASUREMENT_DESC_FLAG].uLabelType  = QCBOR_TYPE_INT64;
    list[CTOKEN_PSA_SW_MEASUREMENT_DESC_FLAG].uDataType   = QCBOR_TYPE_TEXT_STRING;

    list[CTOKEN_PSA_SW_MEASUREMENT_DESC_FLAG+1].uLabelType  = QCBOR_TYPE_NONE;

    QCBORDecode_GetItemsInMap(decode_context, list);
    if(QCBORDecode_GetError(decode_context) != QCBOR_SUCCESS) {
        return_value = CTOKEN_ERR_CBOR_STRUCTURE; // TODO: right error?
        goto Done;
    }

    memset(sw_component, 0, sizeof(struct ctoken_psa_sw_component_t));

    if(list[CTOKEN_PSA_SW_MEASUREMENT_TYPE_FLAG].uDataType != QCBOR_TYPE_NONE) {
        sw_component->measurement_type = list[CTOKEN_PSA_SW_MEASUREMENT_TYPE_FLAG].val.string;
        sw_component->item_flags |= CLAIM_PRESENT_BIT(CTOKEN_PSA_SW_MEASUREMENT_TYPE_FLAG);
    }

    if(list[CTOKEN_PSA_SW_MEASURMENT_VAL_FLAG].uDataType != QCBOR_TYPE_NONE) {
        sw_component->measurement_val = list[CTOKEN_PSA_SW_MEASURMENT_VAL_FLAG].val.string;
        sw_component->item_flags |= CLAIM_PRESENT_BIT(CTOKEN_PSA_SW_MEASURMENT_VAL_FLAG);
    }

    if(list[CTOKEN_PSA_SW_EPOCH_FLAG].uDataType != QCBOR_TYPE_NONE) {
        if(list[CTOKEN_PSA_SW_EPOCH_FLAG].val.int64 < UINT32_MAX && list[CTOKEN_PSA_SW_EPOCH_FLAG].val.int64 > 0) {
            sw_component->epoch = (uint32_t)list[CTOKEN_PSA_SW_EPOCH_FLAG].val.int64;
            sw_component->item_flags |= CLAIM_PRESENT_BIT(CTOKEN_PSA_SW_EPOCH_FLAG);
        }
        // TODO: error here?
    }

    if(list[CTOKEN_PSA_SW_VERSION_FLAG].uDataType != QCBOR_TYPE_NONE) {
        sw_component->version = list[CTOKEN_PSA_SW_VERSION_FLAG].val.string;
        sw_component->item_flags |= CLAIM_PRESENT_BIT(CTOKEN_PSA_SW_VERSION_FLAG);
    }

    if(list[CTOKEN_PSA_SW_SIGNER_ID_FLAG].uDataType != QCBOR_TYPE_NONE) {
        sw_component->signer_id = list[CTOKEN_PSA_SW_VERSION_FLAG].val.string;
        sw_component->item_flags |= CLAIM_PRESENT_BIT(CTOKEN_PSA_SW_SIGNER_ID_FLAG);
    }

    if(list[CTOKEN_PSA_SW_MEASUREMENT_DESC_FLAG].uDataType != QCBOR_TYPE_NONE) {
        sw_component->measurement_desc = list[CTOKEN_PSA_SW_MEASUREMENT_DESC_FLAG].val.string;
        sw_component->item_flags |= CLAIM_PRESENT_BIT(CTOKEN_PSA_SW_MEASUREMENT_DESC_FLAG);
    }

    return_value = CTOKEN_ERR_SUCCESS;

Done:

    QCBORDecode_ExitMap(decode_context);
    return return_value;
}


/*
 * Public function.  See ctoken_decode_psa.h
 */
enum ctoken_err_t
ctoken_decode_psa_sw_component(struct ctoken_decode_ctx         *me,
                               uint32_t                          requested_index,
                               struct ctoken_psa_sw_component_t *sw_components)
{
    enum ctoken_err_t    return_value;
    QCBORDecodeContext   *decode_context;
    QCBORItem            sw_component_item;

    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return_value = me->last_error;
        goto Done;
    }

    return_value = ctoken_decode_enter_array(me,
                                             CTOKEN_PSA_LABEL_SW_COMPONENTS,
                                             &decode_context);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    /* Skip to the SW component index requested */
    for(uint32_t i = 0; i < requested_index; i++) {
        QCBORDecode_VGetNextConsume(decode_context, &sw_component_item);
    }

    if(QCBORDecode_GetError(decode_context)){
        return_value = 99;
        goto Done2;
    }

    /* Let error check for the above happen in decode_sw_component */

    return_value = decode_psa_sw_component(decode_context,
                                           &sw_component_item,
                                            sw_components);

Done2:
    ctoken_decode_exit_array(me);

Done:
    return return_value;
}
