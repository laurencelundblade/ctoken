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

static inline enum ctoken_err_t
get_no_sw_component_indicator(struct ctoken_decode_ctx *me, bool *no_sw_components)
{
    QCBORItem         item;
    enum ctoken_err_t return_value;

    QCBORDecode_GetItemInMapN(&(me->qcbor_decode_context),
                              CTOKEN_PSA_LABEL_NO_SW_COMPONENTS,
                              QCBOR_TYPE_INT64,
                             &item);

    return_value = ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));

    if(return_value == CTOKEN_ERR_SUCCESS) {
        if(item.val.int64 == NO_SW_COMPONENT_FIXED_VALUE) {
            /* Successful omission of SW components. Pass on the
             * success return_value */
            *no_sw_components = true;
            return_value = CTOKEN_ERR_SUCCESS;
        } else {
            /* The no sw components indicator had the wrong value */
            return_value = CTOKEN_ERR_CBOR_STRUCTURE;
        }
    } else if(return_value == CTOKEN_ERR_CLAIM_NOT_PRESENT) {
        /* Should have been an indicator for no SW components */
        *no_sw_components = false;
        return_value = CTOKEN_ERR_SUCCESS;
    }

    return return_value;
}


/*
 * Count the number of items in an entered array or map.
 * This should be made part of QCBOR. This violates
 * layering by setting the QCBOR decoder last error. When
 * it is part of QCBOR, this won't be a layering violation.
 * It is helpful here so ctoken can use get_and_reset_error()
 * with this.
 */
static inline void
CountItems(QCBORDecodeContext *cbor_decoder, uint32_t *num_items)
{
    QCBORItem   item;
    uint32_t    counter;
    QCBORError  cbor_error;

    counter = 0;
    while(1) {
        QCBORDecode_VGetNextConsume(cbor_decoder, &item);
        cbor_error = QCBORDecode_GetAndResetError(cbor_decoder);
        if(cbor_error == QCBOR_ERR_NO_MORE_ITEMS) {
            cbor_decoder->uLastError = QCBOR_SUCCESS;
            break;
        }
        if(cbor_error != QCBOR_SUCCESS) {
            break;
        }
        counter++;
    }

    *num_items = counter;
}


/*
 * Public function.  See ctoken_decode_psa.h
 */
enum ctoken_err_t
ctoken_decode_psa_num_sw_components(struct ctoken_decode_ctx *me,
                                    uint32_t                 *num_sw_components)
{
    enum ctoken_err_t return_value;
    bool              no_sw_components;

    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return_value = me->last_error;
        goto Done;
    }

    /* Get the no components indicator because it always must be checked */
    return_value = get_no_sw_component_indicator(me, &no_sw_components);
    if(return_value != QCBOR_SUCCESS) {
        goto Done;
    }

    QCBORDecode_EnterArrayFromMapN(&(me->qcbor_decode_context), CTOKEN_PSA_LABEL_SW_COMPONENTS);
    return_value = ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));

    if(return_value == CTOKEN_ERR_CLAIM_NOT_PRESENT) {
        /* There is no SW components claim. */
        if(no_sw_components == false) {
            /* No indicator of no SW components and there are no sw componets
             * so this is an error */
            return_value = CTOKEN_ERR_SW_COMPONENTS_PRESENCE;
            goto Done;
        }
        return_value = CTOKEN_ERR_SUCCESS;
        *num_sw_components = 0;
        goto Done;
    }

    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    if(no_sw_components) {
        return_value = CTOKEN_ERR_SW_COMPONENTS_PRESENCE;
        goto Done2;
    }

    CountItems(&(me->qcbor_decode_context), num_sw_components);
    return_value = ctoken_get_and_reset_cbor_error(&(me->qcbor_decode_context));

    if(*num_sw_components == 0) {
         /* Empty SW component not allowed */
         return_value = CTOKEN_ERR_SW_COMPONENTS_PRESENCE;
        goto Done;
    }
    
Done2:
    QCBORDecode_ExitArray(&(me->qcbor_decode_context));

Done:
    return return_value;
}


/**
 * \brief Decode a single SW component
 *
 * \param[in] decode_context    The CBOR decoder context to decode from
 * \param[out] sw_component     The structure to fill in with decoded data.
 *
 * \return An error from \ref CTOKEN_ERR_t.
 *
 */
static inline enum ctoken_err_t
decode_psa_sw_component(QCBORDecodeContext               *decode_context,
                        struct ctoken_psa_sw_component_t *sw_component)
{
    enum ctoken_err_t  return_value;
    QCBORItem          list[CTOKEN_PSA_SW_NUMBER_OF_ITEMS+1];

    QCBORDecode_EnterMap(decode_context, NULL);
    return_value = ctoken_get_and_reset_cbor_error(decode_context);
    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done2;
    }

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
    return_value = ctoken_get_and_reset_cbor_error(decode_context);
    if(return_value != CTOKEN_ERR_SUCCESS) {
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

    const uint32_t required_item_flags =
          CLAIM_PRESENT_BIT(CTOKEN_PSA_SW_SIGNER_ID_FLAG) |
          CLAIM_PRESENT_BIT(CTOKEN_PSA_SW_MEASURMENT_VAL_FLAG);

    if((sw_component->item_flags & required_item_flags) != required_item_flags) {
        return_value = CTOKEN_ERROR_MISSING_REQUIRED_CLAIM;
        goto Done;
    }

    return_value = CTOKEN_ERR_SUCCESS;

Done:
    QCBORDecode_ExitMap(decode_context);
Done2:
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
    QCBORDecodeContext  *decode_context;
    QCBORItem            sw_component_item;
    bool                 no_sw_components;

    if(me->last_error != CTOKEN_ERR_SUCCESS) {
        return_value = me->last_error;
        goto Done;
    }

    /* Get the no components indicator because it always must be checked */
    return_value = get_no_sw_component_indicator(me, &no_sw_components);
    if(return_value != QCBOR_SUCCESS) {
        goto Done;
    }

    ctoken_decode_enter_array(me,
                                             CTOKEN_PSA_LABEL_SW_COMPONENTS,
                                             &decode_context);
    return_value = ctoken_decode_get_and_reset_error(me);
    if(return_value == CTOKEN_ERR_CLAIM_NOT_PRESENT) {
        if(no_sw_components == false) {
            return_value = CTOKEN_ERR_SW_COMPONENTS_PRESENCE;
            goto Done;
        }
        return_value = CTOKEN_ERR_NO_MORE_CLAIMS;
        goto Done;
    }

    if(return_value != CTOKEN_ERR_SUCCESS) {
        goto Done;
    }

    if(no_sw_components == true) {
        return_value = CTOKEN_ERR_SW_COMPONENTS_PRESENCE;
        goto Done2;
    }

    /* Skip to the SW component index requested */
    while(requested_index >0) {
        QCBORDecode_VGetNextConsume(decode_context, &sw_component_item);
        requested_index--;
    }
    /* Let error check for the above happen in decode_sw_component */

    return_value = decode_psa_sw_component(decode_context, sw_components);

Done2:
    ctoken_decode_exit_array(me);

Done:
    return return_value;
}
