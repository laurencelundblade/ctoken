/*
 * ctoken_eat_decode.h
 *
 * Copyright (c) 2020 Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 2/1/20.
 */


#ifndef eat_decode_h
#define eat_decode_h

#include "ctoken_cwt_decode.h"
#include "ctoken_eat_labels.h"
#include "ctoken_decode.h"



static inline enum ctoken_err_t
ctoken_eat_decode_nonce(struct ctoken_decode_cxt *me,
                        struct q_useful_buf_c        *nonce)
{
    return ctoken_decode_get_bstr(me, CTOKEN_EAT_LABEL_NONCE, nonce);
}

static inline enum ctoken_err_t
ctoken_eat_decode_ueid(struct ctoken_decode_cxt *me,
                       struct q_useful_buf_c        *ueid)
{
    return ctoken_decode_get_bstr(me, CTOKEN_EAT_LABEL_UEID, ueid);
}

static inline enum ctoken_err_t
ctoken_eat_decode_oemid(struct ctoken_decode_cxt *me,
                        struct q_useful_buf_c        *oemid)
{
    return ctoken_decode_get_bstr(me, CTOKEN_EAT_LABEL_OEMID, oemid);
}

static inline enum ctoken_err_t
ctoken_eat_decode_origination(struct ctoken_decode_cxt *me,
                              struct q_useful_buf_c        *origination)
{
    return ctoken_decode_get_tstr(me, CTOKEN_EAT_LABEL_ORIGINATION, origination);
}

static inline enum ctoken_err_t
ctoken_eat_decode_security_level(struct ctoken_decode_cxt     *me,
                                 enum ctoken_eat_security_level_t *security_level)
{
    return ctoken_decode_get_int(me, CTOKEN_EAT_LABEL_SECURITY_LEVEL, (int64_t *)security_level);
}

enum ctoken_err_t
ctoken_eat_decode_boot_state(struct ctoken_decode_cxt *me,
                             bool *secure_boot_enabled,
                             enum ctoken_eat_debug_level_t *debug_state);



/**
 * \brief Decode position location (e.g. GPS location)
 *
 * \param[in] context   The decoding context to decode from.
 * \param[out] location The returned location
 *
 * \retval CTOKEN_ERR_NOT_FOUND             No location claims exists.
 * \retval CTOKEN_ERR_CBOR_NOT_WELL_FORMED  CBOR is not well formed.
 * \retval CTOKEN_ERR_CBOR_STRUCTURE        The location claim format is bad.
 *
 * This finds the location claim in the token and returns its
 * contents.
 *
 * Only some of the values in the location claim may be present. See
 * TODO:...
 */
enum ctoken_err_t
ctoken_eat_decode_location(struct ctoken_decode_cxt *context,
                           struct ctoken_eat_location_t *location);


#ifdef SUBMODS_ARE_IMPLEMENTED

// Prototypes for the planned submods impementation
enum ctoken_err_t
ctoken_decode_eat_get_num_submods(struct ctoken_decode_context *me,
                                  uint8_t *num_submods);

enum ctoken_err_t
ctoken_decode_eat_enter_submod(struct ctoken_decode_context *me,
                                     uint8_t submod_index,
                                     struct q_useful_buf_c *name,
                                     int *connection_type);

enum ctoken_err_t
ctoken_decode_eat_leave_submod(struct ctoken_decode_context *me);

#endif


#endif /* eat_decode_h */
