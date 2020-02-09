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



static inline enum ctoken_err_t
ctoken_decode_eat_nonce(struct ctoken_decode_context *me,
                        struct q_useful_buf_c        *nonce)
{
    return ctoken_decode_get_bstr(me, CTOKEN_EAT_LABEL_NONCE, nonce);
}

static inline enum ctoken_err_t
ctoken_decode_eat_ueid(struct ctoken_decode_context *me,
                       struct q_useful_buf_c        *ueid)
{
    return ctoken_decode_get_bstr(me, CTOKEN_EAT_UEID_LABEL, ueid);
}

static inline enum ctoken_err_t
ctoken_decode_eat_oemid(struct ctoken_decode_context *me,
                        struct q_useful_buf_c        *oemid)
{
    return ctoken_decode_get_bstr(me, CTOKEN_EAT_LABEL_OEMID, oemid);
}

static inline enum ctoken_err_t
ctoken_decode_eat_origination(struct ctoken_decode_context *me,
                              struct q_useful_buf_c        *origination)
{
    return ctoken_decode_get_tstr(me, CTOKEN_EAT_LABEL_ORIGINATION, origination);
}

static inline enum ctoken_err_t
ctoken_decode_eat_security_level(struct ctoken_decode_context     *me,
                                 enum ctoken_eat_security_level_t *security_level)
{
    return ctoken_decode_get_int(me, CTOKEN_EAT_LABEL_SECURITY_LEVEL, (int64_t *)security_level);
}




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
