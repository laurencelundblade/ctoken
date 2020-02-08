/*
 * eat_decode.h
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

#include "cwt_decode.h"
#include "eat_labels.h"



static inline enum attest_token_err_t
attest_token_decode_eat_nonce(struct attest_token_decode_context *me,
                              struct q_useful_buf_c *nonce)
{
    return attest_token_decode_get_bstr(me,
                                        EAT_LABEL_NONCE,
                                        nonce);
}

static inline enum attest_token_err_t
attest_token_decode_eat_ueid(struct attest_token_decode_context *me,
                              struct q_useful_buf_c *ueid)
{
    return attest_token_decode_get_bstr(me,
                                        UEID_LABEL,
                                        ueid);
}

static inline enum attest_token_err_t
attest_token_decode_eat_oemid(struct attest_token_decode_context *me,
                             struct q_useful_buf_c *oemid)
{
    return attest_token_decode_get_bstr(me,
                                        EAT_LABEL_OEMID,
                                        oemid);
}

static inline enum attest_token_err_t
attest_token_decode_eat_origination(struct attest_token_decode_context *me,
                            struct q_useful_buf_c *origination)
{
    return attest_token_decode_get_tstr(me,
                                        EAT_LABEL_ORIGINATION,
                                        origination);
}

static inline enum attest_token_err_t
attest_token_decode_eat_security_level(struct attest_token_decode_context *me,
                                    enum eat_security_level_t *security_level)
{
    return attest_token_decode_get_int(me,
                                        EAT_LABEL_SECURITY_LEVEL,
                                        (int64_t *)security_level);
}


#ifdef SUBMODS_ARE_IMPLEMENTED

// Prototypes for the planned submods impementation
enum attest_token_err_t
attest_token_decode_eat_get_num_submods(struct attest_token_decode_context *me,
                                        uint8_t *num_submods);

enum attest_token_err_t
attest_token_decode_eat_enter_submod(struct attest_token_decode_context *me,
                                     uint8_t submod_index,
                                     struct q_useful_buf_c *name,
                                     int *connection_type);

enum attest_token_err_t
attest_token_decode_eat_leave_submod(struct attest_token_decode_context *me);

#endif


#endif /* eat_decode_h */
