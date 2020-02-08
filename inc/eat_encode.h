/*
 * eat_encode.h
 *
 * Copyright (c) 2020 Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 1/31/20.
 */


#ifndef eat_encode_h
#define eat_encode_h

#include "cwt_encode.h"
#include "eat_labels.h"



static inline void attest_token_encode_eat_nonce(struct attest_token_encode_ctx *me,
                                          struct q_useful_buf_c nonce)
{
    attest_token_encode_add_bstr(me, EAT_LABEL_NONCE, nonce);
}



static inline void attest_token_encode_eat_ueid(struct attest_token_encode_ctx *me,
                                         struct q_useful_buf_c ueid)
{
    attest_token_encode_add_bstr(me, UEID_LABEL, ueid);
}


static inline void attest_token_encode_eat_oemid(struct attest_token_encode_ctx *me,
                                         struct q_useful_buf_c oemid)
{
    attest_token_encode_add_bstr(me, EAT_LABEL_OEMID, oemid);
}


static inline void attest_token_encode_eat_origination(struct attest_token_encode_ctx *me,
                                        struct q_useful_buf_c origination)
{
    attest_token_encode_add_bstr(me, EAT_LABEL_ORIGINATION, origination);
}


static inline void attest_token_encode_eat_security_level(struct attest_token_encode_ctx *me,
                                                   enum eat_security_level_t security_level)
{
    attest_token_encode_add_integer(me, EAT_LABEL_SECURITY_LEVEL, (int64_t)security_level);
}

static inline void attest_token_encode_eat_boot_state(struct attest_token_encode_ctx *me,
                                               bool secure_boot_enabled,
                                               enum eat_debug_level_t debug_state)
{
    // TODO: how should this be implemeted? Split into two claims?
    //attest_token_encode_open_array(<#struct attest_token_encode_ctx *me#>, EAT_LABEL_BOOT_STATE);
    //attest_token_encode_add_integer(me, , (int64_t)debug_state);
}




#ifdef SUBMODS_ARE_IMPLEMENTED

// Prototypes for the planned submods impementation
static void attest_token_encode_open_submod(struct attest_token_encode_ctx *me,
                                            char *submod_name,
                                            int nConnectionType);

static void attest_token_encode_close_submod(struct attest_token_encode_ctx *me);


static void attest_token_encode_add_token(struct attest_token_encode_ctx *me,
                                          char *submod_name,
                                          int nConnectionType,
                                          struct q_useful_buf_c token);
#endif

#endif /* eat_encode_h */
