/*
 * psa_ia_encode.h
 *
 * Copyright (c) 2020 Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 1/31/20.
 */


#ifndef psa_ia_encode_h
#define psa_ia_encode_h

#include "ctoken_eat_encode.h"

static inline void attest_token_encode_psa_ia_nonce(struct ctoken_encode_ctx *me,
                                             struct q_useful_buf_c nonce)
{
    ctoken_encode_eat_nonce(me, nonce);
}


static inline void attest_token_encode_psa_id_ueid(struct ctoken_encode_ctx *me,
                                         struct q_useful_buf_c ueid)
{
    ctoken_encode_eat_ueid(me, ueid);
}

#endif /* psa_ia_encode_h */
