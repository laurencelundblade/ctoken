//
//  psa_ia_encode.h
//  CToken
//
//  Created by Laurence Lundblade on 1/31/20.
//  Copyright © 2020 Laurence Lundblade. All rights reserved.
//

#ifndef psa_ia_encode_h
#define psa_ia_encode_h

#include "eat_encode.h"

static void attest_token_encode_psa_ia_nonce(struct attest_token_encode_ctx *me,
                                             struct q_useful_buf_c nonce)
{
    attest_token_encode_eat_nonce(me, nonce);
}


static void attest_token_encode_psa_id_ueid(struct attest_token_encode_ctx *me,
                                         struct q_useful_buf_c ueid)
{
    attest_token_encode_eat_ueid(me, ueid);
}

#endif /* psa_ia_encode_h */
