/*
 * cwt_encode.h
 *
 * Copyright (c) 2020 Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 1/31/20.
 */

#ifndef cwt_encode_h
#define cwt_encode_h

#include "attest_token_encode.h"
#include "cwt_labels.h"




static inline void attest_token_encode_cwt_issuer(struct attest_token_encode_ctx *me,
                                           struct q_useful_buf_c issuer)
{
    attest_token_encode_add_tstr(me, CWT_LABEL_ISSUER, issuer);
}

static inline void attest_token_encode_cwt_subject(struct attest_token_encode_ctx *me,
                                           struct q_useful_buf_c subject)
{
    attest_token_encode_add_tstr(me, CWT_LABEL_SUBJECT, subject);
}

static inline void attest_token_encode_cwt_audience(struct attest_token_encode_ctx *me,
                                            struct q_useful_buf_c audience)
{
    attest_token_encode_add_tstr(me, CWT_LABEL_AUDIENCE, audience);
}


static inline void attest_token_encode_cwt_expiration(struct attest_token_encode_ctx *me,
                                        int64_t expiration)
{
    // TAG by time? No... TODO:
    attest_token_encode_add_integer(me, CWT_LABEL_EXPIRATION, expiration);
}

static inline void attest_token_encode_cwt_not_before(struct attest_token_encode_ctx *me,
                                               int64_t not_before)
{
    // TAG by time? No... TODO:
    attest_token_encode_add_integer(me, CWT_LABEL_NOT_BEFORE, not_before);
}


static inline void attest_token_encode_cwt_iat(struct attest_token_encode_ctx *me,
                                          int64_t iat)
{
    attest_token_encode_add_integer(me, CWT_LABEL_IAT, iat);
}


static inline void attest_token_encode_cwt_cti(struct attest_token_encode_ctx *me,
                                           struct q_useful_buf_c cti)
{
    attest_token_encode_add_bstr(me, CWT_LABEL_CTI, cti);
}



#endif /* cwt_encode_h */
