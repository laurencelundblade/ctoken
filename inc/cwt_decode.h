/*
 * cwt_decode.h
 *
 * Copyright (c) 2020 Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 2/1/20.
 */

#ifndef cwt_decode_h
#define cwt_decode_h

#include "cwt_labels.h"
#include "attest_token_decode.h"

static inline enum attest_token_err_t
attest_token_decode_cwt_issuer(struct attest_token_decode_context *me,
                              struct q_useful_buf_c *issuer)
{
    return attest_token_decode_get_tstr(me,
                                        CWT_LABEL_ISSUER,
                                        issuer);
}


static inline enum attest_token_err_t
attest_token_decode_cwt_subject(struct attest_token_decode_context *me,
                               struct q_useful_buf_c *subject)
{
    return attest_token_decode_get_tstr(me,
                                        CWT_LABEL_SUBJECT,
                                        subject);
}


static inline enum attest_token_err_t
attest_token_decode_cwt_audience(struct attest_token_decode_context *me,
                                struct q_useful_buf_c *audience)
{
    return attest_token_decode_get_tstr(me,
                                        CWT_LABEL_AUDIENCE,
                                        audience);
}


static inline enum attest_token_err_t
attest_token_decode_cwt_expiration(struct attest_token_decode_context *me,
                                 int64_t *expiration)
{
    return attest_token_decode_get_int(me,
                                        CWT_LABEL_EXPIRATION,
                                        expiration);
}

static inline enum attest_token_err_t
attest_token_decode_cwt_not_before(struct attest_token_decode_context *me,
                                   int64_t *not_before)
{
    return attest_token_decode_get_int(me,
                                        CWT_LABEL_NOT_BEFORE,
                                        not_before);
}


static inline enum attest_token_err_t
attest_token_decode_cwt_iat(struct attest_token_decode_context *me,
                                   int64_t *iat)
{
    return attest_token_decode_get_int(me,
                                         CWT_LABEL_NOT_BEFORE,
                                         iat);
}


static inline enum attest_token_err_t
attest_token_decode_cwt_cti(struct attest_token_decode_context *me,
                                 struct q_useful_buf_c *cti)
{
    return attest_token_decode_get_bstr(me,
                                        CWT_LABEL_CTI,
                                        cti);
}

#endif /* cwt_decode_h */
