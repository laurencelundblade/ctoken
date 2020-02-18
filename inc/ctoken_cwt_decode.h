/*
 * ctoken_cwt_decode.h
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

#include "ctoken_cwt_labels.h"
#include "ctoken_decode.h"


#ifdef __cplusplus
extern "C" {
#ifdef 0
} /* Keep editor indention formatting happy */
#endif
#endif

// TODO: Make prototypes of these and document them

static inline enum ctoken_err_t
ctoken_decode_cwt_issuer(struct ctoken_decode_ctx *me,
                         struct q_useful_buf_c *issuer)
{
    return ctoken_decode_get_tstr(me, CTOKEN_CWT_LABEL_ISSUER, issuer);
}


static inline enum ctoken_err_t
ctoken_decode_cwt_subject(struct ctoken_decode_ctx *me,
                          struct q_useful_buf_c *subject)
{
    return ctoken_decode_get_tstr(me, CTOKEN_CWT_LABEL_SUBJECT, subject);
}


static inline enum ctoken_err_t
ctoken_decode_cwt_audience(struct ctoken_decode_ctx *me,
                           struct q_useful_buf_c *audience)
{
    return ctoken_decode_get_tstr(me, CTOKEN_CWT_LABEL_AUDIENCE, audience);
}


static inline enum ctoken_err_t
ctoken_decode_cwt_expiration(struct ctoken_decode_ctx *me,
                             int64_t *expiration)
{
    return ctoken_decode_get_int(me, CTOKEN_CWT_LABEL_EXPIRATION, expiration);
}

static inline enum ctoken_err_t
ctoken_decode_cwt_not_before(struct ctoken_decode_ctx *me,
                             int64_t *not_before)
{
    return ctoken_decode_get_int(me, CTOKEN_CWT_LABEL_NOT_BEFORE, not_before);
}


static inline enum ctoken_err_t
ctoken_decode_cwt_iat(struct ctoken_decode_ctx *me,
                      int64_t *iat)
{
    return ctoken_decode_get_int(me, CTOKEN_CWT_LABEL_NOT_BEFORE, iat);
}


static inline enum ctoken_err_t
ctoken_decode_cwt_cti(struct ctoken_decode_ctx *me,
                      struct q_useful_buf_c *cti)
{
    return ctoken_decode_get_bstr(me, CTOKEN_CWT_LABEL_CTI,  cti);
}

#ifdef __cplusplus
}
#endif

#endif /* cwt_decode_h */
