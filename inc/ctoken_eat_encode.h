/*
 * ctoken_eat_encode.h
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

#include "ctoken_cwt_encode.h"
#include "ctoken_eat_labels.h"

// TODO: prototype and document all these; move the inline implementations to the end.

static inline void
ctoken_eat_encode_nonce(struct ctoken_encode_ctx *me,
                        struct q_useful_buf_c nonce)
{
    ctoken_encode_add_bstr(me, CTOKEN_EAT_LABEL_NONCE, nonce);
}


static inline void
ctoken_eat_encode_ueid(struct ctoken_encode_ctx *me,
                       struct q_useful_buf_c ueid)
{
    ctoken_encode_add_bstr(me, CTOKEN_EAT_LABEL_UEID, ueid);
}


static inline void
ctoken_eat_encode_oemid(struct ctoken_encode_ctx *me,
                        struct q_useful_buf_c oemid)
{
    ctoken_encode_add_bstr(me, CTOKEN_EAT_LABEL_OEMID, oemid);
}


static inline void
ctoken_eat_encode_origination(struct ctoken_encode_ctx *me,
                              struct q_useful_buf_c origination)
{
    ctoken_encode_add_bstr(me, CTOKEN_EAT_LABEL_ORIGINATION, origination);
}


static inline void
ctoken_eat_encode_security_level(struct ctoken_encode_ctx *me,
                                 enum ctoken_eat_security_level_t security_level)
{
    ctoken_encode_add_integer(me,
                              CTOKEN_EAT_LABEL_SECURITY_LEVEL,
                              (int64_t)security_level);
}


void
ctoken_eat_encode_boot_state(struct ctoken_encode_ctx *me,
                             bool secure_boot_enabled,
                             enum ctoken_eat_debug_level_t debug_state);



/**
 * \brief Encode an EAT location claims
 *
 * \param[in] context   ctoken encode context to output to.
 * \param[in] location  The location to output.
 *
 * Only the location fields indicated as present in \c item_flags
 * will be output.
 */
void
ctoken_eat_encode_location(struct ctoken_encode_ctx           *context,
                           const struct ctoken_eat_location_t *location);



#ifdef SUBMODS_ARE_IMPLEMENTED

// Prototypes for the planned submods impementation
static void ctoken_eat_encode_open_submod(struct attest_token_encode_ctx *me,
                                            char *submod_name,
                                            int nConnectionType);

static void ctoken_eat_encode_close_submod(struct attest_token_encode_ctx *me);


static void ctoken_eat_encode_add_token(struct attest_token_encode_ctx *me,
                                          char *submod_name,
                                          int nConnectionType,
                                          struct q_useful_buf_c token);
#endif

#endif /* eat_encode_h */
