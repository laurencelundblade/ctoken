//
//  cwt_encode.h
//  CToken
//
//  Created by Laurence Lundblade on 1/31/20.
//  Copyright © 2020 Laurence Lundblade. All rights reserved.
//

#ifndef cwt_encode_h
#define cwt_encode_h

#include "attest_token_encode.h"
#include "cwt_labels.h"


/*

              +------+-----+----------------------------------+
             | Name | Key | Value Type                       |
             +------+-----+----------------------------------+
             | iss  | 1   | text string                      |
             | sub  | 2   | text string                      |
             | aud  | 3   | text string                      |
             | exp  | 4   | integer or floating-point number |
             | nbf  | 5   | integer or floating-point number |
             | iat  | 6   | integer or floating-point number |
             | cti  | 7   | byte string                      |
             +------+-----+----------------------------------+

 #define CWT_LABEL_ISSUER 1
 #define CWT_LABEL_SUBJECT 2
 #define CWT_LABEL_AUDIENCE 3
 #define CWT_LABEL_EXPIRATION 4
 #define CWT_LABEL_NOT_BEFORE 5
 #define CWT_LABEL_IAT   6
 #define CWT_LABEL_CTI 7
*/


static void attest_token_encode_cwt_issuer(struct attest_token_encode_ctx *me,
                                           struct q_useful_buf_c issuer)
{
    attest_token_encode_add_tstr(me, CWT_LABEL_ISSUER, issuer);
}

static void attest_token_encode_cwt_subject(struct attest_token_encode_ctx *me,
                                           struct q_useful_buf_c subject)
{
    attest_token_encode_add_tstr(me, CWT_LABEL_SUBJECT, subject);
}

static void attest_token_encode_cwt_audience(struct attest_token_encode_ctx *me,
                                            struct q_useful_buf_c audience)
{
    attest_token_encode_add_tstr(me, CWT_LABEL_AUDIENCE, audience);
}


static void attest_token_encode_cwt_expiration(struct attest_token_encode_ctx *me,
                                        int64_t expiration)
{
    // TAG by time? No... TODO:
    attest_token_encode_add_integer(me, CWT_LABEL_EXPIRATION, expiration);
}

static void attest_token_encode_cwt_not_before(struct attest_token_encode_ctx *me,
                                               int64_t not_before)
{
    // TAG by time? No... TODO:
    attest_token_encode_add_integer(me, CWT_LABEL_NOT_BEFORE, not_before);
}


static void attest_token_encode_cwt_iat(struct attest_token_encode_ctx *me,
                                          int64_t iat)
{
    attest_token_encode_add_integer(me, CWT_LABEL_IAT, iat);
}


static void attest_token_encode_cwt_cti(struct attest_token_encode_ctx *me,
                                           struct q_useful_buf_c cti)
{
    attest_token_encode_add_bstr(me, CWT_LABEL_CTI, cti);
}



#endif /* cwt_encode_h */
