//
//  cwt_labels.h
//  CToken
//
//  Created by Laurence Lundblade on 2/1/20.
//  Copyright © 2020 Laurence Lundblade. All rights reserved.
//

#ifndef cwt_labels_h
#define cwt_labels_h


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

 */

#define CWT_LABEL_ISSUER 1
#define CWT_LABEL_SUBJECT 2
#define CWT_LABEL_AUDIENCE 3
#define CWT_LABEL_EXPIRATION 4
#define CWT_LABEL_NOT_BEFORE 5
#define CWT_LABEL_IAT   6
#define CWT_LABEL_CTI 7

#endif /* cwt_labels_h */
