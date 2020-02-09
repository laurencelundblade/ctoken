/*
 * ctoken_cwt_labels.h
 *
 * Copyright (c) 2020 Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 2/1/20.
 */

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

https://www.iana.org/assignments/cwt/cwt.xhtml#claims-registry

 */

#define CTOKEN_CWT_LABEL_ISSUER      1
#define CTOKEN_CWT_LABEL_SUBJECT     2
#define CTOKEN_CWT_LABEL_AUDIENCE    3
#define CTOKEN_CWT_LABEL_EXPIRATION  4
#define CTOKEN_CWT_LABEL_NOT_BEFORE  5
#define CTOKEN_CWT_LABEL_IAT         6
#define CTOKEN_CWT_LABEL_CTI         7

#define CTOKEN_CWT_LABEL_CNF         8

/*
 For claim type CTOKEN_CWT_LABEL_CNF

 https://www.iana.org/assignments/cwt/cwt.xhtml#confirmation-methods */
enum ctoken_cwt_cnf_methods_t {
    CTOKEN_CWT_CNF_COSE_KEY           = 1,
    CTOKEN_CWT_CNF_Encrypted_Cose_Key = 2,
    CTOKEN_CWT_CNF_kid                = 3
};

#endif /* cwt_labels_h */
