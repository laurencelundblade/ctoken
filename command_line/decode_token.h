//
//  decode_token.h
//  CToken
//
//  Created by Laurence Lundblade on 1/11/21.
//  Copyright © 2021 Laurence Lundblade. All rights reserved.
//

#ifndef decode_token_h
#define decode_token_h

#include <stdio.h>



/*
 -claim 44:xx

 -in-form CBOR, JSON
 -out_form CBOR, JSON, text, CBOR diag
 -in <file>
 -out <file>
 -in_prot none, sign, mac, sign_encrypt, mac_encrypt, auto
 -out_prot none, sign, mac, sign_encrypt, mac_encrypt

 -noverify  The input file will be decoded, but any signature or mac will not be verified. No need to supply key material

 -out_sign_alg
 -out_encrypt_alg
 -out_sign_key  private key to sign with
 -out_encrypt_key public key to encrypt with
 -out_certs  certs to include in the output token

 -in_verify_key
 -in_verify_cert
 -in_decrypt_keyh

 -out_tag  none, full, cose









There must be an input that is either a file or some claims.
 If there is a file, it will be verified and key material must be given to do so.
 To skip verification use the -noverify option






 */

struct arguments {
    const char *input_file;
    const char *output_file;

    int input_format;
    int output_format;

    int input_protection;
    int output_protection;

    char **claims;




};


#endif /* decode_token_h */
