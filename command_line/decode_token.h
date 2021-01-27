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
#include <stdbool.h>



/*
 -claim ll:vv

 -in <file>
 -out <file>

 -in_form CBOR, JSON
 -out_form CBOR, JSON, text, CBOR diag

 -in_prot none, sign, mac, sign_encrypt, mac_encrypt, auto
 -out_prot none, sign, mac, sign_encrypt, mac_encrypt

 -no_verify  The input file will be decoded, but any signature or mac will not be verified. No need to supply key material

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
 To skip verification use the -noverify option.

 */

struct ctoken_arguments {
    const char *input_file;
    const char *output_file;

    char **claims;

    enum {IN_FORMAT_CBOR, IN_FORMAT_JSON} input_format;
    enum {OUT_FORMAT_CBOR, OUT_FORMAT_JSON} output_format;

    enum {IN_PROT_DETECT, IN_PROT_NONE, IN_PROT_SIGN, IN_PROT_MAC,
          IN_PROT_SIGN_ENCRYPT, IN_PROT_MAC_ENCRYPT} input_protection;

    enum {OUT_PROT_SIGN, OUT_PROT_NONE, OUT_PROT_MAC, OUT_PROT_SIGN_ENCRYPT,
          OUT_PROT_MAC_ENCRYPT} output_protection;

    enum {OUT_TAG_CWT, OUT_TAG_COSE, OUT_TAG_NONE} output_tagging;

    bool no_verify;

};


#endif /* decode_token_h */
