/*
 *  eat_example_ossl.c
 *
 * Copyright 2019-2022, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


/**
 * \file eat_example_ossl.c
 *
 * \brief Example code for making and verifying a very simple EAT token.
 *
 * This works with OpenSSL. It assumes t_cose has been wired up to the
 * OpenSSL crypto library and hase code specific to OpenSSL to make an
 * EC key pair. See t_cose README for more details on how integration
 * with crypto libraries works.
 */

#include "ctoken/ctoken_encode.h"
#include "ctoken/ctoken_decode.h"

#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_sign1_sign.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/q_useful_buf.h"

#include <stdio.h>
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/x509.h"



/*
 * RFC 5915 format EC private key, including the public key. These
 * are the same key as in t_cose_make_psa_test_key.c
 *
 * They are made by:
 *
 *   openssl ecparam -genkey -name prime256v1 -noout -out ec256-key-pair.pem
 *
 *   Edit the PEM headers off so it is just b64
 *
 *   base64 --decode to get the pure DER
 *
 *   xxd -i to turn it into a C variable
 *
 *
 * See also:
 *  https://stackoverflow.com/
 *  questions/71890050/
 *  set-an-evp-pkey-from-ec-raw-points-pem-or-der-in-both-openssl-1-1-1-and-3-0-x/
 *  71896633#71896633
 */

static const unsigned char ec256_key_pair[] = {
  0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0xd9, 0xb5, 0xe7, 0x1f, 0x77,
  0x28, 0xbf, 0xe5, 0x63, 0xa9, 0xdc, 0x93, 0x75, 0x62, 0x27, 0x7e, 0x32,
  0x7d, 0x98, 0xd9, 0x94, 0x80, 0xf3, 0xdc, 0x92, 0x41, 0xe5, 0x74, 0x2a,
  0xc4, 0x58, 0x89, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
  0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x40, 0x41, 0x6c,
  0x8c, 0xda, 0xa0, 0xf7, 0xa1, 0x75, 0x69, 0x55, 0x53, 0xc3, 0x27, 0x9c,
  0x10, 0x9c, 0xe9, 0x27, 0x7e, 0x53, 0xc5, 0x86, 0x2a, 0xa7, 0x15, 0xed,
  0xc6, 0x36, 0xf1, 0x71, 0xca, 0x32, 0xf1, 0x76, 0x43, 0x54, 0x96, 0x15,
  0xe5, 0xc8, 0x34, 0x0d, 0x43, 0x32, 0xdd, 0x13, 0x77, 0x8a, 0xec, 0x87,
  0x15, 0x76, 0xa3, 0x3c, 0x26, 0x08, 0x6c, 0x32, 0x0c, 0x9f, 0xf3, 0x3f,
  0xc7
};

static const unsigned char ec384_key_pair[] = {
  0x30, 0x81, 0xa4, 0x02, 0x01, 0x01, 0x04, 0x30, 0x63, 0x88, 0x1c, 0xbf,
  0x86, 0x65, 0xec, 0x39, 0x27, 0x33, 0x24, 0x2e, 0x5a, 0xae, 0x63, 0x3a,
  0xf5, 0xb1, 0xb4, 0x54, 0xcf, 0x7a, 0x55, 0x7e, 0x44, 0xe5, 0x7c, 0xca,
  0xfd, 0xb3, 0x59, 0xf9, 0x72, 0x66, 0xec, 0x48, 0x91, 0xdf, 0x27, 0x79,
  0x99, 0xbd, 0x1a, 0xbc, 0x09, 0x36, 0x49, 0x9c, 0xa0, 0x07, 0x06, 0x05,
  0x2b, 0x81, 0x04, 0x00, 0x22, 0xa1, 0x64, 0x03, 0x62, 0x00, 0x04, 0x14,
  0x2a, 0x78, 0x91, 0x06, 0x9b, 0xbe, 0x43, 0xa9, 0xe8, 0xd2, 0xa7, 0xbd,
  0x03, 0xdf, 0xc9, 0x12, 0x62, 0x66, 0xb7, 0x84, 0xe3, 0x33, 0x4a, 0xf2,
  0xb5, 0xf9, 0x5e, 0xe0, 0x3f, 0xe5, 0xc7, 0xdc, 0x1d, 0x56, 0xb3, 0x9f,
  0x30, 0x6f, 0x97, 0xba, 0x00, 0xd8, 0xcf, 0x41, 0xea, 0x95, 0x5f, 0xeb,
  0x55, 0x62, 0xab, 0x7c, 0xb7, 0x58, 0xd0, 0xe8, 0xde, 0xcf, 0x64, 0x69,
  0x32, 0x50, 0xb3, 0x06, 0x70, 0xb0, 0xbc, 0x84, 0xcb, 0xa7, 0x1f, 0x2f,
  0x1b, 0xf6, 0xad, 0x54, 0x56, 0x0a, 0x75, 0x83, 0xe1, 0xcf, 0xb6, 0x12,
  0x2e, 0x0a, 0xde, 0xf9, 0xaa, 0x37, 0x64, 0x1a, 0x51, 0x1c, 0x27
};

static const unsigned char ec521_key_pair[] = {
  0x30, 0x81, 0xdc, 0x02, 0x01, 0x01, 0x04, 0x42, 0x00, 0x4b, 0x35, 0x4d,
  0xa4, 0xab, 0xf7, 0xa5, 0x4f, 0xac, 0xee, 0x06, 0x49, 0x4a, 0x97, 0x0e,
  0xa6, 0x5f, 0x85, 0xf0, 0x6a, 0x2e, 0xfb, 0xf8, 0xdd, 0x60, 0x9a, 0xf1,
  0x0b, 0x7a, 0x13, 0xf7, 0x90, 0xf8, 0x9f, 0x49, 0x02, 0xbf, 0x5d, 0x5d,
  0x71, 0xa0, 0x90, 0x93, 0x11, 0xfd, 0x0c, 0xda, 0x7b, 0x6a, 0x5f, 0x7b,
  0x82, 0x9d, 0x79, 0x61, 0xe1, 0x6b, 0x31, 0x0a, 0x30, 0x6f, 0x4d, 0xf3,
  0x8b, 0xe3, 0xa0, 0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23, 0xa1,
  0x81, 0x89, 0x03, 0x81, 0x86, 0x00, 0x04, 0x00, 0x64, 0x27, 0x45, 0x07,
  0x38, 0xbd, 0xd7, 0x1a, 0x87, 0xea, 0x20, 0xfb, 0x93, 0x6f, 0x1c, 0xde,
  0xb3, 0x42, 0xcc, 0xf4, 0x58, 0x87, 0x79, 0x0f, 0x69, 0xaf, 0x5b, 0xff,
  0x72, 0x96, 0x35, 0xb9, 0x6e, 0x8a, 0x55, 0x64, 0x00, 0x44, 0xfe, 0x63,
  0x20, 0x4f, 0x65, 0x3a, 0x3a, 0x47, 0xcf, 0x3a, 0x7f, 0x60, 0x5d, 0xcb,
  0xe6, 0xb4, 0x5a, 0x57, 0x2f, 0xc8, 0x74, 0x62, 0xcf, 0x98, 0x58, 0x33,
  0x59, 0x00, 0xb9, 0xd0, 0xbc, 0x76, 0x2a, 0x37, 0x15, 0x3b, 0x9d, 0x3c,
  0x62, 0xe9, 0xcc, 0x63, 0x00, 0xab, 0x7b, 0x01, 0xb1, 0x00, 0x77, 0x02,
  0x14, 0xdb, 0x5e, 0xb8, 0xda, 0xac, 0x72, 0xf1, 0xd4, 0xa6, 0x17, 0xc5,
  0x12, 0x97, 0x95, 0x6b, 0x98, 0x0b, 0xe0, 0x19, 0xf1, 0xf6, 0xd1, 0x0c,
  0x09, 0xec, 0x1e, 0x2f, 0x51, 0x7a, 0x87, 0x71, 0x3c, 0x63, 0x25, 0x01,
  0x43, 0xc0, 0xa8, 0x52, 0x1f, 0xf9, 0x53
};


/*
 * Public function, see t_cose_make_test_pub_key.h
 */
/*
 * The key object returned by this is malloced and has to be freed by
 * by calling free_ecdsa_key_pair(). This heap use is a part of
 * OpenSSL and not t_cose which does not use the heap.
 */
enum t_cose_err_t make_ossl_ecdsa_key_pair(int32_t            cose_algorithm_id,
                                      struct t_cose_key *key_pair)
{
    enum t_cose_err_t  return_value;
    EVP_PKEY          *pkey;
    const uint8_t     *rfc5915_key;
    long               rfc5915_key_len;

    switch (cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256:
        rfc5915_key = ec256_key_pair;
        rfc5915_key_len = sizeof(ec256_key_pair);
        break;

    case T_COSE_ALGORITHM_ES384:
        rfc5915_key = ec384_key_pair;
        rfc5915_key_len = sizeof(ec384_key_pair);
        break;

    case T_COSE_ALGORITHM_ES512:
        rfc5915_key = ec521_key_pair;
        rfc5915_key_len = sizeof(ec521_key_pair);
        break;

    default:
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    /* This imports the public key too */
    pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &rfc5915_key, rfc5915_key_len);
    if(pkey == NULL) {
        return_value = T_COSE_ERR_FAIL;
        goto Done;
    }

    key_pair->k.key_ptr  = pkey;
    key_pair->crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    return_value         = T_COSE_SUCCESS;

Done:
    return return_value;
}


/*
 * Public function, see t_cose_make_test_pub_key.h
 */
void free_ossl_ecdsa_key_pair(struct t_cose_key key_pair)
{
    EVP_PKEY_free(key_pair.k.key_ptr);
}


/**
 * \brief  Print a q_useful_buf_c on stdout in hex ASCII text.
 *
 * \param[in] string_label   A string label to output first
 * \param[in] buf            The q_useful_buf_c to output.
 *
 * This is just for pretty printing.
 */
static void print_useful_buf(const char *string_label, struct q_useful_buf_c buf)
{
    if(string_label) {
        printf("%s", string_label);
    }

    printf("    %ld bytes\n", buf.len);

    printf("    ");

    size_t i;
    for(i = 0; i < buf.len; i++) {
        uint8_t Z = ((uint8_t *)buf.ptr)[i];
        printf("%02x ", Z);
        if((i % 8) == 7) {
            printf("\n    ");
        }
    }
    printf("\n");

    fflush(stdout);
}


/**
 \brief Example to encode an EAT token

 @param[in] signing_key    The private key to sign with. This must be in the
                           format of the crypto library that is integrated.
                           See definition in t_cose interface.
 @param[in] nonce          Pointer and length of nonce claim.
 @param[in] output_buffer  Pointer and length of the buffer to output to. Must
                           be big enough to hold the EAT, or an error occurs.
 @param[out] completed_token  Pointer and length of the completed token.
 @return                      0 on success.

 output_buffer is the pointer and length of a buffer to write
 into. The pointer is not const indicating it is for writing.

 completed_token is the const pointer and length of the completed
 token. The storage pointed to by completed_token is inside
 output_buffer, usually the first part, so the pointers point
 to the same place.

 No storage allocation is done and malloc is not used.
 */
int32_t eat_encode(struct t_cose_key signing_key,
                   struct q_useful_buf_c nonce,
                   struct q_useful_buf output_buffer,
                   struct q_useful_buf_c *completed_token)
{
    struct ctoken_encode_ctx encode_ctx;
    int                      return_value;

    /* UEID is hard-coded. A real implementation would fetch it from
     * storage or read it from a register or compute it or such.
     */
    const struct q_useful_buf_c ueid = Q_USEFUL_BUF_FROM_SZ_LITERAL("ueid_ueid");

    /* Initialize, telling is the option (there are none) and
     * the signing algorithm to use.
     */
    ctoken_encode_init(&encode_ctx,
                       0, /* No t_cose options */
                       0, /* No ctoken options */
                       CTOKEN_PROTECTION_COSE_SIGN1,
                       T_COSE_ALGORITHM_ES256);

    

    /* Next give it the signing key. No kid (key id) is given so
     * NULL_Q_USEFUL_BUF_C is passed.
     */
    ctoken_encode_set_key(&encode_ctx, signing_key, NULL_Q_USEFUL_BUF_C);

    /* Pass in the output buffer and get the encoding started.
     * The output buffer must be big enough for EAT payload, COSE
     * formatting and signature. (There is a way to call
     * ctoken_encode_start() to have this computed which is th
     * same as that used by t_cose and QCBOR, but that is not
     * done in this simple example. */
    ctoken_encode_start(&encode_ctx, output_buffer);

    /* Now start adding the claims into the token. Eat claims
     * can be mixed with PSA IA claims and with CWT claims.
     * You can even make up your own claims.
     */

    ctoken_encode_nonce(&encode_ctx, nonce);

    ctoken_encode_ueid(&encode_ctx, ueid);

    /* Finally completed it. This invokes the signing and
     * ties everything off and outputs the completed token.
     * The variable completed_token has the pointer and length
     * of the result that are in output_buffer.
     */
    return_value = ctoken_encode_finish(&encode_ctx, completed_token);

    return return_value;
}


/**
 Simple EAT decode and verify example.

 @param[in] verification_key  The public key to verify the token with. It must
                              be in the format for the crypto library that
                              ctoken and t_cose are integrated with. See
                              the t_cose headers.
 @param[in] token             Pointer and length of the token to verify.
 @param[out] nonce            Place to return pointer and length of the
                              nonce.
 @return                      0 on success.

 This only retrieves the nonce claim from the token (so far).
 */
int32_t eat_decode(struct t_cose_key     verification_key,
                   struct q_useful_buf_c token,
                   struct q_useful_buf_c *nonce)
{
    struct ctoken_decode_ctx decode_context;

    /* Initialize the decoding context. No options are given.
     * The algorithm in use comes from the header in the token
     * so it is not specified here
     */
    ctoken_decode_init(&decode_context,
                       0,
                       0,
                       CTOKEN_PROTECTION_BY_TAG);

    /* Set the verification key to use. It must be a key that works
     * with the algorithm the token was signed with. (This can be
     * be retrieved, but it is not shown here.)
     */
    ctoken_decode_set_verification_key(&decode_context, verification_key);

    /* Validate the signature on the token */
    ctoken_decode_validate_token(&decode_context, token);

    /* Parse the nonce out of the token */
    ctoken_decode_nonce(&decode_context, nonce);

Done:
    return ctoken_decode_get_and_reset_error(&decode_context);
}


int32_t eat_example()
{
    struct t_cose_key key_pair;
    struct q_useful_buf_c decoded_nonce;

    int return_value;

    /* ------   Make an ECDSA key pair    ------
     *
     * The key pair will be used for both signing and encryption. The
     * data type is struct t_cose_key on the outside, but internally
     * the format is that of the crypto library used, PSA in this
     * case. They key is just passed through t_cose to the underlying
     * crypto library.
     *
     * The making and destroying of the key pair is the only code
     * dependent on the crypto library in this file.
     */
    return_value = make_ossl_ecdsa_key_pair(T_COSE_ALGORITHM_ES256, &key_pair);

    printf("Made EC key (OSSL) with curve prime256v1: %d (%s)\n", return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }



    /* ------   Make an EAT   ------ */

    /* Call to macro to make a 300 byte struct useful_buf on the stack
     * named token_buffer. The expected token is less than 200 bytes.
     */
    MakeUsefulBufOnStack(  token_buffer, 300);
    struct q_useful_buf_c  completed_token;


    /* Make the token */
    return_value = eat_encode(key_pair,
                              Q_USEFUL_BUF_FROM_SZ_LITERAL("nonce_nonce"),
                              token_buffer,
                             &completed_token);

    printf("Finished making EAT: %d (%s)\n", return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }

    if(return_value) {
        goto Done;
    }

    print_useful_buf("Completed EAT:\n", completed_token);


    /* ------   Verify the EAT   ------ */

    return_value = eat_decode(key_pair,
                              completed_token,
                              &decoded_nonce);

    printf("EAT Verification complete: %d (%s)\n", return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }

    print_useful_buf("Decoded nonce:\n", decoded_nonce);


    /* ------   Free key pair   ------
     * Both OSSL and PSA allocate space for keys that must be freed.
     */
    printf("Freeing key pair\n\n\n");
    free_ossl_ecdsa_key_pair(key_pair);
Done:

    return return_value;

}


int main(int argc, const char * argv[])
{
    (void)argc; /* Avoid unused parameter error */
    (void)argv;

    eat_example();
}

