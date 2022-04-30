/*
 *  eat_example_psa.c
 *
 * Copyright 2019-2022, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


/**
 * \file t_cose_basic_example_psa.c
 *
 * \brief Example code for signing and verifying a COSE_Sign1 message using PSA
 *
 * This file has simple code to sign a payload and verify it.
 *
 * This works with PSA / MBed Crypto. It assumes t_cose has been wired
 * up to PSA / MBed Crypto and has code specific to this library to
 * make a key pair that will be passed through t_cose. See t_cose
 * README for more details on how integration with crypto libraries
 * works.
 */


#include "ctoken/ctoken_encode.h"
#include "ctoken/ctoken_decode.h"

#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_sign1_sign.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/q_useful_buf.h"

#include "psa/crypto.h"

#include <stdio.h>


/*
 * These are the same keys as in t_cose_make_openssl_test_key.c so that
 * messages made with openssl can be verified those made by mbedtls.
 * These were made with openssl as detailed in t_cose_make_openssl_test_key.c.
 * Then just the private key was pulled out to be put here because
 * mbedtls just needs the private key, unlike openssl for which there
 * is a full rfc5915 DER structure. These were pulled out of the DER
 * by identifying the key with openssl asn1parse and then finding those
 * bytes in the C variable holding the rfc5915 (perhaps there is a better
 * way, but this works).
 */


#define PRIVATE_KEY_prime256v1 \
0xd9, 0xb5, 0xe7, 0x1f, 0x77, 0x28, 0xbf, 0xe5, 0x63, 0xa9, 0xdc, 0x93, 0x75, \
0x62, 0x27, 0x7e, 0x32, 0x7d, 0x98, 0xd9, 0x94, 0x80, 0xf3, 0xdc, 0x92, 0x41, \
0xe5, 0x74, 0x2a, 0xc4, 0x58, 0x89

#define PRIVATE_KEY_secp384r1 \
 0x63, 0x88, 0x1c, 0xbf, \
 0x86, 0x65, 0xec, 0x39, 0x27, 0x33, 0x24, 0x2e, 0x5a, 0xae, 0x63, 0x3a, \
 0xf5, 0xb1, 0xb4, 0x54, 0xcf, 0x7a, 0x55, 0x7e, 0x44, 0xe5, 0x7c, 0xca, \
 0xfd, 0xb3, 0x59, 0xf9, 0x72, 0x66, 0xec, 0x48, 0x91, 0xdf, 0x27, 0x79, \
 0x99, 0xbd, 0x1a, 0xbc, 0x09, 0x36, 0x49, 0x9c

#define PRIVATE_KEY_secp521r1 \
0x00, 0x4b, 0x35, 0x4d, \
0xa4, 0xab, 0xf7, 0xa5, 0x4f, 0xac, 0xee, 0x06, 0x49, 0x4a, 0x97, 0x0e, \
0xa6, 0x5f, 0x85, 0xf0, 0x6a, 0x2e, 0xfb, 0xf8, 0xdd, 0x60, 0x9a, 0xf1, \
0x0b, 0x7a, 0x13, 0xf7, 0x90, 0xf8, 0x9f, 0x49, 0x02, 0xbf, 0x5d, 0x5d, \
0x71, 0xa0, 0x90, 0x93, 0x11, 0xfd, 0x0c, 0xda, 0x7b, 0x6a, 0x5f, 0x7b, \
0x82, 0x9d, 0x79, 0x61, 0xe1, 0x6b, 0x31, 0x0a, 0x30, 0x6f, 0x4d, 0xf3, \
0x8b, 0xe3


/*
 * Public function, see t_cose_make_test_pub_key.h
 */
enum t_cose_err_t make_psa_ecdsa_key_pair(int32_t            cose_algorithm_id,
                                      struct t_cose_key *key_pair)
{
    psa_key_type_t        key_type;
    psa_status_t          crypto_result;
    mbedtls_svc_key_id_t  key_handle;
    psa_algorithm_t       key_alg;
    const uint8_t        *private_key;
    size_t                private_key_len;
    psa_key_attributes_t key_attributes;


    static const uint8_t private_key_256[] = {PRIVATE_KEY_prime256v1};
    static const uint8_t private_key_384[] = {PRIVATE_KEY_secp384r1};
    static const uint8_t private_key_521[] = {PRIVATE_KEY_secp521r1};

    /* There is not a 1:1 mapping from COSE algorithm to key type, but
     * there is usually an obvious curve for an algorithm. That
     * is what this does.
     */

    switch(cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256:
        private_key     = private_key_256;
        private_key_len = sizeof(private_key_256);
        key_type        = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
        break;

    case T_COSE_ALGORITHM_ES384:
        private_key     = private_key_384;
        private_key_len = sizeof(private_key_384);
        key_type        = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_384);
        break;

    case T_COSE_ALGORITHM_ES512:
        private_key     = private_key_521;
        private_key_len = sizeof(private_key_521);
        key_type        = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_512);
        break;

    default:
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }


    /* OK to call this multiple times */
    crypto_result = psa_crypto_init();
    if(crypto_result != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }


    /* When importing a key with the PSA API there are two main things
     * to do.
     *
     * First you must tell it what type of key it is as this cannot be
     * discovered from the raw data (because the import is not of a format
     * like RFC 5915). The variable key_type contains
     * that information including the EC curve. This is sufficient for
     * psa_import_key() to succeed, but you probably want actually use
     * the key.
     *
     * Second, you must say what algorithm(s) and operations the key
     * can be used as the PSA Crypto Library has policy enforcement.
     */

    key_attributes = psa_key_attributes_init();

    /* The type of key including the EC curve */
    psa_set_key_type(&key_attributes, key_type);

    /* Say what algorithm and operations the key can be used with/for */
    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&key_attributes, key_alg);


    /* Import the private key. psa_import_key() automatically
     * generates the public key from the private so no need to import
     * more than the private key. With ECDSA the public key is always
     * deterministically derivable from the private key.
     */
    crypto_result = psa_import_key(&key_attributes,
                                    private_key,
                                    private_key_len,
                                   &key_handle);

    if(crypto_result != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }

    /* This assignment relies on MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
     * not being defined. If it is defined key_handle is a structure.
     * This does not seem to be typically defined as it seems that is
     * for a PSA implementation architecture as a service rather than
     * an linked library. If it is defined, the structure will
     * probably be less than 64 bits, so it can still fit in a
     * t_cose_key. */
    key_pair->k.key_handle = key_handle;
    key_pair->crypto_lib   = T_COSE_CRYPTO_LIB_PSA;

    return T_COSE_SUCCESS;
}


/*
 * Public function, see t_cose_make_test_pub_key.h
 */
void free_psa_ecdsa_key_pair(struct t_cose_key key_pair)
{
   psa_destroy_key((mbedtls_svc_key_id_t)key_pair.k.key_handle);
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
    return_value = make_psa_ecdsa_key_pair(T_COSE_ALGORITHM_ES256, &key_pair);

    printf("Made EC key (PSA mbed) with curve prime256v1: %d (%s)\n", return_value, return_value ? "fail" : "success");
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
    free_psa_ecdsa_key_pair(key_pair);
Done:

    return return_value;

}


int main(int argc, const char * argv[])
{
    (void)argc; /* Avoid unused parameter error */
    (void)argv;

    eat_example();
}


// ((uint8_t *)completed_token.ptr)[59]++;

