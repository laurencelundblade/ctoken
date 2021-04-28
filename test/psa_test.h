/*
 * psa_test.h (formerly attest_token_test.h)
 *
 * Copyright (c) 2018-2021, Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __psa_TEST_H__
#define __psa_TEST_H__

#include <stdint.h>
#include "t_cose/q_useful_buf.h"

#ifdef __cplusplus
extern "C" {
#if 0
} /* Keep editor indention formatting happy */
#endif
#endif


int32_t psa_basic_test(void);


int32_t decode_sw_components_test(void);



// TODO: this tests a lot of the PSA layer about ctoken and needs to be removed
// or refactored.



#if REFACTOR_THIS
/**
 * \file attest_token_test.h
 *
 * \brief Entry points for attestation token tests.
 *
 * Errors codes are in the range of [-32767,32767] so
 * int_fast16_t is used so they will work nice
 * even on 16-bit machines. Plain old int could
 * also be used, but many compilers make it
 * 32-bits for backwards compatibility with
 * SW that assume it is always 32 bits and
 * it isn't efficient.  (This code has probably
 * not yet been tested on a 16-bit machines).
 *
 * https://stackoverflow.com/questions/30942107/
 * whats-the-difference-between-int-and-int-fast16-t
 */


/**
 * \brief Minimal token creation test using a short-circuit signature.
 *
 * \return non-zero on failure.
 */
int32_t minimal_test(void);


/**
 * \brief Test token size calculation.
 *
 * \return non-zero on failure.
 */
int32_t minimal_get_size_test(void);


/**
 * \brief Pass too small a buffer and confirm correct error result.
 *
 * \return non-zero on failure.
 */
int32_t buffer_too_small_test(void);


/**
 * \brief Test by checking signed values of claims.
 *
 * \return non-zero on failure.
 *
 * This is an extensive test that can compare the values in the token
 * to expected valued compiled into the test app from
 * token_test_values.h. All the values represented in \ref
 * attest_token_iat_simple_t and in \ref attest_token_sw_component_t
 * are checked.
 *
 * This uses real ECDSA keys for both signing and verificaiton.  It
 * requires that the t_cose crypto porting layer operates correctly
 * and that all keys are present. See also
 * decode_test_short_circuit_sig().
 */
int32_t decode_test_normal_sig(void);


/**
 * \brief Test by checking short-circuit signed values of claims.
 *
 * \return non-zero on failure.
 *
 * This is an extensive test that can compare the values in the token
 * to expected valued compiled into the test app from
 * token_test_values.h. All the values represented in \ref
 * attest_token_iat_simple_t and in \ref attest_token_sw_component_t
 * are checked.
 *
 * This uses a short-circuit signature rather than real ECDSA
 * keys. This tests everything in the implementation except the final
 * signing of the final hash with ECDSA and the converse
 * verification. It is thorough test of everything by ECDSA
 * integration. It can work even without ECDSA integration and without
 * any keys configured.
 */
int32_t decode_test_short_circuit_sig(void);


int32_t make_normal_token(struct q_useful_buf token_storage, struct q_useful_buf_c *completed_token);


#endif /* REFACTOR_THIS */

#ifdef __cplusplus
}
#endif

#endif /* __psa_TEST_H__ */
