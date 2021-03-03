/*
 * eat_test.h
 *
 * Copyright (c) 2020-2021 Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 2/13/20.
 */

#ifndef eat_test_h
#define eat_test_h

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#if 0
} /* Keep editor indention formatting happy */
#endif
#endif


int32_t basic_eat_test(void);


int32_t submods_test(void);


int32_t submods_errors_test(void);


int32_t submod_decode_errors_test(void);


int32_t location_test(void);


int32_t debug_and_boot_test(void);


int32_t get_next_test(void);



#ifdef __cplusplus
}
#endif

#endif /* eat_test_h */
