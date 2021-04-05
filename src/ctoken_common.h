/*
 * ctoken_common.h
 *
 * Copyright (c) 2021 Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 4/5/21.
 */

#ifndef ctoken_common_h
#define ctoken_common_h

#include "t_cose/t_cose_common.h"
#include "ctoken.h"

enum ctoken_err_t
map_t_cose_errors(enum t_cose_err_t t_cose_error);

#endif /* ctoken_common_h */
