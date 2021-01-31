/*
 * useful_buf_malloc.c
 *
 * Copyright (c) 2021, Laurence Lundblade.
 *
 * Created by Laurence Lundblade on 1/29/21.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "useful_buf_malloc.h"
#include <stdlib.h>

struct q_useful_buf useful_malloc(size_t size)
{
    struct q_useful_buf b;

    b.ptr = malloc(size);
    if(b.ptr == NULL) {
        return NULL_Q_USEFUL_BUF;
    }
    b.len = size;
    return b;
}
