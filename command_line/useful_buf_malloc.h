/*
 * useful_buf_malloc.h
 *
 * Copyright (c) 2021, Laurence Lundblade.
 *
 * Created by Laurence Lundblade on 1/29/21.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef useful_buf_malloc_h
#define useful_buf_malloc_h

#include "t_cose/q_useful_buf.h"
#include <stdlib.h>


/**
 * \brief Malloc memory and return it as a q_useful_buf
 *
 * @return malloced buffer or \ref NULL_Q_USEFUL_BUF
 *
 * This simply mallocs a buffer of requested size and fils in
 * the q_useful_buf.
 */
struct q_useful_buf useful_malloc(size_t size);


/**
 * \brief Free a q_useful_buf_c allocted by useful_malloc().
 *
 * Note that q_useful_buf has to have been converted to a q_useful_buf_c for the types to work
 */
static void useful_buf_c_free(struct q_useful_buf_c b);


/**
 * \brief Free a q_useful_buf allocted by useful_malloc().
 *
 */
static void useful_buf_free(struct q_useful_buf b);



/* ===========================================================================
   BEGINNING OF PRIVATE INLINE IMPLEMENTATION
   ========================================================================== */

static inline void useful_buf_c_free(struct q_useful_buf_c b)
{
    if(b.ptr) {
        /* cast is to remove the constness */
        free((void *)b.ptr);
    }
}


static inline void useful_buf_free(struct q_useful_buf b)
{
    if(b.ptr) {
        /* cast is to remove the constness */
        free(b.ptr);
    }
}

#endif /* useful_buf_malloc_h */
