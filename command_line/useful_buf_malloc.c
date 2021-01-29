//
//  useful_buf_malloc.c
//  CToken
//
//  Created by Laurence Lundblade on 1/29/21.
//  Copyright © 2021 Laurence Lundblade. All rights reserved.
//

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


void useful_buf_free(struct q_useful_buf_c b)
{
    if(b.ptr) {
        /* cast is to remove the constness */
        free((void *)b.ptr);
    }
}
