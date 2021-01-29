//
//  useful_buf_malloc.h
//  CToken
//
//  Created by Laurence Lundblade on 1/29/21.
//  Copyright © 2021 Laurence Lundblade. All rights reserved.
//

#ifndef useful_buf_malloc_h
#define useful_buf_malloc_h

#include "t_cose/q_useful_buf.h"


struct q_useful_buf useful_malloc(size_t size);


void useful_buf_free(struct q_useful_buf_c b);

#endif /* useful_buf_malloc_h */
