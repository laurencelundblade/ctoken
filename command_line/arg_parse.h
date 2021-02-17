/*
 * arg_parse.h
 *
 * Copyright (c) 2021, Laurence Lundblade.
 *
 * Created by Laurence Lundblade on 1/29/21.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef arg_parse_h
#define arg_parse_h

#include "decode_token.h"
#include "ctoken_eat_labels.h"
#include "ctoken.h" // TODO: dependency issue
#include "xclaim.h"



/**
 * @brief Main / initial parse of argv and put results into arguments stucture.
 *
 * @return 0 on success; 1 on failure
 *
 * free_arguments() must be called to deallocate memory that was allocated by this.
 */
int parse_arguments(int                      argc,
                    char                   **argv,
                    struct ctoken_arguments *arguments);


void free_arguments(struct ctoken_arguments *arguments);


struct parg {

    const char **claim_args;

    const char **iterator;
};



int setup1_parg_decode(xclaim_decoder *ic, struct parg *ctx, const char **claims_args);



#endif /* arg_parse_h */
