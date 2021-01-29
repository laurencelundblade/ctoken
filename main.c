/*
 *  main.c
 *
 * Copyright 2019-2021, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md.
 *
 * Created 4/21/2019.
 */

#include <stdio.h>
#include "run_tests.h"
#include "decode_token.h"
#include <string.h>
#include <stdlib.h>
#include "arg_parse.h"


/*
 This is an implementation of OutputStringCB built using stdio. If
 you don't have stdio, replaces this.
 */
static void fputs_wrapper(const char *szString, void *pOutCtx, int bNewLine)
{
    fputs(szString, (FILE *)pOutCtx);
    if(bNewLine) {
        fputs("\n", pOutCtx);
    }
}

void ct_main(void);


int ctoken(const struct ctoken_arguments *arguments);


int main(int argc, char * argv[])
{
    int return_value = 0;

    struct ctoken_arguments arguments;

    return_value = parse_arguments(argc, argv, &arguments);
    if(return_value != 0) {
        return return_value;
    }

    return_value = ctoken(&arguments);

    // ct_main();

    // This call prints out sizes of data structures to remind us
    // to keep them small.
    //PrintSizesCToken(&fputs_wrapper, stdout);

    // This runs all the tests
    //return_value = RunTestsCToken(argv+1, &fputs_wrapper, stdout, NULL);


    return return_value;
}
