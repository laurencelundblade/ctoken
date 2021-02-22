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
#include <string.h>
#include <stdlib.h>


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



int main(int argc, const char * argv[])
{
    int return_value;

    // This call prints out sizes of data structures to remind us
    // to keep them small.
    PrintSizesCToken(&fputs_wrapper, stdout);

    // This runs all the tests
    return_value = RunTestsCToken(argv+1, &fputs_wrapper, stdout, NULL);


    return return_value;
}
