/*==============================================================================
 run_tests.c -- test aggregator and results reporting

 Copyright (c) 2018-2021, Laurence Lundblade. All rights reserved.

 SPDX-License-Identifier: BSD-3-Clause

 See BSD-3-Clause license in README.md

 Created on 9/30/18
 =============================================================================*/

#include "run_tests.h"
#include "qcbor/UsefulBuf.h"
#include <stdbool.h>
#include <stddef.h>

#include "cwt_test.h"
#include "eat_test.h"
#include "psa_test.h"

/*
 Test configuration
 */

typedef int_fast32_t (test_fun_t)(void);
typedef const char * (test_fun2_t)(void);


#define TEST_ENTRY(test_name)  {#test_name, test_name, true}
#define TEST_ENTRY_DISABLED(test_name)  {#test_name, test_name, false}

typedef struct {
    const char  *szTestName;
    test_fun_t  *test_fun;
    bool         bEnabled;
} test_entry;

#ifdef STRING_RETURNING_TESTS
typedef struct {
    const char *szTestName;
    test_fun2_t  *test_fun;
    bool         bEnabled;
} test_entry2;


static test_entry2 s_tests2[] = {
};
#endif

static test_entry s_tests[] = {
    TEST_ENTRY(hw_version_encode_test),
    TEST_ENTRY(hw_version_decode_test),
    TEST_ENTRY(decode_sw_components_test),
    TEST_ENTRY(basic_types_decode_test),
    TEST_ENTRY(basic_types_encode_test),
    TEST_ENTRY(map_and_array_test),
    TEST_ENTRY(profile_decode_test),
    TEST_ENTRY(profile_encode_test),
    TEST_ENTRY(secboot_test),
    TEST_ENTRY(minimal_get_size_test),
    TEST_ENTRY(psa_basic_test),
    TEST_ENTRY(basic_eat_test),
    TEST_ENTRY(cwt_test),
    TEST_ENTRY(submods_test),
    TEST_ENTRY(submods_encode_errors_test),
    TEST_ENTRY(submod_decode_errors_test),
    TEST_ENTRY(location_test),
    TEST_ENTRY(debug_and_boot_test),
    TEST_ENTRY(cwt_tags_test),
    TEST_ENTRY(get_next_test)
};



/**
  \brief Convert number to ASCII string, similar to sprint

  \param [in]  nNum       The 32-bit integer to convert.
  \param [in]  StringMem  The buffer to output to.

  \return POinter to NULL-terminated string with result or "XXX" on failure.

 Convert a number up to 999999999 to a string. This is so sprintf doesn't
 have to be linked in so as to minimized dependencies even in test code.

 StringMem should be 12 bytes long, 9 for digits, 1 for minus and
 1 for \0 termination.
 */
static const char *NumToString(int32_t nNum, UsefulBuf StringMem)
{
   const int32_t nMax = 1000000000;

   UsefulOutBuf OutBuf;
   UsefulOutBuf_Init(&OutBuf, StringMem);

   if(nNum < 0) {
      UsefulOutBuf_AppendByte(&OutBuf, '-');
      nNum = -nNum;
   }
   if(nNum > nMax-1) {
      return "XXX";
   }

   bool bDidSomeOutput = false;
   for(int32_t n = nMax; n > 0; n/=10) {
      int32_t x = nNum/n;
      if(x || bDidSomeOutput){
         bDidSomeOutput = true;
         UsefulOutBuf_AppendByte(&OutBuf, '0' + x);
         nNum -= x * n;
      }
   }
   if(!bDidSomeOutput){
      UsefulOutBuf_AppendByte(&OutBuf, '0');
   }
   UsefulOutBuf_AppendByte(&OutBuf, '\0');

   return UsefulOutBuf_GetError(&OutBuf) ? "" : StringMem.ptr;
}


/*
 Public function. See run_test.h.
 */
int RunTestsCToken(const char    *szTestNames[],
                  OutputStringCB pfOutput,
                  void          *poutCtx,
                  int           *pNumTestsRun)
{
    // int (-32767 to 32767 according to C standard) used by conscious choice
    int nTestsFailed = 0;
    int nTestsRun = 0;
    UsefulBuf_MAKE_STACK_UB(StringStorage, 12);

#ifdef STRING_RETURNING_TESTS

    test_entry2 *t2;
    const test_entry2 *s_tests2_end = s_tests2 + sizeof(s_tests2)/sizeof(test_entry2);

    for(t2 = s_tests2; t2 < s_tests2_end; t2++) {
        if(szTestNames[0]) {
            // Some tests have been named
            const char **szRequestedNames;
            for(szRequestedNames = szTestNames; *szRequestedNames;  szRequestedNames++) {
                if(!strcmp(t2->szTestName, *szRequestedNames)) {
                    break; // Name matched
                }
            }
            if(*szRequestedNames == NULL) {
                // Didn't match this test
                continue;
            }
        } else {
            // no tests named, but don't run "disabled" tests
            if(!t2->bEnabled) {
                // Don't run disabled tests when all tests are being run
                // as indicated by no specific test names being given
                continue;
            }
        }
        const char * szTestResult = (t2->test_fun)();
        nTestsRun++;
        if(pfOutput) {
            (*pfOutput)(t2->szTestName, poutCtx, 0);
        }

        if(szTestResult) {
            if(pfOutput) {
                (*pfOutput)(" FAILED (returned ", poutCtx, 0);
                (*pfOutput)(szTestResult, poutCtx, 0);
                (*pfOutput)(")", poutCtx, 1);
            }
            nTestsFailed++;
        } else {
            if(pfOutput) {
                (*pfOutput)( " PASSED", poutCtx, 1);
            }
        }
    }
#endif


    test_entry *t;
    const test_entry *s_tests_end = s_tests + sizeof(s_tests)/sizeof(test_entry);

    for(t = s_tests; t < s_tests_end; t++) {
        if(szTestNames[0]) {
            // Some tests have been named
            const char **szRequestedNames;
            for(szRequestedNames = szTestNames; *szRequestedNames;  szRequestedNames++) {
                if(!strcmp(t->szTestName, *szRequestedNames)) {
                    break; // Name matched
                }
            }
            if(*szRequestedNames == NULL) {
                // Didn't match this test
                continue;
            }
        } else {
            // no tests named, but don't run "disabled" tests
            if(!t->bEnabled) {
                // Don't run disabled tests when all tests are being run
                // as indicated by no specific test names being given
                continue;
            }
        }

        int nTestResult = (t->test_fun)();
        nTestsRun++;
        if(pfOutput) {
            (*pfOutput)(t->szTestName, poutCtx, 0);
        }

        if(nTestResult) {
            if(pfOutput) {
                (*pfOutput)(" FAILED (returned ", poutCtx, 0);
                (*pfOutput)(NumToString(nTestResult, StringStorage), poutCtx, 0);
                (*pfOutput)(")", poutCtx, 1);
            }
            nTestsFailed++;
        } else {
            if(pfOutput) {
                (*pfOutput)( " PASSED", poutCtx, 1);
            }
        }
    }

    if(pNumTestsRun) {
        *pNumTestsRun = nTestsRun;
    }

    if(pfOutput) {
        (*pfOutput)( "SUMMARY: ", poutCtx, 0);
        (*pfOutput)( NumToString(nTestsRun, StringStorage), poutCtx, 0);
        (*pfOutput)( " tests run; ", poutCtx, 0);
        (*pfOutput)( NumToString(nTestsFailed, StringStorage), poutCtx, 0);
        (*pfOutput)( " tests failed", poutCtx, 1);
    }

    return nTestsFailed;
}


/*
 Public function. See run_test.h.
 */
static void PrintSize(const char *szWhat,
                      uint32_t uSize,
                      OutputStringCB pfOutput,
                      void *pOutCtx)
{
   UsefulBuf_MAKE_STACK_UB(buffer, 20);

   (*pfOutput)(szWhat, pOutCtx, 0);
   (*pfOutput)(" ", pOutCtx, 0);
   (*pfOutput)(NumToString(uSize, buffer), pOutCtx, 0);
   (*pfOutput)("", pOutCtx, 1);
}




#include "ctoken/ctoken_encode.h" /* For struct size printing */
#include "ctoken/ctoken_decode.h" /* For struct size printing */

/*
 Public function. See run_test.h.
 */
void PrintSizesCToken(OutputStringCB pfOutput, void *pOutCtx)
{
   // Type and size of return from sizeof() varies. These will never be large
   // so cast is safe.
    PrintSize("sizeof(ctoken_decode_context)",
              (uint32_t)sizeof(struct ctoken_decode_ctx),
              pfOutput, pOutCtx);
    PrintSize("sizeof(ctoken_encode_ctx)",
              (uint32_t)sizeof(struct ctoken_encode_ctx),
              pfOutput, pOutCtx);
    (*pfOutput)("", pOutCtx, 1);
}

