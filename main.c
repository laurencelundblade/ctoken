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
#include <getopt.h>
#include "decode_token.h"
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

void ct_main(void);


/* options descriptor */
enum arg_id_t {
    INPUT_FILE,
    OUTPUT_FILE,
    CLAIM,
    INPUT_FORMAT,
    OUTPUT_FORMAT,
    INPUT_PROTECTION,
    OUTPUT_PROTECTION,
    OUTPUT_TAGGING,
    NO_VERIFY
};

static const struct option longopts[] = {
    { "in",         required_argument,  NULL,  INPUT_FILE },
    { "out",        required_argument,  NULL,  OUTPUT_FILE },
    { "claim",      required_argument,  NULL,  CLAIM },
    { "in_form",    required_argument,  NULL,  INPUT_FORMAT },
    { "out_form",   required_argument,  NULL,  OUTPUT_FORMAT },
    { "in_prot",    required_argument,  NULL,  INPUT_PROTECTION },
    { "out_prot",   required_argument,  NULL,  OUTPUT_PROTECTION },
    { "out_tag",    required_argument,  NULL,  OUTPUT_TAGGING },
    { "no_verify",  no_argument,        NULL,  NO_VERIFY },
    { NULL,         0,                  NULL,  0 }
};

/*
 * @brief Parse argv and put results into arguments stucture.
 *
 * @return 0 on success; 1 on failure
 */
int parse_arguments(int argc, char **argv, struct ctoken_arguments *arguments)
{
    int return_value;
    int selected_opt;

    memset(arguments, 0, sizeof(*arguments));

    return_value = 0;

    while((selected_opt = getopt_long_only(argc, argv, "", longopts, NULL)) != EOF) {

        switch(selected_opt) {
            case INPUT_FILE:
                arguments->input_file = optarg;
                break;

            case OUTPUT_FILE:
                arguments->output_file = optarg;
                break;

            case CLAIM:
                if(arguments->claims) {
                    char **i;
                    for(i = arguments->claims; *i; i++);
                    size_t count = i - arguments->claims;

                    arguments->claims = realloc(arguments->claims,
                                                (count + 2) * sizeof(char *));
                    arguments->claims[count] = optarg;
                    arguments->claims[count+1] = NULL;
                } else {
                    arguments->claims = malloc(2 * sizeof(char *));
                    arguments->claims[0] = optarg;
                    arguments->claims[1] = NULL;
                }
                break;

            case INPUT_FORMAT:
                if(!strcasecmp(optarg, "cbor")) {
                    arguments->input_format = IN_FORMAT_CBOR;
                } else if(!strcasecmp(optarg, "json")) {
                    arguments->input_format = IN_FORMAT_JSON;
                } else {
                    fprintf(stderr, "Invalid input format: \"%s\"\n", optarg);
                    return_value = 1;
                    goto Done;
                }
                break;

            case OUTPUT_FORMAT:
                if(!strcasecmp(optarg, "cbor")) {
                    arguments->output_format = OUT_FORMAT_CBOR;
                } else if(!strcasecmp(optarg, "json")) {
                    arguments->output_format = OUT_FORMAT_JSON;
                } else {
                    fprintf(stderr, "Invalid output format: \"%s\"\n", optarg);
                    return_value = 1;
                    goto Done;
                }
                break;

            case INPUT_PROTECTION:
                if(!strcasecmp(optarg, "detect")) {
                    arguments->input_protection = IN_PROT_DETECT;
                } else if(!strcasecmp(optarg, "none")) {
                     arguments->input_protection = IN_PROT_NONE;
                } else if(!strcasecmp(optarg, "sign")) {
                     arguments->input_protection = IN_PROT_SIGN;
                } else if(!strcasecmp(optarg, "mac")) {
                     arguments->input_protection = IN_PROT_MAC;
                } else if(!strcasecmp(optarg, "sign_encrypt")) {
                     arguments->input_protection = IN_PROT_SIGN_ENCRYPT;
                } else if(!strcasecmp(optarg, "mac_encrypt")) {
                     arguments->input_protection = IN_PROT_MAC_ENCRYPT;
                } else {
                    fprintf(stderr, "Invalid input protection: \"%s\"\n", optarg);
                    return_value = 1;
                    goto Done;
                }

            case OUTPUT_PROTECTION:
                if(!strcasecmp(optarg, "none")) {
                     arguments->output_protection = OUT_PROT_NONE;
                } else if(!strcasecmp(optarg, "sign")) {
                     arguments->output_protection = OUT_PROT_SIGN;
                } else if(!strcasecmp(optarg, "mac")) {
                     arguments->output_protection = OUT_PROT_MAC;
                } else if(!strcasecmp(optarg, "sign_encrypt")) {
                     arguments->output_protection = OUT_PROT_SIGN_ENCRYPT;
                } else if(!strcasecmp(optarg, "mac_encrypt")) {
                     arguments->output_protection = OUT_PROT_MAC_ENCRYPT;
                } else {
                    fprintf(stderr, "Invalid output protection: \"%s\"\n", optarg);
                    return_value = 1;
                    goto Done;
                }

            case OUTPUT_TAGGING:
                if(!strcasecmp(optarg, "cwt")) {
                    arguments->output_tagging = OUT_TAG_CWT;
                } else if(!strcasecmp(optarg, "cose")) {
                    arguments->output_tagging = OUT_TAG_COSE;
                } else if(!strcasecmp(optarg, "none")) {
                    arguments->output_tagging = OUT_TAG_NONE;
                } else {
                    fprintf(stderr, "Invalid output tagging: \"%s\"\n", optarg);
                    return_value = 1;
                    goto Done;
                }

            case NO_VERIFY:
                arguments->no_verify = true;
                break;

            default:
                fprintf(stderr, "Oops. Input parameter parsing went wrong\n");
                return_value = 1;
        }
    }

  Done:
    return return_value;
}




int main(int argc, char * argv[])
{
    int return_value = 0;

    struct ctoken_arguments arguments;

    return_value = parse_arguments(argc, argv, &arguments);
    if(return_value != 0) {
        return return_value;
    }


    ct_main();

    // This call prints out sizes of data structures to remind us
    // to keep them small.
    //PrintSizesCToken(&fputs_wrapper, stdout);

    // This runs all the tests
    //return_value = RunTestsCToken(argv+1, &fputs_wrapper, stdout, NULL);


    return return_value;
}
