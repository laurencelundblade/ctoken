//
//  decode_token.c
//  CToken
//
//  Created by Laurence Lundblade on 1/11/21.
//  Copyright © 2021 Laurence Lundblade. All rights reserved.
//

#include "decode_token.h"
#include "t_cose/q_useful_buf.h"
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include "ctoken_decode.h"
#include <sys/errno.h>


#define INDENTION_INCREMENT 2

void indent(FILE *output_file, int indention_level)
{
    indention_level *= INDENTION_INCREMENT;

    while(indention_level > 0) {
        fputc(' ', output_file);
        indention_level--;
    }
}


// outputs location claim in json format
int output_location_claim(FILE *output_file, int indention_level, const struct ctoken_location_t *location)
{
    indent(output_file, indention_level);
    fprintf(output_file, "\"location\" : {\n");
    // TODO: spelling of lattitude in ctoken lib
    indent(output_file, indention_level);
    fprintf(output_file, "   \"lattitude\": %f,\n", location->eat_loc_latitude);
    indent(output_file, indention_level);
    fprintf(output_file, "   \"longitude\": %f\n", location->eat_loc_longitude);
    indent(output_file, indention_level);
    fprintf(output_file, "}\n");

// TODO: the rest of parts

    return 0;
}


struct label_map_t {
    int64_t     cbor_label;
    const char *json_name;
};


static const struct label_map_t label_map[] = {
    {CTOKEN_CWT_LABEL_ISSUER, "iss"},
    {CTOKEN_CWT_LABEL_SUBJECT, "sub"},
    {14, "seclevel"},
    {16, "dbgstat"},
    {0, NULL}
};


static const char *cbor_label_to_json_name(int64_t cbor_label)
{
    size_t i;

    for(i = 0; i < C_ARRAY_COUNT(label_map, struct label_map_t); i++) {
        if(label_map[i].cbor_label == cbor_label) {
            return(label_map[i].json_name);
        }
    }
    return NULL;
}

/*
    switch(cbor_label) {

        case CTOKEN_CWT_LABEL_ISSUER: // 1
            return("iss");

        case CTOKEN_CWT_LABEL_SUBJECT: //     2
            return("sub");

        case CTOKEN_CWT_LABEL_AUDIENCE : //   3
            return("aud");

        case CTOKEN_CWT_LABEL_EXPIRATION:  // 4
            return("exp");

        case CTOKEN_CWT_LABEL_NOT_BEFORE: //  5
            return("nbf");

        case CTOKEN_CWT_LABEL_IAT: // 6
            return("iat");

        case CTOKEN_CWT_LABEL_CTI :      //  7
            return("cti");


        case CTOKEN_EAT_LABEL_UEID:
        case 10:
            return("ueid");

        case CTOKEN_EAT_LABEL_NONCE:
        case 11:
            return("nonce");

        case CTOKEN_EAT_LABEL_OEMID:
        case 12:
            return("oemid");

        case CTOKEN_EAT_LABEL_SECURITY_LEVEL:
        case 13:
            return("seclevel");

        case CTOKEN_EAT_LABEL_BOOT_STATE:
        case 14:
            return("bootstate");

            case CTOKEN_EAT_LABEL_SECURE_BOOT -76007
            case CTOKEN_EAT_LABEL_DEBUG_STATE -76008
            case CTOKEN_EAT_LABEL_LOCATION -76004
            case CTOKEN_EAT_LABEL_UPTIME -76006
            case CTOKEN_EAT_LABEL_INTENDED_USE -76009

            // TODO: fill in lots of labels
        default:
            return NULL;
    }
}
*/

void output_int64(FILE *output_file, int indention_level, const char *claim_name, int64_t claim_value)
{
    indent(output_file, indention_level);
    fprintf(output_file, "\"%s\": %lld\n", claim_name, claim_value);
}

void output_text_string(FILE *output_file, int indention_level, const char *claim_name, struct q_useful_buf_c claim_value)
{
    indent(output_file, indention_level);
    fprintf(output_file, "\"%s\":\"", claim_name);
    fwrite(claim_value.ptr, 1, claim_value.len, output_file);
    fprintf(output_file, "\"\n");
}


void output_other_claim(FILE *output_file,
                        int indention_level,
                        struct ctoken_decode_ctx *decode_context,
                        int64_t cbor_label)
{
    struct ctoken_location_t loc;


    switch(cbor_label) {

        case CTOKEN_EAT_LABEL_LOCATION:
            ctoken_decode_location(decode_context, &loc);
            // TODO: error check
            output_location_claim(output_file, indention_level, &loc);
            break;

        default:
            // Claim is aggregate that is not known. Must walk
            // the CBOR and convert to JSON.
            break;

    }
}



int decode_cbor(FILE *output_file, struct q_useful_buf_c input_bytes, int output_format)
{
    struct ctoken_decode_ctx decode_context;
    enum ctoken_err_t error;

    int indention_level = 0;

    ctoken_decode_init(&decode_context,
                       0,
                       0,
                       CTOKEN_PROTECTION_NONE);

    error = ctoken_decode_validate_token(&decode_context, input_bytes);
    if(error) {
        return -9;
    }

    while(1) {
        QCBORItem claim_item;

        error = ctoken_decode_next_claim(&decode_context, &claim_item);

        // TODO: make sure label is of the right type and/or handle alternate types
        const char *json_name = cbor_label_to_json_name(claim_item.label.int64);

        char substitue_json_name[20];
        snprintf(substitue_json_name, sizeof(substitue_json_name), "%lld", claim_item.label.int64);

        switch(claim_item.uDataType) {
            case QCBOR_TYPE_INT64:
                output_int64(output_file,
                             indention_level,
                             json_name ? json_name : substitue_json_name,
                             claim_item.val.int64);
                break;

            case QCBOR_TYPE_TEXT_STRING:
                output_text_string(output_file,
                                   indention_level,
                                   json_name ? json_name : substitue_json_name,
                                   claim_item.val.string);
                break;

            default:
                output_other_claim(output_file,
                                   indention_level,
                                   &decode_context,
                                   claim_item.label.int64);
        }



        /*

         Claim might be string or int in which case it has been obtained.
         Claim label might be known or not known
            If known, map to JSON claim key string

         If value is not string or int and known call the outputter for it.

         If value is not string or int and not known do what can be done.
         */

    }


    return 0;
}




/* Read the contents of a file into malloced buffer
 *
 *
 */
struct q_useful_buf_c read_file(int file_descriptor)
{
    char    input_buf[2048];
    char   *file_content;
    size_t  file_size;
    ssize_t amount_read;


    file_content = NULL;
    file_size    = 0;
    while(1) {
        amount_read = read(file_descriptor, input_buf, sizeof(input_buf));

        if(amount_read == 0) {
            /* normal exit */
            break;
        }

        if(amount_read < 0) {
            /* read error exit */
            return NULL_Q_USEFUL_BUF_C;
        }

        if(file_content == NULL) {
            file_content = malloc(amount_read);
            if(file_content == NULL) {
                return NULL_Q_USEFUL_BUF_C;
            }
        } else {
            file_content = realloc(file_content, amount_read + file_size);
        }

        memcpy(file_content + file_size, input_buf, amount_read);
        file_size += amount_read;
    }

    return (struct q_useful_buf_c){file_content, file_size};
}





int ctoken(const struct ctoken_arguments *arguments)
{
    struct q_useful_buf_c input_bytes = NULL_Q_USEFUL_BUF_C;
    FILE *output;

    if(arguments->input_file) {
        int file_descriptor;
        if(!strcmp(arguments->input_file, "-")) {
            file_descriptor = 0;
        } else {
            file_descriptor = open(arguments->input_file, O_RDONLY);
            if(file_descriptor < 0) {
                fprintf(stderr, "can't open input file \"%s\" (%d)\n", arguments->input_file, errno);
                return -1;
            }
        }
        input_bytes = read_file(file_descriptor);
        if(UsefulBuf_IsNULLC(input_bytes)) {
            fprintf(stderr, "error reading input file \"%s\"\n", arguments->input_file);
            return -2;
        }
    }

    if(arguments->output_file) {
        output = fopen(arguments->output_file, "r");
        if(output == NULL) {
            fprintf(stderr, "error opening output file \"%s\"\n", arguments->output_file);
            return -4;
        }
    } else {
        output = stdout;
    }


    decode_cbor(output, input_bytes, arguments->output_format);


    return 0;
}



void ct_main()
{
    struct ctoken_arguments arguments;

    memset(&arguments, 0, sizeof(arguments));

    arguments.input_file = "token.cbor";

    ctoken(&arguments);

}
