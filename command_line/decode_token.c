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

// outputs location claim in json format
int output_location_claim(FILE *output_file, struct ctoken_location_t *location)
{
    fprintf(output_file, "{\n");
    // TODO: spelling of lattitude in ctoken lib
    fprintf(output_file, "   \"lattitude\": %f,\n", location->eat_loc_latitude);
    fprintf(output_file, "   \"longitude\": %f\n", location->eat_loc_longitude);
    fprintf(output_file, "}\n");

// TODO: the rest of parts

    return 0;
}


int decode_cbor(FILE *output_file, struct q_useful_buf_c input_bytes, int output_format)
{
    struct ctoken_decode_ctx decode_context;
    enum ctoken_err_t error;

    ctoken_decode_init(&decode_context,
                       0,
                       0,
                       0);

    error = ctoken_decode_validate_token(&decode_context, input_bytes);
    if(error) {
        return -9;
    }

    while(1) {
        QCBORItem claim_item;

        error = ctoken_decode_next_claim(&decode_context, &claim_item);
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

    if(arguments->input_file) {
        int file_descriptor;
        if(!strcmp(arguments->input_file, "-")) {
            file_descriptor = 0;
        } else {
            file_descriptor = open(arguments->input_file, O_RDONLY);
            if(file_descriptor < 0) {
                fprintf(stderr, "can't open %s\n", arguments->input_file);
                return -1;
            }
        }
        input_bytes = read_file(file_descriptor);
        if(UsefulBuf_IsNULLC(input_bytes)) {
            fprintf(stderr, "error reading %s\n", arguments->input_file);
            return -2;
        }
    }

    int output_file_descriptor = 1;

    decode_cbor(input_bytes, output_file_descriptor, arguments->output_format);



    return 0;
}
