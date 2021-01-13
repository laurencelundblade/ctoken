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


