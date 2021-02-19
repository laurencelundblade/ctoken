/*
 * useful_file_io.c
 *
 * Copyright (c) 2021, Laurence Lundblade.
 *
 * Created by Laurence Lundblade on 2/1/21.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "useful_file_io.h"

#include <unistd.h>
#include <stdlib.h>




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
                /* malloc error exit */
                return NULL_Q_USEFUL_BUF_C;
            }
        } else {
            file_content = realloc(file_content, amount_read + file_size);
            if(file_content == NULL) {
                /* malloc error exit */
                return NULL_Q_USEFUL_BUF_C;
            }
        }

        memcpy(file_content + file_size, input_buf, amount_read);
        file_size += amount_read;
    }

    return (struct q_useful_buf_c){file_content, file_size};
}



int write_bytes(FILE *out_file, struct q_useful_buf_c data)
{
    size_t x = fwrite(data.ptr, 1, data.len, out_file);

    return x == data.len ? 1 : 0;
}
