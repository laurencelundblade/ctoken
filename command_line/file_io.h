//
//  file_io.h
//  CToken
//
//  Created by Laurence Lundblade on 2/1/21.
//  Copyright © 2021 Laurence Lundblade. All rights reserved.
//

#ifndef file_io_h
#define file_io_h

#include "t_cose/q_useful_buf.h"
#include <stdio.h>


/* Read the contents of a file into malloced buffer
*
*
*/
struct q_useful_buf_c read_file(int file_descriptor);


/* returns 0 if write was successful, 1 if not */
int write_bytes(FILE *out_file, struct q_useful_buf_c token);


#endif /* file_io_h */
