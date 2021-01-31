//
//  base64.h
//  CToken
//
//  Created by Laurence Lundblade on 1/30/21.
//  Copyright © 2021 Laurence Lundblade. All rights reserved.
//

#ifndef base64_h
#define base64_h

#include <stdint.h>

char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length);

unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length);

#endif /* base64_h */
