//
//  jtoken_adapt.h
//  CToken
//
//  Created by Laurence Lundblade on 2/15/21.
//  Copyright © 2021 Laurence Lundblade. All rights reserved.
//

#ifndef jtoken_adapt_h
#define jtoken_adapt_h

#include "xclaim.h"
#include "jtoken_encode.h"
//#include "jtoken_decode.h" // No JWT decoder yet

int xclaim_jtoken_encode_init(xclaim_encode *out, struct jtoken_encode_ctx *ctx);


//int xclaim_jtoken_decode_init(iclaims *ic, struct jtoken_decode_ctx *ctx);

#endif /* jtoken_adapt_h */
