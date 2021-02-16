//
//  ctoken_adapt.h
//  CToken
//
//  Created by Laurence Lundblade on 2/14/21.
//  Copyright © 2021 Laurence Lundblade. All rights reserved.
//

#ifndef ctoken_adapt_h
#define ctoken_adapt_h

#include "xclaim.h"
#include "ctoken_encode.h"
#include "ctoken_decode.h"


int xclaim_ctoken_encode_init(xclaim_encode *out, struct ctoken_encode_ctx *ctx);


int xclaim_ctoken_decode_init(xclaim_decoder *ic, struct ctoken_decode_ctx *ctx);


#endif /* ctoken_adapt_h */
