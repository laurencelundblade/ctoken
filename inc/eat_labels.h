//
//  eat_labels.h
//  CToken
//
//  Created by Laurence Lundblade on 2/1/20.
//  Copyright © 2020 Laurence Lundblade. All rights reserved.
//

#ifndef eat_labels_h
#define eat_labels_h

#define UEID_LABEL 80000

#define EAT_LABEL_NONCE 7999

#define EAT_LABEL_OEMID  80001

#define EAT_LABEL_ORIGINATION  80002

#define EAT_LABEL_SECURITY_LEVEL 80003

enum eat_security_level_t {UNRESTRICTED, RESTRICTED, SECURE_RESTRICTED, HARDWARE};

#define EAT_LABEL_BOOT_STATE 80004

enum eat_debug_level_t {NOT_REPORTED = 0,
                        NOT_DISABLED = 1,
                        DISABLED = 2,
                        DISABLED_SINCE_BOOT = 3,
                        PERMANENT_DISABLE = 4,
                        FULL_PERMANENT_DISABLE = 5};



#endif /* eat_labels_h */
