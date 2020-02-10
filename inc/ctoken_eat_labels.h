/*
 * ctoken_eat_labels.h
 *
 * Copyright (c) 2020 Laurence Lundblade.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created by Laurence Lundblade on 2/1/20.
 */


#ifndef eat_labels_h
#define eat_labels_h

/* These are temporary labels until the real ones are assigned by IANA */

#define CTOKEN_EAT_LABEL_UEID 100000

#define CTOKEN_EAT_LABEL_NONCE 100001

#define CTOKEN_EAT_LABEL_OEMID  100002

#define CTOKEN_EAT_LABEL_ORIGINATION  100003

#define CTOKEN_EAT_LABEL_SECURITY_LEVEL 100004

enum ctoken_eat_security_level_t {UNRESTRICTED, RESTRICTED, SECURE_RESTRICTED, HARDWARE};

#define CTOKEN_EAT_LABEL_BOOT_STATE 100005

enum ctoken_eat_debug_level_t {NOT_REPORTED = 0,
                               NOT_DISABLED = 1,
                               DISABLED = 2,
                               DISABLED_SINCE_BOOT = 3,
                               PERMANENT_DISABLE = 4,
                               FULL_PERMANENT_DISABLE = 5};



#endif /* eat_labels_h */
