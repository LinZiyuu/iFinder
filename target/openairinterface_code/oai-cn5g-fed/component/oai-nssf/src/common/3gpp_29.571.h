/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_3GPP_29_571_SEEN
#define FILE_3GPP_29_571_SEEN

#include "3gpp_23.003.h"
#include "3gpp_29.510.h"

#include <vector>

enum access_type_e { ACESS_3GPP = 1, ACESS_NON_3GPP = 2 };

static const std::vector<std::string> access_type_e2str = {
    "3GPP_ACCESS", "NON_3GPP_ACCESS"};

typedef struct sd_range_s {
  std::string start;
  std::string end;
} sd_range_t;

typedef struct snssai_extension_s {
  std::vector<sd_range_t> sd_ranges;
  bool wildcard_sd;
} snssai_extension_t;

typedef struct ext_snssai_s {
  snssai_t snssai;
  snssai_extension_t snssai_extension;
} ext_snssai_t;
#endif
