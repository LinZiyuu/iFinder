
/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include "3gpp_29.500.h"

#include <pistache/http_headers.h>

namespace oai::pcf::api {

struct api_response {
  uint16_t status_code;
  Pistache::Http::Header::Collection headers;
  std::string body;
};

}  // namespace oai::pcf::api