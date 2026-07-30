/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once
#define FMT_HEADER_ONLY

#include <cpr/cpr.h>
#include <curl/curl.h>
#include <fmt/format.h>

#include <string>

#include "3gpp_29.500.h"

namespace oai::http {

struct response {
  int status_code;
  std::string body;
  cpr::Header headers;
};

struct request {
  std::string uri;
  std::string body;
  cpr::Header headers;

  std::string to_string() const {
    return fmt::format("HTTP Request to URI: {}", uri);
  }
};

enum class request_type_e { SIMPLE, ASYNC, MULTI_ASYNC, MULTI_PERFORM };

}  // namespace oai::http
