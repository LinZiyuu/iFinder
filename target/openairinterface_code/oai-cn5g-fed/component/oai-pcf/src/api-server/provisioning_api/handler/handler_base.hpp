/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once

#include <memory>
#include <functional>
#include <exception>
#include "api_response.h"
#include "database_wrapper_abstraction.hpp"

namespace oai::pcf::provisioning::api {

class handler_base {
 public:
 protected:
  oai::pcf::api::api_response handle_request_with_error_handling(
      std::function<bool()> db_operation);
  oai::pcf::api::api_response handle_request_with_error_handling_json_body(
      std::function<nlohmann::json()> db_operation);
};

}  // namespace oai::pcf::provisioning::api