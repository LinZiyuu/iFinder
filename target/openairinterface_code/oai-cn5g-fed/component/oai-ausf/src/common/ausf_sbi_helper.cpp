/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ausf_sbi_helper.hpp"

#include <boost/algorithm/string.hpp>
#include <regex>
#include <vector>

#include "ProblemDetails.h"
#include "logger.hpp"

namespace oai::ausf::api {
//------------------------------------------------------------------------------
void ausf_sbi_helper::set_problem_details(
    nlohmann::json& json_data, const std::string& detail) {
  Logger::ausf_server().error("%s", detail);
  oai::model::common::ProblemDetails problem_details;
  problem_details.setDetail(detail);
  to_json(json_data, problem_details);
}
}  // namespace oai::ausf::api
