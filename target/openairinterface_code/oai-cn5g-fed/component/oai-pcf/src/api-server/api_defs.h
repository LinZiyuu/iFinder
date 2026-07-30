/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#pragma once
#include <string>

namespace oai::pcf::api {
class sm_policies {
 public:
  static inline const std::string API_NAME     = "npcf-smpolicycontrol";
  static inline const std::string API_BASE     = "/" + API_NAME + "/";
  static inline const std::string CREATE_ROUTE = "/sm-policies";

  static std::string get_route();
};

class app_sessions {
 public:
  static inline const std::string API_NAME     = "npcf-policyauthorization";
  static inline const std::string API_BASE     = "/" + API_NAME + "/";
  static inline const std::string CREATE_ROUTE = "/app-sessions";

  static std::string get_route();
};

class policy_decision_provisioning {
 public:
  static inline const std::string API_NAME = "npcf-provisioning";
  static inline const std::string API_BASE = "/" + API_NAME + "/";

  static std::string get_provisioning_base();
};

}  // namespace oai::pcf::api