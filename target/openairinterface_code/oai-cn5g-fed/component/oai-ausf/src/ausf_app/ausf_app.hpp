/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_AUSF_APP_HPP_SEEN
#define FILE_AUSF_APP_HPP_SEEN
#include <pistache/http.h>

#include <map>
#include <shared_mutex>
#include <string>

#include "AuthenticationInfo.h"
#include "ConfirmationData.h"
#include "UEAuthenticationCtx.h"
#include "ausf.h"
#include "ausf_event.hpp"

namespace oai {
namespace ausf {
namespace app {

using namespace oai::model::ausf;

class security_context {
 public:
  security_context() : xres_star() {
    ausf_av_s  = {};
    supi       = {};
    auth_type  = {};
    serving_nn = {};
    kausf_tmp  = {};
  }

  AUSF_AV_s ausf_av_s;
  uint8_t xres_star[16];   // store xres*
  std::string supi;        // store supi
  std::string auth_type;   // store authType
  std::string serving_nn;  // store serving network name
  std::string kausf_tmp;   // store Kausf(string)
};

// class ausf_config;
class ausf_app {
 public:
  explicit ausf_app(const std::string& config_file, ausf_event& ev);
  ausf_app(ausf_app const&) = delete;
  void operator=(ausf_app const&) = delete;

  virtual ~ausf_app();

  bool start();
  void stop();

  void handle_ue_authentications(
      const AuthenticationInfo& authenticationInfo, nlohmann::json& json_data,
      std::string& location, Pistache::Http::Code& code,
      uint8_t http_version = 1);

  void handle_ue_authentications_confirmation(
      const std::string& authCtxId, const ConfirmationData& confirmation_data,
      nlohmann::json& json_data, Pistache::Http::Code& code);

  bool is_supi_2_security_context(const std::string& supi) const;
  std::shared_ptr<security_context> supi_2_security_context(
      const std::string& supi) const;
  void set_supi_2_security_context(
      const std::string& supi, std::shared_ptr<security_context> sc);

  bool is_contextId_2_security_context(const std::string& contextId) const;
  std::shared_ptr<security_context> contextId_2_security_context(
      const std::string& contextId) const;
  void set_contextId_2_security_context(
      const std::string& contextId, std::shared_ptr<security_context> sc);

 private:
  ausf_event& event_sub;

  std::map<std::string, std::shared_ptr<security_context>>
      supi2security_context;
  mutable std::shared_mutex m_supi2security_context;

  std::map<std::string, std::shared_ptr<security_context>>
      contextId2security_context;
  mutable std::shared_mutex m_contextId2security_context;
};
}  // namespace app
}  // namespace ausf
}  // namespace oai
#include "ausf_config.hpp"

#endif /* FILE_AUSF_APP_HPP_SEEN */
