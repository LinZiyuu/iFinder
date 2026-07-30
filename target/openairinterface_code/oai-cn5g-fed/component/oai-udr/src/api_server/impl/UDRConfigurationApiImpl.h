/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef UDR_CONFIGURATION_API_IMPL_H_
#define UDR_CONFIGURATION_API_IMPL_H_

#include "udr_app.hpp"
#include <UDRConfigurationApi.h>
#include <pistache/http.h>
#include <pistache/optional.h>

namespace oai::udr::api {

using namespace oai::udr::model;
using namespace oai::udr::app;

class UDRConfigurationApiImpl : public oai::udr::api::UDRConfigurationApi {
 private:
  udr_app* m_udr_app;

 public:
  UDRConfigurationApiImpl(
      std::shared_ptr<Pistache::Rest::Router>, udr_app* udr_app_inst);
  ~UDRConfigurationApiImpl() {}

  void read_configuration(Pistache::Http::ResponseWriter& response);

  void update_configuration(
      nlohmann::json& configuration_info,
      Pistache::Http::ResponseWriter& response);
};

}  // namespace oai::udr::api

#endif
