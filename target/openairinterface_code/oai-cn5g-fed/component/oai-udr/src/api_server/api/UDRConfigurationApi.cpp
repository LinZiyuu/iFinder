/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UDRConfigurationApi.h"
#include "Helpers.h"
#include "udr_config.hpp"
#include "udr_sbi_helper.hpp"

extern oai::udr::config::udr_config udr_cfg;

namespace oai::udr::api {

using namespace oai::model::common::helpers;
using namespace oai::udr::api;

UDRConfigurationApi::UDRConfigurationApi(
    std::shared_ptr<Pistache::Rest::Router> rtr) {
  router = rtr;
}

void UDRConfigurationApi::init() {
  setupRoutes();
}

void UDRConfigurationApi::setupRoutes() {
  using namespace Pistache::Rest;

  Routes::Get(
      *router,
      udr_sbi_helper::UdrConfigurationServiceBase +
          udr_sbi_helper::UdrConfPathConfiguration,
      Routes::bind(&UDRConfigurationApi::read_configuration_handler, this));

  Routes::Put(
      *router,
      udr_sbi_helper::UdrConfigurationServiceBase +
          udr_sbi_helper::UdrConfPathConfiguration,
      Routes::bind(&UDRConfigurationApi::update_configuration_handler, this));

  // Default handler, called when a route is not found
  router->addCustomHandler(Routes::bind(
      &UDRConfigurationApi::configuration_api_default_handler, this));
}

void UDRConfigurationApi::read_configuration_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  try {
    this->read_configuration(response);
  } catch (nlohmann::detail::exception& e) {
    // send a 400 error
    response.send(Pistache::Http::Code::Bad_Request, e.what());
    return;
  } catch (Pistache::Http::HttpError& e) {
    response.send(static_cast<Pistache::Http::Code>(e.code()), e.what());
    return;
  } catch (std::exception& e) {
    // send a 500 error
    response.send(Pistache::Http::Code::Internal_Server_Error, e.what());
    return;
  }
}

void UDRConfigurationApi::update_configuration_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  try {
    auto configuration_info = nlohmann::json::parse(request.body());
    this->update_configuration(configuration_info, response);
  } catch (nlohmann::detail::exception& e) {
    // send a 400 error
    response.send(Pistache::Http::Code::Bad_Request, e.what());
    return;
  } catch (Pistache::Http::HttpError& e) {
    response.send(static_cast<Pistache::Http::Code>(e.code()), e.what());
    return;
  } catch (std::exception& e) {
    // send a 500 error
    response.send(Pistache::Http::Code::Internal_Server_Error, e.what());
    return;
  }
}

void UDRConfigurationApi::configuration_api_default_handler(
    const Pistache::Rest::Request&, Pistache::Http::ResponseWriter response) {
  response.send(
      Pistache::Http::Code::Not_Found, "The requested method does not exist");
}

}  // namespace oai::udr::api
