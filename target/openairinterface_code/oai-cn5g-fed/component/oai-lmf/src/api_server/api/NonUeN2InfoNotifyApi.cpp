/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "NonUeN2InfoNotifyApi.h"

#include <nlohmann/json.hpp>

#include "lmf_config.hpp"
#include "lmf_sbi_helper.hpp"
#include "logger.hpp"

using namespace Pistache;

namespace oai::lmf::api {

using namespace oai::lmf::api;

NonUeN2InfoNotifyApi::NonUeN2InfoNotifyApi(
    std::shared_ptr<Pistache::Rest::Router> rtr) {
  router = rtr;
}

void NonUeN2InfoNotifyApi::init() {
  setupRoutes();
}

void NonUeN2InfoNotifyApi::setupRoutes() {
  Rest::Routes::Post(
      *router,
      lmf_sbi_helper::LmfNonUeN2InfoNotifyServiceBase +
          lmf_sbi_helper::LmfNonUeN2InfoNotifyNrppaCallback,
      Rest::Routes::bind(
          &NonUeN2InfoNotifyApi::notify_non_ue_n2info_nrppa_handler, this));

  // Default handler, called when a route is not found
  router->addCustomHandler(Rest::Routes::bind(
      &NonUeN2InfoNotifyApi::notify_non_ue_n2info_default_handler, this));
}

void NonUeN2InfoNotifyApi::notify_non_ue_n2info_nrppa_handler(
    const Rest::Request& request, Http::ResponseWriter response) {
  // Getting the path params
  Logger::lmf_server().debug("Received a NonUeN2InfoNotify NRPPA notification");
  // Getting the body param

  // simple parser
  mime_parser sp = {};
  if (!sp.parse(request.body())) {
    Logger::lmf_server().error("Bad request: parse failed: %s", request.body());
    response.send(Http::Code::Bad_Request);
    return;
  }

  std::vector<mime_part> parts = {};
  sp.get_mime_parts(parts);
  uint8_t size = parts.size();
  Logger::lmf_server().debug("Number of MIME parts %d", size);

  // 2 parts:Json data and N2
  if (size != 2) {
    Logger::lmf_server().debug(
        "Bad request: should have at least 2 MIME parts");
    response.send(Http::Code::Bad_Request);
    return;
  }

  for (auto it : parts) {
    Logger::lmf_server().debug(
        "MIME part: %s (size %d bytes)", it.content_type.c_str(),
        it.body.size());
  }

  try {
    this->receive_non_ue_n2info_nrppa_notification(parts, response);
  } catch (nlohmann::detail::exception& e) {
    // send a 400 error
    response.send(Http::Code::Bad_Request, e.what());
    return;
  } catch (Http::HttpError& e) {
    response.send(static_cast<Http::Code>(e.code()), e.what());
    return;
  } catch (std::exception& e) {
    // send a 500 error
    response.send(Http::Code::Internal_Server_Error, e.what());
    return;
  }
}

void NonUeN2InfoNotifyApi::notify_non_ue_n2info_default_handler(
    const Rest::Request&, Http::ResponseWriter response) {
  response.send(Http::Code::Not_Found, "The requested method does not exist");
}

}  // namespace oai::lmf::api
