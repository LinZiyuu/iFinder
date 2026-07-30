/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "N2InfoNotifyApi.h"

#include <nlohmann/json.hpp>

#include "lmf_config.hpp"
#include "lmf_sbi_helper.hpp"
#include "logger.hpp"

using namespace Pistache;

namespace oai::lmf::api {
using namespace oai::lmf::api;

N2InfoNotifyApi::N2InfoNotifyApi(std::shared_ptr<Pistache::Rest::Router> rtr) {
  router = rtr;
}

void N2InfoNotifyApi::init() {
  setupRoutes();
}

void N2InfoNotifyApi::setupRoutes() {
  Rest::Routes::Post(
      *router,
      lmf_sbi_helper::LmfN2InfoNotifyServiceBase +
          lmf_sbi_helper::LmfN2InfoNotifyNrppaCallbackUeContextId,
      Rest::Routes::bind(&N2InfoNotifyApi::notify_n2info_nrppa_handler, this));

  // Default handler, called when a route is not found
  router->addCustomHandler(Rest::Routes::bind(
      &N2InfoNotifyApi::notify_n2info_default_handler, this));
}

void N2InfoNotifyApi::notify_n2info_nrppa_handler(
    const Rest::Request& request, Http::ResponseWriter response) {
  // Getting the path params
  auto ueContextId = request.param(":ueContextId").as<std::string>();
  Logger::lmf_server().debug(
      "Received a N2InfoNotify NRPPA notification with ue_ctx_id %s",
      ueContextId.c_str());
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
    this->receive_n2info_nrppa_notification(ueContextId, parts, response);
    response.send(Pistache::Http::Code(204));
  } catch (nlohmann::detail::exception& e) {
    // send a 400 error
    response.send(Http::Code::Bad_Request, e.what());
  } catch (Http::HttpError& e) {
    response.send(static_cast<Http::Code>(e.code()), e.what());
  } catch (std::exception& e) {
    // send a 500 error
    response.send(Http::Code::Internal_Server_Error, e.what());
  }
}

void N2InfoNotifyApi::notify_n2info_default_handler(
    const Rest::Request&, Http::ResponseWriter response) {
  response.send(Http::Code::Not_Found, "The requested method does not exist");
}

}  // namespace oai::lmf::api
