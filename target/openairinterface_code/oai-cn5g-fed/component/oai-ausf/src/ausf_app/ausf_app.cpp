/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ausf_app.hpp"

#include <unistd.h>

#include <algorithm>
#include <iterator>
#include <string>

#include "AuthenticationInfo.h"
#include "AuthResult.h"
#include "ConfirmationDataResponse.h"
#include "ProblemDetails.h"
#include "UEAuthenticationCtx.h"
#include "ausf_nrf.hpp"
#include "authentication_algorithms_with_5gaka.hpp"
#include "conversions.hpp"
#include "http_client.hpp"
#include "logger.hpp"
#include "sha256.hpp"

using namespace oai::ausf::app;
using namespace oai::model::common;

extern ausf_app* ausf_app_inst;
extern std::shared_ptr<oai::http::http_client> http_client_inst;
using namespace oai::config;
extern ausf_config ausf_cfg;
ausf_nrf* ausf_nrf_inst = nullptr;

//------------------------------------------------------------------------------
ausf_app::ausf_app(const std::string& config_file, ausf_event& ev)
    : event_sub(ev), contextId2security_context(), supi2security_context() {}

//------------------------------------------------------------------------------
ausf_app::~ausf_app() {
  Logger::ausf_app().debug("Delete AUSF_APP instance...");
  if (ausf_nrf_inst) {
    delete ausf_nrf_inst;
    ausf_nrf_inst = nullptr;
  }
}

//------------------------------------------------------------------------------
bool ausf_app::start() {
  Logger::ausf_app().startup("Starting...");
  // Register to NRF
  if (ausf_cfg.register_nrf) {
    try {
      Logger::ausf_nrf().info("Create NRF TASK");
      ausf_nrf_inst = new ausf_nrf(event_sub);
      Logger::ausf_nrf().info("NRF TASK created");
      ausf_nrf_inst->register_to_nrf();
    } catch (std::exception& e) {
      Logger::ausf_app().error("Cannot create NRF TASK: %s", e.what());
      return false;
    }
  }
  Logger::ausf_app().startup("Started");
  return true;
}

//------------------------------------------------------------------------------
void ausf_app::stop() {
  if (ausf_nrf_inst and ausf_cfg.register_nrf) {
    ausf_nrf_inst->deregister_to_nrf();
    delete ausf_nrf_inst;
    ausf_nrf_inst = nullptr;
  }
}

//------------------------------------------------------------------------------
bool ausf_app::is_supi_2_security_context(const std::string& supi) const {
  std::shared_lock lock(m_supi2security_context);
  return bool{supi2security_context.count(supi) > 0};
}

//------------------------------------------------------------------------------
std::shared_ptr<security_context> ausf_app::supi_2_security_context(
    const std::string& supi) const {
  std::shared_lock lock(m_supi2security_context);
  return supi2security_context.at(supi);
}

//------------------------------------------------------------------------------
void ausf_app::set_supi_2_security_context(
    const std::string& supi, std::shared_ptr<security_context> sc) {
  std::unique_lock lock(m_supi2security_context);
  supi2security_context[supi] = sc;
}

//------------------------------------------------------------------------------
bool ausf_app::is_contextId_2_security_context(
    const std::string& contextId) const {
  std::shared_lock lock(m_contextId2security_context);
  return bool{contextId2security_context.count(contextId) > 0};
}

//------------------------------------------------------------------------------
std::shared_ptr<security_context> ausf_app::contextId_2_security_context(
    const std::string& contextId) const {
  std::shared_lock lock(m_contextId2security_context);
  return contextId2security_context.at(contextId);
}

//------------------------------------------------------------------------------
void ausf_app::set_contextId_2_security_context(
    const std::string& contextId, std::shared_ptr<security_context> sc) {
  std::unique_lock lock(m_contextId2security_context);
  contextId2security_context[contextId] = sc;
}

//------------------------------------------------------------------------------
void ausf_app::handle_ue_authentications(
    const AuthenticationInfo& authentication_info, nlohmann::json& json_data,
    std::string& location, Pistache::Http::Code& code, uint8_t http_version) {
  Logger::ausf_app().info("Handle UE Authentication Request");
  ProblemDetails problem_details = {};

  std::string snn =
      authentication_info.getServingNetworkName();  // serving network name
  std::string supi = authentication_info.getSupiOrSuci();  // supi

  Logger::ausf_app().info("ServingNetworkName %s", snn);
  Logger::ausf_app().info("supiOrSuci %s", supi);

  // 5g he av from UDM
  // get authentication related info
  std::string response = {};
  std::string udm_uri  = ausf_cfg.get_udm_ueau_generate_auth_data_uri(supi);
  Logger::ausf_app().debug("UDM's URI %s", udm_uri);

  // Create AuthInfo to send to UDM
  nlohmann::json auth_info =
      {};  // model AuthenticationInfo do not have ausfInstanceId field
  auth_info["servingNetworkName"] = snn;
  auth_info["ausfInstanceId"]     = ausf_nrf_inst->get_nf_instance_id();

  if (authentication_info
          .resynchronizationInfoIsSet())  // set ResynchronizationInfo
  {
    ResynchronizationInfo resyn_info =
        authentication_info.getResynchronizationInfo();

    auth_info["resynchronizationInfo"]["rand"] = resyn_info.getRand();
    auth_info["resynchronizationInfo"]["auts"] = resyn_info.getAuts();
    Logger::ausf_app().info(
        "Received authInfo from AMF with ResynchronizationInfo IE");
  } else {
    Logger::ausf_app().info(
        "Received authInfo from AMF without ResynchronizationInfo IE");
  }

  // Send request to UDM
  oai::http::request http_request =
      http_client_inst->prepare_json_request(udm_uri, auth_info.dump());
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::POST, http_request);

  if (http_response.status_code ==
      oai::common::sbi::http_status_code::NO_RESPONSE) {
    Logger::ausf_app().warn("Could not get the response from UDM!");
    // TODO: error handling
    problem_details.setCause("UPSTREAM_SERVER_ERROR");
    problem_details.setStatus(http_status_code::GATEWAY_TIMEOUT);
    to_json(json_data, problem_details);
    Logger::ausf_app().info("504 No response is received from a remote peer");
    code = Pistache::Http::Code::Internal_Server_Error;
    return;
  }

  response = http_response.body;
  Logger::ausf_app().info("Response from UDM: %s", response);

  nlohmann::json response_data = {};
  std::string auth_type_udm    = {};
  std::string autn_udm         = {};
  std::string av_type_udm      = {};
  std::string kausf_udm        = {};
  std::string rand_udm         = {};
  std::string xres_star_udm    = {};
  try {
    response_data = nlohmann::json::parse(response.c_str());
    // Get security context
    auth_type_udm = response_data.at("authType");  // AuthType
    Logger::ausf_app().debug("authType %s", auth_type_udm.c_str());
    autn_udm = response_data["authenticationVector"].at("autn");  // autn
    Logger::ausf_app().debug("autn_udm %s", autn_udm.c_str());
    av_type_udm = response_data["authenticationVector"].at("avType");  // avType
    Logger::ausf_app().debug("av_type_udm %s", av_type_udm.c_str());
    kausf_udm = response_data["authenticationVector"].at("kausf");  // kausf
    Logger::ausf_app().debug("kausf_udm %s", kausf_udm.c_str());
    rand_udm = response_data["authenticationVector"].at("rand");  // rand
    Logger::ausf_app().debug("rand_udm %s", rand_udm.c_str());
    xres_star_udm =
        response_data["authenticationVector"].at("xresStar");  // xres*
    Logger::ausf_app().debug("xres*_udm %s", xres_star_udm.c_str());
    // Get SUPI if available
    if (response_data.find("supi") != response_data.end()) {
      supi = response_data.at("supi");
    }

  } catch (nlohmann::json::exception& e) {
    Logger::ausf_app().info("Could not Parse JSON content from UDM response");
    // TODO: error handling
    problem_details.setCause("CONTEXT_NOT_FOUND");
    problem_details.setStatus(http_status_code::NOT_FOUND);
    problem_details.setDetail(
        "Resource corresponding to User " + supi + " not found");
    to_json(json_data, problem_details);

    Logger::ausf_app().error(
        "Resource corresponding to User %s not found", supi.c_str());
    Logger::ausf_app().info("Send 404 Not_Found response");
    code = Pistache::Http::Code::Not_Found;
    return;
  }

  // 5G HE AV
  uint8_t autn[16]      = {0};
  uint8_t rand[16]      = {0};
  uint8_t xres_star[16] = {0};
  uint8_t kausf[32]     = {0};

  oai::utils::conv::hex_str_to_uint8(autn_udm.c_str(), autn);  // autn
  oai::utils::conv::hex_str_to_uint8(rand_udm.c_str(), rand);  // rand
  oai::utils::conv::hex_str_to_uint8(
      xres_star_udm.c_str(), xres_star);                         // xres*
  oai::utils::conv::hex_str_to_uint8(kausf_udm.c_str(), kausf);  // kausf

  // Generating 5G AV from 5G HE AV
  //  HXRES* <-- XRES*
  //  KSEAF  <-- KAUSF
  //  5G HE AV HXRES* XRES*，KSEAF KAUSF
  //  KSEAF，SEAF 5G SE AV（RAND, AUTN, HXRES*）
  //  A.5, 3gpp ts33.501
  Logger::ausf_app().debug("Generating 5G AV");

  // Generating hxres*
  uint8_t rand_ausf[16]      = {0};
  uint8_t autn_ausf[16]      = {0};
  uint8_t xres_star_ausf[16] = {0};
  uint8_t kausf_ausf[32]     = {0};
  uint8_t hxres_star[16]     = {0};

  // Getting params from UDM 5G HE AV
  std::copy(
      std::begin(xres_star), std::end(xres_star), std::begin(xres_star_ausf));
  std::copy(std::begin(rand), std::end(rand), std::begin(rand_ausf));
  std::copy(std::begin(autn), std::end(autn), std::begin(autn_ausf));
  std::copy(std::begin(kausf), std::end(kausf), std::begin(kausf_ausf));

  // Generate_Hxres*
  Authentication_5gaka::generate_Hxres(rand_ausf, xres_star_ausf, hxres_star);
  Logger::ausf_app().debug(
      "HXresStar calculated:\n %s",
      oai::utils::conv::uint8_to_hex_string(hxres_star, 16));

  uint8_t kseaf[32] = {0};
  Authentication_5gaka::derive_kseaf(snn, kausf, kseaf);
  Logger::ausf_app().debug(
      "Kseaf calculated:\n %s",
      oai::utils::conv::uint8_to_hex_string(kseaf, 32));

  // Store the security context
  std::shared_ptr<security_context> sc = {};
  if (is_supi_2_security_context(supi)) {
    Logger::ausf_app().debug("Update security context with SUPI: %s", supi);
    sc = supi_2_security_context(supi);
  } else {
    Logger::ausf_app().debug(
        "Create a new security context with SUPI %s", supi);
    sc = std::make_shared<security_context>();
    set_supi_2_security_context(supi, sc);
  }

  // Update information
  std::copy(
      std::begin(rand_ausf), std::end(rand_ausf),
      std::begin(sc->ausf_av_s.rand));
  std::copy(
      std::begin(autn_ausf), std::end(autn_ausf),
      std::begin(sc->ausf_av_s.autn));
  std::copy(
      std::begin(hxres_star), std::end(hxres_star),
      std::begin(sc->ausf_av_s.hxresStar));
  std::copy(
      std::begin(kseaf), std::end(kseaf), std::begin(sc->ausf_av_s.kseaf));
  // store xres* in ausf
  std::copy(
      std::begin(xres_star), std::end(xres_star), std::begin(sc->xres_star));

  // Store info in AUSF
  sc->supi       = supi;
  sc->serving_nn = snn;
  sc->auth_type  = auth_type_udm;
  sc->kausf_tmp  = oai::utils::conv::uint8_to_hex_string(kausf_ausf, 32);

  // Send authentication context to SEAF (AUSF->SEAF)
  UEAuthenticationCtx ue_auth_ctx = {};
  std::string rand_s = oai::utils::conv::uint8_to_hex_string(rand_ausf, 16);
  std::string autn_s = oai::utils::conv::uint8_to_hex_string(autn_ausf, 16);
  std::string hxresStar_s =
      oai::utils::conv::uint8_to_hex_string(hxres_star, 16);
  ue_auth_ctx.setAuthType(auth_type_udm);  // authType(string)

  std::map<std::string, LinksValueSchema> ausf_links;  // links(std::map)
  LinksValueSchema ausf_href;
  std::string resource_uri  = {};
  std::string auth_ctx_id_s = {};
  auth_ctx_id_s             = autn_s;  // authCtxId = autn
  // Store the security context
  set_contextId_2_security_context(auth_ctx_id_s, sc);

  resource_uri =
      "http://" +
      std::string(inet_ntoa(*((struct in_addr*) &ausf_cfg.sbi.addr4))) + ":" +
      std::to_string(ausf_cfg.sbi.port) + "/nausf-auth/v1/ue-authentications/" +
      auth_ctx_id_s + "/5g-aka-confirmation";
  ausf_href.setHref(resource_uri);

  ausf_links["5g-aka"] = ausf_href;
  ue_auth_ctx.setLinks(ausf_links);

  // 5gAuthData(Av5gAka):rand autn hxresStar
  Av5gAka ausf_5g_auth_data;
  ausf_5g_auth_data.setRand(rand_s);
  ausf_5g_auth_data.setAutn(autn_s);
  ausf_5g_auth_data.setHxresStar(hxresStar_s);
  ue_auth_ctx.setR5gAuthData(ausf_5g_auth_data);

  to_json(json_data, ue_auth_ctx);
  code = Pistache::Http::Code::Created;
  Logger::ausf_app().debug("Auth Response:\n %s", json_data.dump());
  return;
}

//------------------------------------------------------------------------------
void ausf_app::handle_ue_authentications_confirmation(
    const std::string& auth_ctx_id, const ConfirmationData& confirmation_data,
    nlohmann::json& json_data, Pistache::Http::Code& code) {
  // SEAF-> AUSF
  ProblemDetails problem_details = {};
  Logger::ausf_app().debug("Handling 5g-aka-confirmation");

  // Get the security context
  std::shared_ptr<security_context> sc = {};
  if (is_contextId_2_security_context(auth_ctx_id)) {
    Logger::ausf_app().debug(
        "Retrieve security context with authCtxId: %s", auth_ctx_id);
    sc = contextId_2_security_context(auth_ctx_id);
  } else {  // No ue-authentications request before
    Logger::ausf_app().debug(
        "Security context with authCtxId %s does not exist", auth_ctx_id);

    problem_details.setCause("SERVING_NETWORK_NOT_AUTHORIZED");
    problem_details.setStatus(http_status_code::FORBIDDEN);
    problem_details.setDetail("Serving Network Not Authorized");
    to_json(json_data, problem_details);

    Logger::ausf_app().error("Serving Network Not Authorized");
    Logger::ausf_app().info("Send 403 Forbidden response");
    code = Pistache::Http::Code::Forbidden;
    return;
  }

  Logger::ausf_app().info("Received authCtxId %s", auth_ctx_id);  // authCtxId
  Logger::ausf_app().info("Received res* %s", confirmation_data.getResStar());

  uint8_t res_star[16] = {0};
  oai::utils::conv::hex_str_to_uint8(
      confirmation_data.getResStar().c_str(), res_star);

  ConfirmationDataResponse confirm_response;
  AuthResult auth_result = {};
  uint8_t auth_ctx_id_seaf[16];
  oai::utils::conv::hex_str_to_uint8(
      auth_ctx_id.c_str(),
      auth_ctx_id_seaf);  // authCtxId in SEAF

  Logger::ausf_app().debug(
      "authCtxId in AUSF: %s",
      oai::utils::conv::uint8_to_hex_string(sc->ausf_av_s.autn, 16));

  bool is_auth_vectors_present = Authentication_5gaka::equal_uint8(
      sc->ausf_av_s.autn, auth_ctx_id_seaf, 16);
  if (!is_auth_vectors_present)  // AV expired
  {
    Logger::ausf_app().error(
        "Authentication failure by home network with authCtxId %s: AV expired",
        auth_ctx_id);
    auth_result.setValue(AuthResult::eAuthResult::AUTHENTICATION_FAILURE);
    confirm_response.setAuthResult(auth_result);
    sc->kausf_tmp = "invalid";
  } else  // AV valid
  {
    Logger::ausf_app().info("AV is up to date, handling received res*...");
    // Get stored xres* and compare with res*
    uint8_t xres_star[16] = {0};
    // xres* stored for 5g-aka-confirmation
    std::copy(
        std::begin(sc->xres_star), std::end(sc->xres_star),
        std::begin(xres_star));

    Logger::ausf_app().debug(
        "xres* in AUSF: %s",
        oai::utils::conv::uint8_to_hex_string(xres_star, 16));
    Logger::ausf_app().debug(
        "xres in AMF: %s", oai::utils::conv::uint8_to_hex_string(res_star, 16));

    bool auth_result_check =
        Authentication_5gaka::equal_uint8(xres_star, res_star, 16);

    if (!auth_result_check)  // Authentication failed
    {
      auth_result.setValue(AuthResult::eAuthResult::AUTHENTICATION_FAILURE);
      confirm_response.setAuthResult(auth_result);
      Logger::ausf_app().error(
          "Authentication failure by home network with authCtxId %s: res* != "
          "xres*",
          auth_ctx_id);

      problem_details.setCause("AUTHENTICATION_REJECTED");
      problem_details.setStatus(http_status_code::FORBIDDEN);
      problem_details.setDetail(
          "The user cannot be authenticated with this authentication method");
      to_json(json_data, problem_details);

      Logger::ausf_app().error("Serving Network Not Authorized");
      Logger::ausf_app().info("Send 403 Forbidden response");
      code = Pistache::Http::Code::Forbidden;
    } else  // Authentication success
    {
      Logger::ausf_app().info("Authentication successful by home network!");
      auth_result.setValue(AuthResult::eAuthResult::AUTHENTICATION_SUCCESS);
      confirm_response.setAuthResult(auth_result);
      // Send Kseaf to SEAF
      std::string kseaf_s;
      kseaf_s = oai::utils::conv::uint8_to_hex_string(sc->ausf_av_s.kseaf, 32);
      confirm_response.setKseaf(kseaf_s);
      // Send SUPI when supi exists
      if (!sc->supi.empty()) {
        confirm_response.setSupi(sc->supi);
      }
      // Send authResult to UDM (authentication result info)
      std::string response = {};
      std::string udm_uri  = ausf_cfg.get_udm_ueau_confirm_auth_uri(sc->supi);

      Logger::ausf_app().debug("UDM's URI: %s", udm_uri);

      // Form request body
      nlohmann::json confirm_result_info  = {};
      confirm_result_info["nfInstanceId"] = ausf_nrf_inst->get_nf_instance_id();
      confirm_result_info["success"]      = true;

      // TODO: Update timestamp
      time_t rawtime;
      time(&rawtime);
      char buf[32];
      strftime(buf, sizeof(buf), "%FT%TZ", gmtime(&rawtime));
      confirm_result_info["timeStamp"] = buf;  // timestamp generated

      // Get info from the security context (stored in AUSF)
      confirm_result_info["authType"]           = sc->auth_type;
      confirm_result_info["servingNetworkName"] = sc->serving_nn;
      confirm_result_info["authRemovalInd"]     = false;

      auto confirm_result_info_str = confirm_result_info.dump();
      Logger::ausf_app().debug(
          "confirmResultInfo: %s", confirm_result_info_str);

      // Send request to UDM
      oai::http::request http_request = http_client_inst->prepare_json_request(
          udm_uri, confirm_result_info_str);
      auto http_response = http_client_inst->send_http_request(
          oai::common::sbi::method_e::POST, http_request);

      if (http_response.status_code ==
          oai::common::sbi::http_status_code::NO_RESPONSE) {
        Logger::ausf_app().warn("Could not get the response from UDM!");
        // TODO: process the response from UDM
      }

      to_json(json_data, confirm_response);
      code = Pistache::Http::Code::Ok;
    }
  }

  return;
}
