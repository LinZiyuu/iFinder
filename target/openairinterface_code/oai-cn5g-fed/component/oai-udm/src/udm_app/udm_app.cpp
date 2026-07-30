/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "udm_app.hpp"

#include <unistd.h>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/date_time/posix_time/time_formatters.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <chrono>

#include "3gpp_29.500.h"
#include "3gpp_29.503.h"
#include "PatchItem.h"
#include "ProblemDetails.h"
#include "SequenceNumber.h"
#include "authentication_algorithms_with_5gaka.hpp"
#include "conversions.hpp"
#include "http_client.hpp"
#include "logger.hpp"
#include "output_wrapper.hpp"
#include "sha256.hpp"
#include "udm.h"
#include "udm_config.hpp"
#include "udm_nrf.hpp"
#include "udm_sbi_helper.hpp"

using namespace oai::model::udm;
using namespace oai::model::common;
using namespace oai::utils;
using namespace oai::udm::app;
using namespace oai::udm::config;
using namespace std::chrono;
using namespace boost::placeholders;
using namespace oai::udm::api;

extern udm_app* udm_app_inst;
extern udm_config udm_cfg;
udm_nrf* udm_nrf_inst = nullptr;
extern std::shared_ptr<oai::http::http_client> http_client_inst;

//------------------------------------------------------------------------------
udm_app::udm_app(const std::string& config_file, udm_event& ev)
    : event_sub(ev) {}

//------------------------------------------------------------------------------
udm_app::~udm_app() {
  // Disconnect the boost connection
  if (loss_of_connectivity_connection.connected())
    loss_of_connectivity_connection.disconnect();
  if (ue_reachability_for_data_connection.connected())
    ue_reachability_for_data_connection.disconnect();

  if (udm_nrf_inst) {
    delete udm_nrf_inst;
    udm_nrf_inst = nullptr;
  }
  Logger::udm_app().debug("Delete UDM APP instance...");
}

//------------------------------------------------------------------------------
bool udm_app::start() {
  Logger::udm_app().startup("Starting...");

  // Register to NRF
  if (udm_cfg.register_nrf) {
    try {
      udm_nrf_inst = new udm_nrf(event_sub);
      udm_nrf_inst->register_to_nrf();
      Logger::udm_app().info("NRF TASK Created ");
    } catch (std::exception& e) {
      Logger::udm_app().error("Cannot create NRF TASK: %s", e.what());
      return false;
    }
  }

  // Subscribe to UE Loss of Connectivity Status signal
  loss_of_connectivity_connection = event_sub.subscribe_loss_of_connectivity(
      boost::bind(&udm_app::handle_ee_loss_of_connectivity, this, _1, _2, _3));
  ue_reachability_for_data_connection =
      event_sub.subscribe_ue_reachability_for_data(boost::bind(
          &udm_app::handle_ee_ue_reachability_for_data, this, _1, _2, _3));

  Logger::udm_app().startup("Started");
  return true;
}

//------------------------------------------------------------------------------
void udm_app::stop() {
  // Deregister to NRF
  if (udm_cfg.register_nrf) {
    if (udm_nrf_inst) {
      udm_nrf_inst->deregister_to_nrf();
    }
  }
}

//------------------------------------------------------------------------------
void udm_app::handle_generate_auth_data_request(
    const std::string& supiOrSuci,
    const oai::model::udm::AuthenticationInfoRequest& authenticationInfoRequest,
    nlohmann::json& auth_info_response, uint32_t& code) {
  Logger::udm_ueau().info("Handle Generate Auth Data Request");
  uint8_t rand[16] = {0};
  uint8_t opc[16]  = {0};
  uint8_t key[16]  = {0};
  uint8_t sqn[6]   = {0};
  uint8_t amf[2]   = {0};

  uint8_t* r_sqn        = nullptr;  // for resync
  std::string r_sqnms_s = {};       // for resync
  uint8_t r_rand[16]    = {0};      // for resync
  uint8_t r_auts[14]    = {0};      // for resync

  uint8_t mac_a[8]     = {0};
  uint8_t ck[16]       = {0};
  uint8_t ik[16]       = {0};
  uint8_t ak[6]        = {0};
  uint8_t xres[8]      = {0};
  uint8_t xresStar[16] = {0};
  uint8_t autn[16]     = {0};
  uint8_t kausf[32]    = {0};

  std::string rand_s     = {};
  std::string autn_s     = {};
  std::string xresStar_s = {};
  std::string kausf_s    = {};
  std::string sqn_s      = {};
  std::string amf_s      = {};
  std::string key_s      = {};
  std::string opc_s      = {};

  std::string snn        = authenticationInfoRequest.getServingNetworkName();
  std::string supi       = {};
  std::string remote_uri = {};
  std::string msg_body   = {};
  nlohmann::json problem_details_json = {};
  ProblemDetails problem_details      = {};

  if (supiOrSuci.find("imsi-") == 0) {
    Logger::udm_ueau().debug("5GS mobile identity type: SUPI");
    if ((supiOrSuci.length() < (6 + 5)) || (supiOrSuci.length() > (6 + 15))) {
      std::string error = "Invalid IMSI length";
      problem_details.setCause("USER_NOT_FOUND");
      problem_details.setStatus(oai::common::sbi::http_status_code::NOT_FOUND);
      problem_details.setDetail("User " + supiOrSuci + " " + error);
      to_json(problem_details_json, problem_details);

      Logger::udm_ueau().warn("User " + supiOrSuci + " " + error);
      auth_info_response = problem_details_json;
      code               = oai::common::sbi::http_status_code::NOT_FOUND;
      return;
    }
    // No change, format is already IMSI
    supi = supiOrSuci;
  } else if (supiOrSuci.find("suci-") == 0) {
    Logger::udm_ueau().debug("5GS mobile identity type: SUCI");
    std::string error            = {};
    std::string routingIndicator = {};
    if (!Authentication_5gaka::suciSidf(
            udm_cfg.subscriber_profiles, supiOrSuci, routingIndicator, supi,
            error)) {
      problem_details.setCause("USER_NOT_FOUND");
      problem_details.setStatus(oai::common::sbi::http_status_code::NOT_FOUND);
      problem_details.setDetail("User " + supiOrSuci + " " + error);
      to_json(problem_details_json, problem_details);

      Logger::udm_ueau().warn("User " + supiOrSuci + " " + error);
      auth_info_response = problem_details_json;
      code               = oai::common::sbi::http_status_code::NOT_FOUND;
      return;
    }
    Logger::udm_ueau().debug("SUPI %s ", supi);
  }

  // Get authentication related info
  remote_uri = udm_sbi_helper::get_udr_authentication_subscription_uri(supi);
  Logger::udm_ueau().debug("Remote URI: " + remote_uri);

  oai::http::request http_request =
      http_client_inst->prepare_json_request(remote_uri);
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::GET, http_request);

  nlohmann::json response_data = {};
  try {
    response_data = nlohmann::json::parse(http_response.body);
  } catch (nlohmann::json::exception& e) {  // error handling
    Logger::udm_ueau().info("Could not get JSON content from UDR response");
    code = oai::common::sbi::http_status_code::NOT_FOUND;
    std::string problem_description = "User " + supi + " not found";
    set_problem_details(
        code, udm_protocol_application_error::USER_NOT_FOUND,
        problem_description, auth_info_response);
    Logger::udm_ueau().warn(problem_description);

    return;
  }

  // Process the response
  std::string auth_method_s = response_data.at("authenticationMethod");
  if (!auth_method_s.compare("5G_AKA") ||
      !auth_method_s.compare("AuthenticationVector")) {
    try {
      key_s = response_data.at("encPermanentKey");
      conv::hex_str_to_uint8(key_s.c_str(), key);
      output_wrapper::print_buffer(
          "udm_ueau", "Result For F1-Alg Key", key, 16);

      opc_s = response_data.at("encOpcKey");
      conv::hex_str_to_uint8(opc_s.c_str(), opc);
      output_wrapper::print_buffer(
          "udm_ueau", "Result For F1-Alg OPC", opc, 16);

      amf_s = response_data.at("authenticationManagementField");
      conv::hex_str_to_uint8(amf_s.c_str(), amf);
      output_wrapper::print_buffer("udm_ueau", "Result For F1-Alg AMF", amf, 2);

      sqn_s = response_data["sequenceNumber"].at("sqn");
      conv::hex_str_to_uint8(sqn_s.c_str(), sqn);
      output_wrapper::print_buffer(
          "udm_ueau", "Result For F1-Alg SQN: ", sqn, 6);
    } catch (nlohmann::json::exception& e) {
      // error handling
      code = oai::common::sbi::http_status_code::FORBIDDEN;
      std::string problem_description =
          "Missing authentication parameters in UDR's response";
      set_problem_details(
          code, udm_protocol_application_error::AUTHENTICATION_REJECTED,
          problem_description, auth_info_response);
      Logger::udm_ueau().warn(problem_description);
      return;
    }
  } else {
    // error handling
    code = oai::common::sbi::http_status_code::NOT_IMPLEMENTED;
    std::string problem_description =
        "Non 5G_AKA authenticationMethod configuration available, method set "
        "= " +
        auth_method_s;
    set_problem_details(
        code, udm_protocol_application_error::UNSUPPORTED_PROTECTION_SCHEME,
        problem_description, auth_info_response);
    Logger::udm_ueau().warn(problem_description);
    return;
  }

  if (authenticationInfoRequest.resynchronizationInfoIsSet()) {
    // Resync procedure
    Logger::udm_ueau().info("Start Resynchronization procedure");
    ResynchronizationInfo resynchronization_info =
        authenticationInfoRequest.getResynchronizationInfo();
    std::string r_rand_s = resynchronization_info.getRand();
    std::string r_auts_s = resynchronization_info.getAuts();

    Logger::udm_ueau().info("[resync] r_rand = " + r_rand_s);
    Logger::udm_ueau().info("[resync] r_auts = " + r_auts_s);

    conv::hex_str_to_uint8(r_rand_s.c_str(), r_rand);
    conv::hex_str_to_uint8(r_auts_s.c_str(), r_auts);

    r_sqn = Authentication_5gaka::sqn_ms_derive(opc, key, r_auts, r_rand, amf);

    if (r_sqn) {  // Not NULL (validate auts)
      Logger::udm_ueau().info("Valid AUTS, generate new AV with SQNms");

      // Update SQN@UDR, replace SQNhe with SQNms
      remote_uri =
          udm_sbi_helper::get_udr_authentication_subscription_uri(supi);

      Logger::udm_ueau().debug("Remote URI: " + remote_uri);

      nlohmann::json sequence_number_json;
      SequenceNumber sequence_number;
      sequence_number.setSqnScheme("NON_TIME_BASED");
      r_sqnms_s = conv::uint8_to_hex_string(r_sqn, 6);
      sequence_number.setSqn(r_sqnms_s);
      std::map<std::string, int32_t> index;
      index["ausf"] = 0;
      sequence_number.setLastIndexes(index);
      to_json(sequence_number_json, sequence_number);

      Logger::udm_ueau().info(
          "Sequence Number %s", sequence_number_json.dump().c_str());

      nlohmann::json patch_item_json = {};
      PatchItem patch_item           = {};
      patch_item.setValue(sequence_number_json.dump());
      PatchOperation op;
      op.setEnumValue(PatchOperation_anyOf::ePatchOperation_anyOf::REPLACE);
      patch_item.setOp(op);
      patch_item.setFrom("");
      patch_item.setPath("");
      to_json(patch_item_json, patch_item);

      msg_body = "[" + patch_item_json.dump() + "]";
      Logger::udm_ueau().info(
          "Update UDR with PATCH message, body:  %s", msg_body.c_str());

      oai::http::request http_request =
          http_client_inst->prepare_json_request(remote_uri, msg_body);
      auto http_response = http_client_inst->send_http_request(
          oai::common::sbi::method_e::PATCH, http_request);

      // replace SQNhe with SQNms
      for (int i = 0; i < 6; i++)
        sqn[i] = r_sqn[i];  // generate first, increase later
      sqn_s = conv::uint8_to_hex_string(sqn, 16);
      // Logger::udm_ueau().debug("sqn string = "+sqn_s);
      sqn_s[12] = '\0';
      output_wrapper::print_buffer("udm_ueau", "SQNms", sqn, 6);

      if (r_sqn) {  // free
        free(r_sqn);
        r_sqn = NULL;
      }
    } else {
      Logger::udm_ueau().warn(
          "Invalid AUTS, generate new AV with SQNhe = " + sqn_s);
    }
  }

  // Increment SQN (to be used as current SQN)
  std::string current_sqn = {};
  increment_sqn(sqn_s, current_sqn);
  // Update SQN
  conv::hex_str_to_uint8(current_sqn.c_str(), sqn);
  Logger::udm_ueau().info("Current SQN %s", current_sqn.c_str());

  // 5GAKA functions
  Authentication_5gaka::generate_random(rand, 16);  // generate rand
  Authentication_5gaka::f1(
      opc, key, rand, sqn, amf,
      mac_a);  // to compute mac_a
  Authentication_5gaka::f2345(
      opc, key, rand, xres, ck, ik,
      ak);  // to compute XRES, CK, IK, AK
  Authentication_5gaka::generate_autn(
      sqn, ak, amf, mac_a,
      autn);  // generate AUTN
  Authentication_5gaka::annex_a_4_33501(
      ck, ik, xres, rand, snn,
      xresStar);  // generate xres*
  Authentication_5gaka::derive_kausf(
      ck, ik, snn, sqn, ak,
      kausf);  // derive Kausf

  // convert uint8_t to string
  rand_s     = conv::uint8_to_hex_string(rand, 16);
  autn_s     = conv::uint8_to_hex_string(autn, 16);
  xresStar_s = conv::uint8_to_hex_string(xresStar, 16);
  kausf_s    = conv::uint8_to_hex_string(kausf, 32);

  // convert to json
  nlohmann::json AuthInfoResult                      = {};
  AuthInfoResult["authType"]                         = "5G_AKA";
  AuthInfoResult["authenticationVector"]["avType"]   = "5G_HE_AKA";
  AuthInfoResult["authenticationVector"]["rand"]     = rand_s;
  AuthInfoResult["authenticationVector"]["autn"]     = autn_s;
  AuthInfoResult["authenticationVector"]["xresStar"] = xresStar_s;
  AuthInfoResult["authenticationVector"]["kausf"]    = kausf_s;
  AuthInfoResult["supi"]                             = supi;

  // TODO: Separate into a new function
  // Do it after send ok to AUSF (to be verified)

  // Increment SQN (for the next round)
  std::string new_sqn = {};
  increment_sqn(current_sqn, new_sqn);
  Logger::udm_ueau().info("New SQN (for next round) = " + new_sqn);

  // Update SQN@UDR
  remote_uri = udm_sbi_helper::get_udr_authentication_subscription_uri(supi);

  Logger::udm_ueau().debug("Remote URI: " + remote_uri);

  nlohmann::json sequence_number_json;
  SequenceNumber sequence_number;
  sequence_number.setSqnScheme("NON_TIME_BASED");
  sequence_number.setSqn(new_sqn);
  std::map<std::string, int32_t> index;
  index["ausf"] = 0;
  sequence_number.setLastIndexes(index);
  to_json(sequence_number_json, sequence_number);

  nlohmann::json patch_item_json;
  PatchItem patch_item;
  patch_item.setValue(sequence_number_json.dump());
  PatchOperation op;
  op.setEnumValue(PatchOperation_anyOf::ePatchOperation_anyOf::REPLACE);
  patch_item.setOp(op);
  patch_item.setFrom("");
  patch_item.setPath("");
  to_json(patch_item_json, patch_item);

  msg_body = "[" + patch_item_json.dump() + "]";
  Logger::udm_ueau().info(
      "Update UDR with PATCH message, body:  %s", msg_body.c_str());

  http_request  = http_client_inst->prepare_json_request(remote_uri, msg_body);
  http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::PATCH, http_request);

  auth_info_response = AuthInfoResult;
  code               = oai::common::sbi::http_status_code::OK;
  Logger::udm_ueau().info("Send 200 OK response to AUSF");
  Logger::udm_ueau().info("AuthInfoResult %s", AuthInfoResult.dump().c_str());
  return;
}

//------------------------------------------------------------------------------
void udm_app::handle_confirm_auth(
    const std::string& supi, const oai::model::udm::AuthEvent& authEvent,
    nlohmann::json& confirm_response, std::string& location, uint32_t& code) {
  std::string remote_uri              = {};
  std::string msg_body                = {};
  std::string auth_event_id           = {};
  nlohmann::json problem_details_json = {};
  ProblemDetails problem_details      = {};

  // Get user info
  remote_uri = udm_sbi_helper::get_udr_authentication_subscription_uri(supi);
  Logger::udm_ueau().debug("Remote URI: " + remote_uri);

  oai::http::request http_request =
      http_client_inst->prepare_json_request(remote_uri, msg_body);
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::GET, http_request);

  nlohmann::json response_data = {};
  try {
    response_data = nlohmann::json::parse(http_response.body.c_str());
  } catch (nlohmann::json::exception& e) {  // error handling
    Logger::udm_ueau().info("Could not get JSON content from UDR response");
    code = oai::common::sbi::http_status_code::NOT_FOUND;
    std::string problem_description = "User " + supi + " not found";
    set_problem_details(
        code, udm_protocol_application_error::USER_NOT_FOUND,
        problem_description, confirm_response);
    Logger::udm_ueau().warn(problem_description);
    return;
  }

  if (authEvent.isAuthRemovalInd()) {
    // error handling
    code = oai::common::sbi::http_status_code::BAD_REQUEST;
    std::string problem_description = "AuthRemovalInd should be set to false";
    set_problem_details(
        code, protocol_application_error::OPTIONAL_IE_INCORRECT,
        problem_description, confirm_response);
    Logger::udm_ueau().warn(problem_description);
    return;
  }

  // Update authentication status
  remote_uri = udm_sbi_helper::get_udr_authentication_status_uri(supi);
  Logger::udm_ueau().debug("Remote URI:" + remote_uri);

  nlohmann::json auth_event_json;
  to_json(auth_event_json, authEvent);

  msg_body = auth_event_json.dump();
  Logger::udm_ueau().debug("Request body = " + msg_body);

  http_request  = http_client_inst->prepare_json_request(remote_uri, msg_body);
  http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::PUT, http_request);

  std::string hash_value = sha256(supi + authEvent.getServingNetworkName());
  // Logger::udm_ueau().debug("\n\nauthEventId=" +
  // hash_value.substr(0,hash_value.length()/2));
  Logger::udm_ueau().debug("authEventId=" + hash_value);

  auth_event_id = hash_value;  // Represents the authEvent Id per UE per serving
                               // network assigned by the UDM during
                               // ResultConfirmation service operation.
  location = udm_sbi_helper::get_udm_ueau_base() + "/" + supi +
             "/auth-events/" + auth_event_id;

  Logger::udm_ueau().info("Send 201 Created response to AUSF");
  confirm_response = auth_event_json;
  code             = oai::common::sbi::http_status_code::CREATED;
  return;
}

//------------------------------------------------------------------------------
void udm_app::handle_delete_auth(
    const std::string& supi, const std::string& authEventId,
    const oai::model::udm::AuthEvent& authEvent, nlohmann::json& auth_response,
    uint32_t& code) {
  std::string remote_uri              = {};
  std::string msg_body                = {};
  nlohmann::json problem_details_json = {};
  ProblemDetails problem_details      = {};

  // Get user info
  remote_uri = udm_sbi_helper::get_udr_authentication_subscription_uri(supi);
  Logger::udm_ueau().debug("Remote URI:" + remote_uri);

  oai::http::request http_request =
      http_client_inst->prepare_json_request(remote_uri, msg_body);
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::GET, http_request);

  nlohmann::json response_data = {};
  try {
    response_data = nlohmann::json::parse(http_response.body.c_str());
  } catch (nlohmann::json::exception& e) {  // error handling
    Logger::udm_ueau().info("Could not get JSON content from UDR response");
    code = oai::common::sbi::http_status_code::NOT_FOUND;
    std::string problem_description = "User " + supi + " not found";
    set_problem_details(
        code, udm_protocol_application_error::USER_NOT_FOUND,
        problem_description, auth_response);
    Logger::udm_ueau().warn(problem_description);
    return;
  }

  if (!authEvent.isAuthRemovalInd()) {
    // error handling
    code = oai::common::sbi::http_status_code::BAD_REQUEST;
    std::string problem_description = "AuthRemovalInd should be set to true";
    set_problem_details(
        code, protocol_application_error::OPTIONAL_IE_INCORRECT,
        problem_description, auth_response);
    Logger::udm_ueau().warn(problem_description);
    return;
  }

  std::string hash_value = sha256(supi + authEvent.getServingNetworkName());
  // Logger::udm_ueau().debug("\n\nauthEventId=" +
  // hash_value.substr(0,hash_value.length()/2));
  Logger::udm_ueau().debug("authEventId=" + hash_value);

  if (!hash_value.compare(authEventId)) {
    // Delete authentication status
    remote_uri = udm_sbi_helper::get_udr_authentication_status_uri(supi);
    Logger::udm_ueau().debug("DELETE Request:" + remote_uri);

    nlohmann::json auth_event_json;
    to_json(auth_event_json, authEvent);

    oai::http::request http_request =
        http_client_inst->prepare_json_request(remote_uri, msg_body);
    auto http_response = http_client_inst->send_http_request(
        oai::common::sbi::method_e::DELETE, http_request);

    Logger::udm_ueau().info("Send 204 No_Content response to AUSF");
    auth_response = {};
    code          = oai::common::sbi::http_status_code::NO_CONTENT;
    return;
  } else {
    // error handling
    code = oai::common::sbi::http_status_code::NOT_FOUND;
    std::string problem_description = "Wrong authEventId";
    set_problem_details(
        code, udm_protocol_application_error::DATA_NOT_FOUND,
        problem_description, auth_response);
    Logger::udm_ueau().warn(problem_description);
    return;
  }
}

//------------------------------------------------------------------------------
void udm_app::handle_access_mobility_subscription_data_retrieval(
    const std::string& supi, nlohmann::json& response_data, uint32_t& code,
    PlmnId plmn_id) {
  // TODO: check if plmn_id available
  std::string remote_uri =
      udm_sbi_helper::get_udr_access_and_mobility_subscription_data_uri(
          supi, plmn_id);
  std::string body("");
  Logger::udm_sdm().debug("Remote URI: " + remote_uri);

  // Get response from UDR
  oai::http::request http_request =
      http_client_inst->prepare_json_request(remote_uri, body);
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::GET, http_request);

  try {
    Logger::udm_sdm().debug(
        "subscription-data: GET Response: " + http_response.body);
    response_data = nlohmann::json::parse(http_response.body.c_str());
  } catch (nlohmann::json::exception& e) {
    Logger::udm_sdm().info("Could not get JSON content from UDR response");
    code = oai::common::sbi::http_status_code::NOT_FOUND;
    std::string problem_description = "User " + supi + " not found";
    set_problem_details(
        code, udm_protocol_application_error::USER_NOT_FOUND,
        problem_description, response_data);
    Logger::udm_ueau().warn(problem_description);
    return;
  }
}

//------------------------------------------------------------------------------
void udm_app::handle_amf_registration_for_3gpp_access(
    const std::string& ue_id,
    const oai::model::udm::Amf3GppAccessRegistration&
        amf_3gpp_access_registration,
    nlohmann::json& response_data, uint32_t& code) {
  // TODO: to be completed
  std::string remote_uri              = {};
  nlohmann::json problem_details_json = {};
  ProblemDetails problem_details      = {};

  // Get 3gpp_registration related info
  remote_uri = udm_sbi_helper::get_udr_amf_3gpp_registration_uri(ue_id);
  Logger::udm_uecm().debug("Remote URI:" + remote_uri);

  nlohmann::json amf_registration_json;
  to_json(amf_registration_json, amf_3gpp_access_registration);

  oai::http::request http_request = http_client_inst->prepare_json_request(
      remote_uri, amf_registration_json.dump());
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::PUT, http_request);

  try {
    Logger::udm_uecm().debug("HTTP Response: " + http_response.body);
    response_data = nlohmann::json::parse(http_response.body.c_str());

  } catch (nlohmann::json::exception& e) {  // error handling
    Logger::udm_uecm().info("Could not get JSON content from UDR response");
    std::string problem_description = "User " + ue_id + " not found";
    set_problem_details(
        oai::common::sbi::http_status_code::NOT_FOUND,
        udm_protocol_application_error::USER_NOT_FOUND, problem_description,
        response_data);
    Logger::udm_ueau().warn(problem_description);
    return;
  }
  Logger::udm_uecm().debug("HTTP response code %d", http_response.status_code);

  response_data = amf_registration_json;
  code          = http_response.status_code;
  return;
}

//------------------------------------------------------------------------------
void udm_app::handle_session_management_subscription_data_retrieval(
    const std::string& supi, nlohmann::json& response_data, uint32_t& code,
    Snssai snssai, std::string dnn, PlmnId plmn_id) {
  // UDR's URL
  std::string remote_uri =
      udm_sbi_helper::get_udr_session_management_subscription_data_uri(
          supi, plmn_id);
  std::string query_str = {};
  std::string body      = {};

  if (snssai.getSst() > 0) {
    query_str += "?single-nssai={\"sst\":" + std::to_string(snssai.getSst()) +
                 ",\"sd\":\"" + snssai.getSd() + "\"}";
    if (!dnn.empty()) {
      query_str += "&dnn=" + dnn;
    }
  } else if (!dnn.empty()) {
    query_str += "?dnn=" + dnn;
  }

  // URI with Optional SNSSAI/DNN
  remote_uri += query_str;

  Logger::udm_sdm().debug("Remote URI: " + remote_uri);

  oai::http::request http_request =
      http_client_inst->prepare_json_request(remote_uri, body);
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::GET, http_request);
  code = http_response.status_code;

  Logger::udm_sdm().debug("HTTP response code %ld", code);

  // Process response
  try {
    Logger::udm_sdm().debug("Response: " + http_response.body);
    response_data = nlohmann::json::parse(http_response.body.c_str());
  } catch (nlohmann::json::exception& e) {
    Logger::udm_sdm().info("Could not get JSON content from UDR response");
    code = oai::common::sbi::http_status_code::NOT_FOUND;
    std::string problem_description = "User " + supi + " not found";
    set_problem_details(
        code, udm_protocol_application_error::USER_NOT_FOUND,
        problem_description, response_data);
    Logger::udm_ueau().warn(problem_description);
    return;
  }
  return;
}

//------------------------------------------------------------------------------
void udm_app::handle_slice_selection_subscription_data_retrieval(
    const std::string& supi, nlohmann::json& response_data, uint32_t& code,
    std::string supported_features, PlmnId plmn_id) {
  Logger::udm_sdm().debug(
      "Handle Slice Selection Subscription Data Retrieval request");

  // Get the corresponding UDR's URI
  std::string udr_uri =
      udm_sbi_helper::get_udr_slice_selection_subscription_data_retrieval_uri(
          supi, plmn_id);
  std::string body = {};
  Logger::udm_sdm().debug("Remote URI: %s", udr_uri.c_str());
  // Send the request and get the response from UDR
  oai::http::request http_request =
      http_client_inst->prepare_json_request(udr_uri, body);
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::GET, http_request);

  code = http_response.status_code;
  Logger::udm_sdm().debug("HTTP response code %d", http_response.status_code);
  Logger::udm_sdm().debug("Response from UDR: %s", http_response.body.c_str());

  // Process the response
  nlohmann::json return_response_data_json = {};
  try {
    return_response_data_json =
        nlohmann::json::parse(http_response.body.c_str());
    if (return_response_data_json.find("nssai") !=
        return_response_data_json.end()) {
      response_data = return_response_data_json["nssai"];
      Logger::udm_sdm().debug(
          "Slice Selection Subscription Data from UDR: %s",
          response_data.dump().c_str());
    }
  } catch (nlohmann::json::exception& e) {
    Logger::udm_sdm().info("Could not get JSON content from UDR's response");
    code = oai::common::sbi::http_status_code::NOT_FOUND;
    std::string problem_description =
        "Subscription with SUPI " + supi + " not found";
    set_problem_details(
        code, protocol_application_error::SUBSCRIPTION_NOT_FOUND,
        problem_description, response_data);
    Logger::udm_ueau().warn(problem_description);
    return;
  }
}

//------------------------------------------------------------------------------
void udm_app::handle_smf_selection_subscription_data_retrieval(
    const std::string& supi, nlohmann::json& response_data, uint32_t& code,
    std::string supported_features, PlmnId plmn_id) {
  // Get UDR's URI
  std::string remote_uri =
      udm_sbi_helper::get_udr_smf_selection_subscription_data_uri(
          supi, plmn_id);

  std::string body = {};
  Logger::udm_sdm().debug("Remote URI: " + remote_uri);

  // Get info from UDR
  oai::http::request http_request =
      http_client_inst->prepare_json_request(remote_uri, body);
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::GET, http_request);
  code = http_response.status_code;

  // Process response
  try {
    Logger::udm_sdm().debug(
        "subscription-data: GET Response: " + http_response.body);
    response_data = nlohmann::json::parse(http_response.body.c_str());
  } catch (nlohmann::json::exception& e) {
    Logger::udm_sdm().info("Could not get JSON content from UDR response");
    code = oai::common::sbi::http_status_code::NOT_FOUND;
    std::string problem_description = "User " + supi + " not found";
    set_problem_details(
        code, udm_protocol_application_error::USER_NOT_FOUND,
        problem_description, response_data);
    Logger::udm_ueau().warn(problem_description);
    return;
  }
  Logger::udm_sdm().debug("HTTP response code %d", code);
  return;
}

//------------------------------------------------------------------------------
void udm_app::handle_subscription_creation(
    const std::string& supi,
    const oai::model::udm::SdmSubscription& sdmSubscription,
    nlohmann::json& response_data, uint32_t& code) {
  std::string udr_ip =
      std::string(inet_ntoa(*((struct in_addr*) &udm_cfg.udr_addr.ipv4_addr)));
  std::string udr_port = std::to_string(udm_cfg.udr_addr.port);
  std::string remote_uri;
  std::string msg_body;
  nlohmann::json problem_details_json;
  ProblemDetails problem_details;

  // Get 3gpp_registration related info
  remote_uri = udm_sbi_helper::get_udr_sdm_subscriptions_uri(supi);
  Logger::udm_uecm().debug("Remote URI:" + remote_uri);

  nlohmann::json sdm_subscription_json;
  to_json(sdm_subscription_json, sdmSubscription);

  oai::http::request http_request = http_client_inst->prepare_json_request(
      remote_uri, sdm_subscription_json.dump());
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::POST, http_request);

  nlohmann::json response_data_json = {};
  try {
    Logger::udm_uecm().debug("HTTP Response:" + http_response.body);
    response_data_json = nlohmann::json::parse(http_response.body.c_str());

  } catch (nlohmann::json::exception& e) {  // error handling
    Logger::udm_uecm().info("Could not get JSON content from UDR response");
    code = oai::common::sbi::http_status_code::NOT_FOUND;
    std::string problem_description = "User " + supi + " not found";
    set_problem_details(
        code, udm_protocol_application_error::USER_NOT_FOUND,
        problem_description, response_data);
    Logger::udm_ueau().warn(problem_description);
    return;
  }
  Logger::udm_uecm().debug("HTTP response code %d", http_response.status_code);
  response_data = sdm_subscription_json;  // to be verified
  code          = http_response.status_code;
}

//------------------------------------------------------------------------------
evsub_id_t udm_app::handle_create_ee_subscription(
    const std::string& ueIdentity,
    const oai::model::udm::EeSubscription& eeSubscription,
    oai::model::udm::CreatedEeSubscription& createdSub, uint32_t& code) {
  Logger::udm_ee().info("Handle Create EE Subscription");

  // Generate a subscription ID Id and store the corresponding information in a
  // map (subscription id, info)
  evsub_id_t evsub_id = generate_ev_subscription_id();

  oai::model::udm::EeSubscription es = eeSubscription;
  // TODO: Update Subscription

  // MonitoringConfiguration

  es.setSubscriptionId(std::to_string(evsub_id));
  std::shared_ptr<CreatedEeSubscription> ces =
      std::make_shared<CreatedEeSubscription>(createdSub);
  ces->setEeSubscription(es);

  if (!ueIdentity.empty()) {
    ces->setNumberOfUes(1);
  } else {
    // TODO: For group of UEs
  }
  // TODO: MonitoringReport

  add_event_subscription(evsub_id, ueIdentity, ces);
  code = oai::common::sbi::http_status_code::CREATED;

  return evsub_id;
}

//------------------------------------------------------------------------------
void udm_app::handle_delete_ee_subscription(
    const std::string& ueIdentity, const std::string& subscriptionId,
    ProblemDetails& problemDetails, uint32_t& code) {
  Logger::udm_ee().info("Handle Delete EE Subscription");

  if (!delete_event_subscription(subscriptionId, ueIdentity)) {
    // Set ProblemDetails
    // Code
    code = oai::common::sbi::http_status_code::NOT_FOUND;
  }
  code = oai::common::sbi::http_status_code::NO_CONTENT;
  return;
}

//------------------------------------------------------------------------------
void udm_app::handle_update_ee_subscription(
    const std::string& ueIdentity, const std::string& subscriptionId,
    const std::vector<PatchItem>& patchItem, ProblemDetails& problemDetails,
    uint32_t& code) {
  Logger::udm_ee().info("Handle Update EE Subscription");
  // TODO:
  bool op_success = false;

  for (auto p : patchItem) {
    auto op = p.getOp().getEnumValue();
    // Verify Path
    if ((p.getPath().substr(0, 1).compare("/") != 0) or
        (p.getPath().length() < 2)) {
      Logger::udm_ee().warn(
          "Bad value for operation path: %s ", p.getPath().c_str());
      code = oai::common::sbi::http_status_code::BAD_REQUEST;
      problemDetails.setCause(
          oai::common::sbi::protocol_application_error_to_string(
              oai::common::sbi::protocol_application_error::
                  MANDATORY_IE_INCORRECT));
      return;
    }

    std::string path = p.getPath().substr(1);

    switch (op) {
      case PatchOperation_anyOf::ePatchOperation_anyOf::REPLACE: {
        if (replace_ee_subscription_item(path, p.getValue())) {
          code = oai::common::sbi::http_status_code::OK;
        } else {
          op_success = false;
        }
      } break;

      case PatchOperation_anyOf::ePatchOperation_anyOf::ADD: {
        if (add_ee_subscription_item(path, p.getValue())) {
          code = oai::common::sbi::http_status_code::OK;
        } else {
          op_success = false;
        }
      } break;

      case PatchOperation_anyOf::ePatchOperation_anyOf::REMOVE: {
        if (remove_ee_subscription_item(path)) {
          code = oai::common::sbi::http_status_code::OK;
        } else {
          op_success = false;
        }
      } break;

      default: {
        Logger::udm_ee().warn("Requested operation is not valid!");
        op_success = false;
      }
    }

    if (!op_success) {
      code = oai::common::sbi::http_status_code::BAD_REQUEST;
      problemDetails.setCause(
          oai::common::sbi::protocol_application_error_to_string(
              oai::common::sbi::protocol_application_error::
                  INVALID_QUERY_PARAM));  // TODO:
    } else {
    }
  }
}

//------------------------------------------------------------------------------
evsub_id_t udm_app::generate_ev_subscription_id() {
  return evsub_id_generator.get_uid();
}

//------------------------------------------------------------------------------
void udm_app::add_event_subscription(
    const evsub_id_t& sub_id, const std::string& ue_id,
    std::shared_ptr<oai::model::udm::CreatedEeSubscription>& ces) {
  std::unique_lock lock(m_mutex_udm_event_subscriptions);
  udm_event_subscriptions[sub_id] = ces;
  std::vector<evsub_id_t> ev_subs;

  if (udm_event_subscriptions_per_ue.count(ue_id) > 0) {
    ev_subs = udm_event_subscriptions_per_ue.at(ue_id);
  }
  ev_subs.push_back(sub_id);
  udm_event_subscriptions_per_ue[ue_id] = ev_subs;
  return;
}

//------------------------------------------------------------------------------
bool udm_app::delete_event_subscription(
    const std::string& subscription_id, const std::string& ue_id) {
  std::unique_lock lock(m_mutex_udm_event_subscriptions);
  bool result     = true;
  uint32_t sub_id = 0;
  try {
    sub_id = std::stoul(subscription_id);
  } catch (std::exception e) {
    Logger::udm_ee().warn(
        "Bad value for subscription id %s ", subscription_id.c_str());
    return false;
  }

  if (udm_event_subscriptions.count(sub_id)) {
    udm_event_subscriptions.erase(sub_id);
  } else {
    result = false;
  }

  if (udm_event_subscriptions_per_ue.count(ue_id) > 0) {
    udm_event_subscriptions_per_ue.erase(ue_id);
  } else {
    result = false;
  }

  return result;
}

//------------------------------------------------------------------------------
bool udm_app::replace_ee_subscription_item(
    const std::string& path, const std::string& value) {
  Logger::udm_ee().debug(
      "Replace member %s with new value %s", path.c_str(), value.c_str());
  // TODO:

  return true;
}

//------------------------------------------------------------------------------
bool udm_app::add_ee_subscription_item(
    const std::string& path, const std::string& value) {
  Logger::udm_ee().debug(
      "Add member %s with value %s", path.c_str(), value.c_str());
  // TODO:
  return true;
}

//------------------------------------------------------------------------------
bool udm_app::remove_ee_subscription_item(const std::string& path) {
  Logger::udm_ee().debug("Remove member %s", path.c_str());
  // TODO:
  return true;
}

//------------------------------------------------------------------------------
void udm_app::handle_ee_loss_of_connectivity(
    const std::string& ue_id, uint8_t status, uint8_t http_version) {
  // TODO:
}

//------------------------------------------------------------------------------
void udm_app::handle_ee_ue_reachability_for_data(
    const std::string& ue_id, uint8_t status, uint8_t http_version) {
  // TODO:
}

//------------------------------------------------------------------------------
void udm_app::increment_sqn(const std::string& c_sqn, std::string& n_sqn) {
  unsigned long long sqn_value;
  std::stringstream s1;
  s1 << std::hex << c_sqn;
  s1 >> sqn_value;  // hex string to decimal value
  sqn_value += 32;
  std::stringstream s2;
  s2 << std::hex << std::setw(12) << std::setfill('0')
     << sqn_value;  // decimal value to hex string

  std::string sqn_tmp(s2.str());
  n_sqn = sqn_tmp;
}

//------------------------------------------------------------------------------
void udm_app::set_problem_details(
    uint16_t status, uint16_t cause, const std::string& detail,
    nlohmann::json& problem_details) {
  ProblemDetails p = {};
  p.setStatus(status);
  p.setCause(udm_protocol_application_error_to_string(cause));
  p.setDetail(detail);
  to_json(problem_details, p);
}
