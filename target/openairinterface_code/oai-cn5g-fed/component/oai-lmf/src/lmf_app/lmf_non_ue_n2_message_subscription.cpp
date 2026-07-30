/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "lmf_non_ue_n2_message_subscription.hpp"

#include <arpa/inet.h>

#include <string>
using namespace std::string_literals;

#include "NonUeN2InfoSubscriptionCreateData.h"
#include "NonUeN2InfoSubscriptionCreatedData.h"
#include "ProblemDetails.h"
#include "http_client.hpp"
#include "lmf_config.hpp"
#include "lmf_nrf.hpp"
#include "lmf_sbi_helper.hpp"
#include "logger.hpp"
#include "nlohmann/json.hpp"
#include "pistache/http_defs.h"

using namespace oai::model::lmf;
using namespace oai::lmf::api;

extern std::shared_ptr<oai::http::http_client> http_client_inst;

//------------------------------------------------------------------------------
// 5.2.2.4.3 NonUeN2InfoUnsubscribe
void NonUeN2MessageSubscription::unsubscribe(std::string const& id) {
  // 1. DELETE
  // ./namf_comm/v1/non-ue-n2-messages/subscriptions/{n2NotifySubscriptionId}
  std::string amf_uri = {};
  lmf_sbi_helper::get_amf_comm_non_ue_n2_info_un_subscribe_uri(
      lmf_cfg.amf_addr, id, amf_uri);
  Logger::lmf_app().debug("AMF's URI %s", amf_uri);

  // 2. 204 No Content
  std::string response;
  // Send HTTP request
  oai::http::request http_request =
      http_client_inst->prepare_json_request(amf_uri);
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::DELETE, http_request);
  response = http_response.body;

  Logger::lmf_app().debug("Response from AMF: %s"s, response);
  if (!response.empty()) {
    Logger::lmf_app().error("deleted NonUeN2InfoUnsubscribe %s failed", id);
  } else {
    Logger::lmf_app().info(
        "deleted NonUeN2InfoUnsubscribe %s successfully", id);
  }
}

//------------------------------------------------------------------------------
// 5.2.2.4.2 NonUeN2InfoSubscribe
std::string NonUeN2MessageSubscription::subscribe() {
  // 1. POST
  // ./namf_comm/v1/non-ue-n2-messages/subscriptions
  // (NonUeN2InfoSubscriptionCreateData)
  std::string amf_uri = {};
  lmf_sbi_helper::get_amf_comm_non_ue_n2_info_subscribe_uri(
      lmf_cfg.amf_addr, amf_uri);

  // 5.2.2.4.4 NonUeN2InfoNotify n2NotifyCallbackUri
  std::string n2NotifyCallbackUri = {};
  lmf_sbi_helper::get_lmf_non_ue_n2_info_notify_nrppa_callback_uri(
      lmf_cfg.sbi, n2NotifyCallbackUri);

  Logger::lmf_app().debug("AMF's URI %s", amf_uri);

  // 6.1.6.2.10 Type: NonUeN2InfoSubscriptionCreateData
  N2InformationClass n2InformationClass;
  n2InformationClass.setEnumValue(
      N2InformationClass_anyOf::eN2InformationClass_anyOf::NRPPA);

  NonUeN2InfoSubscriptionCreateData nonUeN2InfoSubscriptionCreateData;
  // setGlobalRanNodeList / setAnTypeList
  nonUeN2InfoSubscriptionCreateData.setN2InformationClass(n2InformationClass);
  nonUeN2InfoSubscriptionCreateData.setN2NotifyCallbackUri(n2NotifyCallbackUri);
  nonUeN2InfoSubscriptionCreateData.setNfId(lmf_nrf_inst->lmf_instance_id);

  // 2. 201 Created (nonUeN2InfoSubscriptionCreateData)
  std::string response;
  // Send HTTP request
  oai::http::request http_request = http_client_inst->prepare_json_request(
      amf_uri, nlohmann::json(nonUeN2InfoSubscriptionCreateData).dump());
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::POST, http_request);
  response = http_response.body;
  Logger::lmf_app().debug("Response from AMF: %s", response);

  try {
    // 6.1.6.2.11 Type: NonUeN2InfoSubscriptionCreatedData
    NonUeN2InfoSubscriptionCreatedData nonUeN2InfoSubscriptionCreatedData{
        nlohmann::json::parse(response)};
    auto const& id =
        nonUeN2InfoSubscriptionCreatedData.getN2NotifySubscriptionId();
    return id;
  } catch (nlohmann::detail::exception const& ex) {
    auto title  = "NonUeN2InfoSubscription failed"s;
    auto detail = "amf_uri: '" + amf_uri + "', respone: '" + response +
                  "', ex: " + ex.what();
    oai::lmf::api::lmf_sbi_helper::throwHttpError(title, detail);
    return {};  // suppress no return warning
  }
}
