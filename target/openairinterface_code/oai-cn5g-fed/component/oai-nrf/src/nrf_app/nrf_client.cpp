/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "nrf_client.hpp"

#include "3gpp_29.500.h"
#include "http_client.hpp"
#include "logger.hpp"
#include "nrf_config.hpp"

extern std::shared_ptr<oai::http::http_client> http_client_inst;

//------------------------------------------------------------------------------
nrf_client::nrf_client() {}

//------------------------------------------------------------------------------
nrf_client::~nrf_client() {
  Logger::nrf_app().debug("Delete NRF Client instance...");
}

//------------------------------------------------------------------------------
void nrf_client::notify_subscribed_event(
    const std::shared_ptr<nrf_profile>& profile, const uint8_t& event_type,
    const std::vector<std::string>& uris, uint8_t http_version) {
  Logger::nrf_app().debug(
      "Send notification for the subscribed event to the subscriptions (HTTP "
      "VERSION %d)",
      http_version);

  std::map<std::string, std::string> responses = {};
  // Fill the json part
  nlohmann::json json_data = {};
  json_data["event"]       = notification_event_type_e2str[event_type];

  std::vector<struct in_addr> instance_addrs = {};
  profile.get()->get_nf_ipv4_addresses(instance_addrs);
  // TODO: use the first IPv4 addr for now
  std::string instance_uri =
      std::string(inet_ntoa(*((struct in_addr*) &(instance_addrs[0]))));
  Logger::nrf_app().debug("NF instance URI: %s", instance_uri.c_str());
  json_data["nfInstanceUri"] = instance_uri;

  // NF profile
  if ((event_type == NOTIFICATION_TYPE_NF_REGISTERED) or
      (event_type == NOTIFICATION_TYPE_NF_PROFILE_CHANGED)) {
    nlohmann::json json_profile = {};
    switch (profile.get()->get_nf_type()) {
      case NF_TYPE_AMF: {
        std::static_pointer_cast<amf_profile>(profile).get()->to_json(
            json_profile);
      } break;
      case NF_TYPE_SMF: {
        std::static_pointer_cast<smf_profile>(profile).get()->to_json(
            json_profile);
      } break;
      case NF_TYPE_UPF: {
        std::static_pointer_cast<upf_profile>(profile).get()->to_json(
            json_profile);
      } break;
      case NF_TYPE_AUSF: {
        std::static_pointer_cast<ausf_profile>(profile).get()->to_json(
            json_profile);
      } break;
      default: {
        profile.get()->to_json(json_profile);
      }
    }
    json_data["nfProfile"] = json_profile;
  }

  // TODO: profileChanges in case of "NF_PROFILE_CHANGED" instead of NF Profile

  std::string body = json_data.dump();

  for (auto uri : uris) {
    responses[uri] = "";
    std::unique_ptr<std::string> httpData(new std::string());

    Logger::nrf_app().debug(
        "Send notification for the subscribed event to the subscriptions, URI: "
        "%s",
        uri.c_str());
    oai::http::request http_request =
        http_client_inst->prepare_json_request(uri, body);
    auto http_response = http_client_inst->send_http_request(
        oai::common::sbi::method_e::POST, http_request);
    responses[uri] = http_response.body;
    // TODO: process response
  }
}
