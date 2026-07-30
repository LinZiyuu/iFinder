/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "pcf_nrf.hpp"
#include "logger.hpp"
#include "3gpp_29.500.h"
#include "3gpp_29.510.h"
#include "pcf_config.hpp"
#include "Snssai.h"
#include "api_defs.h"
#include "http_client.hpp"
#include "sbi_helper.hpp"

#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>

using namespace oai::pcf::app;
using namespace oai::config::pcf;
using namespace oai::model::common;
using namespace boost::placeholders;
using namespace std;

extern std::unique_ptr<pcf_config> pcf_cfg;
extern std::shared_ptr<oai::http::http_client> http_client_inst;

//------------------------------------------------------------------------------
pcf_nrf::pcf_nrf(pcf_event& ev) : m_event_sub(ev) {
  m_pcf_instance_id = to_string(boost::uuids::random_generator()());
  generate_pcf_profile();
  nf_addr_t nf_addr;
  nf_addr.api_version =
      pcf_cfg->get_nf(config::NRF_CONFIG_NAME)->get_sbi().get_api_version();
  nf_addr.uri_root =
      pcf_cfg->get_nf(config::NRF_CONFIG_NAME)->get_sbi().get_url();

  sbi_helper::get_nrf_nf_instance_uri(nf_addr, m_pcf_instance_id, m_nrf_url);
}

//---------------------------------------------------------------------------------------------
void pcf_nrf::generate_pcf_profile() {
  // TODO: remove hardcoded values
  // generate UUID
  m_nf_instance_profile.set_nf_instance_id(m_pcf_instance_id);
  m_nf_instance_profile.set_nf_instance_name("OAI-PCF");
  m_nf_instance_profile.set_nf_type("PCF");
  m_nf_instance_profile.set_nf_status("REGISTERED");
  m_nf_instance_profile.set_nf_heartBeat_timer(50);
  m_nf_instance_profile.set_nf_priority(1);
  m_nf_instance_profile.set_nf_capacity(100);
  m_nf_instance_profile.add_nf_ipv4_addresses(
      pcf_cfg->local().get_sbi().get_addr4());

  // NF services
  nf_service_t nf_service        = {};
  nf_service.service_instance_id = oai::pcf::api::sm_policies::API_NAME;
  nf_service.service_name        = oai::pcf::api::sm_policies::API_NAME;
  nf_service_version_t version   = {};
  version.api_version_in_uri     = pcf_cfg->local().get_sbi().get_api_version();
  version.api_full_version       = "1.0.0";  // TODO: to be updated
  nf_service.versions.push_back(version);
  nf_service.scheme            = "http";
  nf_service.nf_service_status = "REGISTERED";
  // IP Endpoint
  ip_endpoint_t endpoint = {};
  // TODO: use only one IP address from cfg for now
  endpoint.ipv4_address = pcf_cfg->local().get_sbi().get_addr4();
  endpoint.transport    = "TCP";
  endpoint.port         = pcf_cfg->local().get_sbi().get_port();
  nf_service.ip_endpoints.push_back(endpoint);

  m_nf_instance_profile.add_nf_service(nf_service);

  // PCF info
  pcf_info_t pcf_info_item;
  pcf_info_item.groupid = "oai-pcf-testgroupid";
  pcf_info_item.dnn_list.emplace_back("default");
  pcf_info_item.dnn_list.emplace_back("oai");
  pcf_info_item.dnn_list.emplace_back("oai.ipv4");
  pcf_info_item.dnn_list.emplace_back("ims");
  supi_range_info_item_t supi_ranges;
  supi_ranges.supi_range.start   = "208950000000031";
  supi_ranges.supi_range.pattern = "^imsi-20895[31-131]{10}$";
  supi_ranges.supi_range.end     = "208950000000131";
  pcf_info_item.supi_ranges.push_back(supi_ranges);
  identity_range_info_item_t gpsi_ranges;
  gpsi_ranges.identity_range.start   = "752740000";
  gpsi_ranges.identity_range.pattern = "^gpsi-75274[0-9]{4}$";
  gpsi_ranges.identity_range.end     = "752749999";
  pcf_info_item.gpsi_ranges.push_back(gpsi_ranges);
  m_nf_instance_profile.set_pcf_info(pcf_info_item);
  // ToDo: rxDiamHost, rxDiamRealm, v2xSupportInd.
  // Display the profile
  m_nf_instance_profile.display();
}

//---------------------------------------------------------------------------------------------
void pcf_nrf::register_to_nrf() {
  nlohmann::json body;
  m_nf_instance_profile.to_json(body);

  Logger::pcf_sbi().info("Sending NF registration request");
  auto request = http_client_inst->prepare_json_request(m_nrf_url, body.dump());
  auto http_response =
      http_client_inst->send_http_request(method_e::PUT, request);

  if (http_response.status_code == http_status_code::CREATED ||
      http_response.status_code == http_status_code::OK) {
    try {
      if (http_response.body.find("REGISTERED") != 0) {
        start_event_nf_heartbeat(m_nrf_url);
      }
      Logger::pcf_sbi().debug("NF registration successful");
    } catch (nlohmann::json::exception& e) {
      Logger::pcf_sbi().warn("NF registration procedure failed");
    }
  } else {
    Logger::pcf_sbi().warn(
        "NF registration failed: Wrong response code: %d",
        http_response.status_code);
  }
}
//------------------------------------------------------------------------------
void pcf_nrf::start_event_nf_heartbeat(std::string& /* remoteURI */) {
  // get current time
  uint64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count();
  const uint64_t interval = HEART_BEAT_TIMER * 1000;  // ms

  m_task_connection = m_event_sub.subscribe_task_nf_heartbeat(
      boost::bind(&pcf_nrf::trigger_nf_heartbeat_procedure, this, _1), interval,
      ms + interval);
}

//---------------------------------------------------------------------------------------------
void pcf_nrf::trigger_nf_heartbeat_procedure(uint64_t /* ms */) {
  PatchItem patch_item = {};
  std::vector<PatchItem> patch_items;
  PatchOperation op;
  op.setEnumValue(PatchOperation_anyOf::ePatchOperation_anyOf::REPLACE);
  patch_item.setOp(op);
  patch_item.setPath("/nfStatus");
  patch_item.setValue("REGISTERED");
  patch_items.push_back(patch_item);
  Logger::pcf_sbi().info("Sending NF heartbeat request");

  nlohmann::json j;
  to_json(j, patch_item);

  auto request = http_client_inst->prepare_json_request(m_nrf_url, j.dump());
  auto http_response =
      http_client_inst->send_http_request(method_e::PATCH, request);

  if (http_response.status_code == http_status_code::OK ||
      http_response.status_code == http_status_code::NO_CONTENT) {
    Logger::pcf_sbi().debug("NF heartbeat request successful");
  } else {
    // TODO what should we do in this case?
    // We disconnect, but we dont trigger anything else
    Logger::pcf_sbi().warn(
        "NF heartbeat request failed. Wrong response code %d",
        http_response.status_code);
    m_task_connection.disconnect();
  }
}
//------------------------------------------------------------------------------
pcf_nrf::~pcf_nrf() {
  Logger::pcf_sbi().debug("Delete PCF_NRF instance...");
}

//------------------------------------------------------------------------------
void pcf_nrf::deregister_to_nrf() {
  std::string body_response;
  std::string response_header;

  Logger::pcf_sbi().info("Sending NF de-registration request");

  http::request req;
  req.uri = m_nrf_url;
  auto http_response =
      http_client_inst->send_http_request(method_e::DELETE, req);

  if (http_response.status_code == http_status_code::NO_CONTENT) {
    Logger::pcf_sbi().info("NF Deregistration successful");
  } else {
    Logger::pcf_sbi().warn(
        "NF Deregistration failed! Wrong response code: %d",
        http_response.status_code);
  }
}
