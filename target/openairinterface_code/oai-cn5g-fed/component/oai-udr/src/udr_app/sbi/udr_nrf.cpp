/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "udr_nrf.hpp"

#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <nlohmann/json.hpp>
#include <stdexcept>

#include "3gpp_29.500.h"
#include "http_client.hpp"
#include "logger.hpp"
#include "udr.h"
#include "udr_app.hpp"
#include "udr_profile.hpp"

using namespace oai::udr::config;
using namespace oai::udr::app;
using namespace boost::placeholders;

using json = nlohmann::json;

extern udr_config udr_cfg;
extern udr_nrf* udr_nrf_inst;
extern std::shared_ptr<oai::http::http_client> http_client_inst;

//------------------------------------------------------------------------------
udr_nrf::udr_nrf(udr_event& ev) : m_event_sub(ev) {
  // generate UUID
  udr_instance_id = to_string(boost::uuids::random_generator()());
  // Generate UDR profile
  generate_udr_profile();
}

//------------------------------------------------------------------------------
void udr_nrf::start() {
  // Register to NRF
  if (udr_cfg.register_nrf) {
    Logger::udr_app().info("NRF TASK Created ");
    register_to_nrf();
  }
}

//------------------------------------------------------------------------------
void udr_nrf::stop() {
  // Deregister to NRF
  if (udr_cfg.register_nrf) {
    deregister_to_nrf();
  }
}

//---------------------------------------------------------------------------------------------
void udr_nrf::generate_udr_profile() {
  // TODO: remove hardcoded values
  udr_nf_profile.set_nf_instance_id(udr_instance_id);
  udr_nf_profile.set_nf_instance_name("OAI-UDR");
  udr_nf_profile.set_nf_type("UDR");
  udr_nf_profile.set_nf_status("REGISTERED");
  udr_nf_profile.set_nf_heartBeat_timer(50);
  udr_nf_profile.set_nf_priority(1);
  udr_nf_profile.set_nf_capacity(100);
  // udr_nf_profile.set_fqdn(udr_cfg.fqdn);
  udr_nf_profile.add_nf_ipv4_addresses(udr_cfg.nudr.addr4);

  // UDR info (Hardcoded for now)
  // ToDo:-If none of these parameters are provided, the UDR can serve any
  // external group and any SUPI or GPSI managed by the PLMN of the UDR
  // instance. If "supiRanges", "gpsiRanges" and
  // "externalGroupIdentifiersRanges" attributes are absent, and "groupId" is
  // present, the SUPIs / GPSIs / ExternalGroups served by this UDR instance is
  // determined by the NRF (see 3GPP TS 23.501 [2], clause 6.2.6.2).
  oai::common::sbi::udr_info_t udr_info_item;
  oai::common::sbi::supi_range_info_item_t supi_ranges;
  udr_info_item.groupid = "oai-udr-testgroupid";
  udr_info_item.data_set_id.push_back("0210");
  udr_info_item.data_set_id.push_back("9876");
  supi_ranges.supi_range.start   = "208950000000031";
  supi_ranges.supi_range.pattern = "^imsi-20895[31-131]{6}$";
  supi_ranges.supi_range.start   = "208950000000131";
  udr_info_item.supi_ranges.push_back(supi_ranges);
  oai::common::sbi::identity_range_info_item_t gpsi_ranges;
  gpsi_ranges.identity_range.start   = "752740000";
  gpsi_ranges.identity_range.pattern = "^gpsi-75274[0-9]{4}$";
  gpsi_ranges.identity_range.end     = "752749999";
  udr_info_item.gpsi_ranges.push_back(gpsi_ranges);
  udr_nf_profile.set_udr_info(udr_info_item);
  // ToDo:- Add remaining fields
  // UDR info item end

  udr_nf_profile.display();
}
//---------------------------------------------------------------------------------------------
void udr_nrf::register_to_nrf() {
  nlohmann::json response_data = {};

  // Send NF registration request
  std::string nrf_uri = {};
  oai::common::sbi::sbi_helper::get_nrf_nf_instance_uri(
      udr_cfg.nrf_addr, udr_instance_id, nrf_uri);
  nlohmann::json json_data = {};
  udr_nf_profile.to_json(json_data);

  Logger::udr_nrf().info("Sending NF Registration request");
  bool is_registration_success = false;

  oai::http::request http_request =
      http_client_inst->prepare_json_request(nrf_uri, json_data.dump());
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::PUT, http_request);

  if ((http_response.status_code == oai::common::sbi::http_status_code::OK) or
      (http_response.status_code ==
       oai::common::sbi::http_status_code::CREATED)) {
    try {
      response_data = nlohmann::json::parse(http_response.body);
      // TODO: use Heart-beart timer interval returned from NRF
      if (response_data.find("nfStatus") != response_data.end()) {
        std::string status = response_data["nfStatus"].get<std::string>();
        if (status.compare("REGISTERED") == 0) {
          is_registration_success = true;
          stop_nrf_registration_retry();
          start_event_nf_heartbeat(nrf_uri);
        }
      }
    } catch (nlohmann::json::exception& e) {
      Logger::udr_nrf().info("NF Registration procedure failed.");
    }
  }

  if (!is_registration_success) {
    Logger::udr_app().debug("NF registration procedure failed, try again ...");
    start_nrf_registration_retry();
  }
}

//---------------------------------------------------------------------------------------------
void udr_nrf::deregister_to_nrf() {
  nlohmann::json response_data = {};
  // Send NFs deregistration request
  std::string nrf_uri = {};
  oai::common::sbi::sbi_helper::get_nrf_nf_instance_uri(
      udr_cfg.nrf_addr, udr_instance_id, nrf_uri);

  Logger::udr_nrf().info("Sending NF Deregistration request");

  oai::http::request http_request =
      http_client_inst->prepare_json_request(nrf_uri);
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::DELETE, http_request);

  if (http_response.status_code ==
      oai::common::sbi::http_status_code::NO_CONTENT) {
    // TODO:
  } else {
    Logger::udr_nrf().info("NF Deregistration procedure failed.");
    // TODO:
  }
}

//---------------------------------------------------------------------------------------------
void udr_nrf::start_event_nf_heartbeat(std::string& nrf_uri) {
  // get current time
  uint64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count();
  struct itimerspec its;
  its.it_value.tv_sec  = HEART_BEAT_TIMER;  // seconds
  its.it_value.tv_nsec = 0;                 // 100 * 1000 * 1000; //100ms
  const uint64_t interval =
      its.it_value.tv_sec * 1000 +
      its.it_value.tv_nsec / 1000000;  // convert sec, nsec to msec

  task_connection = m_event_sub.subscribe_task_nf_heartbeat(
      boost::bind(&udr_nrf::trigger_nf_heartbeat_procedure, this, _1), interval,
      ms + interval);
}
//---------------------------------------------------------------------------------------------
void udr_nrf::trigger_nf_heartbeat_procedure(uint64_t ms) {
  _unused(ms);
  oai::model::common::PatchItem patch_item = {};
  std::vector<oai::model::common::PatchItem> patch_items;
  //{"op":"replace","path":"/nfStatus", "value": "REGISTERED"}
  oai::model::common::PatchOperation op;
  op.setEnumValue(
      oai::model::common::PatchOperation_anyOf::ePatchOperation_anyOf::REPLACE);
  patch_item.setOp(op);
  patch_item.setPath("/nfStatus");
  patch_item.setValue("REGISTERED");
  patch_items.push_back(patch_item);
  Logger::udr_nrf().info("Sending NF Heartbeat Request");

  std::string method       = {"PATCH"};
  nlohmann::json json_data = nlohmann::json::array();
  for (auto i : patch_items) {
    nlohmann::json item = {};
    to_json(item, i);
    json_data.push_back(item);
  }

  std::string nrf_uri = {};
  oai::common::sbi::sbi_helper::get_nrf_nf_instance_uri(
      udr_cfg.nrf_addr, udr_instance_id, nrf_uri);

  oai::http::request http_request =
      http_client_inst->prepare_json_request(nrf_uri, json_data.dump());
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::PATCH, http_request);

  if ((http_response.status_code == oai::common::sbi::http_status_code::OK) or
      (http_response.status_code ==
       oai::common::sbi::http_status_code::NO_CONTENT)) {
    // TODO: process the response
  } else {
    Logger::udr_nrf().info(
        "NF Heartbeat procedure failed, try to register again");
    if (task_connection.connected()) task_connection.disconnect();
    register_to_nrf();
  }
}

//---------------------------------------------------------------------------------------------
void udr_nrf::start_nrf_registration_retry() {
  if (!retry_nrf_registration_task_connection.connected()) {
    // get current time
    uint64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count();
    const uint64_t interval =
        NRF_REGISTRATION_RETRY_TIMER * 1000;  // convert sec to msec

    Logger::udr_nrf().debug("Start NRF registration retry task");
    retry_nrf_registration_task_connection =
        m_event_sub.subscribe_task_nf_heartbeat(
            boost::bind(
                &udr_nrf::trigger_nrf_registration_retry_procedure, this, _1),
            interval, ms + interval);
  }
}

//---------------------------------------------------------------------------------------------
void udr_nrf::trigger_nrf_registration_retry_procedure(uint64_t ms) {
  _unused(ms);
  register_to_nrf();
}

//---------------------------------------------------------------------------------------------
void udr_nrf::stop_nrf_registration_retry() {
  // get current time
  uint64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count();
  if (retry_nrf_registration_task_connection.connected()) {
    Logger::udr_nrf().debug("Stop NRF registration retry task");
    retry_nrf_registration_task_connection.disconnect();
  }
}
