/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "ausf_nrf.hpp"

#include <pistache/http.h>

#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <nlohmann/json.hpp>
#include <stdexcept>

#include "3gpp_29.500.h"
#include "ausf.h"
#include "ausf_app.hpp"
#include "ausf_profile.hpp"
#include "http_client.hpp"
#include "logger.hpp"

using namespace oai::config;
using namespace boost::placeholders;
using namespace oai::ausf::app;

using json = nlohmann::json;

extern ausf_config ausf_cfg;
extern std::shared_ptr<oai::http::http_client> http_client_inst;

//------------------------------------------------------------------------------
ausf_nrf::ausf_nrf(ausf_event& ev) : m_event_sub(ev) {
  // generate UUID
  {
    std::mutex m_generate_uuid;
    const std::lock_guard<std::mutex> lock(m_generate_uuid);
    ausf_instance_id = to_string(boost::uuids::random_generator()());
  }

  // Generate AUSF profile
  generate_ausf_profile();
}

//------------------------------------------------------------------------------
ausf_nrf::~ausf_nrf() {
  if (task_connection.connected()) task_connection.disconnect();
  if (retry_nrf_registration_task_connection.connected())
    retry_nrf_registration_task_connection.disconnect();
}

//---------------------------------------------------------------------------------------------
void ausf_nrf::generate_ausf_profile() {
  // TODO: remove hardcoded values
  ausf_nf_profile.set_nf_instance_id(ausf_instance_id);
  ausf_nf_profile.set_nf_instance_name("OAI-AUSF");
  ausf_nf_profile.set_nf_type("AUSF");
  ausf_nf_profile.set_nf_status("REGISTERED");
  ausf_nf_profile.set_nf_heartBeat_timer(50);
  ausf_nf_profile.set_nf_priority(1);
  ausf_nf_profile.set_nf_capacity(100);
  ausf_nf_profile.add_nf_ipv4_addresses(ausf_cfg.sbi.addr4);

  // AUSF info (Hardcoded for now)
  oai::common::sbi::ausf_info_t ausf_info_item;
  oai::common::sbi::supi_range_info_item_t supi_ranges;
  ausf_info_item.groupid = "oai-ausf-testgroupid";
  ausf_info_item.routing_indicators.push_back("0210");
  ausf_info_item.routing_indicators.push_back("9876");
  supi_ranges.supi_range.start   = "109238210938";
  supi_ranges.supi_range.pattern = "209238210938";
  supi_ranges.supi_range.start   = "q0930j0c80283ncjf";
  ausf_info_item.supi_ranges.push_back(supi_ranges);
  ausf_nf_profile.set_ausf_info(ausf_info_item);

  ausf_nf_profile.display();
}

//------------------------------------------------------------------------------
std::string ausf_nrf::get_nf_instance_id() const {
  return ausf_instance_id;
}

//---------------------------------------------------------------------------------------------
void ausf_nrf::register_to_nrf() {
  nlohmann::json response_data = {};

  // Send NF registration request
  std::string nrf_uri = {};

  sbi_helper::get_nrf_nf_instance_uri(
      ausf_cfg.nrf_addr, ausf_instance_id, nrf_uri);
  nlohmann::json json_data = {};
  ausf_nf_profile.to_json(json_data);

  bool registration_success = false;
  Logger::ausf_nrf().info("Sending NF registration request");

  oai::http::request http_request =
      http_client_inst->prepare_json_request(nrf_uri, json_data.dump());
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::PUT, http_request);

  if (http_response.status_code !=
      oai::common::sbi::http_status_code::NO_RESPONSE) {
    try {
      response_data = nlohmann::json::parse(http_response.body);
      if (response_data.find("nfStatus") != response_data.end()) {
        std::string status = response_data["nfStatus"].get<std::string>();
        if (status.compare("REGISTERED") == 0) {
          registration_success = true;
          start_event_nf_heartbeat(nrf_uri);
          stop_nrf_registration_retry();
        }
      }
    } catch (nlohmann::json::exception& e) {
      Logger::ausf_nrf().info(
          "NF Registration procedure failed (%s), try again ...", e.what());
    } catch (std::exception& e) {
      Logger::ausf_nrf().info(
          "NF Registration procedure failed (%s), try again ...", e.what());
    }
  } else {
    Logger::ausf_nrf().warn("Could not get the response from NRF!");
  }

  if (!registration_success) {
    start_nrf_registration_retry();
  }
}

//---------------------------------------------------------------------------------------------
void ausf_nrf::deregister_to_nrf() {
  std::string nrf_uri = {};

  sbi_helper::get_nrf_nf_instance_uri(
      ausf_cfg.nrf_addr, ausf_instance_id, nrf_uri);

  Logger::ausf_nrf().info(
      "Sending NF Deregistration request to NRF: %s", nrf_uri);

  oai::http::request http_request =
      http_client_inst->prepare_json_request(nrf_uri, "");
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::DELETE, http_request);
  // TODO: process the response
}

//---------------------------------------------------------------------------------------------
void ausf_nrf::start_event_nf_heartbeat(std::string& remoteURI) {
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
      boost::bind(&ausf_nrf::trigger_nf_heartbeat_procedure, this, _1),
      interval, ms + interval);
}

//---------------------------------------------------------------------------------------------
void ausf_nrf::trigger_nf_heartbeat_procedure(uint64_t ms) {
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
  Logger::ausf_nrf().info("Sending NF heartbeat request");

  nlohmann::json json_data = nlohmann::json::array();
  for (auto i : patch_items) {
    nlohmann::json item = {};
    to_json(item, i);
    json_data.push_back(item);
  }

  std::string nrf_api = {};
  sbi_helper::get_nrf_nf_instance_uri(
      ausf_cfg.nrf_addr, ausf_instance_id, nrf_api);

  bool is_heartbeat_success = false;

  oai::http::request http_request =
      http_client_inst->prepare_json_request(nrf_api, json_data.dump());
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::PATCH, http_request);

  if ((http_response.status_code == oai::common::sbi::http_status_code::OK) or
      (http_response.status_code ==
       oai::common::sbi::http_status_code::CREATED) or
      (http_response.status_code ==
       oai::common::sbi::http_status_code::NO_CONTENT)) {
    is_heartbeat_success = true;
    // TODO: process the response
  }

  if (!is_heartbeat_success) {
    Logger::ausf_nrf().info(
        "NF Heartbeat procedure failed, try to register again");
    if (task_connection.connected()) task_connection.disconnect();
    register_to_nrf();
  }
}

//---------------------------------------------------------------------------------------------
void ausf_nrf::start_nrf_registration_retry() {
  if (!retry_nrf_registration_task_connection.connected()) {
    // get current time
    uint64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count();
    const uint64_t interval =
        NRF_REGISTRATION_RETRY_TIMER * 1000;  // convert sec to msec

    Logger::ausf_nrf().debug("Start NRF registration retry task");
    retry_nrf_registration_task_connection =
        m_event_sub.subscribe_task_nf_heartbeat(
            boost::bind(
                &ausf_nrf::trigger_nrf_registration_retry_procedure, this, _1),
            interval, ms + interval);
  }
}

//---------------------------------------------------------------------------------------------
void ausf_nrf::trigger_nrf_registration_retry_procedure(uint64_t ms) {
  _unused(ms);
  register_to_nrf();
}

//---------------------------------------------------------------------------------------------
void ausf_nrf::stop_nrf_registration_retry() {
  // get current time
  uint64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count();
  if (retry_nrf_registration_task_connection.connected()) {
    Logger::ausf_nrf().debug("Stop NRF registration retry task");
    retry_nrf_registration_task_connection.disconnect();
  }
}
