/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "lmf_nrf.hpp"

#include <pistache/http.h>
#include <pistache/mime.h>

#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <nlohmann/json.hpp>
#include <stdexcept>

#include "PatchItem.h"
#include "http_client.hpp"
#include "lmf.h"
#include "lmf_config.hpp"
#include "lmf_profile.hpp"
#include "logger.hpp"
#include "sbi_helper.hpp"

using namespace oai::lmf::config;
using namespace oai::lmf::app;
using namespace oai::model::common;
using namespace boost::placeholders;

using json = nlohmann::json;

extern lmf_config lmf_cfg;
extern std::shared_ptr<oai::http::http_client> http_client_inst;

//------------------------------------------------------------------------------
lmf_nrf::lmf_nrf(lmf_event& ev) : m_event_sub(ev) {
  // generate UUID
  lmf_instance_id = to_string(boost::uuids::random_generator()());
  generate_lmf_profile(lmf_nf_profile, lmf_instance_id);
}

//------------------------------------------------------------------------------
lmf_nrf::~lmf_nrf() {
  if (task_connection.connected()) task_connection.disconnect();
  if (retry_nrf_registration_task_connection.connected())
    retry_nrf_registration_task_connection.disconnect();
}

//---------------------------------------------------------------------------------------------
void lmf_nrf::generate_lmf_profile(
    lmf_profile& lmf_nf_profile, std::string& lmf_instance_id) {
  // TODO: remove hardcoded values
  lmf_nf_profile.set_nf_instance_id(lmf_instance_id);
  lmf_nf_profile.set_nf_instance_name("OAI-LMF");
  lmf_nf_profile.set_nf_type("LMF");
  lmf_nf_profile.set_nf_status("REGISTERED");
  lmf_nf_profile.set_nf_heartBeat_timer(50);
  lmf_nf_profile.set_nf_priority(1);
  lmf_nf_profile.set_nf_capacity(100);
  lmf_nf_profile.add_nf_ipv4_addresses(lmf_cfg.sbi.addr4);  // N4's Addr

  // LMF info (Hardcoded for now)

  lmf_info_t lmf_info_item;
  lmf_info_item.lmfId = lmf_instance_id;
  lmf_info_item.servingClientTypes.push_back(
      externalClientType_e2str.at(ExternalClientType_t::VALUE_ADDED_SERVICES));
  lmf_info_item.servingAccessTypes.push_back(
      accessType_e2str.at(AccessType_t::_3GPP_ACCESS));
  lmf_info_item.servingAnNodeTypes.push_back(
      anNodeType_e2str.at(AnNodeType_t::GNB));
  lmf_info_item.servingRatTypes.push_back(ratType_e2str.at(RatType_t::NR));
  lmf_nf_profile.set_lmf_info(lmf_info_item);

  lmf_nf_profile.display();
}

//---------------------------------------------------------------------------------------------
void lmf_nrf::register_to_nrf() {
  nlohmann::json response_data = {};

  // Send NF registration request
  std::string response  = {};
  std::string remoteUri = {};
  sbi_helper::get_nrf_nf_instance_uri(
      lmf_cfg.nrf_addr, lmf_instance_id, remoteUri);

  nlohmann::json json_data = {};
  lmf_nf_profile.to_json(json_data);

  bool registration_success = false;
  Logger::lmf_nrf().debug("Sending NF registration request");

  oai::http::request http_request =
      http_client_inst->prepare_json_request(remoteUri, json_data.dump());
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::PUT, http_request);
  response = http_response.body;

  if (http_response.status_code !=
      oai::common::sbi::http_status_code::NO_RESPONSE) {
    try {
      response_data = nlohmann::json::parse(response);
      if (response.find("REGISTERED") != 0) {
        registration_success = true;
        Logger::lmf_nrf().debug("Registered to NRF");
        start_event_nf_heartbeat(remoteUri);
        stop_nrf_registration_retry();
      }
    } catch (nlohmann::json::exception& e) {
      Logger::lmf_nrf().info(
          "NF Registration procedure failed (%s), try again ...", e.what());
    }
  } else {
    Logger::lmf_nrf().warn(
        "Could not get the response from NRF, try again ...");
  }

  if (!registration_success) {
    start_nrf_registration_retry();
  }
}

//---------------------------------------------------------------------------------------------
void lmf_nrf::deregister_to_nrf() {
  std::string nrf_uri = {};

  sbi_helper::get_nrf_nf_instance_uri(
      lmf_cfg.nrf_addr, lmf_instance_id, nrf_uri);

  Logger::lmf_nrf().info(
      "Sending NF Deregistration request to NRF: %s", nrf_uri);

  oai::http::request http_request =
      http_client_inst->prepare_json_request(nrf_uri, "");
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::DELETE, http_request);
  // TODO: process the response
}

//---------------------------------------------------------------------------------------------
void lmf_nrf::start_event_nf_heartbeat(std::string& remoteURI) {
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
      boost::bind(&lmf_nrf::trigger_nf_heartbeat_procedure, this, _1), interval,
      ms + interval);
}

//---------------------------------------------------------------------------------------------
void lmf_nrf::trigger_nf_heartbeat_procedure(uint64_t ms) {
  _unused(ms);
  PatchItem patch_item = {};
  std::vector<PatchItem> patch_items;
  //{"op":"replace","path":"/nfStatus", "value": "REGISTERED"}
  PatchOperation patch_operation;
  patch_operation.setEnumValue(
      PatchOperation_anyOf::ePatchOperation_anyOf::REPLACE);
  patch_item.setOp(patch_operation);
  patch_item.setPath("/nfStatus");
  patch_item.setValue("REGISTERED");
  patch_items.push_back(patch_item);
  Logger::lmf_nrf().info("Sending NF heartbeat request");

  std::string response     = {};
  nlohmann::json json_data = nlohmann::json::array();
  for (auto i : patch_items) {
    nlohmann::json item = {};
    to_json(item, i);
    json_data.push_back(item);
  }

  std::string remoteUri = {};
  sbi_helper::get_nrf_nf_instance_uri(
      lmf_cfg.nrf_addr, lmf_instance_id, remoteUri);

  bool is_heartbeat_success = false;

  oai::http::request http_request =
      http_client_inst->prepare_json_request(remoteUri, json_data.dump());
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::PATCH, http_request);
  response = http_response.body;

  if ((http_response.status_code == oai::common::sbi::http_status_code::OK) or
      (http_response.status_code ==
       oai::common::sbi::http_status_code::CREATED) or
      (http_response.status_code ==
       oai::common::sbi::http_status_code::NO_CONTENT)) {
    is_heartbeat_success = true;
    // TODO: process the response
  }

  if (!is_heartbeat_success) {
    Logger::lmf_nrf().info(
        "NF Heartbeat procedure failed, try to register again");
    if (task_connection.connected()) task_connection.disconnect();
    register_to_nrf();
  }
}

//---------------------------------------------------------------------------------------------
void lmf_nrf::start_nrf_registration_retry() {
  if (!retry_nrf_registration_task_connection.connected()) {
    // get current time
    uint64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count();
    const uint64_t interval =
        NRF_REGISTRATION_RETRY_TIMER * 1000;  // convert sec to msec

    Logger::lmf_nrf().debug("Start NRF registration retry task");
    retry_nrf_registration_task_connection =
        m_event_sub.subscribe_task_nf_heartbeat(
            boost::bind(
                &lmf_nrf::trigger_nrf_registration_retry_procedure, this, _1),
            interval, ms + interval);
  }
}

//---------------------------------------------------------------------------------------------
void lmf_nrf::trigger_nrf_registration_retry_procedure(uint64_t ms) {
  _unused(ms);
  register_to_nrf();
}

//---------------------------------------------------------------------------------------------
void lmf_nrf::stop_nrf_registration_retry() {
  // get current time
  uint64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count();
  if (retry_nrf_registration_task_connection.connected()) {
    Logger::lmf_nrf().debug("Stop NRF registration retry task");
    retry_nrf_registration_task_connection.disconnect();
  }
}
