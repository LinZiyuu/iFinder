/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

#include "logger.hpp"
#include "pcf-api-server.hpp"
#include "pcf-http2-server.hpp"
#include "pcf_app.hpp"
#include "pcf_config.hpp"
#include "options.hpp"
#include "pistache/http.h"
#include "nf_launch.hpp"
#include "conversions.hpp"
#include "http_client.hpp"

#include <iostream>
#include <csignal>
#include <thread>
#include <chrono>

using namespace std;
using namespace oai::pcf::app;
using namespace oai::config::pcf;
using namespace oai::utils;
using namespace oai::pcf::api;

using namespace oai::config;

std::unique_ptr<pcf_app> pcf_app_inst                      = nullptr;
std::unique_ptr<pcf_config> pcf_cfg                        = nullptr;
std::unique_ptr<PCFApiServer> pcf_api_server_1             = nullptr;
std::unique_ptr<pcf_http2_server> pcf_api_server_2         = nullptr;
std::shared_ptr<oai::http::http_client> http_client_inst   = nullptr;
std::unique_ptr<database_wrapper_abstraction> db_connector = nullptr;
std::unique_ptr<oai::config::lttng_configuration> lttng_config_yaml;
//------------------------------------------------------------------------------
void signal_handler_sigint(int s) {
  auto shutdown_start = std::chrono::system_clock::now();
  // Setting log level arbitrarly to debug to show the whole
  // shutdown procedure in the logs even in case of off-logging
  Logger::set_level(spdlog::level::debug);
  Logger::system().info("Exiting: caught signal %d", s);

  Logger::system().debug("Shutting down HTTP servers...");
  if (pcf_api_server_1) {
    pcf_api_server_1->shutdown();
  }
  if (pcf_api_server_2) {
    pcf_api_server_2->stop();
  }
  if (pcf_app_inst) {
    pcf_app_inst->stop();
  }
  // TODO exit is not always clean, check again after complete refactor
  // Ensure that objects are destructed before static libraries (e.g. Logger)
  Logger::system().debug("Freeing Allocated memory...");
  pcf_api_server_1 = nullptr;
  pcf_api_server_2 = nullptr;
  pcf_app_inst     = nullptr;
  pcf_cfg          = nullptr;

  Logger::system().debug("PCF APP memory done");
  Logger::system().debug("Freeing allocated memory done");
  auto elapsed = std::chrono::system_clock::now() - shutdown_start;
  auto ms_diff = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed);
  Logger::system().info("Bye. Shutdown Procedure took %d ms", ms_diff.count());
  exit(0);
}

//------------------------------------------------------------------------------
int main(int argc, char** argv) {
  if (nf_launch::already_running()) {
    std::cout << "NF instance already running. Exiting" << std::endl;
    return 1;
  }

  // Command line options
  if (!oai::utils::options::parse(argc, argv)) {
    std::cout << "Options::parse() failed" << std::endl;
    return 1;
  }

  // Logger
  const std::string conf_file_name =
      static_cast<std::string>(oai::utils::options::getlibconfigConfig());

  std::cout << "Trying to read .yaml configuration file: " << conf_file_name
            << "\n";
  lttng_config_yaml =
      std::make_unique<oai::config::lttng_configuration>(conf_file_name);
  lttng_config_yaml->read_from_file();

#ifdef LOGGER_CAN_USE_LTTNG
  std::cout << "LTTNG Log Activation: " << lttng_config_yaml->is_lttng_active()
            << "\n";
  std::cout << "Log Level of LTTng: "
            << lttng_config_yaml->get_lttng_log_level() << "\n";
#else
  std::cout << "LTTNG Tracing disabled at build-time!\n";
  if (lttng_config_yaml->is_lttng_active())
    std::cout << "Cannot use lttng log scheme on this build variant!\n";
#endif

  Logger::set_lttng(static_cast<bool>(lttng_config_yaml->is_lttng_active()));

  Logger::init(
      "pcf", oai::utils::options::getlogStdout(),
      oai::utils::options::getlogRotFilelog());

  std::signal(SIGTERM, signal_handler_sigint);
  std::signal(SIGINT, signal_handler_sigint);

  pcf_cfg = std::make_unique<pcf_config>(
      oai::utils::options::getlibconfigConfig(),
      oai::utils::options::getlogStdout(),
      oai::utils::options::getlogRotFilelog());
  if (!pcf_cfg->init()) {
    pcf_cfg->display();
    Logger::system().error("Reading the configuration failed. Exiting.");
    return 1;
  }
  pcf_cfg->display();

  // HTTP Client
  http_client_inst = oai::http::http_client::create_instance(
      Logger::pcf_client(), oai::common::sbi::kNfDefaultHttpRequestTimeout,
      pcf_cfg->local().get_sbi().get_if_name(), pcf_cfg->get_http_version());

  // Event subsystem
  pcf_event ev;

  // PCF application layer
  pcf_app_inst = std::make_unique<pcf_app>(ev);

  std::string v4_address =
      oai::utils::conv::toString(pcf_cfg->local().get_sbi().get_addr4());

  if (pcf_cfg->get_http_version() == 1) {
    // PCF Pistache API server (HTTP1)
    Pistache::Address addr(
        v4_address, Pistache::Port(pcf_cfg->local().get_sbi().get_port()));

    pcf_api_server_1 = std::make_unique<PCFApiServer>(addr, pcf_app_inst);
    pcf_api_server_1->init(2);
    std::thread pcf_http1_manager(&PCFApiServer::start, pcf_api_server_1.get());
    pcf_http1_manager.join();
  } else if (pcf_cfg->get_http_version() == 2) {
    // PCF NGHTTP API server (HTTP2)
    pcf_api_server_2 = std::make_unique<pcf_http2_server>(
        v4_address, pcf_cfg->local().get_sbi().get_port(), pcf_app_inst);
    std::thread pcf_http2_manager(
        &pcf_http2_server::start, pcf_api_server_2.get());
    pcf_http2_manager.join();
  }

  Logger::pcf_app().info("HTTP servers successfully stopped. Exiting");

  return 0;
}
