/*
 * Copyright (c) 2017 Sprint
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>  // srand
#include <unistd.h>  // get_pid(), pause()

#include <iostream>
#include <thread>
#include <chrono>

#include "conversions.hpp"
#include "http_client.hpp"
#include "logger.hpp"
#include "options.hpp"
#include "pid_file.hpp"
#include "sbi_helper.hpp"
#include "udr-api-server.h"
#include "udr-http2-server.h"
#include "udr_app.hpp"
#include "udr_config.hpp"
#include "udr_config_yaml.hpp"
#include "udr_nrf.hpp"

using namespace oai::config;
using namespace oai::udr::app;
using namespace oai::udr::config;
using namespace oai::utils;

udr_config udr_cfg;
udr_app* udr_app_inst                                    = nullptr;
udr_nrf* udr_nrf_inst                                    = nullptr;
UDRApiServer* http_server1                               = nullptr;
udr_http2_server* http_server2                           = nullptr;
task_manager* tm_inst                                    = nullptr;
std::shared_ptr<oai::http::http_client> http_client_inst = nullptr;
std::unique_ptr<udr_config_yaml> udr_cfg_yaml;
std::unique_ptr<lttng_configuration> lttng_config_yaml;
//------------------------------------------------------------------------------
void my_app_signal_handler(int s) {
  auto shutdown_start = std::chrono::system_clock::now();
  // Setting log level arbitrarly to debug to show the whole
  // shutdown procedure in the logs even in case of off-logging
  Logger::set_level(spdlog::level::debug);
  Logger::system().info("Exiting: caught signal %d", s);
  Logger::system().debug("Freeing Allocated memory...");

  // Stop on-going tasks
  Logger::system().debug("First stop the nrf inst");
  if (udr_nrf_inst) {
    udr_nrf_inst->stop();
  }

  Logger::system().debug("Then stop the http servers");
  if (http_server1) {
    http_server1->shutdown();
  }
  if (http_server2) {
    http_server2->stop();
  }
  Logger::system().debug("HTTP servers are shutdown");

  if (udr_app_inst) {
    udr_app_inst->stop();
  }

  Logger::system().debug("Freeing Allocated memory...");
  // Delete instances
  if (http_server1) {
    delete http_server1;
    http_server1 = nullptr;
  }
  if (http_server2) {
    delete http_server2;
    http_server2 = nullptr;
  }

  if (tm_inst) {
    delete tm_inst;
    tm_inst = nullptr;
  }
  Logger::system().debug("Stopped the UDR Task Manager.");

  if (udr_app_inst) {
    delete udr_app_inst;
    udr_app_inst = nullptr;
  }
  Logger::system().debug("UDR APP memory done");

  Logger::system().debug("Freeing allocated memory done");
  auto elapsed = std::chrono::system_clock::now() - shutdown_start;
  auto ms_diff = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed);
  Logger::system().info("Bye. Shutdown Procedure took %d ms", ms_diff.count());
  exit(0);
}

//------------------------------------------------------------------------------
int main(int argc, char** argv) {
  srand(time(NULL));

  // Command line options
  if (!Options::parse(argc, argv)) {
    std::cout << "Options::parse() failed" << std::endl;
    return 1;
  }

  // Logger

  std::string conf_file_name = Options::getlibconfigConfig();

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

  Logger::init("udr", Options::getlogStdout(), Options::getlogRotFilelog());
  Logger::system().startup("Options parsed");

  std::signal(SIGTERM, my_app_signal_handler);
  std::signal(SIGINT, my_app_signal_handler);

  // Event subsystem
  udr_event ev;

  // Config
  Logger::system().debug("Parsing the configuration file, file type YAML.");
  udr_cfg_yaml = std::make_unique<udr_config_yaml>(
      conf_file_name, Options::getlogStdout(), Options::getlogRotFilelog());
  if (!udr_cfg_yaml->init()) {
    Logger::system().error("Reading the configuration failed. Exiting.");
    return 1;
  }
  udr_cfg_yaml->pre_process();
  udr_cfg_yaml->display();
  // Convert from YAML to internal structure
  udr_cfg_yaml->to_udr_config(udr_cfg);

  // HTTP Client
  uint8_t http_version = udr_cfg.use_http2 ? 2 : 1;
  http_client_inst     = oai::http::http_client::create_instance(
      Logger::udr_nrf(), udr_cfg.http_request_timeout, udr_cfg.nudr.if_name,
      http_version);

  // UDR application layer
  udr_app_inst = new udr_app(Options::getlibconfigConfig(), ev);
  if (!udr_app_inst->start()) {
    udr_app_inst->stop();
    Logger::system().error("Could not start UDR APP, exiting.");
    return 1;
  }

  // Task Manager
  tm_inst = new task_manager(ev);
  std::thread task_manager_thread(&task_manager::run, tm_inst);

  // UDR NRF
  udr_nrf_inst = new udr_nrf(ev);
  std::thread udr_nrf_manager(&udr_nrf::start, udr_nrf_inst);

  if (!udr_cfg.use_http2) {
    // UDR Pistache API server (HTTP1)
    Pistache::Address addr(
        std::string(inet_ntoa(*((struct in_addr*) &udr_cfg.nudr.addr4))),
        Pistache::Port(udr_cfg.nudr.port));

    http_server1 = new UDRApiServer(addr, udr_app_inst);
    http_server1->init(2);
    std::thread udr_http1_manager(&UDRApiServer::start, http_server1);
    udr_http1_manager.join();
  } else {
    // UDR NGHTTP API server (HTTP2)
    http_server2 = new udr_http2_server(
        conv::toString(udr_cfg.nudr.addr4), udr_cfg.nudr.port, udr_app_inst);
    std::thread udr_http2_manager(&udr_http2_server::start, http_server2);
    udr_http2_manager.join();
  }

  Logger::system().info("Initiation Done!");

  task_manager_thread.join();
  udr_nrf_manager.join();

  pause();
  return 0;
}
