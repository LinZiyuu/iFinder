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

#include "http_client.hpp"
#include "logger.hpp"
#include "options.hpp"
#include "pid_file.hpp"
#include "pistache/endpoint.h"
#include "pistache/http.h"
#include "pistache/router.h"
#include "udm-api-server.h"
#include "udm-http2-server.h"
#include "udm_app.hpp"
#include "udm_config.hpp"
#include "udm_config_yaml.hpp"

using namespace oai::udm::app;
using namespace oai::udm::config;
using namespace oai::config;
using namespace oai::utils;

udm_config udm_cfg;
udm_app* udm_app_inst              = nullptr;
UDMApiServer* api_server           = nullptr;
udm_http2_server* udm_api_server_2 = nullptr;
task_manager* tm_inst              = nullptr;

std::shared_ptr<oai::http::http_client> http_client_inst = nullptr;
std::unique_ptr<udm_config_yaml> udm_cfg_yaml;
std::unique_ptr<oai::config::lttng_configuration> lttng_config_yaml;
//------------------------------------------------------------------------------
void my_app_signal_handler(int s) {
  auto shutdown_start = std::chrono::system_clock::now();
  // Setting log level arbitrarly to debug to show the whole
  // shutdown procedure in the logs even in case of off-logging
  Logger::set_level(spdlog::level::debug);
  Logger::system().info("Exiting: caught signal %d", s);

  // Stop on-going tasks
  Logger::system().debug("First the app stop");
  if (udm_app_inst) {
    udm_app_inst->stop();
  }

  Logger::system().debug("Then HTTP server stop");
  if (api_server) {
    api_server->shutdown();
  }
  if (udm_api_server_2) {
    udm_api_server_2->stop();
  }
  Logger::system().debug("HTTP servers are shutdown");

  Logger::system().debug("Freeing Allocated memory...");
  // Delete instances
  if (api_server) {
    delete api_server;
    api_server = nullptr;
  }

  if (udm_api_server_2) {
    delete udm_api_server_2;
    udm_api_server_2 = nullptr;
  }
  Logger::system().debug("Stopped HTTP servers");

  if (tm_inst) {
    delete tm_inst;
    tm_inst = nullptr;
  }
  Logger::system().debug("Stopped the UDM Task Manager.");

  if (udm_app_inst) {
    delete udm_app_inst;
    udm_app_inst = nullptr;
  }

  Logger::system().debug("UDM APP memory done");
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

  const std::string conf_file_name =
      static_cast<std::string>(Options::getlibconfigConfig());

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

  Logger::init("udm", Options::getlogStdout(), Options::getlogRotFilelog());
  Logger::system().startup("Options parsed");

  std::signal(SIGTERM, my_app_signal_handler);
  std::signal(SIGINT, my_app_signal_handler);

  // Event subsystem
  udm_event ev;

  Logger::system().debug("Parsing the configuration file (YAML).");
  udm_cfg_yaml = std::make_unique<udm_config_yaml>(
      conf_file_name, Options::getlogStdout(), Options::getlogRotFilelog());
  if (!udm_cfg_yaml->init()) {
    Logger::system().error("Reading the configuration failed. Exiting.");
    return 1;
  }
  udm_cfg_yaml->pre_process();
  udm_cfg_yaml->display();
  // Convert from YAML to internal structure
  udm_cfg_yaml->to_udm_config(udm_cfg);

  // HTTP Client
  uint8_t http_version = udm_cfg.use_http2 ? 2 : 1;
  http_client_inst     = oai::http::http_client::create_instance(
      Logger::udm_client(), udm_cfg.http_request_timeout, udm_cfg.sbi.if_name,
      http_version);

  // UDM application layer
  udm_app_inst = new udm_app(Options::getlibconfigConfig(), ev);
  if (!udm_app_inst->start()) {
    udm_app_inst->stop();
    Logger::system().error("Could not start UDM APP, exiting.");
    return 1;
  }

  // Task Manager
  tm_inst = new task_manager(ev);
  std::thread task_manager_thread(&task_manager::run, tm_inst);

  // PID file
  std::string pid_file_name =
      get_exe_absolute_path(udm_cfg.pid_dir, udm_cfg.instance);
  if (!is_pid_file_lock_success(pid_file_name.c_str())) {
    Logger::system().error("Lock PID file %s failed\n", pid_file_name.c_str());
    exit(-EDEADLK);
  }

  FILE* fp             = NULL;
  std::string filename = fmt::format("/tmp/udm_{}.status", getpid());
  fp                   = fopen(filename.c_str(), "w+");
  fprintf(fp, "STARTED\n");

  if (!udm_cfg.use_http2) {
    // UDM Pistache API server (HTTP1)
    Pistache::Address addr(
        std::string(inet_ntoa(*((struct in_addr*) &udm_cfg.sbi.addr4))),
        Pistache::Port(udm_cfg.sbi.port));
    api_server = new UDMApiServer(addr, udm_app_inst);
    api_server->init(2);
    std::thread udm_manager(&UDMApiServer::start, api_server);
    udm_manager.join();
  } else {
    // UDM NGHTTP API server (HTTP2)
    udm_api_server_2 = new udm_http2_server(
        oai::utils::conv::toString(udm_cfg.sbi.addr4), udm_cfg.sbi.port,
        udm_app_inst);
    std::thread udm_http2_manager(&udm_http2_server::start, udm_api_server_2);
    udm_http2_manager.join();
  }

  Logger::udm_server().info("Initiation Done!");
  task_manager_thread.join();

  fflush(fp);
  fclose(fp);

  pause();
  return 0;
}
