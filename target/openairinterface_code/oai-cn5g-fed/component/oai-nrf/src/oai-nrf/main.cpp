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
#include "nrf-api-server.h"
#include "nrf-http2-server.h"
#include "nrf_app.hpp"
#include "nrf_client.hpp"
#include "nrf_config.hpp"
#include "sbi_helper.hpp"
#include "options.hpp"
#include "pid_file.hpp"
#include "pistache/endpoint.h"
#include "pistache/http.h"
#include "pistache/router.h"

using namespace oai::nrf::app;
using namespace oai::utils;
using namespace oai::config::nrf;

nrf_app* nrf_app_inst = nullptr;
std::unique_ptr<nrf_config> nrf_cfg;
std::shared_ptr<oai::http::http_client> http_client_inst = nullptr;
NRFApiServer* api_server                                 = nullptr;
nrf_http2_server* nrf_api_server_2                       = nullptr;
task_manager* tm_inst                                    = nullptr;
std::unique_ptr<oai::config::lttng_configuration> lttng_config_yaml;
//------------------------------------------------------------------------------
void my_app_signal_handler(int s) {
  auto shutdown_start = std::chrono::system_clock::now();
  // Setting log level arbitrarly to debug to show the whole
  // shutdown procedure in the logs even in case of off-logging
  Logger::set_level(spdlog::level::debug);
  Logger::system().info("Caught signal %d", s);
  Logger::system().debug("Freeing Allocated memory...");

  if (api_server) {
    api_server->shutdown();
    delete api_server;
    api_server = nullptr;
  }
  if (nrf_api_server_2) {
    nrf_api_server_2->stop();
    delete nrf_api_server_2;
    nrf_api_server_2 = nullptr;
  }
  Logger::system().debug("NRF API Server memory done");

  if (tm_inst) {
    delete tm_inst;
    tm_inst = nullptr;
  }
  Logger::system().debug("Stopped the NRF Task Manager.");

  if (nrf_app_inst) {
    delete nrf_app_inst;
    nrf_app_inst = nullptr;
  }
  Logger::system().debug("NRF APP memory done");
  Logger::system().info("Freeing allocated memory done");
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

  Logger::init("nrf", Options::getlogStdout(), Options::getlogRotFilelog());
  Logger::nrf_app().startup("Options parsed");

  std::signal(SIGTERM, my_app_signal_handler);
  std::signal(SIGINT, my_app_signal_handler);

  // Config
  nrf_cfg = std::make_unique<nrf_config>(
      Options::getlibconfigConfig(), Options::getlogStdout(),
      Options::getlogRotFilelog());
  if (!nrf_cfg->init()) {
    nrf_cfg->display();
    Logger::system().error("Reading the configuration failed. Exiting");
    return 1;
  }
  nrf_cfg->display();

  // HTTP Client
  http_client_inst = oai::http::http_client::create_instance(
      Logger::nrf_sbi(), oai::common::sbi::kNfDefaultHttpRequestTimeout,
      nrf_cfg->local().get_sbi().get_if_name(), nrf_cfg->get_http_version());

  // Event subsystem
  nrf_event ev;

  // NRF application layer
  nrf_app_inst = new nrf_app(Options::getlibconfigConfig(), ev);

  // Task Manager
  tm_inst = new task_manager(ev);
  std::thread task_manager_thread(&task_manager::run, tm_inst);

  // PID file
  // Currently hard-coded value. TODO: add as config option.
  std::string pid_file_name =
      oai::utils::get_exe_absolute_path("/var/run", nrf_cfg->instance);
  if (!oai::utils::is_pid_file_lock_success(pid_file_name.c_str())) {
    Logger::nrf_app().error("Lock PID file %s failed\n", pid_file_name.c_str());
    exit(-EDEADLK);
  }

  if (nrf_cfg->get_http_version() == 1) {
    // NRF Pistache API server (HTTP1)
    Pistache::Address addr(
        std::string(inet_ntoa(
            *((struct in_addr*) &nrf_cfg->local().get_sbi().get_addr4()))),
        Pistache::Port(nrf_cfg->local().get_sbi().get_port()));
    api_server = new NRFApiServer(addr, nrf_app_inst);
    api_server->init(2);
    std::thread nrf_manager(&NRFApiServer::start, api_server);
    nrf_manager.join();
  } else if (nrf_cfg->get_http_version() == 2) {
    // NRF NGHTTP API server (HTTP2)
    nrf_api_server_2 = new nrf_http2_server(
        conv::toString(nrf_cfg->local().get_sbi().get_addr4()),
        nrf_cfg->local().get_sbi().get_port(), nrf_app_inst);
    std::thread nrf_http2_manager(&nrf_http2_server::start, nrf_api_server_2);
    nrf_http2_manager.join();
  }

  FILE* fp             = NULL;
  std::string filename = fmt::format("/tmp/nrf_{}.status", getpid());
  fp                   = fopen(filename.c_str(), "w+");
  fprintf(fp, "STARTED\n");
  fflush(fp);
  fclose(fp);

  Logger::nrf_app().info("Initiation Done!");
  pause();

  return 0;
}
