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

#include <stdlib.h>  // srand
#include <unistd.h>  // get_pid(), pause()

#include <chrono>
#include <iostream>
#include <thread>

#include "ausf-api-server.h"
#include "ausf-http2-server.h"
#include "ausf_app.hpp"
#include "ausf_config.hpp"
#include "ausf_config_yaml.hpp"
#include "http_client.hpp"
#include "logger.hpp"
#include "options.hpp"
#include "pid_file.hpp"
#include "pistache/http.h"

using namespace oai::ausf::app;
using namespace oai::config;

ausf_config ausf_cfg;
ausf_app* ausf_app_inst              = nullptr;
AUSFApiServer* api_server            = nullptr;
ausf_http2_server* ausf_api_server_2 = nullptr;
task_manager* tm_inst                = nullptr;

std::shared_ptr<oai::http::http_client> http_client_inst = nullptr;
std::unique_ptr<ausf_config_yaml> ausf_cfg_yaml          = nullptr;
std::unique_ptr<lttng_configuration> lttng_config_yaml;
//------------------------------------------------------------------------------
void my_app_signal_handler(int s) {
  auto shutdown_start = std::chrono::system_clock::now();
  // Setting log level arbitrarly to debug to show the whole
  // shutdown procedure in the logs even in case of off-logging
  Logger::set_level(spdlog::level::debug);
  Logger::system().info("Caught signal %d", s);
  Logger::system().debug("Freeing Allocated memory...");

  // Stop on-going tasks
  if (api_server) {
    api_server->shutdown();
  }
  if (ausf_api_server_2) {
    ausf_api_server_2->stop();
  }

  if (ausf_app_inst) {
    ausf_app_inst->stop();
  }

  // Delete instances
  if (api_server) {
    delete api_server;
    api_server = nullptr;
  }

  if (ausf_api_server_2) {
    delete ausf_api_server_2;
    ausf_api_server_2 = nullptr;
  }
  Logger::system().debug("AUSF API Servers memory done");

  if (tm_inst) {
    delete tm_inst;
    tm_inst = nullptr;
  }
  Logger::system().debug("Stopped the AUSF Task Manager.");

  if (ausf_app_inst) {
    delete ausf_app_inst;
    ausf_app_inst = nullptr;
  }

  Logger::system().debug("AUSF APP memory done");
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
  lttng_config_yaml = std::make_unique<lttng_configuration>(conf_file_name);
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

  Logger::init("ausf", Options::getlogStdout(), Options::getlogRotFilelog());
  Logger::ausf_server().startup("Options parsed");

  std::signal(SIGTERM, my_app_signal_handler);
  std::signal(SIGINT, my_app_signal_handler);

  // Event subsystem
  ausf_event ev;

  // Config
  Logger::ausf_server().debug(
      "Parsing the configuration file, file type YAML.");
  ausf_cfg_yaml = std::make_unique<ausf_config_yaml>(
      conf_file_name, Options::getlogStdout(), Options::getlogRotFilelog());
  if (!ausf_cfg_yaml->init()) {
    Logger::ausf_server().error("Reading the configuration failed. Exiting.");
    return 1;
  }
  ausf_cfg_yaml->pre_process();
  ausf_cfg_yaml->display();
  // Convert from YAML to internal structure
  ausf_cfg_yaml->to_ausf_config(ausf_cfg);

  // HTTP Client
  http_client_inst = oai::http::http_client::create_instance(
      Logger::ausf_client(), ausf_cfg.http_request_timeout,
      ausf_cfg.sbi.if_name, ausf_cfg.http_version);

  // AUSF application layer
  ausf_app_inst = new ausf_app(Options::getlibconfigConfig(), ev);
  if (!ausf_app_inst->start()) {
    ausf_app_inst->stop();
    Logger::system().error("Could not start AUSF APP, exiting.");
    if (ausf_app_inst) {
      delete ausf_app_inst;
      ausf_app_inst = nullptr;
    }
    return 1;
  }

  // Task Manager
  tm_inst = new task_manager(ev);
  std::thread task_manager_thread(&task_manager::run, tm_inst);

  // PID file
  std::string pid_file_name =
      oai::utils::get_exe_absolute_path(ausf_cfg.pid_dir, ausf_cfg.instance);
  if (!oai::utils::is_pid_file_lock_success(pid_file_name.c_str())) {
    Logger::ausf_server().error(
        "Lock PID file %s failed\n", pid_file_name.c_str());
    exit(-EDEADLK);
  }

  FILE* fp             = NULL;
  std::string filename = fmt::format("/tmp/ausf_{}.status", getpid());
  fp                   = fopen(filename.c_str(), "w+");
  fprintf(fp, "STARTED\n");

  if (ausf_cfg.http_version == 1) {
    // AUSF Pistache API server (HTTP1)
    Pistache::Address addr(
        std::string(inet_ntoa(*((struct in_addr*) &ausf_cfg.sbi.addr4))),
        Pistache::Port(ausf_cfg.sbi.port));
    api_server = new AUSFApiServer(addr, ausf_app_inst);
    api_server->init(2);
    std::thread ausf_manager(&AUSFApiServer::start, api_server);
    ausf_manager.join();
  } else {
    // AUSF NGHTTP API server (HTTP2)
    ausf_api_server_2 = new ausf_http2_server(
        oai::utils::conv::toString(ausf_cfg.sbi.addr4), ausf_cfg.sbi.port,
        ausf_app_inst);
    std::thread ausf_http2_manager(
        &ausf_http2_server::start, ausf_api_server_2);
    ausf_http2_manager.join();
  }

  Logger::ausf_server().info("Initiation Done!");
  task_manager_thread.join();

  fflush(fp);
  fclose(fp);

  pause();
  return 0;
}
