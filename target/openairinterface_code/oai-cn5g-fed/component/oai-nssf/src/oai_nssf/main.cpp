/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "common_defs.h"
#include "logger.hpp"
#include "nssf-api-server.h"
#include "nssf-http2-server.h"
#include "nssf_app.hpp"
#include "nssf_config.hpp"
#include "options.hpp"
#include "pid_file.hpp"
#include "pistache/endpoint.h"
#include "pistache/http.h"
#include "pistache/router.h"

#include <algorithm>
#include <boost/asio.hpp>
#include <iostream>
#include <signal.h>
#include <stdint.h>
#include <thread>
#include <unistd.h>  // get_pid(), pause()
#include <vector>
#include <chrono>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/split.hpp>

using namespace nssf;
using namespace oai::utils;
using namespace std;
using namespace oai::nssf_server::api;
using namespace oai::config::nssf;

nssf_app* nssf_app_inst = nullptr;
std::unique_ptr<nssf_config> nssf_cfg;
boost::asio::io_service io_service;
NSSFApiServer* nssf_api_server_1     = nullptr;
nssf_http2_server* nssf_api_server_2 = nullptr;

//------------------------------------------------------------------------------
void my_app_signal_handler(int s) {
  auto shutdown_start = std::chrono::system_clock::now();
  // Setting log level arbitrarly to debug to show the whole
  // shutdown procedure in the logs even in case of off-logging
  Logger::set_level(spdlog::level::debug);
  Logger::system().info("Exiting: caught signal %d", s);

  Logger::system().debug("Shutting down HTTP servers...");
  if (nssf_api_server_1) {
    nssf_api_server_1->shutdown();
  }
  if (nssf_api_server_2) {
    nssf_api_server_2->stop();
  }
  Logger::system().debug("Freeing Allocated memory...");
  if (nssf_api_server_1) {
    delete nssf_api_server_1;
    nssf_api_server_1 = nullptr;
  }
  if (nssf_api_server_2) {
    delete nssf_api_server_2;
    nssf_api_server_2 = nullptr;
  }
  if (nssf_app_inst) {
    delete nssf_app_inst;
    nssf_app_inst = nullptr;
  }
  Logger::system().debug("NSSF APP memory done");
  Logger::system().debug("Freeing allocated memory done");
  auto elapsed = std::chrono::system_clock::now() - shutdown_start;
  auto ms_diff = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed);
  Logger::system().info("Bye. Shutdown Procedure took %d ms", ms_diff.count());
  exit(0);
}
//------------------------------------------------------------------------------
int main(int argc, char** argv) {
  // Command line options
  if (!Options::parse(argc, argv)) {
    std::cout << "Options::parse() failed" << std::endl;
    return 1;
  }

  // Logger
  Logger::init("nssf", Options::getlogStdout(), Options::getlogRotFilelog());

  std::signal(SIGTERM, my_app_signal_handler);
  std::signal(SIGINT, my_app_signal_handler);

  nssf_cfg = std::make_unique<nssf_config>(
      Options::getlibconfigConfig(), Options::getlogStdout(),
      Options::getlogRotFilelog());

  if (!nssf_cfg->init()) {
    nssf_cfg->display();
    Logger::system().error("Reading the configuration failed. Exiting");
    return 1;
  }
  nssf_cfg->display();

  // PID file
  // Currently hard-coded value. TODO: add as config option.
  string pid_file_name =
      oai::utils::get_exe_absolute_path("/var/run", nssf_cfg->instance);
  if (!oai::utils::is_pid_file_lock_success(pid_file_name.c_str())) {
    Logger::nssf_app().error(
        "Lock PID file %s failed\n", pid_file_name.c_str());
    exit(-EDEADLK);
  }

  if (nssf_cfg->get_http_version() == 1) {
    // NSSF Pistache API server (HTTP1)
    Pistache::Address addr(
        std::string(inet_ntoa(
            *((struct in_addr*) &nssf_cfg->local().get_sbi().get_addr4()))),
        Pistache::Port(nssf_cfg->local().get_sbi().get_port()));
    nssf_api_server_1 = new NSSFApiServer(addr, nssf_app_inst);
    nssf_api_server_1->init(2);
    std::thread nssf_http1_manager(&NSSFApiServer::start, nssf_api_server_1);
    nssf_http1_manager.join();
  } else if (nssf_cfg->get_http_version() == 2) {
    // NSSF NGHTTP API server (HTTP2)
    nssf_api_server_2 = new nssf_http2_server(
        conv::toString(nssf_cfg->local().get_sbi().get_addr4()),
        nssf_cfg->local().get_sbi().get_port(), nssf_app_inst);
    std::thread nssf_http2_manager(
        &nssf_http2_server::start, nssf_api_server_2);
    nssf_http2_manager.join();
  }

  FILE* fp             = NULL;
  std::string filename = fmt::format("/tmp/nssf_{}.status", getpid());
  fp                   = fopen(filename.c_str(), "w+");
  fprintf(fp, "STARTED\n");
  fflush(fp);
  fclose(fp);

  pause();
  return 0;
}
