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

#include "conversions.hpp"
#include "logger.hpp"
#include "nef-api-server.h"
#include "nef-http2-server.h"
#include "nef_app.hpp"
#include "nef_client.hpp"
#include "options.hpp"
#include "pid_file.hpp"
#include "pistache/endpoint.h"
#include "pistache/http.h"
#include "pistache/router.h"

using namespace oai::nef::app;
using namespace util;
using namespace std;

nef_app* nef_app_inst = nullptr;
nef_config nef_cfg;
NEFApiServer* api_server               = nullptr;
nef_http2_server* nef_api_server_http2 = nullptr;

//------------------------------------------------------------------------------
void my_app_signal_handler(int s) {
  std::cout << "Caught signal " << s << std::endl;
  Logger::system().startup("exiting");
  std::cout << "Freeing Allocated memory..." << std::endl;
  if (api_server) {
    api_server->shutdown();
    delete api_server;
    api_server = nullptr;
  }
  std::cout << "NEF API Server memory done" << std::endl;

  if (nef_app_inst) {
    delete nef_app_inst;
    nef_app_inst = nullptr;
  }

  std::cout << "NEF APP memory done" << std::endl;
  std::cout << "Freeing allocated memory done" << std::endl;

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
  Logger::init("nef", Options::getlogStdout(), Options::getlogRotFilelog());
  Logger::nef_app().startup("Options parsed");

  std::signal(SIGTERM, my_app_signal_handler);
  std::signal(SIGINT, my_app_signal_handler);

  // Config
  nef_cfg.load(Options::getlibconfigConfig());
  nef_cfg.display();

  // Event subsystem

  // NEF application layer
  nef_app_inst = new nef_app(Options::getlibconfigConfig());

  // TODO: Task Manager

  // PID file
  string pid_file_name =
      get_exe_absolute_path(nef_cfg.pid_dir, nef_cfg.instance);
  if (!is_pid_file_lock_success(pid_file_name.c_str())) {
    Logger::nef_app().error("Lock PID file %s failed\n", pid_file_name.c_str());
    exit(-EDEADLK);
  }

  // NEF Pistache API server (HTTP1)
  Pistache::Address addr(
      std::string(inet_ntoa(*((struct in_addr*) &nef_cfg.sbi.addr4))),
      Pistache::Port(nef_cfg.sbi.port));
  api_server = new NEFApiServer(addr, nef_app_inst);
  api_server->init(2);
  std::thread nef_manager(&NEFApiServer::start, api_server);

  // NEF NGHTTP API server (HTTP2)
  nef_api_server_http2 = new nef_http2_server(
      conv::toString(nef_cfg.sbi.addr4), nef_cfg.sbi.http2_port, nef_app_inst);
  std::thread nef_http2_manager(&nef_http2_server::start, nef_api_server_http2);

  nef_manager.join();
  nef_http2_manager.join();

  FILE* fp             = NULL;
  std::string filename = fmt::format("/tmp/nef_{}.status", getpid());
  fp                   = fopen(filename.c_str(), "w+");
  fprintf(fp, "STARTED\n");
  fflush(fp);
  fclose(fp);

  pause();
  return 0;
}
