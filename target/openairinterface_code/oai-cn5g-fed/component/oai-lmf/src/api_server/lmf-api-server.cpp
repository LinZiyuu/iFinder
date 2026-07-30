/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "lmf-api-server.h"
#include "logger.hpp"
#include "pistache/endpoint.h"
#include "pistache/http.h"
#include "pistache/router.h"
#ifdef __linux__
#include <vector>
#include <signal.h>
#include <unistd.h>
#endif

#define PISTACHE_SERVER_MAX_PAYLOAD 32768

#ifdef __linux__
void sigHandler(int sig) {
  switch (sig) {
    case SIGINT:
    case SIGQUIT:
    case SIGTERM:
    case SIGHUP:
    default:
      break;
  }
  exit(0);
}

void setUpUnixSignals(std::vector<int> quitSignals) {
  sigset_t blocking_mask;
  sigemptyset(&blocking_mask);
  for (auto sig : quitSignals) sigaddset(&blocking_mask, sig);

  struct sigaction sa;
  sa.sa_handler = sigHandler;
  sa.sa_mask    = blocking_mask;
  sa.sa_flags   = 0;

  for (auto sig : quitSignals) sigaction(sig, &sa, nullptr);
}
#endif

using namespace oai::lmf::api;
using namespace oai::model::lmf;
using namespace oai::lmf::app;

void LMFApiServer::init(size_t thr) {
  auto opts = Pistache::Http::Endpoint::options().threads(thr);
  opts.flags(Pistache::Tcp::Options::ReuseAddr);
  opts.maxRequestSize(PISTACHE_SERVER_MAX_PAYLOAD);
  m_httpEndpoint->init(opts);

  // m_authenticationResultDeletionApiImpl->init();
  // m_defaultApiImpl->init();
  m_determineLocationApiImpl->init();
  m_n2InfoNotifyApiImpl->init();
  m_nonUeN2InfoNotifyApiImpl->init();
}
void LMFApiServer::start() {
  if (m_determineLocationApiImpl != nullptr)
    Logger::lmf_server().debug("LMF handler for DetermineLocationApiImpl");
  if (m_n2InfoNotifyApiImpl != nullptr)
    Logger::lmf_server().debug("LMF handler for N2InfoNotifyApiImpl");
  Logger::lmf_server().info("HTTP1 server started");
  m_httpEndpoint->setHandler(m_router->handler());
  m_httpEndpoint->serve();
}
void LMFApiServer::shutdown() {
  m_httpEndpoint->shutdown();
}
