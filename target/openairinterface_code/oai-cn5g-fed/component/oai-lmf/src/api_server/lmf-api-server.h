/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_LMF_API_SERVER_SEEN
#define FILE_LMF_API_SERVER_SEEN

#include "pistache/endpoint.h"
#include "pistache/http.h"
#include "pistache/router.h"
#ifdef __linux__
#include <vector>
#include <signal.h>
#include <unistd.h>
#endif

#include "lmf_app.hpp"
#include "DetermineLocationApiImpl.h"
#include "N2InfoNotifyApiImpl.h"
#include "NonUeN2InfoNotifyApiImpl.h"

using namespace oai::lmf::api;
using namespace oai::lmf::app;

class LMFApiServer {
 public:
  LMFApiServer(Pistache::Address address, lmf_app* lmf_app_inst)
      : m_httpEndpoint(std::make_shared<Pistache::Http::Endpoint>(address)) {
    m_router  = std::make_shared<Pistache::Rest::Router>();
    m_address = address.host() + ":" + (address.port()).toString();

    m_determineLocationApiImpl =
        std::make_shared<DetermineLocationApiImpl>(m_router, lmf_app_inst);
    m_n2InfoNotifyApiImpl =
        std::make_shared<N2InfoNotifyApiImpl>(m_router, lmf_app_inst);
    m_nonUeN2InfoNotifyApiImpl =
        std::make_shared<NonUeN2InfoNotifyApiImpl>(m_router, lmf_app_inst);
  }
  void init(size_t thr = 1);
  void start();
  void shutdown();

 private:
  std::shared_ptr<Pistache::Http::Endpoint> m_httpEndpoint;
  std::shared_ptr<Pistache::Rest::Router> m_router;
  std::string m_address;
  std::shared_ptr<DetermineLocationApiImpl> m_determineLocationApiImpl;
  std::shared_ptr<N2InfoNotifyApiImpl> m_n2InfoNotifyApiImpl;
  std::shared_ptr<NonUeN2InfoNotifyApiImpl> m_nonUeN2InfoNotifyApiImpl;
};

#endif
