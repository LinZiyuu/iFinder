/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * N2InfoNotifyApiImpl.h
 *
 *
 */

#ifndef N2Info_NOTIFY_API_IMPL_H_
#define N2Info_NOTIFY_API_IMPL_H_

#include <pistache/endpoint.h>
#include <pistache/http.h>
#include <pistache/router.h>
#include <memory>

#include <pistache/optional.h>

#include "N2InfoNotifyApi.h"
#include "ProblemDetails.h"
#include "lmf_app.hpp"

namespace oai::lmf::api {

class N2InfoNotifyApiImpl : public oai::lmf::api::N2InfoNotifyApi {
 public:
  N2InfoNotifyApiImpl(
      std::shared_ptr<Pistache::Rest::Router>,
      oai::lmf::app::lmf_app* lmf_app_inst);
  ~N2InfoNotifyApiImpl() {}

  void receive_n2info_nrppa_notification(
      const std::string& ueContextId, std::vector<mime_part>& parts,
      Pistache::Http::ResponseWriter& response);

 private:
  oai::lmf::app::lmf_app* m_lmf_app;
  // std::string m_address;
};

}  // namespace oai::lmf::api

#endif
