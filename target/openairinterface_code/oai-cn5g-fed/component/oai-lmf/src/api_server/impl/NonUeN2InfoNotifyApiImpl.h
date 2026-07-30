/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * N2InfoNotifyApiImpl.h
 *
 *
 */

#ifndef NonUeN2InfoNotifyApiImpl_H_
#define NonUeN2InfoNotifyApiImpl_H_

#include <pistache/endpoint.h>
#include <pistache/http.h>
#include <pistache/router.h>
#include <memory>

#include <pistache/optional.h>

#include "NonUeN2InfoNotifyApi.h"
#include "ProblemDetails.h"
#include "lmf_app.hpp"

namespace oai::lmf::api {

class NonUeN2InfoNotifyApiImpl : public oai::lmf::api::NonUeN2InfoNotifyApi {
 public:
  NonUeN2InfoNotifyApiImpl(
      std::shared_ptr<Pistache::Rest::Router>,
      oai::lmf::app::lmf_app* lmf_app_inst);
  ~NonUeN2InfoNotifyApiImpl() {}

  void receive_non_ue_n2info_nrppa_notification(
      std::vector<mime_part>& parts, Pistache::Http::ResponseWriter& response);

 private:
  oai::lmf::app::lmf_app* m_lmf_app;
  // std::string m_address;
};

}  // namespace oai::lmf::api

#endif  // NonUeN2InfoNotifyApiImpl_H_
