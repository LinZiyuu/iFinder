/*
 * NFEventNotifyApiImpl.h
 *
 *
 */

/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef NF_EVENT_NOTIFY_API_IMPL_H_
#define NF_EVENT_NOTIFY_API_IMPL_H_

#include <NFEventNotifyApi.h>
#include <pistache/endpoint.h>
#include <pistache/http.h>
#include <pistache/optional.h>
#include <pistache/router.h>

#include <memory>

#include "ProblemDetails.h"
#include "nef_app.hpp"

namespace oai::nef::api {

using namespace oai::nef::model;

class NFEventNotifyApiImpl : public oai::nef::api::NFEventNotifyApi {
 public:
  NFEventNotifyApiImpl(
      std::shared_ptr<Pistache::Rest::Router>,
      oai::nef::app::nef_app* nef_app_inst, std::string address);
  ~NFEventNotifyApiImpl() {}

  void receive_nf_event_notification(
      const NefEventExposureNotif& eventExposureNotif,
      Pistache::Http::ResponseWriter& response);

  void receive_amf_event_notification(
      const AmfEventNotification& amfEventNotification,
      Pistache::Http::ResponseWriter& response);

  void receive_smf_event_notification(
      const NsmfEventExposureNotification& smfEventExposureNotification,
      Pistache::Http::ResponseWriter& response);

  void receive_udm_event_notification(
      const std::vector<MonitoringReport>& eventExposureNotif,
      Pistache::Http::ResponseWriter& response);

 private:
  oai::nef::app::nef_app* m_nef_app;
  std::string m_address;
};

}  // namespace oai::nef::api
#endif
