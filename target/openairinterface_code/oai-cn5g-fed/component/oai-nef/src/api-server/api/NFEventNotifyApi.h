/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * NFEventNotifyApi.h
 *
 *
 */

#ifndef NFEventNotifyApi_H_
#define NFEventNotifyApi_H_

#include <pistache/http.h>
#include <pistache/http_headers.h>
#include <pistache/optional.h>
#include <pistache/router.h>

#include "AmfEventNotification.h"
#include "MonitoringReport.h"
#include "NefEventExposureNotif.h"
#include "NsmfEventExposureNotification.h"
#include "ProblemDetails.h"

namespace oai::nef::api {

using namespace oai::nef::model;

class NFEventNotifyApi {
 public:
  NFEventNotifyApi(std::shared_ptr<Pistache::Rest::Router>);
  virtual ~NFEventNotifyApi() {}
  void init();
  static const std::string base;

 private:
  void setupRoutes();

  void notify_udm_event_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);
  void notify_amf_event_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);
  void notify_smf_event_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);

  void notify_nf_event_default_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);

  std::shared_ptr<Pistache::Rest::Router> router;

  /// <summary>
  ///
  /// </summary>
  /// <remarks>
  ///
  /// </remarks>
  /// <param name="NefEventExposureNotif"></param>
  virtual void receive_nf_event_notification(
      const NefEventExposureNotif& eventExposureNotif,
      Pistache::Http::ResponseWriter& response) = 0;

  virtual void receive_amf_event_notification(
      const AmfEventNotification& amfEventNotification,
      Pistache::Http::ResponseWriter& response) = 0;

  virtual void receive_smf_event_notification(
      const NsmfEventExposureNotification& smfEventExposureNotification,
      Pistache::Http::ResponseWriter& response) = 0;

  virtual void receive_udm_event_notification(
      const std::vector<MonitoringReport>& eventExposureNotif,
      Pistache::Http::ResponseWriter& response) = 0;
};

}  // namespace oai::nef::api

#endif /* NFEventNotifyApi_H_ */
