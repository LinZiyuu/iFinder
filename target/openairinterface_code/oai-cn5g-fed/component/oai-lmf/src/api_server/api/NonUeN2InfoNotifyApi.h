/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 *  .h
 *
 *
 */

#ifndef NonUeN2InfoNotifyApi_H_
#define NonUeN2InfoNotifyApi_H_

#include <pistache/http.h>
#include <pistache/router.h>

#include "mime_parser.hpp"

namespace oai::lmf::api {

class NonUeN2InfoNotifyApi {
 public:
  NonUeN2InfoNotifyApi(std::shared_ptr<Pistache::Rest::Router>);
  virtual ~NonUeN2InfoNotifyApi() {}
  void init();

 private:
  void setupRoutes();

  void notify_non_ue_n2info_nrppa_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);
  void notify_non_ue_n2info_default_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);

  std::shared_ptr<Pistache::Rest::Router> router;

  virtual void receive_non_ue_n2info_nrppa_notification(
      std::vector<mime_part>& parts,
      Pistache::Http::ResponseWriter& response) = 0;
};

}  // namespace oai::lmf::api

#endif /* NonUeN2InfoNotifyApi_H_ */
