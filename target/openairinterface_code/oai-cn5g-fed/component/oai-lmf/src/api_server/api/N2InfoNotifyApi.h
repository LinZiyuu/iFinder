/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/*
 * N2InfoNotifyApi.h
 *
 *
 */

#ifndef N2InfoNotifyApi_H_
#define N2InfoNotifyApi_H_

#include <pistache/http.h>
#include <pistache/router.h>

#include "mime_parser.hpp"

namespace oai::lmf::api {

class N2InfoNotifyApi {
 public:
  N2InfoNotifyApi(std::shared_ptr<Pistache::Rest::Router>);
  virtual ~N2InfoNotifyApi() {}
  void init();

 private:
  void setupRoutes();

  void notify_n2info_nrppa_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);
  void notify_n2info_default_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);

  std::shared_ptr<Pistache::Rest::Router> router;

  virtual void receive_n2info_nrppa_notification(
      const std::string& ueContextId, std::vector<mime_part>& parts,
      Pistache::Http::ResponseWriter& response) = 0;
};

}  // namespace oai::lmf::api

#endif /* N2InfoNotifyApi_H_ */
