/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_NRF_CLIENT_HPP_SEEN
#define FILE_NRF_CLIENT_HPP_SEEN

#include "nrf_profile.hpp"

namespace oai {
namespace nrf {
namespace app {

class nrf_client {
 public:
  nrf_client();
  virtual ~nrf_client();

  nrf_client(nrf_client const&) = delete;
  void operator=(nrf_client const&) = delete;

  /*
   * Send Notification for the associated event to the subscribers
   * @param [const std::shared_ptr<nrf_profile> &] profile: NF profile
   * @param [const uint8_t &] event_type: notification type
   * @param [const std::vector<std::string> &] uris: list of subscribed NFs' URI
   * @return void
   */
  void notify_subscribed_event(
      const std::shared_ptr<nrf_profile>& profile, const uint8_t& event_type,
      const std::vector<std::string>& uris, uint8_t http_version);
};
}  // namespace app
}  // namespace nrf
}  // namespace oai
#endif /* FILE_NRF_CLIENT_HPP_SEEN */
