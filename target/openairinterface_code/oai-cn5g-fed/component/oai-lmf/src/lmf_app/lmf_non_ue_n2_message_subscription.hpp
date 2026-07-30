/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_NON_UE_N2_MESSAGE_SUBSCRIPTION_SEEN
#define FILE_NON_UE_N2_MESSAGE_SUBSCRIPTION_SEEN

#include <string>
#include <memory>

#include <boost/core/noncopyable.hpp>

namespace oai::lmf::app {

// 3GPP TS 29.518 version 16.4.0 Release 16
class NonUeN2MessageSubscription : private boost::noncopyable {
 public:
  const std::string id;

  NonUeN2MessageSubscription() : id{NonUeN2MessageSubscription::subscribe()} {}
  ~NonUeN2MessageSubscription() {
    NonUeN2MessageSubscription::unsubscribe(this->id);
  }

  static std::string subscribe();
  static void unsubscribe(std::string const& id);
};

}  // namespace oai::lmf::app

#endif  // ifndef FILE_NON_UE_N2_MESSAGE_SUBSCRIPTION_SEEN
