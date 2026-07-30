/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_N1_N2_MESSAGE_SUBSCRIPTION_SEEN
#define FILE_N1_N2_MESSAGE_SUBSCRIPTION_SEEN

#include <string>
#include <memory>

#include <boost/core/noncopyable.hpp>

namespace oai::lmf::app {

class N1N2MessageSubscription : private boost::noncopyable {
 public:
  const std::string id, supi;

  N1N2MessageSubscription(const std::string& supi)
      : id{N1N2MessageSubscription::subscribe(supi)}, supi{supi} {}

  ~N1N2MessageSubscription() {
    N1N2MessageSubscription::unsubscribe(this->id, this->supi);
  }

  static std::string subscribe(std::string const& supi);
  static void unsubscribe(std::string const& id, std::string const& supi);
};

}  // namespace oai::lmf::app

#endif  // ifndef FILE_N1_N2_MESSAGE_SUBSCRIPTION_SEEN
