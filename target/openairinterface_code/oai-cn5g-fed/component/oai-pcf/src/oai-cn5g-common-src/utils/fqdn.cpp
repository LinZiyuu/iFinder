/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "fqdn.hpp"
#include "logger_base.hpp"
#include <boost/asio.hpp>
#include <iostream>
#include <chrono>
#include <thread>

#define MAX_NB_RESOLVE_TRIES 4
#define TIME_IN_SECS_BETWEEN_TRIES 2

using namespace oai::utils;
using namespace oai::logger;

//------------------------------------------------------------------------------
bool fqdn::resolve(
    const std::string& host_name, std::string& address, uint32_t& port,
    uint8_t& addr_type, const std::string& protocol) {
  int tries = 0;
  logger_common::common().debug("Resolving a DNS (name %s)", host_name.c_str());
  while (tries < MAX_NB_RESOLVE_TRIES) {
    try {
      boost::asio::io_context io_context = {};
      logger_common::common().debug("Resolving DNS Try #%u", tries);

      boost::asio::ip::tcp::resolver resolver{io_context};
      boost::asio::ip::tcp::resolver::results_type endpoints =
          resolver.resolve(host_name, protocol);

      addr_type = 0;  // IPv4 by default
      for (auto it = endpoints.cbegin(); it != endpoints.cend(); it++) {
        // get the first Endpoint
        boost::asio::ip::tcp::endpoint endpoint = *it;
        address = endpoint.address().to_string();
        port    = endpoint.port();
        logger_common::common().debug(
            "Resolved a DNS (name %s, protocol %s): Ip Addr %s, port %u",
            host_name.c_str(), protocol.c_str(), address.c_str(), port);
        if (endpoint.address().is_v4()) {
          addr_type = 0;
        } else {
          addr_type = 1;
          // In case of IPv6, let see if IPv4 was detected.
          continue;
        }
        return true;
      }
    } catch (std::exception& e) {
      tries++;
      if (tries == MAX_NB_RESOLVE_TRIES) {
        throw std::runtime_error(
            "Cannot resolve a DNS name " + std::string(e.what()) + " after " +
            std::to_string(tries) + " tries");
        return false;
      }
      std::this_thread::sleep_for(
          std::chrono::seconds(TIME_IN_SECS_BETWEEN_TRIES));
    }
  }

  return false;
}
