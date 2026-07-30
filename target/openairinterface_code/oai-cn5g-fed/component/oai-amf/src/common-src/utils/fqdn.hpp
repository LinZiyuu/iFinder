/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_FQDN_HPP_SEEN
#define FILE_FQDN_HPP_SEEN

#include <string>
#include "3gpp_29.244.h"

namespace oai::utils {
class fqdn {
 public:
  /*
   * Resolve a DNS name to get host's IP Addr
   * @param [const std::string &] host_name: host's name/url
   * @param [const std::string &] protocol: protocol
   * @param [uint8_t &] addr_type: addr_type (Ipv4/v6)
   * @return void
   */
  static bool resolve(
      const std::string& host_name, std::string& address, uint32_t& port,
      uint8_t& addr_type, const std::string& protocol = "http");

  static bool resolve(pfcp::node_id_t& node_id);
  /**
   * @brief Resolves an IP address to get the hostname
   * @param ip_address to resolve
   * @param host_name result, if return=true
   * @return true if successful
   */
  static bool reverse_resolve(
      const std::string& ip_address, std::string& host_name);
};
}  // namespace oai::utils
#endif /* FILE_FQDN_HPP_SEEN */
