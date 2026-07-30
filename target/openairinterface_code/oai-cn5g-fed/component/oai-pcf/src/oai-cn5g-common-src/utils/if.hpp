/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_IF_HPP_SEEN
#define FILE_IF_HPP_SEEN

#include <netinet/in.h>
#include <string>

namespace oai::utils {

int get_inet_addr_infos_from_iface(
    const std::string& if_name, struct in_addr& inet_addr,
    struct in_addr& inet_netmask, unsigned int& mtu);
}  // namespace oai::utils
#endif /* FILE_IF_HPP_SEEN */
