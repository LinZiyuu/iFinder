/* From https://gist.github.com/javiermon/6272065#file-gateway_netlink-c */
/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "if.hpp"

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "common_defs.h"
#include "logger_base.hpp"

#define BUFFER_SIZE 4096

using namespace oai::logger;

//------------------------------------------------------------------------------
int oai::utils::get_inet_addr_infos_from_iface(
    const std::string& if_name, struct in_addr& inet_addr,
    struct in_addr& inet_network, unsigned int& mtu) {
  struct ifreq ifr;
  char str[INET_ADDRSTRLEN];

  inet_addr.s_addr    = INADDR_ANY;
  inet_network.s_addr = INADDR_ANY;
  mtu                 = 0;

  memset(&ifr, 0, sizeof(ifr));
  int fd                 = socket(AF_INET, SOCK_DGRAM, 0);
  ifr.ifr_addr.sa_family = AF_INET;
  // strncpy(ifr.ifr_name, (const char *)if_name.c_str(), IFNAMSIZ-1);
  strcpy(ifr.ifr_name, (const char*) if_name.c_str());
  if (ioctl(fd, SIOCGIFADDR, &ifr)) {
    close(fd);
    logger_common::system().error(
        "Failed to probe %s inet addr: error %s\n", if_name.c_str(),
        strerror(errno));
    return RETURNerror;
  }
  struct sockaddr_in* ipaddr = (struct sockaddr_in*) &ifr.ifr_addr;
  // check
  if (inet_ntop(
          AF_INET, (const void*) &ipaddr->sin_addr, str, INET_ADDRSTRLEN) ==
      NULL) {
    close(fd);
    return RETURNerror;
  }
  inet_addr.s_addr = ipaddr->sin_addr.s_addr;

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_addr.sa_family = AF_INET;
  // strncpy(ifr.ifr_name, (const char *)if_name.c_str(), IFNAMSIZ-1);
  strcpy(ifr.ifr_name, (const char*) if_name.c_str());
  if (ioctl(fd, SIOCGIFNETMASK, &ifr)) {
    close(fd);
    logger_common::system().error(
        "Failed to probe %s inet netmask: error %s\n", if_name.c_str(),
        strerror(errno));
    return RETURNerror;
  }
  ipaddr = (struct sockaddr_in*) &ifr.ifr_netmask;
  // check
  if (inet_ntop(
          AF_INET, (const void*) &ipaddr->sin_addr, str, INET_ADDRSTRLEN) ==
      NULL) {
    close(fd);
    return RETURNerror;
  }
  inet_network.s_addr = ipaddr->sin_addr.s_addr;

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_addr.sa_family = AF_INET;
  // strncpy(ifr.ifr_name, (const char *)if_name.c_str(), IFNAMSIZ-1);
  strcpy(ifr.ifr_name, (const char*) if_name.c_str());
  if (ioctl(fd, SIOCGIFMTU, &ifr)) {
    logger_common::system().error(
        "Failed to probe %s MTU: error %s\n", if_name.c_str(), strerror(errno));
  } else {
    mtu = ifr.ifr_mtu;
  }
  close(fd);
  return RETURNok;
}
