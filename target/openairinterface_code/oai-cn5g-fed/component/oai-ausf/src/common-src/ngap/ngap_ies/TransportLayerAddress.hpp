/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _TRANSPORT_LAYER_ADDRESS_H_
#define _TRANSPORT_LAYER_ADDRESS_H_

#include <netinet/in.h>

#include <optional>
#include <string>

extern "C" {
#include "Ngap_TransportLayerAddress.h"
}

namespace oai::ngap {

struct TransportLayerAddressType {
  constexpr static uint8_t kTransportLayerAddressTypeIpv4   = 1;
  constexpr static uint8_t kTransportLayerAddressTypeIpv6   = 2;
  constexpr static uint8_t kTransportLayerAddressTypeIpv4v6 = 3;
};

class TransportLayerAddress {
 public:
  TransportLayerAddress();
  virtual ~TransportLayerAddress();

  void setAddressType(uint8_t pdu_session_type);
  uint8_t getAddressType() const;

  void setIpv4Address(const struct in_addr& ipv4_address);
  std::optional<struct in_addr> getIpv4Address() const;

  void setIpv6Address(struct in6_addr ipv6_address);
  std::optional<struct in6_addr> getIpv6Address() const;

  void setIpv4v6Address(
      struct in_addr ipv4_address, struct in6_addr ipv6_address);
  void getIpv4v6Address(
      std::optional<struct in_addr>& ipv4_address,
      std::optional<struct in6_addr>& ipv6_address) const;

  bool encode(Ngap_TransportLayerAddress_t& transportLayerAddress) const;
  bool decode(const Ngap_TransportLayerAddress_t& transportLayerAddress);

 private:
  uint8_t m_AddressType;
  std::optional<struct in_addr> ipv4_address_;
  std::optional<struct in6_addr> ipv6_address_;
};

}  // namespace oai::ngap

#endif
