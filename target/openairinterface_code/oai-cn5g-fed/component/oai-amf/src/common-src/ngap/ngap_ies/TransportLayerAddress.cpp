/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "TransportLayerAddress.hpp"

#include <vector>

#include "ngap_utils.hpp"
#include "string.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
TransportLayerAddress::TransportLayerAddress() {
  ipv4_address_ = std::nullopt;
  ipv6_address_ = std::nullopt;
}

//------------------------------------------------------------------------------
TransportLayerAddress::~TransportLayerAddress() {}

//------------------------------------------------------------------------------
void TransportLayerAddress::setAddressType(uint8_t address_type) {
  m_AddressType = address_type;
}
//------------------------------------------------------------------------------
uint8_t TransportLayerAddress::getAddressType() const {
  return m_AddressType;
}
//------------------------------------------------------------------------------
void TransportLayerAddress::setIpv4Address(const struct in_addr& ipv4_address) {
  ipv4_address_ = std::make_optional<struct in_addr>(ipv4_address);
  m_AddressType = TransportLayerAddressType::kTransportLayerAddressTypeIpv4;
}
//------------------------------------------------------------------------------
std::optional<struct in_addr> TransportLayerAddress::getIpv4Address() const {
  return ipv4_address_;
}
//------------------------------------------------------------------------------
void TransportLayerAddress::setIpv6Address(struct in6_addr ipv6_address) {
  ipv6_address_ = std::make_optional<struct in6_addr>(ipv6_address);
  m_AddressType = TransportLayerAddressType::kTransportLayerAddressTypeIpv6;
}
//------------------------------------------------------------------------------
std::optional<struct in6_addr> TransportLayerAddress::getIpv6Address() const {
  return ipv6_address_;
}

//------------------------------------------------------------------------------
void TransportLayerAddress::setIpv4v6Address(
    struct in_addr ipv4_address, struct in6_addr ipv6_address) {
  ipv4_address_ = std::make_optional<struct in_addr>(ipv4_address);
  ipv6_address_ = std::make_optional<struct in6_addr>(ipv6_address);
  m_AddressType = TransportLayerAddressType::kTransportLayerAddressTypeIpv4v6;
}

//------------------------------------------------------------------------------
void TransportLayerAddress::getIpv4v6Address(
    std::optional<struct in_addr>& ipv4_address,
    std::optional<struct in6_addr>& ipv6_address) const {
  ipv4_address = ipv4_address_;
  ipv6_address = ipv6_address_;
}

//------------------------------------------------------------------------------
std::vector<std::string> splite(const std::string& s, const std::string& c) {
  std::string::size_type pos1, pos2;
  std::vector<std::string> v;
  pos2 = s.find(c);
  pos1 = 0;
  while (std::string::npos != pos2) {
    v.push_back(s.substr(pos1, pos2 - pos1));

    pos1 = pos2 + c.size();
    pos2 = s.find(c, pos1);
  }
  if (pos1 != s.length()) {
    v.push_back(s.substr(pos1));
  }
  return v;
}

//------------------------------------------------------------------------------
bool TransportLayerAddress::encode(
    Ngap_TransportLayerAddress_t& transportLayerAddress) const {
  bstring str;
  if (m_AddressType ==
      TransportLayerAddressType::kTransportLayerAddressTypeIpv4) {
    if (ipv4_address_.has_value()) {
      str = bfromcstralloc(4, "\0");
      oai::utils::ipv4_to_bstring(ipv4_address_.value(), str);
    }
  } else if (
      m_AddressType ==
      TransportLayerAddressType::kTransportLayerAddressTypeIpv6) {
    if (ipv6_address_.has_value()) {
      str = bfromcstralloc(16, "\0");
      oai::utils::ipv6_to_bstring(ipv6_address_.value(), str);
    }
  } else if (
      m_AddressType ==
      TransportLayerAddressType::kTransportLayerAddressTypeIpv4v6) {
    str = bfromcstralloc(20, "\0");
    oai::utils::ipv4v6_to_transport_layer_address(
        ipv4_address_.value(), ipv6_address_.value(), str);
  }

  ngap_utils::bstring_2_bit_string(str, transportLayerAddress);

  return true;
}

//------------------------------------------------------------------------------
bool TransportLayerAddress::decode(
    const Ngap_TransportLayerAddress_t& transportLayerAddress) {
  if (!transportLayerAddress.buf) return false;

  switch (transportLayerAddress.size) {
    case 4: {  // 32 bits, Ipv4
      struct in_addr ipv4_address;
      ipv4_address.s_addr = *((uint32_t*) transportLayerAddress.buf);
      ipv4_address_       = std::make_optional<struct in_addr>(ipv4_address);
      m_AddressType = TransportLayerAddressType::kTransportLayerAddressTypeIpv4;
    } break;
    case 16: {  // 128 bits, ipv6 addr
      struct in6_addr ipv6_address;
      memcpy(ipv6_address.s6_addr, transportLayerAddress.buf, 16);
      ipv6_address_ = std::make_optional<struct in6_addr>(ipv6_address);
      m_AddressType = TransportLayerAddressType::kTransportLayerAddressTypeIpv6;
    } break;
    case 20: {  // 160 bits, both IPv4 and IPv6 addresses, IPv4 address is
                // contained in the first 32
      // Ipv4
      struct in_addr ipv4_address;
      unsigned char ipv4_addr_str[4];
      memcpy(ipv4_addr_str, transportLayerAddress.buf, 4);
      ipv4_address.s_addr = *((uint32_t*) ipv4_addr_str);
      ipv4_address_       = std::make_optional<struct in_addr>(ipv4_address);
      // Ipv6
      struct in6_addr ipv6_address;
      memcpy(ipv6_address.s6_addr, transportLayerAddress.buf + 4, 16);
      ipv6_address_ = std::make_optional<struct in6_addr>(ipv6_address);
      m_AddressType =
          TransportLayerAddressType::kTransportLayerAddressTypeIpv4v6;
    } break;
    default: {
      // TODO:
      return false;
    }
  }

  return true;
}

}  // namespace oai::ngap
