/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "TransportLayerAddress.hpp"

#include <vector>

#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
TransportLayerAddress::TransportLayerAddress() {}

//------------------------------------------------------------------------------
TransportLayerAddress::~TransportLayerAddress() {}

//------------------------------------------------------------------------------
void TransportLayerAddress::set(const std::string& address) {
  // m_IpAddress = oai::utils::utils::fromString<long>(address);
  m_IpAddress = address;
}

//------------------------------------------------------------------------------
bool TransportLayerAddress::get(std::string& address) const {
  // address = to_string(m_IpAddress);
  address = m_IpAddress;

  return true;
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
  transportLayerAddress.size        = sizeof(uint32_t);
  transportLayerAddress.bits_unused = 0;
  transportLayerAddress.buf = (uint8_t*) calloc(1, transportLayerAddress.size);
  if (!transportLayerAddress.buf) return false;

  std::vector<std::string> ipAddress = splite(m_IpAddress, ".");

  for (int i = 0; i < transportLayerAddress.size; i++) {
    transportLayerAddress.buf[i] =
        oai::utils::utils::fromString<int>(ipAddress[i]);
  }

  return true;
}

//------------------------------------------------------------------------------
bool TransportLayerAddress::decode(
    const Ngap_TransportLayerAddress_t& transportLayerAddress) {
  if (!transportLayerAddress.buf) return false;

  m_IpAddress = std::to_string(transportLayerAddress.buf[0]);
  for (int i = 1; i < transportLayerAddress.size; i++) {
    m_IpAddress =
        m_IpAddress + '.' + std::to_string(transportLayerAddress.buf[i]);
  }

  return true;
}

}  // namespace oai::ngap
