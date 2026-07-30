/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _TRANSPORT_LAYER_ADDRESS_H_
#define _TRANSPORT_LAYER_ADDRESS_H_

#include <string>

extern "C" {
#include "Ngap_TransportLayerAddress.h"
}

namespace oai::ngap {

class TransportLayerAddress {
 public:
  TransportLayerAddress();
  virtual ~TransportLayerAddress();

  void set(const std::string& address);
  bool get(std::string& address) const;

  bool encode(Ngap_TransportLayerAddress_t& transportLayerAddress) const;
  bool decode(const Ngap_TransportLayerAddress_t& transportLayerAddress);

 private:
  std::string m_IpAddress;
};

}  // namespace oai::ngap

#endif
