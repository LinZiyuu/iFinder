/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UP_TRANSPORT_LAYER_INFORMATION_H_
#define _UP_TRANSPORT_LAYER_INFORMATION_H_

#include <optional>

#include "GtpTeid.hpp"
#include "GtpTunnel.hpp"
#include "TransportLayerAddress.hpp"

extern "C" {
#include "Ngap_UPTransportLayerInformation.h"
}

namespace oai::ngap {

class UpTransportLayerInformation {
 public:
  UpTransportLayerInformation();
  virtual ~UpTransportLayerInformation();

  void set(
      const TransportLayerAddress& transportLayerAddress,
      const GtpTeid& gtpTeid);
  bool get(
      TransportLayerAddress& transportLayerAddress, GtpTeid& gtpTeid) const;

  void set(const GtpTunnel& gtpTunnel);
  void get(std::optional<GtpTunnel>& gtpTunnel) const;

  bool encode(Ngap_UPTransportLayerInformation_t& upTransportLayerInfo) const;
  bool decode(const Ngap_UPTransportLayerInformation_t& upTransportLayerInfo);

 private:
  std::optional<GtpTunnel> m_GtpTunnel;
};

}  // namespace oai::ngap

#endif
