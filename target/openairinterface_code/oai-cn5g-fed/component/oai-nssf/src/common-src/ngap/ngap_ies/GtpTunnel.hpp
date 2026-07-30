/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _GTP_TUNNEL_H_
#define _GTP_TUNNEL_H_

#include "GtpTeid.hpp"
#include "TransportLayerAddress.hpp"

extern "C" {
#include "Ngap_GTPTunnel.h"
}

namespace oai::ngap {

class GtpTunnel {
 public:
  GtpTunnel();
  virtual ~GtpTunnel();

  void set(
      const TransportLayerAddress& transportLayerAddress,
      const GtpTeid& gtpTeid);
  bool get(
      TransportLayerAddress& transportLayerAddress, GtpTeid& gtpTeid) const;

  bool encode(Ngap_GTPTunnel& upTransportLayerInfo) const;
  bool decode(const Ngap_GTPTunnel& upTransportLayerInfo);

 private:
  TransportLayerAddress m_TransportLayerAddress;
  GtpTeid m_GtpTeid;
};

}  // namespace oai::ngap

#endif
