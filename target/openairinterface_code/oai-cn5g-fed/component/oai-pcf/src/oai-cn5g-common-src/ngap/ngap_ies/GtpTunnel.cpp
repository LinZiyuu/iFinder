/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "GtpTunnel.hpp"

#include "utils.hpp"

extern "C" {
#include "Ngap_GTPTunnel.h"
}

namespace oai::ngap {

//------------------------------------------------------------------------------
GtpTunnel::GtpTunnel() {}

//------------------------------------------------------------------------------
GtpTunnel::~GtpTunnel() {}

//------------------------------------------------------------------------------
void GtpTunnel::set(
    const TransportLayerAddress& transportLayerAddress,
    const GtpTeid& gtpTeid) {
  m_TransportLayerAddress = transportLayerAddress;
  m_GtpTeid               = gtpTeid;
}

//------------------------------------------------------------------------------
bool GtpTunnel::get(
    TransportLayerAddress& transportLayerAddress, GtpTeid& gtpTeid) const {
  transportLayerAddress = m_TransportLayerAddress;
  gtpTeid               = m_GtpTeid;

  return true;
}

//------------------------------------------------------------------------------
bool GtpTunnel::encode(Ngap_GTPTunnel& gtpTunnel) const {
  if (!m_TransportLayerAddress.encode(gtpTunnel.transportLayerAddress)) {
    return false;
  }

  if (!m_GtpTeid.encode(gtpTunnel.gTP_TEID)) {
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool GtpTunnel::decode(const Ngap_GTPTunnel& gtpTunnel) {
  if (!m_TransportLayerAddress.decode(gtpTunnel.transportLayerAddress))
    return false;
  if (!m_GtpTeid.decode(gtpTunnel.gTP_TEID)) return false;

  return true;
}

}  // namespace oai::ngap
