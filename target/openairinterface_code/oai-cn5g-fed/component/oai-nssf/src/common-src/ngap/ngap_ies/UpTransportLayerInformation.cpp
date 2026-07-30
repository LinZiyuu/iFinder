/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UpTransportLayerInformation.hpp"

#include "utils.hpp"

extern "C" {
#include "Ngap_GTPTunnel.h"
}

namespace oai::ngap {

//------------------------------------------------------------------------------
UpTransportLayerInformation::UpTransportLayerInformation() {}

//------------------------------------------------------------------------------
UpTransportLayerInformation::~UpTransportLayerInformation() {}

//------------------------------------------------------------------------------
void UpTransportLayerInformation::set(
    const TransportLayerAddress& transportLayerAddress,
    const GtpTeid& gtpTeid) {
  m_TransportLayerAddress = transportLayerAddress;
  m_GtpTeid               = gtpTeid;
}

//------------------------------------------------------------------------------
bool UpTransportLayerInformation::get(
    TransportLayerAddress& transportLayerAddress, GtpTeid& gtpTeid) const {
  transportLayerAddress = m_TransportLayerAddress;
  gtpTeid               = m_GtpTeid;

  return true;
}

//------------------------------------------------------------------------------
void UpTransportLayerInformation::set(const GtpTunnel& gtpTunnel) {
  m_GtpTunnel = std::make_optional<GtpTunnel>(gtpTunnel);
}

//------------------------------------------------------------------------------
void UpTransportLayerInformation::get(
    std::optional<GtpTunnel>& gtpTunnel) const {
  gtpTunnel = m_GtpTunnel;
}

//------------------------------------------------------------------------------
bool UpTransportLayerInformation::encode(
    Ngap_UPTransportLayerInformation_t& upTransportLayerInfo) const {
  upTransportLayerInfo.present = Ngap_UPTransportLayerInformation_PR_gTPTunnel;
  Ngap_GTPTunnel_t* gtpTunnel =
      (Ngap_GTPTunnel_t*) calloc(1, sizeof(Ngap_GTPTunnel_t));
  if (!gtpTunnel) return false;
  if (!m_TransportLayerAddress.encode(gtpTunnel->transportLayerAddress)) {
    oai::utils::utils::free_wrapper((void**) &gtpTunnel);
    return false;
  }

  if (!m_GtpTeid.encode(gtpTunnel->gTP_TEID)) {
    oai::utils::utils::free_wrapper((void**) &gtpTunnel);
    return false;
  }
  upTransportLayerInfo.choice.gTPTunnel = gtpTunnel;
  return true;
}

//------------------------------------------------------------------------------
bool UpTransportLayerInformation::decode(
    const Ngap_UPTransportLayerInformation_t& upTransportLayerInfo) {
  if (upTransportLayerInfo.present !=
      Ngap_UPTransportLayerInformation_PR_gTPTunnel)
    return false;
  if (!upTransportLayerInfo.choice.gTPTunnel) return false;

  if (!m_TransportLayerAddress.decode(
          upTransportLayerInfo.choice.gTPTunnel->transportLayerAddress))
    false;
  if (!m_GtpTeid.decode(upTransportLayerInfo.choice.gTPTunnel->gTP_TEID))
    return false;

  return true;
}

}  // namespace oai::ngap
