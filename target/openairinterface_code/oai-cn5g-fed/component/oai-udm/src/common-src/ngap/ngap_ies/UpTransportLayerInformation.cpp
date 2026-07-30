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
UpTransportLayerInformation::UpTransportLayerInformation() {
  m_GtpTunnel = std::nullopt;
}

//------------------------------------------------------------------------------
UpTransportLayerInformation::~UpTransportLayerInformation() {}

//------------------------------------------------------------------------------
void UpTransportLayerInformation::set(
    const TransportLayerAddress& transportLayerAddress,
    const GtpTeid& gtpTeid) {
  GtpTunnel gtpTunnel = {};
  gtpTunnel.set(transportLayerAddress, gtpTeid);
  m_GtpTunnel = std::make_optional<GtpTunnel>(gtpTunnel);
}

//------------------------------------------------------------------------------
bool UpTransportLayerInformation::get(
    TransportLayerAddress& transportLayerAddress, GtpTeid& gtpTeid) const {
  if (m_GtpTunnel.has_value()) {
    m_GtpTunnel.value().get(transportLayerAddress, gtpTeid);
    return true;
  } else {
    return false;
  }
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

  if (!m_GtpTunnel.has_value()) return false;

  if (!m_GtpTunnel.value().encode(*gtpTunnel)) {
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

  GtpTunnel gtpTunnel = {};
  if (!gtpTunnel.decode(*upTransportLayerInfo.choice.gTPTunnel)) false;

  m_GtpTunnel = std::make_optional<GtpTunnel>(gtpTunnel);

  return true;
}

}  // namespace oai::ngap
