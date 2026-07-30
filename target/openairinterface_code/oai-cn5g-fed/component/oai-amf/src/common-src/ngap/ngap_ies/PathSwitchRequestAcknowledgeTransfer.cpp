/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PathSwitchRequestAcknowledgeTransfer.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PathSwitchRequestAcknowledgeTransfer::PathSwitchRequestAcknowledgeTransfer() {
  m_Ie = (Ngap_PathSwitchRequestAcknowledgeTransfer_t*) calloc(
      1, sizeof(Ngap_PathSwitchRequestAcknowledgeTransfer_t));
}

//------------------------------------------------------------------------------
void PathSwitchRequestAcknowledgeTransfer::setUlNgUUpTnlInformation(
    const UpTransportLayerInformation& ulNgUUpTnlInformation) {
  m_UlNgUUpTnlInformation = ulNgUUpTnlInformation;
}

//------------------------------------------------------------------------------
void PathSwitchRequestAcknowledgeTransfer::getUlNgUUpTnlInformation(
    std::optional<UpTransportLayerInformation>& ulNgUUpTnlInformation) const {
  ulNgUUpTnlInformation = m_UlNgUUpTnlInformation;
}

//------------------------------------------------------------------------------
void PathSwitchRequestAcknowledgeTransfer::setQosFlowParametersList(
    const std::vector<QosFlowParametersItem> list) {
  QosFlowParametersList qosFlowParametersList = {};
  qosFlowParametersList.set(list);
  m_QosFlowParametersList =
      std::make_optional<QosFlowParametersList>(qosFlowParametersList);
}

//------------------------------------------------------------------------------
void PathSwitchRequestAcknowledgeTransfer::setQosFlowParametersList(
    const QosFlowParametersList& list) {
  m_QosFlowParametersList = std::make_optional<QosFlowParametersList>(list);
}

//------------------------------------------------------------------------------
void PathSwitchRequestAcknowledgeTransfer::getQosFlowParametersList(
    std::optional<QosFlowParametersList>& list) const {
  list = m_QosFlowParametersList;
}

//------------------------------------------------------------------------------
int PathSwitchRequestAcknowledgeTransfer::encode(uint8_t* buf, int bufSize) {
  ngap_utils::print_asn_msg(
      &asn_DEF_Ngap_PathSwitchRequestAcknowledgeTransfer, m_Ie);
  asn_enc_rval_t er = aper_encode_to_buffer(
      &asn_DEF_Ngap_PathSwitchRequestAcknowledgeTransfer, NULL, m_Ie, buf,
      bufSize);
  oai::logger::logger_common::ngap().debug("er.encoded( %d)", er.encoded);
  // asn_fprint(stderr, er.failed_type, er.structure_ptr);
  return er.encoded;
}

//------------------------------------------------------------------------------
bool PathSwitchRequestAcknowledgeTransfer::decode(uint8_t* buf, int bufSize) {
  asn_dec_rval_t rc = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER,
      &asn_DEF_Ngap_PathSwitchRequestAcknowledgeTransfer, (void**) &m_Ie, buf,
      bufSize);
  if (rc.code == RC_OK) {
    oai::logger::logger_common::ngap().debug("Decoded successfully");
  } else if (rc.code == RC_WMORE) {
    oai::logger::logger_common::ngap().debug("More data expected, call again");
    return false;
  } else {
    oai::logger::logger_common::ngap().debug("Failure to decode data");
    return false;
  }

  // asn_fprint(stderr, &asn_DEF_Ngap_PathSwitchRequestAcknowledgeTransfer,
  // m_Ie);

  // Decode DL NG-U UP TNL Information
  if (m_Ie->uL_NGU_UP_TNLInformation) {
    UpTransportLayerInformation upTransportLayerInformation = {};
    if (!upTransportLayerInformation.decode(*m_Ie->uL_NGU_UP_TNLInformation)) {
      oai::logger::logger_common::ngap().error(
          "Failure to decode DL NG-U UP TNL Information IE");
      return false;
    }
    m_UlNgUUpTnlInformation = std::make_optional<UpTransportLayerInformation>(
        upTransportLayerInformation);
  }

  // TODO: Decode QoS Flow Parameters List

  return true;
}

}  // namespace oai::ngap
