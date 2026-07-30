/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceModifyConfirmTransfer.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceModifyConfirmTransfer::
    PduSessionResourceModifyConfirmTransfer() {
  m_Ie = (Ngap_PDUSessionResourceModifyConfirmTransfer_t*) calloc(
      1, sizeof(Ngap_PDUSessionResourceModifyConfirmTransfer_t));
  m_QosFlowFailedToModifyList = std::nullopt;
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyConfirmTransfer::setQosFlowModifyConfirmList(
    const std::vector<QosFlowModifyConfirmItem> list) {
  m_QosFlowModifyConfirmList.set(list);
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyConfirmTransfer::setQosFlowModifyConfirmList(
    const QosFlowModifyConfirmList& list) {
  m_QosFlowModifyConfirmList = list;
}
//------------------------------------------------------------------------------
void PduSessionResourceModifyConfirmTransfer::getQosFlowModifyConfirmList(
    QosFlowModifyConfirmList& list) const {
  list = m_QosFlowModifyConfirmList;
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyConfirmTransfer::setUlNgUUpTnlInformation(
    const UpTransportLayerInformation& ulNgUUpTnlInformation) {
  m_UlNgUUpTnlInformation = ulNgUUpTnlInformation;
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyConfirmTransfer::getUlNgUUpTnlInformation(
    UpTransportLayerInformation& ulNgUUpTnlInformation) const {
  ulNgUUpTnlInformation = m_UlNgUUpTnlInformation;
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyConfirmTransfer::setQosFlowFailedToModifyList(
    const QosFlowListWithCause& qosFlowFailedToModifyList) {
  m_QosFlowFailedToModifyList =
      std::make_optional<QosFlowListWithCause>(qosFlowFailedToModifyList);
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyConfirmTransfer::getQosFlowFailedToModifyList(
    std::optional<QosFlowListWithCause>& qosFlowFailedToModifyList) const {
  qosFlowFailedToModifyList = m_QosFlowFailedToModifyList;
}

//------------------------------------------------------------------------------
int PduSessionResourceModifyConfirmTransfer::encode(uint8_t* buf, int bufSize) {
  ngap_utils::print_asn_msg(
      &asn_DEF_Ngap_PDUSessionResourceModifyConfirmTransfer, m_Ie);
  asn_enc_rval_t er = aper_encode_to_buffer(
      &asn_DEF_Ngap_PDUSessionResourceModifyConfirmTransfer, NULL, m_Ie, buf,
      bufSize);
  oai::logger::logger_common::ngap().debug("er.encoded( %d)", er.encoded);
  // asn_fprint(stderr, er.failed_type, er.structure_ptr);
  return er.encoded;
}

//------------------------------------------------------------------------------
bool PduSessionResourceModifyConfirmTransfer::decode(
    uint8_t* buf, int bufSize) {
  asn_dec_rval_t rc = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER,
      &asn_DEF_Ngap_PDUSessionResourceModifyConfirmTransfer, (void**) &m_Ie,
      buf, bufSize);
  if (rc.code == RC_OK) {
    oai::logger::logger_common::ngap().debug("Decoded successfully");
  } else if (rc.code == RC_WMORE) {
    oai::logger::logger_common::ngap().debug("More data expected, call again");
    return false;
  } else {
    oai::logger::logger_common::ngap().debug("Failure to decode data");
    return false;
  }

  // asn_fprint(stderr, &asn_DEF_Ngap_PDUSessionResourceModifyConfirmTransfer,
  // m_Ie);

  // Decode QoS Flow Modify Confirm List
  if (!m_QosFlowModifyConfirmList.decode(m_Ie->qosFlowModifyConfirmList)) {
    oai::logger::logger_common::ngap().error(
        "Failure to decode QoS Flow Modify Confirm List IE");
    return false;
  }

  // Decode UL NG-U UP TNL Information
  UpTransportLayerInformation ulNgUUpTnlInformation = {};
  if (!m_UlNgUUpTnlInformation.decode(m_Ie->uLNGU_UP_TNLInformation)) {
    oai::logger::logger_common::ngap().error(
        "Failure to decode UL NG-U UP TNL Information IE");
    return false;
  }

  // Decode QoS Flow Failed Modify List
  if (m_Ie->qosFlowFailedToModifyList) {
    QosFlowListWithCause qosFlowFailedToModifyList = {};
    if (!qosFlowFailedToModifyList.decode(*m_Ie->qosFlowFailedToModifyList)) {
      oai::logger::logger_common::ngap().error(
          "Failure to decode  QoS Flow Failed Modify List IE");
      return false;
    }
    m_QosFlowFailedToModifyList =
        std::make_optional<QosFlowListWithCause>(qosFlowFailedToModifyList);
  }

  return true;
}

}  // namespace oai::ngap
