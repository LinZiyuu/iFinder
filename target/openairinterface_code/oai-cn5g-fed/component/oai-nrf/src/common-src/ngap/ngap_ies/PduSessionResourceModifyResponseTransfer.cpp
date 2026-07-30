/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceModifyResponseTransfer.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceModifyResponseTransfer::
    PduSessionResourceModifyResponseTransfer() {
  m_Ie = (Ngap_PDUSessionResourceModifyResponseTransfer_t*) calloc(
      1, sizeof(Ngap_PDUSessionResourceModifyResponseTransfer_t));
  m_DlNgUUpTnlInformation          = std::nullopt;
  m_UlNgUUpTnlInformation          = std::nullopt;
  m_QosFlowAddOrModifyResponseList = std::nullopt;
  m_QosFlowFailedToAddOrModifyList = std::nullopt;
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyResponseTransfer::setDlNgUUpTnlInformation(
    const UpTransportLayerInformation& dlNgUUpTnlInformation) {
  m_DlNgUUpTnlInformation =
      std::make_optional<UpTransportLayerInformation>(dlNgUUpTnlInformation);
}
//------------------------------------------------------------------------------
void PduSessionResourceModifyResponseTransfer::getDlNgUUpTnlInformation(
    std::optional<UpTransportLayerInformation>& dlNgUUpTnlInformation) const {
  dlNgUUpTnlInformation = m_DlNgUUpTnlInformation;
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyResponseTransfer::setUlNgUUpTnlInformation(
    const UpTransportLayerInformation& ulNgUUpTnlInformation) {
  m_UlNgUUpTnlInformation =
      std::make_optional<UpTransportLayerInformation>(ulNgUUpTnlInformation);
}
//------------------------------------------------------------------------------
void PduSessionResourceModifyResponseTransfer::getUlNgUUpTnlInformation(
    std::optional<UpTransportLayerInformation>& ulNgUUpTnlInformation) const {
  ulNgUUpTnlInformation = m_UlNgUUpTnlInformation;
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyResponseTransfer::
    setQosFlowAddOrModifyResponseList(
        const std::vector<QosFlowAddOrModifyResponseItem> list) {
  QosFlowAddOrModifyResponseList qosFlowAddOrModifyResponseList = {};
  qosFlowAddOrModifyResponseList.set(list);
  m_QosFlowAddOrModifyResponseList =
      std::make_optional<QosFlowAddOrModifyResponseList>(
          qosFlowAddOrModifyResponseList);
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyResponseTransfer::
    setQosFlowAddOrModifyResponseList(
        const QosFlowAddOrModifyResponseList& list) {
  m_QosFlowAddOrModifyResponseList =
      std::make_optional<QosFlowAddOrModifyResponseList>(list);
}
//------------------------------------------------------------------------------
void PduSessionResourceModifyResponseTransfer::getQosFlowAddOrModifyRequestList(
    std::optional<QosFlowAddOrModifyResponseList>& list) const {
  list = m_QosFlowAddOrModifyResponseList;
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyResponseTransfer::
    setQosFlowFailedToAddOrModifyList(
        const QosFlowListWithCause& qosFlowFailedToAddOrModifyList) {
  m_QosFlowFailedToAddOrModifyList = qosFlowFailedToAddOrModifyList;
}
//------------------------------------------------------------------------------
void PduSessionResourceModifyResponseTransfer::
    getQosFlowFailedToAddOrModifyList(
        std::optional<QosFlowListWithCause>& qosFlowFailedToAddOrModifyList)
        const {
  qosFlowFailedToAddOrModifyList = m_QosFlowFailedToAddOrModifyList;
}

//------------------------------------------------------------------------------
int PduSessionResourceModifyResponseTransfer::encode(
    uint8_t* buf, int bufSize) {
  ngap_utils::print_asn_msg(
      &asn_DEF_Ngap_PDUSessionResourceModifyResponseTransfer, m_Ie);
  asn_enc_rval_t er = aper_encode_to_buffer(
      &asn_DEF_Ngap_PDUSessionResourceModifyResponseTransfer, NULL, m_Ie, buf,
      bufSize);
  oai::logger::logger_common::ngap().debug("er.encoded( %d)", er.encoded);
  // asn_fprint(stderr, er.failed_type, er.structure_ptr);
  return er.encoded;
}

//------------------------------------------------------------------------------
bool PduSessionResourceModifyResponseTransfer::decode(
    uint8_t* buf, int bufSize) {
  asn_dec_rval_t rc = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER,
      &asn_DEF_Ngap_PDUSessionResourceModifyResponseTransfer, (void**) &m_Ie,
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

  // asn_fprint(stderr, &asn_DEF_Ngap_PDUSessionResourceModifyResponseTransfer,
  // m_Ie);

  // Decode DL NG-U UP TNL Information

  if (m_Ie->dL_NGU_UP_TNLInformation) {
    UpTransportLayerInformation dlNgUUpTnlInformation = {};
    if (!dlNgUUpTnlInformation.decode(*m_Ie->dL_NGU_UP_TNLInformation)) {
      oai::logger::logger_common::ngap().error(
          "Failure to decode DL NG-U UP TNL Information IE");
      return false;
    }
    m_DlNgUUpTnlInformation =
        std::make_optional<UpTransportLayerInformation>(dlNgUUpTnlInformation);
  }

  // Decode UL NG-U UP TNL Information
  if (m_Ie->uL_NGU_UP_TNLInformation) {
    UpTransportLayerInformation ulNgUUpTnlInformation = {};
    if (!ulNgUUpTnlInformation.decode(*m_Ie->uL_NGU_UP_TNLInformation)) {
      oai::logger::logger_common::ngap().error(
          "Failure to decode UL NG-U UP TNL Information IE");
      return false;
    }
    m_UlNgUUpTnlInformation =
        std::make_optional<UpTransportLayerInformation>(ulNgUUpTnlInformation);
  }

  // Decode QoS Flow Add or Modify Response List
  if (m_Ie->qosFlowAddOrModifyResponseList) {
    QosFlowAddOrModifyResponseList qosFlowAddOrModifyResponseList = {};
    if (!qosFlowAddOrModifyResponseList.decode(
            *m_Ie->qosFlowAddOrModifyResponseList)) {
      oai::logger::logger_common::ngap().error(
          "Failure to decode QoS Flow Add or Modify Response List IE");
      return false;
    }
    m_QosFlowAddOrModifyResponseList =
        std::make_optional<QosFlowAddOrModifyResponseList>(
            qosFlowAddOrModifyResponseList);
  }

  // Decode QoS Flow Failed to Add or Modify List
  if (m_Ie->qosFlowFailedToAddOrModifyList) {
    QosFlowListWithCause qosFlowFailedToAddOrModifyList = {};
    if (!qosFlowFailedToAddOrModifyList.decode(
            *m_Ie->qosFlowFailedToAddOrModifyList)) {
      oai::logger::logger_common::ngap().error(
          "Failure to decode QoS Flow Failed to Add or Modify List IE");
      return false;
    }
    m_QosFlowFailedToAddOrModifyList = std::make_optional<QosFlowListWithCause>(
        qosFlowFailedToAddOrModifyList);
  }

  return true;
}

}  // namespace oai::ngap
