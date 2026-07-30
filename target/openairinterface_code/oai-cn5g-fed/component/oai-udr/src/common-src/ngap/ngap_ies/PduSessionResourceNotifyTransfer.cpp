/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceNotifyTransfer.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceNotifyTransfer::PduSessionResourceNotifyTransfer() {
  m_Ie = (Ngap_PDUSessionResourceNotifyTransfer_t*) calloc(
      1, sizeof(Ngap_PDUSessionResourceNotifyTransfer_t));
  m_QosFlowNotifyList   = std::nullopt;
  m_QosFlowReleasedList = std::nullopt;
  m_QosFlowFeedbackList = std::nullopt;
}

//------------------------------------------------------------------------------
void PduSessionResourceNotifyTransfer::setQosFlowNotifyList(
    const std::vector<QosFlowNotifyItem> list) {
  QosFlowNotifyList qosFlowNotifyList = {};
  qosFlowNotifyList.set(list);
  m_QosFlowNotifyList =
      std::make_optional<QosFlowNotifyList>(qosFlowNotifyList);
}

//------------------------------------------------------------------------------
void PduSessionResourceNotifyTransfer::setQosFlowNotifyList(
    const QosFlowNotifyList& list) {
  m_QosFlowNotifyList = std::make_optional<QosFlowNotifyList>(list);
}

//------------------------------------------------------------------------------
void PduSessionResourceNotifyTransfer::getQosFlowNotifyList(
    std::optional<QosFlowNotifyList>& list) const {
  list = m_QosFlowNotifyList;
}

//------------------------------------------------------------------------------
void PduSessionResourceNotifyTransfer::setQosFlowReleasedList(
    const std::vector<QosFlowWithCauseItem> list) {
  QosFlowListWithCause qosFlowReleasedList = {};
  qosFlowReleasedList.set(list);
  m_QosFlowReleasedList =
      std::make_optional<QosFlowListWithCause>(qosFlowReleasedList);
}

//------------------------------------------------------------------------------
void PduSessionResourceNotifyTransfer::setQosFlowReleasedList(
    const QosFlowListWithCause& list) {
  m_QosFlowReleasedList = std::make_optional<QosFlowListWithCause>(list);
}

//------------------------------------------------------------------------------
void PduSessionResourceNotifyTransfer::getQosFlowReleasedList(
    std::optional<QosFlowListWithCause>& list) const {
  list = m_QosFlowReleasedList;
}

//------------------------------------------------------------------------------
void PduSessionResourceNotifyTransfer::setQosFlowFeedbackList(
    const std::vector<QosFlowFeedbackItem> list) {
  QosFlowFeedbackList qosFlowFeedbackList = {};
  qosFlowFeedbackList.set(list);
  m_QosFlowFeedbackList =
      std::make_optional<QosFlowFeedbackList>(qosFlowFeedbackList);
}

//------------------------------------------------------------------------------
void PduSessionResourceNotifyTransfer::setQosFlowFeedbackList(
    const QosFlowFeedbackList& list) {
  m_QosFlowFeedbackList = std::make_optional<QosFlowFeedbackList>(list);
}
//------------------------------------------------------------------------------
void PduSessionResourceNotifyTransfer::getQosFlowFeedbackList(
    std::optional<QosFlowFeedbackList>& list) const {
  list = m_QosFlowFeedbackList;
}

//------------------------------------------------------------------------------
int PduSessionResourceNotifyTransfer::encode(uint8_t* buf, int bufSize) {
  ngap_utils::print_asn_msg(
      &asn_DEF_Ngap_PDUSessionResourceNotifyTransfer, m_Ie);
  asn_enc_rval_t er = aper_encode_to_buffer(
      &asn_DEF_Ngap_PDUSessionResourceNotifyTransfer, NULL, m_Ie, buf, bufSize);
  oai::logger::logger_common::ngap().debug("er.encoded( %d)", er.encoded);
  // asn_fprint(stderr, er.failed_type, er.structure_ptr);
  return er.encoded;
}

//------------------------------------------------------------------------------
bool PduSessionResourceNotifyTransfer::decode(uint8_t* buf, int bufSize) {
  asn_dec_rval_t rc = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER,
      &asn_DEF_Ngap_PDUSessionResourceNotifyTransfer, (void**) &m_Ie, buf,
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

  // asn_fprint(stderr, &asn_DEF_Ngap_PDUSessionResourceModifyResponseTransfer,
  // m_Ie);

  // QoS Flow Notify List
  if (m_Ie->qosFlowNotifyList) {
    QosFlowNotifyList qosFlowNotifyList = {};
    if (!qosFlowNotifyList.decode(*m_Ie->qosFlowNotifyList)) {
      oai::logger::logger_common::ngap().error(
          "Failure to decode QoS Flow Notify List IE");
      return false;
    }
    m_QosFlowNotifyList =
        std::make_optional<QosFlowNotifyList>(qosFlowNotifyList);
  }

  // Decode QoS Flow Released List
  if (m_Ie->qosFlowReleasedList) {
    QosFlowListWithCause qosFlowReleasedList = {};

    if (!qosFlowReleasedList.decode(*m_Ie->qosFlowReleasedList)) {
      oai::logger::logger_common::ngap().error(
          "Failure to decode QoS Flow Released List IE");
      return false;
    }
    m_QosFlowReleasedList =
        std::make_optional<QosFlowListWithCause>(qosFlowReleasedList);
  }

  // TODO: Decode QoS Flow Feedback List

  return true;
}

}  // namespace oai::ngap
