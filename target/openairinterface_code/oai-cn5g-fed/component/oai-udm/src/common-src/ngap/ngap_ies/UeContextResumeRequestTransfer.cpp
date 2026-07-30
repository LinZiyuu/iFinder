/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "UeContextResumeRequestTransfer.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
UeContextResumeRequestTransfer::UeContextResumeRequestTransfer() {
  m_UeContextResumeRequestTransferIe =
      (Ngap_UEContextResumeRequestTransfer_t*) calloc(
          1, sizeof(Ngap_UEContextResumeRequestTransfer_t));
}

//------------------------------------------------------------------------------
UeContextResumeRequestTransfer::~UeContextResumeRequestTransfer() {}

//------------------------------------------------------------------------------
void UeContextResumeRequestTransfer::setQosFlowFailedToResumeList(
    const std::vector<QosFlowWithCauseItem> list) {
  QosFlowListWithCause qosFlowFailedToResumeList = {};
  qosFlowFailedToResumeList.set(list);
  m_QosFlowFailedToResumeList =
      std::make_optional<QosFlowListWithCause>(qosFlowFailedToResumeList);
}

//------------------------------------------------------------------------------
void UeContextResumeRequestTransfer::setQosFlowFailedToResumeList(
    const QosFlowListWithCause& list) {
  m_QosFlowFailedToResumeList = std::make_optional<QosFlowListWithCause>(list);
}

//------------------------------------------------------------------------------
void UeContextResumeRequestTransfer::getQosFlowFailedToResumeList(
    std::optional<QosFlowListWithCause>& list) const {
  list = m_QosFlowFailedToResumeList;
}

//------------------------------------------------------------------------------
int UeContextResumeRequestTransfer::encode(uint8_t* buf, int bufSize) {
  ngap_utils::print_asn_msg(
      &asn_DEF_Ngap_UEContextResumeRequestTransfer,
      m_UeContextResumeRequestTransferIe);
  asn_enc_rval_t er = aper_encode_to_buffer(
      &asn_DEF_Ngap_UEContextResumeRequestTransfer, NULL,
      m_UeContextResumeRequestTransferIe, buf, bufSize);
  oai::logger::logger_common::ngap().debug("er.encoded %d", er.encoded);
  return er.encoded;
}

//------------------------------------------------------------------------------
bool UeContextResumeRequestTransfer::decode(uint8_t* buf, int bufSize) {
  asn_dec_rval_t rc = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER,
      &asn_DEF_Ngap_UEContextResumeRequestTransfer,
      (void**) &m_UeContextResumeRequestTransferIe, buf, bufSize);
  if (rc.code == RC_OK) {
    oai::logger::logger_common::ngap().debug(
        "Decoded UeContextResumeRequestTransfer successfully");
  } else if (rc.code == RC_WMORE) {
    oai::logger::logger_common::ngap().debug("More data expected, call again");
    return false;
  } else {
    oai::logger::logger_common::ngap().debug(
        "Failure to decode UeContextResumeRequestTransfer data");
    // return false;
  }
  oai::logger::logger_common::ngap().debug(
      "rc.consumed to decode: %d", rc.consumed);

  if (m_UeContextResumeRequestTransferIe->qosFlowFailedToResumeList) {
    QosFlowListWithCause qosFlowFailedToResumeList = {};

    if (!qosFlowFailedToResumeList.decode(
            *m_UeContextResumeRequestTransferIe->qosFlowFailedToResumeList)) {
      oai::logger::logger_common::ngap().error(
          "Decode NGAP  QoS Flow Failed to Resume List IE error");
      return false;
    }
    m_QosFlowFailedToResumeList =
        std::make_optional<QosFlowListWithCause>(qosFlowFailedToResumeList);
  }

  return true;
}

}  // namespace oai::ngap
