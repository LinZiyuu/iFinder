/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceHandoverRequestAckTransfer.hpp"

#include "logger.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceHandoverRequestAckTransfer::
    PduSessionResourceHandoverRequestAckTransfer() {
  m_HandoverRequestAcknowledegTransferIe =
      (Ngap_HandoverRequestAcknowledgeTransfer_t*) calloc(
          1, sizeof(Ngap_HandoverRequestAcknowledgeTransfer_t));
}

//------------------------------------------------------------------------------
PduSessionResourceHandoverRequestAckTransfer::
    ~PduSessionResourceHandoverRequestAckTransfer() {}

//------------------------------------------------------------------------------
bool PduSessionResourceHandoverRequestAckTransfer::decode(
    uint8_t* buf, int buf_size) {
  asn_dec_rval_t rc = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER,
      &asn_DEF_Ngap_HandoverRequestAcknowledgeTransfer,
      (void**) &m_HandoverRequestAcknowledegTransferIe, buf, buf_size);
  if (rc.code == RC_OK) {
    Logger::ngap().debug(
        "Decoded handoverRequestAcknowledegTransfer successfully");
  } else if (rc.code == RC_WMORE) {
    Logger::ngap().debug("More data expected, call again");
    return false;
  } else {
    Logger::ngap().debug(
        "Failure to decode handoverRequestAcknowledegTransfer data");
    // return false;
  }
  Logger::ngap().debug("rc.consumed to decode: %d", rc.consumed);

  if (!m_DlForwardingUpTnlInformation.decode(
          *m_HandoverRequestAcknowledegTransferIe
               ->dLForwardingUP_TNLInformation)) {
    Logger::ngap().error("Decode NGAP DL_NGU_UP_TNLInformation IE error");
    return false;
  }

  if (!m_QosFlowSetupResponseList.decode(
          m_HandoverRequestAcknowledegTransferIe->qosFlowSetupResponseList)) {
    Logger::ngap().error("Decode NGAP QosFlowSetupResponseList IE error");
    return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceHandoverRequestAckTransfer::
    getUpTransportLayerInformation2(GtpTunnel_t*& upTnlInfo) {
  if (!m_DlForwardingUpTnlInformation.decode(
          *m_HandoverRequestAcknowledegTransferIe
               ->dLForwardingUP_TNLInformation))
    return false;
  TransportLayerAddress m_transportLayerAddress = {};
  GtpTeid m_gtpTeid                             = {};
  if (!m_DlForwardingUpTnlInformation.get(m_transportLayerAddress, m_gtpTeid))
    return false;
  if (!m_transportLayerAddress.get(upTnlInfo->ipAddress)) return false;
  if (!m_gtpTeid.get(upTnlInfo->gtpTeid)) return false;
  return true;
}

//------------------------------------------------------------------------------
bool PduSessionResourceHandoverRequestAckTransfer::getQosFlowSetupResponseList(
    std::vector<QosFlowLItemWithDataForwarding_t>& list) const {
  std::vector<QosFlowItemWithDataForWarding> m_qosflowitemwithdataforwarding;
  m_QosFlowSetupResponseList.get(m_qosflowitemwithdataforwarding);
  for (int i = 0; i < m_qosflowitemwithdataforwarding.size(); i++) {
    QosFlowLItemWithDataForwarding_t item;
    m_qosflowitemwithdataforwarding[i].getQosFlowIdentifier(
        item.qosFlowIdentifier);
    list.push_back(item);
  }
  return true;
}
}  // namespace oai::ngap
