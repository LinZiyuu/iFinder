/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "HandoverRequestAcknowledgeTransfer.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
HandoverRequestAcknowledgeTransfer::HandoverRequestAcknowledgeTransfer() {
  m_HandoverRequestAcknowledegTransferIe =
      (Ngap_HandoverRequestAcknowledgeTransfer_t*) calloc(
          1, sizeof(Ngap_HandoverRequestAcknowledgeTransfer_t));
}

//------------------------------------------------------------------------------
HandoverRequestAcknowledgeTransfer::~HandoverRequestAcknowledgeTransfer() {}

//------------------------------------------------------------------------------
void HandoverRequestAcknowledgeTransfer::setDlNgUUpTnlInformation(
    const UpTransportLayerInformation& dlNgUUpTnlInformation) {
  m_DlNgUUpTnlInformation = dlNgUUpTnlInformation;
}

//------------------------------------------------------------------------------
void HandoverRequestAcknowledgeTransfer::getDlNgUUpTnlInformation(
    UpTransportLayerInformation& dlNgUUpTnlInformation) const {
  dlNgUUpTnlInformation = m_DlNgUUpTnlInformation;
}

//------------------------------------------------------------------------------
void HandoverRequestAcknowledgeTransfer::setDlForwardingUpTnlInformation(
    const UpTransportLayerInformation& dlForwardingUpTnlInformation) {
  m_DlForwardingUpTnlInformation =
      std::make_optional<UpTransportLayerInformation>(
          dlForwardingUpTnlInformation);
}
//------------------------------------------------------------------------------
void HandoverRequestAcknowledgeTransfer::getDlForwardingUpTnlInformation(
    std::optional<UpTransportLayerInformation>& dlForwardingUpTnlInformation)
    const {
  dlForwardingUpTnlInformation = m_DlForwardingUpTnlInformation;
}

//------------------------------------------------------------------------------
void HandoverRequestAcknowledgeTransfer::setQosFlowSetupResponseList(
    const std::vector<QosFlowItemWithDataForwarding>& list) {
  m_QosFlowSetupResponseList.set(list);
}

//------------------------------------------------------------------------------
void HandoverRequestAcknowledgeTransfer::setQosFlowSetupResponseList(
    const QosFlowListWithDataForwarding& list) {
  m_QosFlowSetupResponseList = list;
}
//------------------------------------------------------------------------------
void HandoverRequestAcknowledgeTransfer::getQosFlowSetupResponseList(
    std::vector<QosFlowItemWithDataForwarding>& list) const {
  m_QosFlowSetupResponseList.get(list);
}
//------------------------------------------------------------------------------
void HandoverRequestAcknowledgeTransfer::getQosFlowSetupResponseList(
    QosFlowListWithDataForwarding& list) const {
  list = m_QosFlowSetupResponseList;
}

//------------------------------------------------------------------------------
int HandoverRequestAcknowledgeTransfer::encode(uint8_t* buf, int bufSize) {
  ngap_utils::print_asn_msg(
      &asn_DEF_Ngap_HandoverRequestAcknowledgeTransfer,
      m_HandoverRequestAcknowledegTransferIe);
  asn_enc_rval_t er = aper_encode_to_buffer(
      &asn_DEF_Ngap_HandoverRequestAcknowledgeTransfer, NULL,
      m_HandoverRequestAcknowledegTransferIe, buf, bufSize);
  oai::logger::logger_common::ngap().debug("er.encoded %d", er.encoded);
  return er.encoded;
}

//------------------------------------------------------------------------------
bool HandoverRequestAcknowledgeTransfer::decode(uint8_t* buf, int bufSize) {
  asn_dec_rval_t rc = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER,
      &asn_DEF_Ngap_HandoverRequestAcknowledgeTransfer,
      (void**) &m_HandoverRequestAcknowledegTransferIe, buf, bufSize);
  if (rc.code == RC_OK) {
    oai::logger::logger_common::ngap().debug(
        "Decoded handoverRequestAcknowledegTransfer successfully");
  } else if (rc.code == RC_WMORE) {
    oai::logger::logger_common::ngap().debug("More data expected, call again");
    return false;
  } else {
    oai::logger::logger_common::ngap().debug(
        "Failure to decode handoverRequestAcknowledegTransfer data");
    // return false;
  }
  oai::logger::logger_common::ngap().debug(
      "rc.consumed to decode: %d", rc.consumed);

  if (!m_DlNgUUpTnlInformation.decode(
          m_HandoverRequestAcknowledegTransferIe->dL_NGU_UP_TNLInformation)) {
    oai::logger::logger_common::ngap().error(
        "Decode NGAP DL NG-U UP TNL Information IE error");
    return false;
  }

  if (m_HandoverRequestAcknowledegTransferIe->dLForwardingUP_TNLInformation) {
    UpTransportLayerInformation dlForwardingUpTnlInformation = {};

    if (!dlForwardingUpTnlInformation.decode(
            *m_HandoverRequestAcknowledegTransferIe
                 ->dLForwardingUP_TNLInformation)) {
      oai::logger::logger_common::ngap().error(
          "Decode NGAP  DL Forwarding UP TNL Information IE error");
      return false;
    }
    m_DlForwardingUpTnlInformation =
        std::make_optional<UpTransportLayerInformation>(
            dlForwardingUpTnlInformation);
  }

  if (!m_QosFlowSetupResponseList.decode(
          m_HandoverRequestAcknowledegTransferIe->qosFlowSetupResponseList)) {
    oai::logger::logger_common::ngap().error(
        "Decode NGAP QosFlowSetupResponseList IE error");
    return false;
  }
  return true;
}

}  // namespace oai::ngap
