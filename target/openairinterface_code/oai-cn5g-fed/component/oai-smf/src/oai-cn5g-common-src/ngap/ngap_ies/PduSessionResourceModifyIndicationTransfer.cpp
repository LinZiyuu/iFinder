/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceModifyIndicationTransfer.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceModifyIndicationTransfer::
    PduSessionResourceModifyIndicationTransfer() {
  m_Ie = (Ngap_PDUSessionResourceModifyIndicationTransfer_t*) calloc(
      1, sizeof(Ngap_PDUSessionResourceModifyIndicationTransfer_t));
}

//------------------------------------------------------------------------------
PduSessionResourceModifyIndicationTransfer::
    ~PduSessionResourceModifyIndicationTransfer() {}

//------------------------------------------------------------------------------
void PduSessionResourceModifyIndicationTransfer::setDlQosFlowPerTnlInformation(
    const QosFlowPerTnlInformation& dlQosFlowPerTnlInformation) {
  m_DlQosFlowPerTnlInformation = dlQosFlowPerTnlInformation;
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyIndicationTransfer::getDlQosFlowPerTnlInformation(
    QosFlowPerTnlInformation& dlQosFlowPerTnlInformation) const {
  dlQosFlowPerTnlInformation = m_DlQosFlowPerTnlInformation;
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyIndicationTransfer::
    setAdditionalDlQosFlowPerTnlInformation(
        const std::vector<QosFlowPerTnlInformationItem>& list) {
  QosFlowPerTnlInformationList additionalDlQosFlowPerTnlInformation = {};
  additionalDlQosFlowPerTnlInformation.set(list);
  m_AdditionalDlQosFlowPerTnlInformation =
      std::make_optional<QosFlowPerTnlInformationList>(
          additionalDlQosFlowPerTnlInformation);
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyIndicationTransfer::
    setAdditionalDlQosFlowPerTnlInformation(
        const QosFlowPerTnlInformationList& list) {
  m_AdditionalDlQosFlowPerTnlInformation =
      std::make_optional<QosFlowPerTnlInformationList>(list);
}

//------------------------------------------------------------------------------
void PduSessionResourceModifyIndicationTransfer::
    getAdditionalDlQosFlowPerTnlInformation(
        std::optional<QosFlowPerTnlInformationList>& list) const {
  list = m_AdditionalDlQosFlowPerTnlInformation;
}

//------------------------------------------------------------------------------
int PduSessionResourceModifyIndicationTransfer::encode(
    uint8_t* buf, int bufSize) {
  ngap_utils::print_asn_msg(
      &asn_DEF_Ngap_PDUSessionResourceModifyIndicationTransfer, m_Ie);
  asn_enc_rval_t er = aper_encode_to_buffer(
      &asn_DEF_Ngap_PDUSessionResourceModifyIndicationTransfer, NULL, m_Ie, buf,
      bufSize);
  oai::logger::logger_common::ngap().debug("er.encoded( %d)", er.encoded);
  // asn_fprint(stderr, er.failed_type, er.structure_ptr);
  return er.encoded;
}

//------------------------------------------------------------------------------
bool PduSessionResourceModifyIndicationTransfer::decode(
    uint8_t* buf, int bufSize) {
  asn_dec_rval_t rc = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER,
      &asn_DEF_Ngap_PDUSessionResourceModifyIndicationTransfer, (void**) &m_Ie,
      buf, bufSize);
  if (rc.code == RC_OK) {
    oai::logger::logger_common::ngap().debug(
        "Decoded PduSessionResourceModifyIndicationTransfer successfully");
  } else if (rc.code == RC_WMORE) {
    oai::logger::logger_common::ngap().debug("More data expected, call again");
    return false;
  } else {
    oai::logger::logger_common::ngap().debug(
        "Failure to decode PduSessionResourceModifyIndicationTransfer data");
    // return false;
  }
  oai::logger::logger_common::ngap().debug(
      "rc.consumed to decode: %d", rc.consumed);

  if (!m_DlQosFlowPerTnlInformation.decode(m_Ie->dLQosFlowPerTNLInformation)) {
    oai::logger::logger_common::ngap().error(
        "Decode DL QoS Flow per TNL Information IE error");
    return false;
  }

  if (m_Ie->additionalDLQosFlowPerTNLInformation) {
    QosFlowPerTnlInformationList additionalDlQosFlowPerTnlInformation = {};
    if (!additionalDlQosFlowPerTnlInformation.decode(
            *m_Ie->additionalDLQosFlowPerTNLInformation)) {
      oai::logger::logger_common::ngap().error(
          "Decode Additional DL QoS Flow per TNL Information IE error");
      return false;
    }
    m_AdditionalDlQosFlowPerTnlInformation =
        std::make_optional<QosFlowPerTnlInformationList>(
            additionalDlQosFlowPerTnlInformation);
  }

  return true;
}

}  // namespace oai::ngap
