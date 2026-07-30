/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PathSwitchRequestTransfer.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"
#include "utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PathSwitchRequestTransfer::PathSwitchRequestTransfer() {
  m_Ie = (Ngap_PathSwitchRequestTransfer_t*) calloc(
      1, sizeof(Ngap_PathSwitchRequestTransfer_t));
}

//------------------------------------------------------------------------------
void PathSwitchRequestTransfer::setDlNgUUpTnlInformation(
    const UpTransportLayerInformation& dlNgUUpTnlInformation) {
  m_DlNgUUpTnlInformation = dlNgUUpTnlInformation;
}

//------------------------------------------------------------------------------
void PathSwitchRequestTransfer::getDlNgUUpTnlInformation(
    UpTransportLayerInformation& dlNgUUpTnlInformation) const {
  dlNgUUpTnlInformation = m_DlNgUUpTnlInformation;
}

//------------------------------------------------------------------------------
void PathSwitchRequestTransfer::setQosFlowAcceptedList(
    const std::vector<QosFlowAcceptedItem> list) {
  m_QosFlowAcceptedList.set(list);
}

//------------------------------------------------------------------------------
void PathSwitchRequestTransfer::setQosFlowAcceptedList(
    const QosFlowAcceptedList& list) {
  m_QosFlowAcceptedList = list;
}
//------------------------------------------------------------------------------
void PathSwitchRequestTransfer::getQosFlowAcceptedList(
    QosFlowAcceptedList& list) const {
  list = m_QosFlowAcceptedList;
}

//------------------------------------------------------------------------------
int PathSwitchRequestTransfer::encode(uint8_t* buf, int bufSize) {
  ngap_utils::print_asn_msg(&asn_DEF_Ngap_PathSwitchRequestTransfer, m_Ie);
  asn_enc_rval_t er = aper_encode_to_buffer(
      &asn_DEF_Ngap_PathSwitchRequestTransfer, NULL, m_Ie, buf, bufSize);
  oai::logger::logger_common::ngap().debug("er.encoded( %d)", er.encoded);
  // asn_fprint(stderr, er.failed_type, er.structure_ptr);
  return er.encoded;
}

//------------------------------------------------------------------------------
bool PathSwitchRequestTransfer::decode(uint8_t* buf, int bufSize) {
  asn_dec_rval_t rc = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER, &asn_DEF_Ngap_PathSwitchRequestTransfer,
      (void**) &m_Ie, buf, bufSize);
  if (rc.code == RC_OK) {
    oai::logger::logger_common::ngap().debug("Decoded successfully");
  } else if (rc.code == RC_WMORE) {
    oai::logger::logger_common::ngap().debug("More data expected, call again");
    return false;
  } else {
    oai::logger::logger_common::ngap().debug("Failure to decode data");
    return false;
  }

  // asn_fprint(stderr, &asn_DEF_Ngap_PathSwitchRequestTransfer,
  // m_Ie);

  // Decode DL NG-U UP TNL Information
  if (!m_DlNgUUpTnlInformation.decode(m_Ie->dL_NGU_UP_TNLInformation)) {
    oai::logger::logger_common::ngap().error(
        "Failure to decode DL NG-U UP TNL Information IE");
    return false;
  }

  // Decode QoS Flow Accepted List
  if (!m_QosFlowAcceptedList.decode(m_Ie->qosFlowAcceptedList)) {
    oai::logger::logger_common::ngap().error(
        "Failure to decode  QoS Flow Accepted List IE");
    return false;
  }

  return true;
}

}  // namespace oai::ngap
