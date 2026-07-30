/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "HandoverCommandTransfer.hpp"

#include <vector>

#include "logger_base.hpp"
#include "ngap_utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
HandoverCommandTransfer::HandoverCommandTransfer() {
  m_Ie = (Ngap_HandoverCommandTransfer_t*) calloc(
      1, sizeof(Ngap_HandoverCommandTransfer_t));
  m_DlForwardingUpTnlInformation = std::nullopt;
  m_QosFlowToBeForwardedList     = std::nullopt;
}

//------------------------------------------------------------------------------
HandoverCommandTransfer::~HandoverCommandTransfer() {}

//------------------------------------------------------------------------------
void HandoverCommandTransfer::setDlForwardingUpTnlInformation(
    const GtpTunnel& upTransportLayerInfo) {
  UpTransportLayerInformation tmp = {};
  tmp.set(upTransportLayerInfo);
  m_DlForwardingUpTnlInformation =
      std::make_optional<UpTransportLayerInformation>(tmp);

  m_Ie->dLForwardingUP_TNLInformation =
      (Ngap_UPTransportLayerInformation*) calloc(
          1, sizeof(Ngap_UPTransportLayerInformation));
  int ret = m_DlForwardingUpTnlInformation.value().encode(
      *m_Ie->dLForwardingUP_TNLInformation);
  if (!ret) {
    oai::logger::logger_common::ngap().debug(
        "Encode dLForwardingUP_TNLInformation IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void HandoverCommandTransfer::setDlForwardingUpTnlInformation(
    const UpTransportLayerInformation& dlForwardingUpTnlInformation) {
  m_DlForwardingUpTnlInformation =
      std::make_optional<UpTransportLayerInformation>(
          dlForwardingUpTnlInformation);
}
//------------------------------------------------------------------------------
void HandoverCommandTransfer::getDlForwardingUpTnlInformation(
    std::optional<UpTransportLayerInformation>& dlForwardingUpTnlInformation)
    const {
  dlForwardingUpTnlInformation = m_DlForwardingUpTnlInformation;
}

//------------------------------------------------------------------------------
void HandoverCommandTransfer::setQosFlowToBeForwardedList(
    const std::vector<QosFlowToBeForwardedItem_t>& list) {
  QosFlowToBeForwardedList qosList = {};

  std::vector<QosFlowToBeForwardedItem> item_list;

  for (int i = 0; i < list.size(); i++) {
    QosFlowIdentifier qfi             = {};
    QosFlowToBeForwardedItem qos_item = {};
    qfi.set(list[i].qfi);

    qos_item.setQosFlowIdentifier(qfi);
    item_list.push_back(qos_item);
  }

  qosList.set(item_list);
  m_QosFlowToBeForwardedList =
      std::make_optional<QosFlowToBeForwardedList>(qosList);
  int ret =
      m_QosFlowToBeForwardedList.value().encode(m_Ie->qosFlowToBeForwardedList);
  oai::logger::logger_common::ngap().debug(
      "Number of QoS flows in the list %d",
      m_Ie->qosFlowToBeForwardedList->list.count);
  if (m_Ie->qosFlowToBeForwardedList->list.array) {
    if (m_Ie->qosFlowToBeForwardedList->list.array[0]) {
      oai::logger::logger_common::ngap().debug(
          "QFI in the list %d",
          m_Ie->qosFlowToBeForwardedList->list.array[0]->qosFlowIdentifier);
    }
  }

  if (!ret) {
    oai::logger::logger_common::ngap().debug(
        "Encode QosFlowToBeForwardedList IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void HandoverCommandTransfer::setQosFlowToBeForwardedList(
    const std::vector<QosFlowToBeForwardedItem> list) {
  QosFlowToBeForwardedList qosFlowToBeForwardedList = {};
  qosFlowToBeForwardedList.set(list);
  m_QosFlowToBeForwardedList =
      std::make_optional<QosFlowToBeForwardedList>(qosFlowToBeForwardedList);
}

//------------------------------------------------------------------------------
void HandoverCommandTransfer::setQosFlowToBeForwardedList(
    const QosFlowToBeForwardedList& list) {
  m_QosFlowToBeForwardedList =
      std::make_optional<QosFlowToBeForwardedList>(list);
}

//------------------------------------------------------------------------------
void HandoverCommandTransfer::getQosFlowToBeForwardedList(
    std::optional<QosFlowToBeForwardedList>& list) const {
  list = m_QosFlowToBeForwardedList;
}

//------------------------------------------------------------------------------
int HandoverCommandTransfer::encode(uint8_t* buf, int bufSize) const {
  ngap_utils::print_asn_msg(&asn_DEF_Ngap_HandoverCommandTransfer, m_Ie);
  asn_enc_rval_t er = aper_encode_to_buffer(
      &asn_DEF_Ngap_HandoverCommandTransfer, NULL, m_Ie, buf, bufSize);
  oai::logger::logger_common::ngap().debug("er.encoded( %d)", er.encoded);
  return er.encoded;
}

//------------------------------------------------------------------------------
bool HandoverCommandTransfer::decode(uint8_t* buf, int bufSize) {
  asn_dec_rval_t rc = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER, &asn_DEF_Ngap_HandoverCommandTransfer,
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

  // asn_fprint(stderr, &asn_DEF_Ngap_HandoverCommandTransfer,
  // m_Ie);

  // Decode DL Forwarding UP TNL Information
  if (m_Ie->dLForwardingUP_TNLInformation) {
    UpTransportLayerInformation dlForwardingUpTnlInformation = {};
    if (!dlForwardingUpTnlInformation.decode(
            *m_Ie->dLForwardingUP_TNLInformation)) {
      oai::logger::logger_common::ngap().error(
          "Failure to decode  DL Forwarding UP TNL Information IE");
      return false;
    }
    m_DlForwardingUpTnlInformation =
        std::make_optional<UpTransportLayerInformation>(
            dlForwardingUpTnlInformation);
  }

  // Decode QoS Flow to be Forwarded List
  if (m_Ie->qosFlowToBeForwardedList) {
    QosFlowToBeForwardedList qosFlowToBeForwardedList = {};
    if (!qosFlowToBeForwardedList.decode(*m_Ie->qosFlowToBeForwardedList)) {
      oai::logger::logger_common::ngap().error(
          "Failure to decode QoS Flow to be Forwarded List IE");
      return false;
    }
    m_QosFlowToBeForwardedList =
        std::make_optional<QosFlowToBeForwardedList>(qosFlowToBeForwardedList);
  }

  return true;
}

}  // namespace oai::ngap
