/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "PduSessionResourceSetupResponseTransfer.hpp"

#include "logger_base.hpp"
#include "ngap_utils.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
PduSessionResourceSetupResponseTransfer::
    PduSessionResourceSetupResponseTransfer() {
  m_Ie = (Ngap_PDUSessionResourceSetupResponseTransfer_t*) calloc(
      1, sizeof(Ngap_PDUSessionResourceSetupResponseTransfer_t));
  m_AdditionalDlQosFlowPerTnlInformation = std::nullopt;
  m_SecurityResult                       = std::nullopt;
}

//------------------------------------------------------------------------------
PduSessionResourceSetupResponseTransfer::
    ~PduSessionResourceSetupResponseTransfer() {}

//------------------------------------------------------------------------------
void PduSessionResourceSetupResponseTransfer::setDlQosFlowPerTnlInformation(
    const QosFlowPerTnlInformation& qosFlowPerTnlInformation) {
  m_DlQosFlowPerTnlInformation = qosFlowPerTnlInformation;

  int ret =
      m_DlQosFlowPerTnlInformation.encode(m_Ie->dLQosFlowPerTNLInformation);
  if (!ret) {
    oai::logger::logger_common::ngap().error(
        "Encode DLQoSFlowPerTNLInformation IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PduSessionResourceSetupResponseTransfer::getDlQosFlowPerTnlInformation(
    QosFlowPerTnlInformation& qosFlowPerTnlInformation) const {
  qosFlowPerTnlInformation = m_DlQosFlowPerTnlInformation;
}

//------------------------------------------------------------------------------
void PduSessionResourceSetupResponseTransfer::setDlQosFlowPerTnlInformation(
    const GtpTunnel& upTransportLayerInfo,
    const std::vector<AssociatedQosFlow_t>& list) {
  UpTransportLayerInformation upTransportLayerInformation = {};
  upTransportLayerInformation.set(upTransportLayerInfo);

  AssociatedQosFlowList associatedQosFlowList = {};
  std::vector<AssociatedQosFlowItem> flowItemVector;
  for (int i = 0; i < list.size(); i++) {
    QosFlowIdentifier qosFlowIdentifier = {};
    qosFlowIdentifier.set(list[i].qosFlowIdentifier);
    AssociatedQosFlowItem item = {};
    if (list[i].qosFlowMappingIndication) {
      item.set(*list[i].qosFlowMappingIndication, qosFlowIdentifier);
    } else {
      item.set(qosFlowIdentifier);
    }
    flowItemVector.push_back(item);
  }
  associatedQosFlowList.set(flowItemVector);

  m_DlQosFlowPerTnlInformation.set(
      upTransportLayerInformation, associatedQosFlowList);

  int ret =
      m_DlQosFlowPerTnlInformation.encode(m_Ie->dLQosFlowPerTNLInformation);
  if (!ret) {
    oai::logger::logger_common::ngap().error(
        "Encode DLQoSFlowPerTNLInformation IE error");
    return;
  }
}

//------------------------------------------------------------------------------
void PduSessionResourceSetupResponseTransfer::getDlQosFlowPerTnlInformation(
    GtpTunnel& upTransportLayerInfo,
    std::vector<AssociatedQosFlow_t>& list) const {
  UpTransportLayerInformation upTransportLayerInformation = {};
  AssociatedQosFlowList associatedQosFlowList             = {};
  m_DlQosFlowPerTnlInformation.get(
      upTransportLayerInformation, associatedQosFlowList);

  std::optional<GtpTunnel> upTransportLayerInfo_opt = std::nullopt;
  upTransportLayerInformation.get(upTransportLayerInfo_opt);
  if (upTransportLayerInfo_opt.has_value())
    upTransportLayerInfo = upTransportLayerInfo_opt.value();

  std::vector<AssociatedQosFlowItem> vector_associated_qos_flow_item;
  associatedQosFlowList.get(vector_associated_qos_flow_item);
  for (int i = 0; i < vector_associated_qos_flow_item.size(); i++) {
    AssociatedQosFlow_t AssociatedQosFlow_str;
    long m_qosFlowMappingIndication;
    QosFlowIdentifier qosFlowIdentifier = {};
    vector_associated_qos_flow_item[i].get(
        m_qosFlowMappingIndication, qosFlowIdentifier);
    qosFlowIdentifier.get(AssociatedQosFlow_str.qosFlowIdentifier);
    if (m_qosFlowMappingIndication < 0) {
      AssociatedQosFlow_str.qosFlowMappingIndication = nullptr;
    } else {
      AssociatedQosFlow_str.qosFlowMappingIndication =
          (e_Ngap_AssociatedQosFlowItem__qosFlowMappingIndication*) calloc(
              1,
              sizeof(e_Ngap_AssociatedQosFlowItem__qosFlowMappingIndication));
      *AssociatedQosFlow_str.qosFlowMappingIndication =
          (e_Ngap_AssociatedQosFlowItem__qosFlowMappingIndication)
              m_qosFlowMappingIndication;
    }

    list.push_back(AssociatedQosFlow_str);
  }
}

//------------------------------------------------------------------------------
void PduSessionResourceSetupResponseTransfer::
    setAdditionalDLQoSFlowPerTNLInformation(
        const QosFlowPerTnlInformationList&
            additionDlQoSFlowPerTnlInformation) {
  /*  UpTransportLayerInformation upTransportLayerInformation = {};

    TransportLayerAddress transportLayerAddress = {};
    GtpTeid gtpTeid                              = {};
    transportLayerAddress.set(
        upTransportLayerInfo.ipAddress);
    gtpTeid.set(upTransportLayerInfo.gtpTeid);
    upTransportLayerInformation.set(
        transportLayerAddress, gtpTeid);

    AssociatedQosFlowList associatedQosFlowList = {};
    std::vector<AssociatedQosFlowItem> vector_associated_qos_flow_item;
    for (int i = 0; i < list.size(); i++) {
      AssociatedQosFlowItem item            = {};
      QosFlowIdentifier qosFlowIdentifier = {};
      qosFlowIdentifier.set(list[i].qosFlowIdentifier);
      if (list[i].qosFlowMappingIndication) {
        item.set(
            *list[i].qosFlowMappingIndication, qosFlowIdentifier);
      } else {
        item.set(qosFlowIdentifier);
      }
      vector_associated_qos_flow_item.push_back(item);
    }
    associatedQosFlowList.set(
        vector_associated_qos_flow_item);

    QosFlowPerTnlInformation additional_qos_flow = {};
    additional_qos_flow.set(
        upTransportLayerInformation, associatedQosFlowList);
    m_AdditionalDlQosFlowPerTnlInformation =
        std::make_optional<QosFlowPerTnlInformationList>(additional_qos_flow);

    Ngap_QosFlowPerTNLInformationList_t* ie =
                (Ngap_QosFlowPerTNLInformationList_t*) calloc(1,
    sizeof(Ngap_QosFlowPerTNLInformationList_t));

    int ret = m_AdditionalDlQosFlowPerTnlInformation.value().encode(ie);
    if (!ret) {
      oai::logger::logger_common::ngap().error(
          "Encode AdditionalDLQoSFlowPerTNLInformation IE error");
      return;
    }
    m_Ie
        ->additionalDLQosFlowPerTNLInformation = ie;
        */
  // TODO
}

//------------------------------------------------------------------------------
bool PduSessionResourceSetupResponseTransfer::
    getAdditionalDLQoSFlowPerTNLInformation(
        QosFlowPerTnlInformationList& additionDlQoSFlowPerTnlInformation)
        const {
  return true;
}

//------------------------------------------------------------------------------
void PduSessionResourceSetupResponseTransfer::setSecurityResult(
    e_Ngap_IntegrityProtectionResult e_integrity_protection_result,
    e_Ngap_ConfidentialityProtectionResult
        e_confidentiality_protection_result) {
  IntegrityProtectionResult integrity_protection_result_tmp = {};
  integrity_protection_result_tmp.set(e_integrity_protection_result);
  ConfidentialityProtectionResult confidentiality_protection_result_tmp = {};
  confidentiality_protection_result_tmp.set(
      e_confidentiality_protection_result);
  SecurityResult security_result = {};
  security_result.set(
      integrity_protection_result_tmp, confidentiality_protection_result_tmp);
  m_SecurityResult = std::make_optional<SecurityResult>(security_result);

  Ngap_SecurityResult_t* ie =
      (Ngap_SecurityResult_t*) calloc(1, sizeof(Ngap_SecurityResult_t));
  int ret = m_SecurityResult.value().encode(*ie);
  if (!ret) {
    oai::logger::logger_common::ngap().error("Encode SecurityResult IE error");
    return;
  }
  m_Ie->securityResult = ie;
}

//------------------------------------------------------------------------------
bool PduSessionResourceSetupResponseTransfer::getSecurityResult(
    long& integrity_protection_result,
    long& confidentialityProtectionResult) const {
  if (!m_SecurityResult.has_value()) return false;

  IntegrityProtectionResult integrity_protection_result_tmp             = {};
  ConfidentialityProtectionResult confidentiality_protection_result_tmp = {};

  m_SecurityResult.value().get(
      integrity_protection_result_tmp, confidentiality_protection_result_tmp);

  integrity_protection_result_tmp.get(integrity_protection_result);
  confidentiality_protection_result_tmp.get(confidentialityProtectionResult);

  return true;
}

//------------------------------------------------------------------------------
int PduSessionResourceSetupResponseTransfer::encode(uint8_t* buf, int bufSize) {
  ngap_utils::print_asn_msg(
      &asn_DEF_Ngap_PDUSessionResourceSetupResponseTransfer, m_Ie);
  asn_enc_rval_t er = aper_encode_to_buffer(
      &asn_DEF_Ngap_PDUSessionResourceSetupResponseTransfer, nullptr, m_Ie, buf,
      bufSize);
  oai::logger::logger_common::ngap().debug("er.encoded %d", er.encoded);
  return er.encoded;
}

//------------------------------------------------------------------------------
// Decapsulation
bool PduSessionResourceSetupResponseTransfer::decode(
    uint8_t* buf, int bufSize) {
  asn_dec_rval_t rc = asn_decode(
      nullptr, ATS_ALIGNED_CANONICAL_PER,
      &asn_DEF_Ngap_PDUSessionResourceSetupResponseTransfer, (void**) &m_Ie,
      buf, bufSize);
  if (rc.code == RC_OK) {
    oai::logger::logger_common::ngap().debug("Decoded successfully");
  } else if (rc.code == RC_WMORE) {
    oai::logger::logger_common::ngap().debug("More data expected, call again");
    return false;
  } else {
    oai::logger::logger_common::ngap().error("Failure to decode data");
    return false;
  }
  oai::logger::logger_common::ngap().debug(
      "rc.consumed to decode %d", rc.consumed);
  // asn_fprint(stderr, &asn_DEF_Ngap_PDUSessionResourceSetupResponseTransfer,
  // m_Ie);

  if (!m_DlQosFlowPerTnlInformation.decode(m_Ie->dLQosFlowPerTNLInformation)) {
    oai::logger::logger_common::ngap().error(
        "Decode NGAP DLQoSFlowPerTNLInformation IE error");
    return false;
  }

  if (m_Ie->additionalDLQosFlowPerTNLInformation) {
    QosFlowPerTnlInformationList additional_qos_flow = {};
    if (!additional_qos_flow.decode(
            *m_Ie->additionalDLQosFlowPerTNLInformation)) {
      oai::logger::logger_common::ngap().error(
          "Decode NGAP AdditionalDLQoSFlowPerTNLInformation IE error");
      return false;
    }
    m_AdditionalDlQosFlowPerTnlInformation =
        std::make_optional<QosFlowPerTnlInformationList>(additional_qos_flow);
  }
  if (m_Ie->securityResult) {
    SecurityResult security_result = {};
    if (!security_result.decode(*m_Ie->securityResult)) {
      oai::logger::logger_common::ngap().error(
          "Decode NGAP SecurityResult IE error");
      return false;
    }
    m_SecurityResult = std::make_optional<SecurityResult>(security_result);
  }

  return true;
}

}  // namespace oai::ngap
