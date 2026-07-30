/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_SETUP_RESPONSE_TRANSFER_H_
#define _PDU_SESSION_RESOURCE_SETUP_RESPONSE_TRANSFER_H_

#include "NgapIesStruct.hpp"
#include "QosFlowPerTnlInformationList.hpp"
#include "SecurityResult.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceSetupResponseTransfer.h"
#include "Ngap_ProtocolIE-Field.h"
#include "Ngap_QosFlowPerTNLInformationList.h"
}

namespace oai::ngap {

class PduSessionResourceSetupResponseTransfer {
 public:
  PduSessionResourceSetupResponseTransfer();
  virtual ~PduSessionResourceSetupResponseTransfer();

  void setDlQosFlowPerTnlInformation(
      const QosFlowPerTnlInformation& qosFlowPerTnlInformation);
  void getDlQosFlowPerTnlInformation(
      QosFlowPerTnlInformation& qosFlowPerTnlInformation) const;
  void setDlQosFlowPerTnlInformation(
      const GtpTunnel& upTransportLayerInfo,
      const std::vector<AssociatedQosFlow_t>& list);
  void getDlQosFlowPerTnlInformation(
      GtpTunnel& upTransportLayerInfo,
      std::vector<AssociatedQosFlow_t>& list) const;

  void setAdditionalDLQoSFlowPerTNLInformation(
      const QosFlowPerTnlInformationList& additionDlQoSFlowPerTnlInformation);
  bool getAdditionalDLQoSFlowPerTNLInformation(
      QosFlowPerTnlInformationList& additionDlQoSFlowPerTnlInformation) const;

  void setSecurityResult(
      e_Ngap_IntegrityProtectionResult integrityProtectionResult,
      e_Ngap_ConfidentialityProtectionResult confidentialityProtectionResult);
  bool getSecurityResult(
      long& integrityProtectionResult,
      long& confidentialityProtectionResult) const;

  int encode(uint8_t* buf, int bufSize);
  bool decode(uint8_t* buf, int bufSize);

 private:
  Ngap_PDUSessionResourceSetupResponseTransfer_t* m_Ie;

  QosFlowPerTnlInformation m_DlQosFlowPerTnlInformation;  // Mandatory
  std::optional<QosFlowPerTnlInformationList>
      m_AdditionalDlQosFlowPerTnlInformation;
  std::optional<SecurityResult> m_SecurityResult;  // Optional
  // TODO: Security Result (Optional)
  // TODO: QoS Flow Failed to Setup List (Optional)
};

}  // namespace oai::ngap
#endif
