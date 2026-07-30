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

class PduSessionResourceSetupResponseTransferIE {
 public:
  PduSessionResourceSetupResponseTransferIE();
  virtual ~PduSessionResourceSetupResponseTransferIE();

  void set(
      const GtpTunnel_t& upTransportLayerInfo,
      const std::vector<AssociatedQosFlow_t>& list);
  bool get(
      GtpTunnel_t& upTransportLayerInfo,
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

  int encode(uint8_t* buf, int buf_size);   // TODO: remove naked pointer
  bool decode(uint8_t* buf, int buf_size);  // TODO: remove naked pointer

 private:
  Ngap_PDUSessionResourceSetupResponseTransfer_t*
      m_PduSessionResourceSetupResponseTransferIe;

  QosFlowPerTnlInformation m_DlQosFlowPerTnlInformation;  // Mandatory
  std::optional<QosFlowPerTnlInformationList>
      m_AdditionalDlQosFlowPerTnlInformation;
  std::optional<SecurityResult> m_SecurityResult;  // Optional
  // TODO: QoS Flow Failed to Setup List
};

}  // namespace oai::ngap
#endif
