/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_SETUP_REQUEST_TRANSFER_H_
#define _PDU_SESSION_RESOURCE_SETUP_REQUEST_TRANSFER_H_

#include <vector>

#include "DataForwardingNotPossible.hpp"
#include "NetworkInstance.hpp"
#include "NgapIesStruct.hpp"
#include "PduSessionAggregateMaximumBitRate.hpp"
#include "PduSessionType.hpp"
#include "QosFlowSetupRequestList.hpp"
#include "SecurityIndication.hpp"
#include "UpTransportLayerInformation.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceSetupRequestTransfer.h"
#include "Ngap_ProtocolIE-Field.h"
}

namespace oai::ngap {

class PduSessionResourceSetupRequestTransferIE {
 public:
  PduSessionResourceSetupRequestTransferIE();
  virtual ~PduSessionResourceSetupRequestTransferIE();

  void setPduSessionAggregateMaximumBitRate(
      const long& bitRateDl, const long& bitRateUl);
  bool getPduSessionAggregateMaximumBitRate(
      long& bitRateDl, long& bitRateUl) const;

  void setUlNgUUpTnlInformation(GtpTunnel_t upTnlInfo);
  bool getUlNgUUpTnlInformation(GtpTunnel_t& upTnlInfo) const;

  // void
  // setAdditionalUlNgUUpTnlInformation(std::vector<GtpTunnel>list);
  // bool
  // getAdditionalUlNgUUpTnlInformation(std::vector<GtpTunnel>&list);

  void setDataForwardingNotPossible();
  bool getDataForwardingNotPossible() const;

  void setPduSessionType(e_Ngap_PDUSessionType type);
  bool getPduSessionType(long& type) const;

  void setSecurityIndication(
      e_Ngap_IntegrityProtectionIndication integrity_protection,
      e_Ngap_ConfidentialityProtectionIndication confidentiality_protection,
      e_Ngap_MaximumIntegrityProtectedDataRate maxIntProtDataRate);
  void setSecurityIndication(
      e_Ngap_IntegrityProtectionIndication integrity_protection,
      e_Ngap_ConfidentialityProtectionIndication confidentiality_protection);
  bool getSecurityIndication(
      long& integrity_protection, long& confidentiality_protection,
      long& maxIntProtDataRate) const;

  void setNetworkInstance(const long& value);
  bool getNetworkInstance(long& value) const;

  void setQosFlowSetupRequestList(std::vector<QosFlowSetupReq_t> list);
  bool getQosFlowSetupRequestList(std::vector<QosFlowSetupReq_t>& list) const;

  int encode(uint8_t* buf, int buf_size);   // TODO: remove naked pointer
  bool decode(uint8_t* buf, int buf_size);  // TODO: remove naked pointer

 private:
  Ngap_PDUSessionResourceSetupRequestTransfer_t*
      m_PduSessionResourceSetupRequestTransferIe;

  std::optional<PduSessionAggregateMaximumBitRate>
      m_PduSessionAggregateMaximumBitRateIe;                  // Optional
  UpTransportLayerInformation m_UpTransportLayerInformation;  // Mandatory
  // TODO: Additional UL NG-U UP TNL Information //Optional
  std::optional<DataForwardingNotPossible>
      m_DataForwardingNotPossible;                         // Optional
  PduSessionType m_PduSessionType;                         // Mandatory
  std::optional<SecurityIndication> m_SecurityIndication;  // Optional
  std::optional<NetworkInstance> m_NetworkInstance;        // Optional
  QosFlowSetupRequestList m_QosFlowSetupRequestList;       // Mandatory
  // TODO: Common Network Instance //Optional
  // TODO: Direct Forwarding Path Availability //Optional
};

}  // namespace oai::ngap
#endif
