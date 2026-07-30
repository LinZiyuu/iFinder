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

class PduSessionResourceSetupRequestTransfer {
 public:
  PduSessionResourceSetupRequestTransfer();
  virtual ~PduSessionResourceSetupRequestTransfer(){};

  // PDU Session Aggregate Maximum Bit Rate (optional)
  bool setPduSessionAggregateMaximumBitRate(
      const long& bitRateDl, const long& bitRateUl);
  bool setPduSessionAggregateMaximumBitRate(
      const PduSessionAggregateMaximumBitRate& maxBitRate);
  void getPduSessionAggregateMaximumBitRate(
      std::optional<PduSessionAggregateMaximumBitRate>& maxBitRate) const;

  // UL NG-U UP TNL Information (Mandatory)
  bool setUlNgUUpTnlInformation(const GtpTunnel& upTnlInfo);
  bool setUlNgUUpTnlInformation(const UpTransportLayerInformation& upTnlInfo);
  bool getUlNgUUpTnlInformation(GtpTunnel& upTnlInfo) const;

  // TODO: Additional UL NG-U UP TNL Information (Optional)

  // Data Forwarding Not Possible (Optional)
  bool setDataForwardingNotPossible();
  bool getDataForwardingNotPossible() const;

  // PDU Session Type (Mandatory)
  bool setPduSessionType(e_Ngap_PDUSessionType type);
  bool getPduSessionType(long& type) const;

  // Security Indication (Optional)
  bool setSecurityIndication(
      e_Ngap_IntegrityProtectionIndication integrityProtectionIndication,
      e_Ngap_ConfidentialityProtectionIndication
          confidentialityProtectionIndication,
      e_Ngap_MaximumIntegrityProtectedDataRate maxIntProtDataRate);
  bool setSecurityIndication(
      e_Ngap_IntegrityProtectionIndication integrityProtectionIndication,
      e_Ngap_ConfidentialityProtectionIndication
          confidentialityProtectionIndication);
  bool setSecurityIndication(const SecurityIndication& securityIndication);
  bool getSecurityIndication(
      long& integrityProtectionIndication,
      long& confidentialityProtectionIndication,
      long& maxIntProtDataRate) const;
  void getSecurityIndication(
      std::optional<SecurityIndication>& securityIndication) const;

  // Network Instance (Optional)
  bool setNetworkInstance(const long& value);
  bool getNetworkInstance(long& value) const;
  void getNetworkInstance(
      std::optional<NetworkInstance>& networkInstance) const;

  // QoS Flow Setup Request List (Mandatory 1..)
  bool setQosFlowSetupRequestList(std::vector<QosFlowSetupReq_t> list);
  bool getQosFlowSetupRequestList(std::vector<QosFlowSetupReq_t>& list) const;
  bool setQosFlowSetupRequestList(const QosFlowSetupRequestList& list);
  void getQosFlowSetupRequestList(QosFlowSetupRequestList& list) const;

  // TODO: Common Network Instance
  // TODO: Direct Forwarding Path Availability

  int encode(uint8_t* buf, int bufSize);
  void encode2NewBuffer(uint8_t*& buf, int& encoded_size);
  bool decode(uint8_t* buf, int bufSize);

 private:
  Ngap_PDUSessionResourceSetupRequestTransfer_t* m_Ie;

  // PDU Session Aggregate Maximum Bit Rate (optional)
  std::optional<PduSessionAggregateMaximumBitRate>
      m_PduSessionAggregateMaximumBitRateIe;
  // UL NG-U UP TNL Information (Mandatory)
  UpTransportLayerInformation m_UlNgUUpTnlInformation;
  // Additional UL NG-U UP TNL Information (Optional)
  std::vector<UpTransportLayerInformation> m_UpTransportLayerInformationList;
  // Data Forwarding Not Possible (Optional)
  std::optional<DataForwardingNotPossible> m_DataForwardingNotPossible;
  // PDU Session Type (Mandatory)
  PduSessionType m_PduSessionType;
  // Security Indication (Optional)
  std::optional<SecurityIndication> m_SecurityIndication;
  // Network Instance (Optional)
  std::optional<NetworkInstance> m_NetworkInstance;
  // QoS Flow Setup Request List (Mandatory 1..)
  QosFlowSetupRequestList m_QosFlowSetupRequestList;
  // TODO: Common Network Instance
  // TODO: Direct Forwarding Path Availability

  bool addUlNgUUpTnlInformation();
  bool addPduSessionAggregateMaximumBitRate();
  bool addSecurityIndication();
  bool addQosFlowSetupRequestList();
};

}  // namespace oai::ngap
#endif
