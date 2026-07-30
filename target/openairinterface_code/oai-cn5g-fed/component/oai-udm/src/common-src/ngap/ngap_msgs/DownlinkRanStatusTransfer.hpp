/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _DOWNLINK_RAN_STATUS_TRANSFER_H_
#define _DOWNLINK_RAN_STATUS_TRANSFER_H_

#include "NgapUeMessage.hpp"
#include "RanStatusTransferTransparentContainer.hpp"

extern "C" {
#include "Ngap_RANStatusTransfer-TransparentContainer.h"
}
namespace oai::ngap {
class DownlinkRanStatusTransfer : public NgapUeMessage {
 public:
  DownlinkRanStatusTransfer();
  virtual ~DownlinkRanStatusTransfer();

  void initialize();
  void setAmfUeNgapId(const uint64_t& id) override;
  void setRanUeNgapId(const uint32_t& id) override;
  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  void setRanStatusTransferTransparentContainer(
      const long& drbIDValue, const long& ulPdcpValue,
      const long& ulHfnPdcpValue, const long& dlPdcpValue,
      const long& dlHfnPdcpValue);
  void getRanStatusTransferTransparentContainer(
      long& drbIDValue, long& ulPdcpValue, long& ulHfnPdcpValue,
      long& dlPdcpValue, long& dlHfnPdcpValue) const;

 private:
  Ngap_DownlinkRANStatusTransfer_t* m_DownlinkranstatustransferIes;
  // AMF_UE_NGAP_ID (Mandatory)
  // RAN_UE_NGAP_ID (Mandatory)
  RanStatusTransferTransparentContainer
      m_RanStatusTransferTransparentContainer;  // Mandatory
};
}  // namespace oai::ngap
#endif
