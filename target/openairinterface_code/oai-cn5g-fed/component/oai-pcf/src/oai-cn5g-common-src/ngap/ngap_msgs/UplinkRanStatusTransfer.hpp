/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UPLINK_RAN_STATUS_TRANSFER_H_
#define _UPLINK_RAN_STATUS_TRANSFER_H_

#include "NgapUeMessage.hpp"
#include "RanStatusTransferTransparentContainer.hpp"

extern "C" {
#include "Ngap_UplinkRANStatusTransfer.h"
}

namespace oai::ngap {
class UplinkRanStatusTransfer : public NgapUeMessage {
 public:
  UplinkRanStatusTransfer();
  virtual ~UplinkRanStatusTransfer();

  void initialize();

  void setAmfUeNgapId(const uint64_t& id) override;
  void setRanUeNgapId(const uint32_t& id) override;
  bool decode(Ngap_NGAP_PDU_t* ngapMsgPdu) override;

  void getRanStatusTransferTransparentContainer(
      RanStatusTransferTransparentContainer& ranContainer) const;
  void setRanStatusTransferTransparentContainer(
      const RanStatusTransferTransparentContainer& ranContainer);

 private:
  Ngap_UplinkRANStatusTransfer_t* m_UplinkRanStatusTransferIes;
  // AMF_UE_NGAP_ID (Mandatory)
  // RAN_UE_NGAP_ID (Mandatory)
  RanStatusTransferTransparentContainer
      m_RanStatusTransferTransparentContainer;  // Mandatory
};
}  // namespace oai::ngap

#endif
