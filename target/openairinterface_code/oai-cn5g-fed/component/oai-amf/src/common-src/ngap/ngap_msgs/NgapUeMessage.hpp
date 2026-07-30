/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NGAP_UE_MESSAGE_H_
#define _NGAP_UE_MESSAGE_H_

#include "AmfUeNgapId.hpp"
#include "NgapMessage.hpp"
#include "RanUeNgapId.hpp"

extern "C" {
#include "Ngap_ProtocolIE-Field.h"
}

namespace oai::ngap {

class NgapUeMessage : public NgapMessage {
 public:
  NgapUeMessage(NgapUeMessage const&) = delete;
  NgapUeMessage();
  virtual ~NgapUeMessage();

  virtual void setAmfUeNgapId(const uint64_t& id) = 0;
  uint64_t getAmfUeNgapId() const;

  virtual void setRanUeNgapId(const uint32_t& id) = 0;
  uint32_t getRanUeNgapId() const;

 protected:
  AmfUeNgapId m_AmfUeNgapId;
  RanUeNgapId m_RanUeNgapId;
};

}  // namespace oai::ngap
#endif
