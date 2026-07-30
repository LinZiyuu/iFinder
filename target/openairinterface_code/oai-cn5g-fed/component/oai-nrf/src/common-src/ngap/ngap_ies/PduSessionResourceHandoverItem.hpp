/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_HANDOVER_ITEM_H_
#define _PDU_SESSION_RESOURCE_HANDOVER_ITEM_H_

#include "PduSessionId.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceHandoverItem.h"
}

namespace oai::ngap {

class PduSessionResourceHandoverItem {
 public:
  PduSessionResourceHandoverItem();
  virtual ~PduSessionResourceHandoverItem();

  void set(
      const PduSessionId& sessionId, const OCTET_STRING_t& commandTransfer);
  void get(PduSessionId& sessionId, OCTET_STRING_t& commandTransfer) const;

  bool encode(Ngap_PDUSessionResourceHandoverItem_t& item) const;
  bool decode(const Ngap_PDUSessionResourceHandoverItem_t& item);

 private:
  PduSessionId m_PduSessionId;               // Mandatory
  OCTET_STRING_t m_HandoverCommandTransfer;  // Mandatory
};

}  // namespace oai::ngap

#endif
