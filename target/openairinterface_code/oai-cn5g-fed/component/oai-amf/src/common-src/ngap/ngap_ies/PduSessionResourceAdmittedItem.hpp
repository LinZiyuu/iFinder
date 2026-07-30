/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef PDU_SESSION_RESOURCE_ADMITTED_ITEM_H_
#define PDU_SESSION_RESOURCE_ADMITTED_ITEM_H_

#include "PduSessionId.hpp"
#include "HandoverRequestAcknowledgeTransfer.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceAdmittedItem.h"
}

namespace oai::ngap {

class PduSessionResourceAdmittedItem {
 public:
  PduSessionResourceAdmittedItem();
  virtual ~PduSessionResourceAdmittedItem();

  void set(
      const PduSessionId& pduSessionId,
      const OCTET_STRING_t& handoverRequestAckTransfer);
  void get(
      PduSessionId& pduSessionId,
      OCTET_STRING_t& handoverRequestAckTransfer) const;

  bool encode(Ngap_PDUSessionResourceAdmittedItem_t& pduItem) const;
  bool decode(const Ngap_PDUSessionResourceAdmittedItem_t& pduItem);

 private:
  PduSessionId m_PduSessionId;                  // Mandatory
  OCTET_STRING_t m_HandoverRequestAckTransfer;  // Mandatory
};

}  // namespace oai::ngap

#endif
