/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_ITEM_HO_RQD_H_
#define _PDU_SESSION_RESOURCE_ITEM_HO_RQD_H_

#include "PduSessionId.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceItemHORqd.h"
}

namespace oai::ngap {

class PduSessionResourceItemHoRqd {
 public:
  PduSessionResourceItemHoRqd();
  virtual ~PduSessionResourceItemHoRqd();

  void set(
      const PduSessionId& pduSessionId,
      const OCTET_STRING_t& handoverRequiredTransfer);
  void get(PduSessionId& pduSessionId, OCTET_STRING_t& handoverRequiredTransfer)
      const;

  bool encode(
      Ngap_PDUSessionResourceItemHORqd_t& pduSessionResourceItemHORqd) const;
  bool decode(
      const Ngap_PDUSessionResourceItemHORqd_t& pduSessionResourceItemHORqd);

 private:
  PduSessionId m_PduSessionId;                // Mandatory
  OCTET_STRING_t m_HandoverRequiredTransfer;  // Mandatory
};

}  // namespace oai::ngap

#endif
