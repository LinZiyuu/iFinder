/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_RELEASED_ITEM_REL_RES_H_
#define _PDU_SESSION_RESOURCE_RELEASED_ITEM_REL_RES_H_

#include "PduSessionId.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceReleasedItemRelRes.h"
}

namespace oai::ngap {

class PduSessionResourceReleasedItemRelRes {
 public:
  PduSessionResourceReleasedItemRelRes();
  virtual ~PduSessionResourceReleasedItemRelRes();

  void set(
      const PduSessionId& pduSessionId,
      const OCTET_STRING_t& pduSessionResourceReleaseResponseTransfer);

  void get(
      PduSessionId& pduSessionId,
      OCTET_STRING_t& pduSessionResourceReleaseResponseTransfer) const;

  bool encode(Ngap_PDUSessionResourceReleasedItemRelRes_t&
                  pduSessionResourceItem) const;
  bool decode(const Ngap_PDUSessionResourceReleasedItemRelRes_t&
                  pduSessionResourceItem);

 private:
  PduSessionId m_PduSessionId;
  OCTET_STRING_t m_PduSessionResourceReleaseResponseTransfer;
};

}  // namespace oai::ngap

#endif
