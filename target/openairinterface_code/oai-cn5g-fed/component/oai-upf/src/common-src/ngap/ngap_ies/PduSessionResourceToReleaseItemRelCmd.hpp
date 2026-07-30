/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_TO_RELEASE_ITEM_REL_CMD_H_
#define _PDU_SESSION_RESOURCE_TO_RELEASE_ITEM_REL_CMD_H_

#include "PduSessionId.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceToReleaseItemRelCmd.h"
}

namespace oai::ngap {

class PduSessionResourceToReleaseItemRelCmd {
 public:
  PduSessionResourceToReleaseItemRelCmd();
  virtual ~PduSessionResourceToReleaseItemRelCmd();

  void set(
      const PduSessionId& pduSessionId,
      const OCTET_STRING_t& pduSessionResourceReleaseCommandTransfer);
  void get(
      PduSessionId& pduSessionId,
      OCTET_STRING_t& pduSessionResourceReleaseCommandTransfer) const;

  bool encode(Ngap_PDUSessionResourceToReleaseItemRelCmd_t&
                  pduSessionResourceItem) const;
  bool decode(const Ngap_PDUSessionResourceToReleaseItemRelCmd_t&
                  pduSessionResourceItem);

 private:
  PduSessionId m_PduSessionId;                                // Mandatory
  OCTET_STRING_t m_PduSessionResourceReleaseCommandTransfer;  // Mandatory
};

}  // namespace oai::ngap

#endif
