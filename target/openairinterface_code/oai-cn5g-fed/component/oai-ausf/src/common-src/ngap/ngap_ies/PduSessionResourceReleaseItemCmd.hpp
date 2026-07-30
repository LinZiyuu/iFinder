/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_RELEASE_ITEM_CMD_H_
#define _PDU_SESSION_RESOURCE_RELEASE_ITEM_CMD_H_

#include "NasPdu.hpp"
#include "PduSessionId.hpp"
#include "PduSessionResourceReleaseCommandTransfer.hpp"
#include "SNssai.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceToReleaseItemRelCmd.h"
}

namespace oai::ngap {

class PduSessionResourceReleaseItemCmd {
 public:
  PduSessionResourceReleaseItemCmd();
  virtual ~PduSessionResourceReleaseItemCmd();

  void set(
      const PduSessionId& pduSessionId,
      const OCTET_STRING_t& pduSessionResourceRelease);
  void get(
      PduSessionId& pduSessionId,
      OCTET_STRING_t& pduSessionResourceRelease) const;

  bool encode(Ngap_PDUSessionResourceToReleaseItemRelCmd_t&
                  pduSessionResourceReleaseItem) const;
  bool decode(const Ngap_PDUSessionResourceToReleaseItemRelCmd_t&
                  pduSessionResourceReleaseItem);

 private:
  PduSessionId m_PduSessionId;                                // Mandatory
  OCTET_STRING_t m_PduSessionResourceReleaseCommandTransfer;  // Mandatory
};

}  // namespace oai::ngap

#endif
