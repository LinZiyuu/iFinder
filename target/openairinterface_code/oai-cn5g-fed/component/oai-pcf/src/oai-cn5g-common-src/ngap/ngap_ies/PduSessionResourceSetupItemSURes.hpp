/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_SETUP_ITEM_SU_RES_H_
#define _PDU_SESSION_RESOURCE_SETUP_ITEM_SU_RES_H_

#include "PduSessionId.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceSetupItemSURes.h"
}

namespace oai::ngap {

class PduSessionResourceSetupItemSURes {
 public:
  PduSessionResourceSetupItemSURes();
  virtual ~PduSessionResourceSetupItemSURes();

  void set(
      const PduSessionId& pduSessionId,
      const OCTET_STRING_t& pduSessionResourceSetupResponseTransfer);
  void get(
      PduSessionId& pduSessionId,
      OCTET_STRING_t& pduSessionResourceSetupResponseTransfer) const;

  bool encode(
      Ngap_PDUSessionResourceSetupItemSURes_t& pduSessionResourceItem) const;
  bool decode(
      const Ngap_PDUSessionResourceSetupItemSURes_t& pduSessionResourceItem);

 private:
  PduSessionId m_PduSessionId;                               // Mandatory
  OCTET_STRING_t m_PduSessionResourceSetupResponseTransfer;  // Mandatory
};

}  // namespace oai::ngap

#endif
