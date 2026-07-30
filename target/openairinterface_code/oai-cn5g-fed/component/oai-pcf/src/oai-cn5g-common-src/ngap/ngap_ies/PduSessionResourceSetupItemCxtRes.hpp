/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_SETUP_ITEM_CXT_RES_H_
#define _PDU_SESSION_RESOURCE_SETUP_ITEM_CXT_RES_H_

#include "PduSessionId.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceSetupItemCxtRes.h"
}

namespace oai::ngap {

class PduSessionResourceSetupItemCxtRes {
 public:
  PduSessionResourceSetupItemCxtRes();
  virtual ~PduSessionResourceSetupItemCxtRes();

  void set(
      const PduSessionId& pduSessionId,
      const OCTET_STRING_t& pduSessionResourceSetupResponseTransfer);
  void get(
      PduSessionId& pduSessionId,
      OCTET_STRING_t& pduSessionResourceSetupResponseTransfer) const;

  bool encode(
      Ngap_PDUSessionResourceSetupItemCxtRes_t& pduSessionResourceItem) const;
  bool decode(
      const Ngap_PDUSessionResourceSetupItemCxtRes_t& pduSessionResourceItem);

 private:
  PduSessionId m_PduSessionId;                               // Mandatory
  OCTET_STRING_t m_PduSessionResourceSetupResponseTransfer;  // Mandatory
};

}  // namespace oai::ngap

#endif
