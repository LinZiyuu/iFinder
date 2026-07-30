/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_FAILED_TO_SETUP_ITEM_CXT_RES_H_
#define _PDU_SESSION_RESOURCE_FAILED_TO_SETUP_ITEM_CXT_RES_H_

#include "PduSessionId.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceFailedToSetupItemCxtRes.h"
}

namespace oai::ngap {

class PduSessionResourceFailedToSetupItemCxtRes {
 public:
  PduSessionResourceFailedToSetupItemCxtRes();
  virtual ~PduSessionResourceFailedToSetupItemCxtRes();

  void set(
      const PduSessionId& pduSessionId,
      const OCTET_STRING_t& pduSessionResource);
  void get(
      PduSessionId& pduSessionId, OCTET_STRING_t& pduSessionResource) const;

  bool encode(
      Ngap_PDUSessionResourceFailedToSetupItemCxtRes_t& pduSessionCxt) const;
  bool decode(
      const Ngap_PDUSessionResourceFailedToSetupItemCxtRes_t& pduSessionCxt);

 private:
  PduSessionId m_PduSessionId;                                   // Mandatory
  OCTET_STRING_t m_PduSessionResourceSetupUnsuccessfulTransfer;  // Mandatory
};

}  // namespace oai::ngap

#endif
