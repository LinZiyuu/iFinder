/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_MODIFY_ITEM_MOD_RES_H_
#define _PDU_SESSION_RESOURCE_MODIFY_ITEM_MOD_RES_H_

#include "PduSessionId.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceModifyItemModRes.h"
}

namespace oai::ngap {

class PduSessionResourceModifyItemModRes {
 public:
  PduSessionResourceModifyItemModRes();
  virtual ~PduSessionResourceModifyItemModRes();

  void set(
      const PduSessionId& pduSessionId,
      const OCTET_STRING_t& pduSessionResourceModifyResponseTransfer);
  void get(
      PduSessionId& pduSessionId,
      OCTET_STRING_t& pduSessionResourceModifyResponseTransfer) const;

  bool encode(
      Ngap_PDUSessionResourceModifyItemModRes_t& pduSessionResourceItem) const;
  bool decode(
      const Ngap_PDUSessionResourceModifyItemModRes_t& pduSessionResourceItem);

 private:
  PduSessionId m_PduSessionId;                                // Mandatory
  OCTET_STRING_t m_PduSessionResourceModifyResponseTransfer;  // Mandatory
};

}  // namespace oai::ngap

#endif
