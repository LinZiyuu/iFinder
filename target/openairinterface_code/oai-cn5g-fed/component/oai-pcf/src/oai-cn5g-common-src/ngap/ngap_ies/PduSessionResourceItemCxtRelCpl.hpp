/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_ITEM_CXT_REL_CPL_H_
#define _PDU_SESSION_RESOURCE_ITEM_CXT_REL_CPL_H_

#include "PduSessionId.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceItemCxtRelCpl.h"
}

namespace oai::ngap {

class PduSessionResourceItemCxtRelCpl {
 public:
  PduSessionResourceItemCxtRelCpl();
  virtual ~PduSessionResourceItemCxtRelCpl();

  void set(const PduSessionId& pduSessionId);
  void get(PduSessionId& pduSessionId) const;

  bool encode(
      Ngap_PDUSessionResourceItemCxtRelCpl_t& pduSessionResourceItem) const;
  bool decode(
      const Ngap_PDUSessionResourceItemCxtRelCpl_t& pduSessionResourceItem);

 private:
  PduSessionId m_PduSessionId;  // Mandatory
  // TODO (not defined in ASN1C) OCTET_STRING_t
  // pdu_session_resource_release_response_transfer_; //Optional
};

}  // namespace oai::ngap

#endif
