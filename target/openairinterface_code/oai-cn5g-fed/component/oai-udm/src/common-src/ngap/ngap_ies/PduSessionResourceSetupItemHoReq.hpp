/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_SETUP_ITEM_HO_REQ_H_
#define _PDU_SESSION_RESOURCE_SETUP_ITEM_HO_REQ_H_

#include "PduSessionResourceItem.hpp"
#include "PduSessionResourceSetupRequestTransfer.hpp"
#include "SNssai.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceSetupItemHOReq.h"
}

namespace oai::ngap {

class PduSessionResourceSetupItemHoReq : public PduSessionResourceItem {
 public:
  PduSessionResourceSetupItemHoReq();
  virtual ~PduSessionResourceSetupItemHoReq();

  void set(
      const PduSessionId& pduSessionId, const SNssai& sNssai,
      const OCTET_STRING_t& handoverRequestTransfer);
  void get(
      PduSessionId& pduSessionId, SNssai& sNssai,
      OCTET_STRING_t& handoverRequestTransfer) const;

  bool encode(Ngap_PDUSessionResourceSetupItemHOReq_t&
                  pduSessionResourceSetupItemHOReq) const;
  bool decode(const Ngap_PDUSessionResourceSetupItemHOReq_t&
                  pduSessionResourceSetupItemHOReq);

 private:
  // PduSessionId //Mandatory;
  SNssai m_SNssai;  // Mandatory
  // Handover Request Transfer - Mandatory
};

}  // namespace oai::ngap

#endif
