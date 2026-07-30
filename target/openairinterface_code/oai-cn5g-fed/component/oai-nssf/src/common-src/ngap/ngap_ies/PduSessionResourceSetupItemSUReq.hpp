/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_SETUP_ITEM_SU_REQ_H_
#define _PDU_SESSION_RESOURCE_SETUP_ITEM_SU_REQ_H_

#include <optional>

#include "NasPdu.hpp"
#include "PduSessionId.hpp"
#include "SNssai.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceSetupItemSUReq.h"
}

namespace oai::ngap {

class PduSessionResourceSetupItemSUReq {
 public:
  PduSessionResourceSetupItemSUReq();
  virtual ~PduSessionResourceSetupItemSUReq();

  void set(
      const PduSessionId& pduSessionId, std::optional<NasPdu>& nasPdu,
      const SNssai& sNssai,
      const OCTET_STRING_t& pduSessionResourceSetupRequestTransfer);
  void get(
      PduSessionId& pduSessionId, std::optional<NasPdu>& nasPdu, SNssai& sNssai,
      OCTET_STRING_t& pduSessionResourceSetupRequestTransfer) const;

  bool encode(
      Ngap_PDUSessionResourceSetupItemSUReq_t& pduSessionResourceItem) const;
  bool decode(
      const Ngap_PDUSessionResourceSetupItemSUReq_t& pduSessionResourceItem);

 private:
  PduSessionId m_PduSessionId;                              // Mandatory
  std::optional<NasPdu> m_NasPdu;                           // Optional
  SNssai m_SNssai;                                          // Mandatory
  OCTET_STRING_t m_PduSessionResourceSetupRequestTransfer;  // Mandatory
};

}  // namespace oai::ngap

#endif
