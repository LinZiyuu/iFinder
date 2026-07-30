/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_RESOURCE_MODIFY_ITEM_MOD_REQ_H_
#define _PDU_SESSION_RESOURCE_MODIFY_ITEM_MOD_REQ_H_

#include <optional>

#include "NasPdu.hpp"
#include "PduSessionId.hpp"
#include "SNssai.hpp"

extern "C" {
#include "Ngap_PDUSessionResourceModifyItemModReq.h"
}

namespace oai::ngap {

class PduSessionResourceModifyItemModReq {
 public:
  PduSessionResourceModifyItemModReq();
  virtual ~PduSessionResourceModifyItemModReq();

  void set(
      const PduSessionId& pduSessionId, const std::optional<NasPdu>& nasPdu,
      const OCTET_STRING_t& pduSessionResourceModifyRequestTransfer,
      const std::optional<SNssai>& sNssai);
  void get(
      PduSessionId& pduSessionId, std::optional<NasPdu>& nasPdu,
      OCTET_STRING_t& pduSessionResourceModifyRequestTransfer,
      std::optional<SNssai>& sNssai) const;

  bool encode(Ngap_PDUSessionResourceModifyItemModReq_t&
                  pduSessionResourceModifyItemModReq) const;
  bool decode(const Ngap_PDUSessionResourceModifyItemModReq_t&
                  pduSessionResourceModifyItemModReq);

 private:
  PduSessionId m_PduSessionId;                               // Mandatory
  std::optional<NasPdu> m_NasPdu;                            // Optional
  OCTET_STRING_t m_PduSessionResourceModifyRequestTransfer;  // Mandatory
  std::optional<SNssai> m_SNssai;                            // Optional
};

}  // namespace oai::ngap

#endif
