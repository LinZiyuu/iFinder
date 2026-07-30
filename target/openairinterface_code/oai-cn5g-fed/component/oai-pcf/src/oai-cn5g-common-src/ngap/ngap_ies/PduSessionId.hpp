/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_ID_H_
#define _PDU_SESSION_ID_H_

extern "C" {
#include "Ngap_PDUSessionID.h"
}

namespace oai::ngap {

class PduSessionId {
 public:
  PduSessionId();
  virtual ~PduSessionId();

  void set(const uint8_t& id);
  void get(uint8_t& id) const;
  uint8_t get() const;

  bool encode(Ngap_PDUSessionID_t& pduSessionId) const;
  bool decode(Ngap_PDUSessionID_t pduSessionId);

 private:
  uint8_t m_PduSessionId;
};

}  // namespace oai::ngap

#endif
