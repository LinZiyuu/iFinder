/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_TYPE_H_
#define _PDU_SESSION_TYPE_H_

extern "C" {
#include "Ngap_PDUSessionType.h"
}

namespace oai::ngap {

class PduSessionType {
 public:
  PduSessionType();
  virtual ~PduSessionType();

  void set(e_Ngap_PDUSessionType pduSessionType);
  bool get(long& pduSessionType) const;

  bool encode(Ngap_PDUSessionType_t&) const;
  bool decode(const Ngap_PDUSessionType_t&);

 private:
  long m_PduSessionType;
};

}  // namespace oai::ngap

#endif
