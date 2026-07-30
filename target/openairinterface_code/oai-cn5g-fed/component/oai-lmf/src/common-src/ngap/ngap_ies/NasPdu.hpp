/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NAS_PDU_H_
#define _NAS_PDU_H_

#include "bstrlib.h"

extern "C" {
#include "Ngap_NAS-PDU.h"
}

namespace oai::ngap {

class NasPdu {
 public:
  NasPdu();
  virtual ~NasPdu();

  // bool get(uint8_t*& buffer, size_t& size) const;
  void set(uint8_t* buffer, size_t size);

  bool get(OCTET_STRING_t& pdu) const;
  bool set(const OCTET_STRING_t& pdu);

  bool get(bstring& pdu) const;
  bool set(const bstring& pdu);

  bool get(NasPdu& nasPdu) const;
  bool set(const NasPdu& nasPdu);

  bool encode(Ngap_NAS_PDU_t&) const;
  bool decode(const Ngap_NAS_PDU_t&);

 private:
  bstring m_Pdu;
};

}  // namespace oai::ngap

#endif
