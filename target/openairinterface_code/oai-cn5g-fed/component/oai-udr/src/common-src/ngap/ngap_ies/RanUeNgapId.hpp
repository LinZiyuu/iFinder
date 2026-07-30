/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _RAN_UE_NGAP_ID_H_
#define _RAN_UE_NGAP_ID_H_

extern "C" {
#include "Ngap_RAN-UE-NGAP-ID.h"
}

namespace oai::ngap {

class RanUeNgapId {
 public:
  RanUeNgapId();
  RanUeNgapId(uint32_t);
  virtual ~RanUeNgapId();

  void set(const uint32_t&);
  uint32_t get() const;

  bool encode(Ngap_RAN_UE_NGAP_ID_t&) const;
  bool decode(const Ngap_RAN_UE_NGAP_ID_t&);

 private:
  uint32_t m_Id;
};

}  // namespace oai::ngap

#endif
