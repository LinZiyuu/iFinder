/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _AMF_UE_NGAP_ID_H_
#define _AMF_UE_NGAP_ID_H_

#include <cstdint>

constexpr uint64_t AMF_UE_NGAP_ID_MAX_VALUE = 1099511627775;  // 2^40 -1

extern "C" {
#include "Ngap_AMF-UE-NGAP-ID.h"
}

namespace oai::ngap {

class AmfUeNgapId {
 public:
  AmfUeNgapId();
  virtual ~AmfUeNgapId();

  bool set(const uint64_t&);
  uint64_t get() const;

  bool encode(Ngap_AMF_UE_NGAP_ID_t&) const;
  bool decode(const Ngap_AMF_UE_NGAP_ID_t&);

 private:
  uint64_t m_AmfUeNgapId;
};

}  // namespace oai::ngap

#endif
