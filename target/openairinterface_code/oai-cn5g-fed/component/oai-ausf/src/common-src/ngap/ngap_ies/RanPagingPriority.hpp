/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _RAN_PAGING_PRIORITY_H_
#define _RAN_PAGING_PRIORITY_H_

#include <cstdint>

constexpr uint32_t kRANPagingPriorityMaxValue = 256;

extern "C" {
#include "Ngap_RANPagingPriority.h"
}

namespace oai::ngap {

class RanPagingPriority {
 public:
  RanPagingPriority();
  virtual ~RanPagingPriority();

  bool set(const uint32_t&);
  uint32_t get() const;

  bool encode(Ngap_RANPagingPriority_t&) const;
  bool decode(const Ngap_RANPagingPriority_t&);

 private:
  uint32_t m_RanPagingPriority;
};

}  // namespace oai::ngap

#endif
