/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _UE_AGGREGATE_MAX_BITRATE_H_
#define _UE_AGGREGATE_MAX_BITRATE_H_

extern "C" {
#include "Ngap_UEAggregateMaximumBitRate.h"
}

namespace oai::ngap {

class UeAggregateMaxBitRate {
 public:
  UeAggregateMaxBitRate();
  virtual ~UeAggregateMaxBitRate();

  void set(const uint64_t& dl, const uint64_t& ul);
  bool get(uint64_t& dl, uint64_t& ul) const;

  bool encode(Ngap_UEAggregateMaximumBitRate_t& bitrate) const;
  bool decode(const Ngap_UEAggregateMaximumBitRate_t& bitrate);

 private:
  uint64_t m_Dl;
  uint64_t m_Ul;
};

}  // namespace oai::ngap

#endif
