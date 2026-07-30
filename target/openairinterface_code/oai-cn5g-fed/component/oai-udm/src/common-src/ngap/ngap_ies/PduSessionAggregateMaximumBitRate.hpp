/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PDU_SESSION_AGGREGATE_MAXIMUM_BIT_RATE_H_
#define _PDU_SESSION_AGGREGATE_MAXIMUM_BIT_RATE_H_

extern "C" {
#include "Ngap_PDUSessionAggregateMaximumBitRate.h"
}

namespace oai::ngap {

class PduSessionAggregateMaximumBitRate {
 public:
  PduSessionAggregateMaximumBitRate();
  PduSessionAggregateMaximumBitRate(
      const long& bitRateDl, const long& bitRateUl);
  virtual ~PduSessionAggregateMaximumBitRate();

  void set(const long& bitRateDl, const long& bitRateUl);
  bool get(long& bitRateDl, long& bitRateUl) const;

  bool encode(Ngap_PDUSessionAggregateMaximumBitRate_t& bitRate) const;
  bool decode(const Ngap_PDUSessionAggregateMaximumBitRate_t& bitRate);

 private:
  long m_Dl;
  long m_Ul;
};

}  // namespace oai::ngap

#endif
