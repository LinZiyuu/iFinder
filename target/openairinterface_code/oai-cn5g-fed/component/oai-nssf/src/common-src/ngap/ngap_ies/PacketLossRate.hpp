/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PACKET_LOSS_RATE_H_
#define _PACKET_LOSS_RATE_H_

extern "C" {
#include "Ngap_PacketLossRate.h"
}

namespace oai::ngap {

class PacketLossRate {
 public:
  PacketLossRate();
  virtual ~PacketLossRate();

  void set(long value);
  bool get(long& value) const;

  bool encode(Ngap_PacketLossRate_t&) const;
  bool decode(const Ngap_PacketLossRate_t&);

 private:
  long m_PacketLossRate;
};

}  // namespace oai::ngap

#endif
