/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PACKET_ERROR_RATE_H_
#define _PACKET_ERROR_RATE_H_

extern "C" {
#include "Ngap_PacketErrorRate.h"
}

namespace oai::ngap {

class PacketErrorRate {
 public:
  PacketErrorRate();
  virtual ~PacketErrorRate();

  void set(const long& scalar, const long& exponent);
  bool get(long& scalar, long& exponent) const;

  bool encode(Ngap_PacketErrorRate_t&) const;
  bool decode(const Ngap_PacketErrorRate_t&);

 private:
  long m_Scalar;
  long m_Exponent;
};

}  // namespace oai::ngap

#endif
