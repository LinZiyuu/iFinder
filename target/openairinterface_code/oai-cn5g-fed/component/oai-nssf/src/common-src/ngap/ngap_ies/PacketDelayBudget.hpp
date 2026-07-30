/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _PACKET_DELAY_BUDGET_H_
#define _PACKET_DELAY_BUDGET_H_

extern "C" {
#include "Ngap_PacketDelayBudget.h"
}

namespace oai::ngap {

class PacketDelayBudget {
 public:
  PacketDelayBudget();
  virtual ~PacketDelayBudget();

  void set(const long& value);
  bool get(long& value) const;

  bool encode(Ngap_PacketDelayBudget_t&) const;
  bool decode(const Ngap_PacketDelayBudget_t&);

 private:
  long m_PacketDelayBudget;
};

}  // namespace oai::ngap

#endif
