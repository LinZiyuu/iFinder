/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NR_CELL_IDENTITY_H_
#define _NR_CELL_IDENTITY_H_

extern "C" {
#include "Ngap_NRCellIdentity.h"
}

namespace oai::ngap {

class NrCellIdentity {
 public:
  NrCellIdentity();
  virtual ~NrCellIdentity();

  unsigned long get() const;
  void set(const unsigned long& nrCellIdentity);

  bool encode(Ngap_NRCellIdentity_t& nrCellIdentity) const;
  bool decode(const Ngap_NRCellIdentity_t& nrCellIdentity);

 private:
  unsigned long
      m_NrCellIdentity;  // TODO: only 32 bits while NRCELL is a bitstring(36)
};
}  // namespace oai::ngap

#endif
