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

  uint64_t get() const;
  void set(const uint64_t& nrCellIdentity);

  bool encode(Ngap_NRCellIdentity_t& nrCellIdentity) const;
  bool decode(const Ngap_NRCellIdentity_t& nrCellIdentity);

 private:
  uint64_t m_NrCellIdentity;
};
}  // namespace oai::ngap

#endif
