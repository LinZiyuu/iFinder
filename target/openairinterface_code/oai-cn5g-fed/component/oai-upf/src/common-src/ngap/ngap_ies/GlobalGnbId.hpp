/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _GLOBAL_GNB_ID_H
#define _GLOBAL_GNB_ID_H

#include "GnbId.hpp"
#include "PlmnId.hpp"

extern "C" {
#include "Ngap_GlobalGNB-ID.h"
}

namespace oai::ngap {

class GlobalGnbId {
 public:
  GlobalGnbId();
  virtual ~GlobalGnbId();

  void set(const PlmnId& plmn, const GnbId& gnbId);
  void get(PlmnId& plmn, GnbId& gnbId) const;

  bool encode(Ngap_GlobalGNB_ID_t&) const;
  bool decode(const Ngap_GlobalGNB_ID_t&);

 private:
  PlmnId m_PlmnId;  // Mandatory
  GnbId m_GnbId;    // Mandatory
};

}  // namespace oai::ngap

#endif
