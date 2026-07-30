/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _GLOBAL_NG_ENB_ID_H
#define _GLOBAL_NG_ENB_ID_H

#include "NgEnbId.hpp"
#include "PlmnId.hpp"

extern "C" {
#include "Ngap_GlobalNgENB-ID.h"
}

namespace oai::ngap {

class GlobalNgEnbId {
 public:
  GlobalNgEnbId();
  virtual ~GlobalNgEnbId();

  void set(const PlmnId& plmn, const NgEnbId& ngEnbId);
  void get(PlmnId& plmn, NgEnbId& ngEnbId) const;

  bool encode(Ngap_GlobalNgENB_ID_t&) const;
  bool decode(const Ngap_GlobalNgENB_ID_t&);

 private:
  PlmnId m_PlmnId;    // Mandatory
  NgEnbId m_NgEnbId;  // Mandatory
};

}  // namespace oai::ngap

#endif
