/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _NG_ENB_ID_H_
#define _NG_ENB_ID_H_

#include "PlmnId.hpp"

extern "C" {
#include "Ngap_NgENB-ID.h"
}

namespace oai::ngap {

class NgEnbId {
 public:
  NgEnbId();
  virtual ~NgEnbId();

  void get(uint32_t& id, Ngap_NgENB_ID_PR& present) const;
  void set(const uint32_t& id, const Ngap_NgENB_ID_PR& present);

  bool encode(Ngap_NgENB_ID_t&) const;
  bool decode(const Ngap_NgENB_ID_t&);

 private:
  PlmnId m_PlmnId;  // Mandatory
  union {
    uint32_t macro_ngenb_id;
    uint32_t short_macro_ngENB_id;
    uint32_t long_macro_ngENB_id;
  } m_Id;  // Mandatory
  Ngap_NgENB_ID_PR m_Present;
};

}  // namespace oai::ngap

#endif
