/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _TAC_H_
#define _TAC_H_

extern "C" {
#include "Ngap_TAC.h"
}

namespace oai::ngap {

class TAC {
 public:
  TAC();
  virtual ~TAC();

  uint32_t get() const;
  void set(const uint32_t& tac);

  bool encode(Ngap_TAC_t&) const;
  bool decode(const Ngap_TAC_t& m_tac);

 private:
  uint32_t m_Tac : 24;
};

}  // namespace oai::ngap

#endif
