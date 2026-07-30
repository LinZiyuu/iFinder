/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _DRB_STATUS_UL_H_
#define _DRB_STATUS_UL_H_

#include <optional>

#include "DrbStatusUl12.hpp"
#include "DrbStatusUl18.hpp"

extern "C" {
#include "Ngap_DRBStatusUL.h"
}

namespace oai::ngap {
class DrbStatusUl {
 public:
  DrbStatusUl();
  virtual ~DrbStatusUl();

  void setDrbStatusUl(const DrbStatusUl18& ul18);
  void getDrbStatusUl(std::optional<DrbStatusUl18>& ul18) const;

  void setDrbStatusUl(const DrbStatusUl12& ul12);
  void getDrbStatusUl(std::optional<DrbStatusUl12>& ul12) const;

  bool encode(Ngap_DRBStatusUL_t& ul) const;
  bool decode(const Ngap_DRBStatusUL_t& ul);

 private:
  std::optional<DrbStatusUl18> m_Ul18;
  std::optional<DrbStatusUl12> m_Ul12;
};
}  // namespace oai::ngap
#endif
