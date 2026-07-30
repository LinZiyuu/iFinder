/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _DRB_STATUS_DL_H_
#define _DRB_STATUS_DL_H_

#include <optional>

#include "DrbStatusDl12.hpp"
#include "DrbStatusDl18.hpp"

extern "C" {
#include "Ngap_DRBStatusDL.h"
#include "Ngap_DRBStatusDL12.h"
#include "Ngap_DRBStatusDL18.h"
}

namespace oai::ngap {

class DrbStatusDl {
 public:
  DrbStatusDl();
  virtual ~DrbStatusDl();

  void setDrbStatusDl18(const DrbStatusDl18& dl18);
  void getDrbStatusDl18(std::optional<DrbStatusDl18>& dl18) const;

  void setDrbStatusDl12(const DrbStatusDl12& dl12);
  void getDrbStatusDl12(std::optional<DrbStatusDl12>& dl12) const;

  bool encode(Ngap_DRBStatusDL_t& dl) const;
  bool decode(const Ngap_DRBStatusDL_t& dl);

 private:
  std::optional<DrbStatusDl18> m_Dl18;
  std::optional<DrbStatusDl12> m_Dl12;
};

}  // namespace oai::ngap
#endif
