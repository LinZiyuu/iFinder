/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
#include "DrbStatusDl.hpp"

#include "logger_base.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
DrbStatusDl::DrbStatusDl() {
  m_Dl18 = std::nullopt;
  m_Dl12 = std::nullopt;
}

//------------------------------------------------------------------------------
DrbStatusDl::~DrbStatusDl() {}

//------------------------------------------------------------------------------
void DrbStatusDl::setDrbStatusDl18(const DrbStatusDl18& dl18) {
  m_Dl18 = std::make_optional<DrbStatusDl18>(dl18);
  m_Dl12 = std::nullopt;
}

//------------------------------------------------------------------------------
void DrbStatusDl::getDrbStatusDl18(std::optional<DrbStatusDl18>& dl18) const {
  dl18 = m_Dl18;
}

//------------------------------------------------------------------------------
void DrbStatusDl::setDrbStatusDl12(const DrbStatusDl12& dl12) {
  m_Dl18 = std::nullopt;
  m_Dl12 = std::make_optional<DrbStatusDl12>(dl12);
}

//------------------------------------------------------------------------------
void DrbStatusDl::getDrbStatusDl12(std::optional<DrbStatusDl12>& dl12) const {
  dl12 = m_Dl12;
}

//------------------------------------------------------------------------------
bool DrbStatusDl::encode(Ngap_DRBStatusDL_t& dl) const {
  if (m_Dl18.has_value()) {
    dl.present = Ngap_DRBStatusDL_PR_dRBStatusDL18;
    dl.choice.dRBStatusDL18 =
        (Ngap_DRBStatusDL18_t*) calloc(1, sizeof(Ngap_DRBStatusDL18_t));
    if (!m_Dl18.value().encode(*dl.choice.dRBStatusDL18)) {
      oai::logger::logger_common::ngap().error("Encode DRBStatusDL18 IE error");
      return false;
    }
  } else if (m_Dl12.has_value()) {
    dl.present = Ngap_DRBStatusDL_PR_dRBStatusDL12;
    dl.choice.dRBStatusDL12 =
        (Ngap_DRBStatusDL12_t*) calloc(1, sizeof(Ngap_DRBStatusDL12_t));
    if (!m_Dl12.value().encode(*dl.choice.dRBStatusDL12)) {
      oai::logger::logger_common::ngap().error("Encode DRBStatusDL12 IE error");
      return false;
    }
  }
  return true;
}

//------------------------------------------------------------------------------
bool DrbStatusDl::decode(const Ngap_DRBStatusDL_t& dl) {
  if (dl.present == Ngap_DRBStatusDL_PR_dRBStatusDL18) {
    DrbStatusDl18 dl18 = {};
    if (!dl18.decode(*dl.choice.dRBStatusDL18)) {
      oai::logger::logger_common::ngap().error("Decode DRBStatusDL18 IE error");
      return false;
    }
    m_Dl18 = std::make_optional<DrbStatusDl18>(dl18);
  } else if (dl.present == Ngap_DRBStatusDL_PR_dRBStatusDL12) {
    DrbStatusDl12 dl12 = {};
    if (!dl12.decode(*dl.choice.dRBStatusDL12)) {
      oai::logger::logger_common::ngap().error("Decode DRBStatusDL12 IE error");
      return false;
    }
    m_Dl12 = std::make_optional<DrbStatusDl12>(dl12);
  }
  return true;
}
}  // namespace oai::ngap
