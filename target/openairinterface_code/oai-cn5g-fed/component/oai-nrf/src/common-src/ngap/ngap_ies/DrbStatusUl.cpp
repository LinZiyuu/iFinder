/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "DrbStatusUl.hpp"

#include "logger_base.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
DrbStatusUl::DrbStatusUl() {
  m_Ul18 = std::nullopt;
  m_Ul12 = std::nullopt;
}

//------------------------------------------------------------------------------
DrbStatusUl::~DrbStatusUl() {}

//------------------------------------------------------------------------------
void DrbStatusUl::setDrbStatusUl(const DrbStatusUl18& ul18) {
  m_Ul18 = std::make_optional<DrbStatusUl18>(ul18);
  m_Ul12 = std::nullopt;
}

//------------------------------------------------------------------------------
void DrbStatusUl::getDrbStatusUl(std::optional<DrbStatusUl18>& ul18) const {
  ul18 = m_Ul18;
}

//------------------------------------------------------------------------------
void DrbStatusUl::setDrbStatusUl(const DrbStatusUl12& ul12) {
  m_Ul18 = std::nullopt;
  m_Ul12 = std::make_optional<DrbStatusUl12>(ul12);
}

//------------------------------------------------------------------------------
void DrbStatusUl::getDrbStatusUl(std::optional<DrbStatusUl12>& ul12) const {
  ul12 = m_Ul12;
}

//------------------------------------------------------------------------------
bool DrbStatusUl::encode(Ngap_DRBStatusUL_t& ul) const {
  if (m_Ul18.has_value()) {
    ul.present = Ngap_DRBStatusUL_PR_dRBStatusUL18;
    ul.choice.dRBStatusUL18 =
        (Ngap_DRBStatusUL18_t*) calloc(1, sizeof(Ngap_DRBStatusUL18_t));
    if (!m_Ul18.value().encode(*ul.choice.dRBStatusUL18)) {
      oai::logger::logger_common::ngap().error("Encode DRBStatusUL18 IE error");
      return false;
    }
  } else if (m_Ul12.has_value()) {
    ul.present = Ngap_DRBStatusUL_PR_dRBStatusUL12;
    ul.choice.dRBStatusUL12 =
        (Ngap_DRBStatusUL12_t*) calloc(1, sizeof(Ngap_DRBStatusUL12_t));
    if (!m_Ul12.value().encode(*ul.choice.dRBStatusUL12)) {
      oai::logger::logger_common::ngap().error("Encode DRBStatusUL18 IE error");
      return false;
    }
  }

  return true;
}

//------------------------------------------------------------------------------
bool DrbStatusUl::decode(const Ngap_DRBStatusUL_t& ul) {
  if (ul.present == Ngap_DRBStatusUL_PR_dRBStatusUL18) {
    DrbStatusUl18 item = {};
    if (!item.decode(*ul.choice.dRBStatusUL18)) {
      oai::logger::logger_common::ngap().error("Decode DRBStatusUL18 IE error");
      return false;
    }
    m_Ul18 = std::make_optional<DrbStatusUl18>(item);
  } else if (ul.present == Ngap_DRBStatusUL_PR_dRBStatusUL12) {
    DrbStatusUl12 item = {};
    if (!item.decode(*ul.choice.dRBStatusUL12)) {
      oai::logger::logger_common::ngap().error("Decode DRBStatusUL12 IE error");
      return false;
    }
    m_Ul12 = std::make_optional<DrbStatusUl12>(item);
  }

  return true;
}
}  // namespace oai::ngap
