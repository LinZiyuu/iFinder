/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "GlobalRanNodeId.hpp"

#include "logger_base.hpp"

namespace oai::ngap {

//------------------------------------------------------------------------------
GlobalRanNodeId::GlobalRanNodeId() {
  m_GlobalGnbId   = std::nullopt;
  m_GlobalNgEnbId = std::nullopt;
  m_IdPresent     = Ngap_GlobalRANNodeID_PR_NOTHING;
}

//------------------------------------------------------------------------------
GlobalRanNodeId::~GlobalRanNodeId() {}

//------------------------------------------------------------------------------
void GlobalRanNodeId::setChoiceOfRanNodeId(
    const Ngap_GlobalRANNodeID_PR& idPresent) {
  m_IdPresent = idPresent;
}

//------------------------------------------------------------------------------
Ngap_GlobalRANNodeID_PR GlobalRanNodeId::getChoiceOfRanNodeId() const {
  return m_IdPresent;
}

//------------------------------------------------------------------------------
void GlobalRanNodeId::set(const GlobalGnbId& globalGnbId) {
  m_GlobalGnbId = std::optional<GlobalGnbId>{globalGnbId};
  m_IdPresent   = Ngap_GlobalRANNodeID_PR_globalGNB_ID;
}

//------------------------------------------------------------------------------
void GlobalRanNodeId::set(const GlobalNgEnbId& globalNgEnbId) {
  m_GlobalNgEnbId = std::optional<GlobalNgEnbId>{globalNgEnbId};
  m_IdPresent     = Ngap_GlobalRANNodeID_PR_globalNgENB_ID;
}

//------------------------------------------------------------------------------
bool GlobalRanNodeId::get(GlobalGnbId& globalGnbId) const {
  if (m_GlobalGnbId.has_value()) {
    globalGnbId = m_GlobalGnbId.value();
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
bool GlobalRanNodeId::get(GlobalNgEnbId& globalNgEnbId) const {
  if (m_GlobalNgEnbId.has_value()) {
    globalNgEnbId = m_GlobalNgEnbId.value();
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
bool GlobalRanNodeId::encode(Ngap_GlobalRANNodeID_t& globalRANNodeID) const {
  globalRANNodeID.present = m_IdPresent;

  switch (m_IdPresent) {
    case Ngap_GlobalRANNodeID_PR_globalGNB_ID: {
      globalRANNodeID.choice.globalGNB_ID =
          (Ngap_GlobalGNB_ID_t*) calloc(1, sizeof(struct Ngap_GlobalGNB_ID));
      if (!globalRANNodeID.choice.globalGNB_ID) return false;
      if (!m_GlobalGnbId.value().encode(*globalRANNodeID.choice.globalGNB_ID))
        return false;
      break;
    }
    case Ngap_GlobalRANNodeID_PR_globalNgENB_ID: {
      // TODO:
      break;
    }
    case Ngap_GlobalRANNodeID_PR_globalN3IWF_ID: {
      // TODO:
      break;
    }
    default:
      oai::logger::logger_common::ngap().warn(
          "GlobalRanNodeId Present encode error!");
      return false;
  }
  return true;
}

//------------------------------------------------------------------------------
bool GlobalRanNodeId::decode(const Ngap_GlobalRANNodeID_t& globalRANNodeID) {
  m_IdPresent = globalRANNodeID.present;

  switch (m_IdPresent) {
    case Ngap_GlobalRANNodeID_PR_globalGNB_ID: {
      GlobalGnbId tmp = {};
      if (!tmp.decode(*globalRANNodeID.choice.globalGNB_ID)) return false;
      m_GlobalGnbId = std::optional<GlobalGnbId>(tmp);
      break;
    }
    case Ngap_GlobalRANNodeID_PR_globalNgENB_ID: {
      // TODO:
      oai::logger::logger_common::ngap().warn(
          "GlobalRANNodeID Present is globalNgENB!");
      break;
    }
    case Ngap_GlobalRANNodeID_PR_globalN3IWF_ID: {
      // TODO:
      oai::logger::logger_common::ngap().warn(
          "GlobalRANNodeID Present is globalN3IWF!");
      break;
    }
    default:
      oai::logger::logger_common::ngap().warn(
          "GlobalRanNodeId Present decode error!");
      return false;
  }
  return true;
}
}  // namespace oai::ngap
