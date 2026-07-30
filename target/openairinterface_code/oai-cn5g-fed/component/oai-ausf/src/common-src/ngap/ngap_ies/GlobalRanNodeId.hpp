/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef _GLOBAL_RAN_NODE_ID_H_
#define _GLOBAL_RAN_NODE_ID_H_

extern "C" {
#include "Ngap_GlobalRANNodeID.h"
}

#include <optional>

#include "GlobalGnbId.hpp"
#include "GlobalNgEnbId.hpp"

namespace oai::ngap {

class GlobalRanNodeId {
 public:
  GlobalRanNodeId();
  virtual ~GlobalRanNodeId();

  void set(const GlobalGnbId& globalGnbId);
  bool get(GlobalGnbId& globalGnbId) const;

  void set(const GlobalNgEnbId& globalNgEnbId);
  bool get(GlobalNgEnbId& globalNgEnbId) const;

  void setChoiceOfRanNodeId(const Ngap_GlobalRANNodeID_PR& idPresent);
  Ngap_GlobalRANNodeID_PR getChoiceOfRanNodeId() const;

  bool encode(Ngap_GlobalRANNodeID_t&) const;
  bool decode(const Ngap_GlobalRANNodeID_t&);

 private:
  std::optional<GlobalGnbId> m_GlobalGnbId;
  std::optional<GlobalNgEnbId> m_GlobalNgEnbId;
  // TODO: Global N3IWF ID
  Ngap_GlobalRANNodeID_PR m_IdPresent;
};

}  // namespace oai::ngap

#endif
